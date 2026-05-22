//! Pure-Rust read-only legacy VHD disk image reader.
//!
//! Implements the MS-VHD specification (Virtual PC / Virtual Server / Hyper-V
//! Generation-1 format). Supports Fixed and Dynamic disk types. Differencing
//! disks are rejected (parent locator resolution is out of scope).
//!
//! # Format overview
//! Every VHD ends with a 512-byte footer (`cookie = "conectix"`).
//! - **Fixed**: the footer immediately follows the raw sector data.
//! - **Dynamic**: footer → dynamic header → Block Allocation Table (BAT)
//!   → data blocks, with a copy of the footer at byte 0.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

mod error;
mod dynamic;

#[cfg(feature = "test-helpers")]
pub mod footer;
#[cfg(not(feature = "test-helpers"))]
mod footer;

pub use error::VhdError;
pub use footer::{DiskType, VhdFooter};

/// Read-only VHD container reader.
///
/// Implements `Read + Seek` over the virtual sector stream.
pub struct VhdReader {
    inner: VhdInner,
    pos: u64,
    virtual_disk_size: u64,
}

enum VhdInner {
    Fixed {
        file: std::fs::File,
    },
    Dynamic {
        file: std::fs::File,
        bat: dynamic::BlockAllocationTable,
        block_size: u32,
    },
}

impl VhdReader {
    /// Open a VHD disk image.
    ///
    /// Returns [`VhdError`] if the file is not a valid VHD, or if it is a
    /// Differencing disk (parent resolution is not supported).
    pub fn open(path: &Path) -> Result<Self, VhdError> {
        let data = std::fs::read(path)?;
        let footer = footer::VhdFooter::parse(&data)?;

        let (inner, virtual_disk_size) = match footer.disk_type {
            footer::DiskType::Fixed => {
                let file = std::fs::File::open(path)?;
                (VhdInner::Fixed { file }, footer.current_size)
            }
            footer::DiskType::Dynamic => {
                let dyn_hdr = dynamic::DynamicHeader::parse(&data, footer.data_offset)?;
                let bat = dynamic::BlockAllocationTable::parse(&data, &dyn_hdr)?;
                let file = std::fs::File::open(path)?;
                let size = footer.current_size;
                (VhdInner::Dynamic { file, bat, block_size: dyn_hdr.block_size }, size)
            }
        };

        Ok(VhdReader { inner, pos: 0, virtual_disk_size })
    }

    /// Virtual disk size in bytes as recorded in the VHD footer.
    pub fn virtual_disk_size(&self) -> u64 {
        self.virtual_disk_size
    }

    /// Disk type (Fixed or Dynamic).
    pub fn disk_type(&self) -> DiskType {
        match &self.inner {
            VhdInner::Fixed { .. } => DiskType::Fixed,
            VhdInner::Dynamic { .. } => DiskType::Dynamic,
        }
    }
}

impl Read for VhdReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.virtual_disk_size || buf.is_empty() {
            return Ok(0);
        }
        let remaining = (self.virtual_disk_size - self.pos) as usize;
        let to_read = buf.len().min(remaining);

        match &mut self.inner {
            VhdInner::Fixed { file } => {
                file.seek(SeekFrom::Start(self.pos))?;
                let n = file.read(&mut buf[..to_read])?;
                self.pos += n as u64;
                Ok(n)
            }
            VhdInner::Dynamic { file, bat, block_size } => {
                let block_size_u64 = u64::from(*block_size);
                let block_end = ((self.pos / block_size_u64) + 1) * block_size_u64;
                let chunk = to_read.min((block_end - self.pos) as usize);

                match bat.file_offset_for_byte(self.pos)
                    .map_err(|e| std::io::Error::other(e.to_string()))?
                {
                    Some(file_off) => {
                        file.seek(SeekFrom::Start(file_off))?;
                        let n = file.read(&mut buf[..chunk])?;
                        self.pos += n as u64;
                        Ok(n)
                    }
                    None => {
                        // Sparse block — return zeroes.
                        buf[..chunk].fill(0);
                        self.pos += chunk as u64;
                        Ok(chunk)
                    }
                }
            }
        }
    }
}

impl Seek for VhdReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::Current(n) => self.pos as i64 + n,
            SeekFrom::End(n) => self.virtual_disk_size as i64 + n,
        };
        if new_pos < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal valid Fixed VHD: 512 bytes of sector data + 512-byte footer.
    fn fixed_vhd_bytes(sector_data: &[u8]) -> Vec<u8> {
        let mut buf = sector_data.to_vec();
        buf.extend_from_slice(&footer::test_fixed_footer(sector_data.len() as u64));
        buf
    }

    fn write_tmp(data: &[u8]) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f
    }

    #[test]
    fn open_nonexistent_returns_err() {
        assert!(VhdReader::open(Path::new("/tmp/no_such.vhd")).is_err());
    }

    #[test]
    fn open_empty_file_returns_err() {
        let f = write_tmp(&[]);
        assert!(VhdReader::open(f.path()).is_err());
    }

    #[test]
    fn open_non_vhd_file_returns_err() {
        let f = write_tmp(b"this is not a vhd file at all, no footer here");
        assert!(VhdReader::open(f.path()).is_err());
    }

    #[test]
    fn fixed_vhd_size_matches_footer() {
        let sector = vec![0u8; 512];
        let vhd = fixed_vhd_bytes(&sector);
        let f = write_tmp(&vhd);
        let reader = VhdReader::open(f.path()).expect("open fixed vhd");
        assert_eq!(reader.virtual_disk_size(), 512);
    }

    #[test]
    fn fixed_vhd_disk_type_is_fixed() {
        let sector = vec![0u8; 512];
        let vhd = fixed_vhd_bytes(&sector);
        let f = write_tmp(&vhd);
        let reader = VhdReader::open(f.path()).expect("open fixed vhd");
        assert_eq!(reader.disk_type(), DiskType::Fixed);
    }

    #[test]
    fn fixed_vhd_read_returns_sector_data() {
        let mut sector = vec![0u8; 512];
        sector[42] = 0xDE;
        sector[43] = 0xAD;
        let vhd = fixed_vhd_bytes(&sector);
        let f = write_tmp(&vhd);
        let mut reader = VhdReader::open(f.path()).expect("open");
        let mut buf = vec![0u8; 512];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(buf[42], 0xDE);
        assert_eq!(buf[43], 0xAD);
    }

    #[test]
    fn seek_and_read_at_offset() {
        let mut sector = vec![0u8; 512];
        sector[100] = 0xBE;
        sector[101] = 0xEF;
        let vhd = fixed_vhd_bytes(&sector);
        let f = write_tmp(&vhd);
        let mut reader = VhdReader::open(f.path()).expect("open");
        reader.seek(SeekFrom::Start(100)).unwrap();
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0xBE, 0xEF]);
    }

    #[test]
    fn differencing_disk_returns_err() {
        // A footer with disk_type=4 (Differencing) must be rejected.
        let mut footer_bytes = footer::test_fixed_footer(512);
        // Disk type field is at offset 60 in the footer; set to 4.
        footer_bytes[60] = 0;
        footer_bytes[61] = 0;
        footer_bytes[62] = 0;
        footer_bytes[63] = 4;
        let mut vhd = vec![0u8; 512];
        vhd.extend_from_slice(&footer_bytes);
        let f = write_tmp(&vhd);
        assert!(VhdReader::open(f.path()).is_err());
    }

    #[test]
    fn vhd_reader_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<VhdReader>();
    }
}
