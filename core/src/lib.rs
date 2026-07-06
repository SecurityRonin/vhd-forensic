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

mod dynamic;
mod error;

#[cfg(feature = "test-helpers")]
pub mod footer;
#[cfg(not(feature = "test-helpers"))]
mod footer;

pub use error::VhdError;
pub use footer::{DiskType, VhdFooter};

/// A seekable, thread-safe byte source the reader can sit on: a `File`, an
/// in-RAM `Cursor`, or a positioned sub-range of a `.zip`. Lets a caller open a
/// VHD straight out of an archive (no temp-file extraction) via
/// [`VhdReader::open_reader`], while [`VhdReader::open`] keeps the file-path
/// convenience.
pub trait ReadSeekSend: Read + Seek + Send + Sync {}
impl<T: Read + Seek + Send + Sync> ReadSeekSend for T {}

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
        file: Box<dyn ReadSeekSend>,
    },
    Dynamic {
        file: Box<dyn ReadSeekSend>,
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
        Self::open_reader(Box::new(std::fs::File::open(path)?))
    }

    /// Open a VHD image from any seekable byte source (a `Cursor` over inflated
    /// bytes, a positioned sub-range of a `.zip`, …) rather than a file path —
    /// so an image stored inside an archive can be read without extracting it to
    /// a temp file first.
    pub fn open_reader(mut backing: Box<dyn ReadSeekSend>) -> Result<Self, VhdError> {
        // The footer (last 512 B) + dynamic header + BAT parsers take a whole-file
        // slice, so materialize the backing once (the file-path `open` did the
        // same via `std::fs::read`). The backing is then kept for block reads.
        let mut data = Vec::new();
        backing.read_to_end(&mut data)?;
        let footer = footer::VhdFooter::parse(&data)?;

        let (inner, virtual_disk_size) = match footer.disk_type {
            footer::DiskType::Fixed => (VhdInner::Fixed { file: backing }, footer.current_size),
            footer::DiskType::Dynamic => {
                let dyn_hdr = dynamic::DynamicHeader::parse(&data, footer.data_offset)?;
                let bat = dynamic::BlockAllocationTable::parse(&data, &dyn_hdr)?;
                (
                    VhdInner::Dynamic {
                        file: backing,
                        bat,
                        block_size: dyn_hdr.block_size,
                    },
                    footer.current_size,
                )
            }
        };

        Ok(VhdReader {
            inner,
            pos: 0,
            virtual_disk_size,
        })
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
            VhdInner::Dynamic {
                file,
                bat,
                block_size,
            } => {
                let block_size_u64 = u64::from(*block_size);
                let block_end = ((self.pos / block_size_u64) + 1) * block_size_u64;
                let chunk = to_read.min((block_end - self.pos) as usize);

                if let Some(file_off) = bat
                    .file_offset_for_byte(self.pos)
                    .map_err(|e| std::io::Error::other(e.to_string()))?
                {
                    file.seek(SeekFrom::Start(file_off))?;
                    let n = file.read(&mut buf[..chunk])?;
                    self.pos += n as u64;
                    Ok(n)
                } else {
                    // Sparse block — return zeroes.
                    buf[..chunk].fill(0);
                    self.pos += chunk as u64;
                    Ok(chunk)
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
    fn open_reader_over_cursor_matches_open_path() {
        use std::io::Cursor;
        let sector: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let image = fixed_vhd_bytes(&sector);

        // Oracle: open(path) and read the whole virtual disk.
        let tmp = write_tmp(&image);
        let mut via_path = VhdReader::open(tmp.path()).expect("open path");
        let mut want = Vec::new();
        via_path.read_to_end(&mut want).expect("read path");

        // Under test: open_reader over an in-RAM Cursor of the SAME bytes — the
        // zip-direct backing path.
        let mut via_reader =
            VhdReader::open_reader(Box::new(Cursor::new(image.clone()))).expect("open_reader");
        let mut got = Vec::new();
        via_reader.read_to_end(&mut got).expect("read reader");

        assert_eq!(
            got, want,
            "open_reader must read byte-identically to open(path)"
        );
        assert_eq!(via_reader.virtual_disk_size(), via_path.virtual_disk_size());
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

    // ── block_size=0 in dynamic header must be rejected, not panic ────────────
    //
    // A crafted dynamic VHD with block_size=0 causes div-by-zero in:
    //   file_offset_for_byte: virtual_byte / block_size
    //   Read::read: self.pos / block_size_u64
    // open() must return Err before reaching those sites.
    #[test]
    fn dynamic_vhd_block_size_zero_rejected() {
        use std::io::Write;

        const BLOCK_SIZE: u64 = 0; // deliberately invalid
        let mut file = vec![0u8; 4096];

        let footer = {
            let mut f = vec![0u8; 512];
            f[0..8].copy_from_slice(b"conectix");
            f[8..12].copy_from_slice(&0x0000_0002u32.to_be_bytes());
            f[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes());
            f[16..24].copy_from_slice(&512u64.to_be_bytes());
            f[40..48].copy_from_slice(&(512u64).to_be_bytes()); // original_size (offset 40)
            f[48..56].copy_from_slice(&(512u64).to_be_bytes()); // current_size (offset 48)
            f[60..64].copy_from_slice(&3u32.to_be_bytes()); // Dynamic
            let mut s: u32 = 0;
            for (i, &b) in f.iter().enumerate() {
                if !(64..68).contains(&i) {
                    s = s.wrapping_add(u32::from(b));
                }
            }
            f[64..68].copy_from_slice(&(!s).to_be_bytes());
            f
        };

        file[0..512].copy_from_slice(&footer);
        file[3584..4096].copy_from_slice(&footer);
        file[512..520].copy_from_slice(b"cxsparse");
        file[512 + 16..512 + 24].copy_from_slice(&1536u64.to_be_bytes());
        file[512 + 28..512 + 32].copy_from_slice(&1u32.to_be_bytes());
        file[512 + 32..512 + 36].copy_from_slice(&(BLOCK_SIZE as u32).to_be_bytes()); // 0!

        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&file).unwrap();
        assert!(
            VhdReader::open(tmp.path()).is_err(),
            "block_size=0 must be rejected at open() to prevent div-by-zero"
        );
    }

    // ── BITMAP_SECTORS must be computed from block_size, not hardcoded to 1 ────
    //
    // MS-VHD spec §2.3: each dynamic block is preceded by a sector bitmap whose
    // size (in sectors) = ((block_size / (8 * 512) + 511) & ~511) / 512.
    // For the standard 2 MiB block_size this is 1 sector; for 4 MiB it is 2.
    // Hardcoding BITMAP_SECTORS = 1 causes 4 MiB blocks to be mis-read by exactly
    // 512 bytes — returning the second bitmap sector instead of the first data sector.
    #[test]
    fn bitmap_sectors_computed_for_4mib_block_size() {
        use std::io::Write;

        // Build a minimal dynamic VHD with block_size = 4 MiB.
        //
        // File layout (all offsets in bytes):
        //   [0..512)   : footer copy (dynamic, data_offset=512, virtual_size=4MiB)
        //   [512..1536): dynamic header (bat_offset=1536, block_size=4MiB, max_bat_entries=1)
        //   [1536..2048): BAT (entry 0 = sector 4, padded)
        //   [2048..2560): block 0 bitmap sector 1 (0xFF — all sectors present)
        //   [2560..3072): block 0 bitmap sector 2 (0xFF)
        //   [3072..3584): block 0 data sector 0 (0xAB pattern — the "right" answer)
        //   [3584..4096): real footer (same as copy)

        const BLOCK_SIZE: u64 = 4 * 1024 * 1024;
        let mut file = vec![0u8; 4096];

        // Footer builder (dynamic disk type).
        let footer = {
            let mut f = vec![0u8; 512];
            f[0..8].copy_from_slice(b"conectix");
            f[8..12].copy_from_slice(&0x0000_0002u32.to_be_bytes()); // features
            f[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes()); // file format version
            f[16..24].copy_from_slice(&512u64.to_be_bytes()); // data_offset → dynamic header
            f[40..48].copy_from_slice(&BLOCK_SIZE.to_be_bytes()); // original_size (offset 40)
            f[48..56].copy_from_slice(&BLOCK_SIZE.to_be_bytes()); // current_size (offset 48)
            f[60..64].copy_from_slice(&3u32.to_be_bytes()); // disk_type = Dynamic
                                                            // One's-complement checksum (bytes 64-67 zeroed during computation).
            let mut s: u32 = 0;
            for (i, &b) in f.iter().enumerate() {
                if !(64..68).contains(&i) {
                    s = s.wrapping_add(u32::from(b));
                }
            }
            f[64..68].copy_from_slice(&(!s).to_be_bytes());
            f
        };

        file[0..512].copy_from_slice(&footer); // footer copy
        file[3584..4096].copy_from_slice(&footer); // real footer at end

        // Dynamic header (bat_offset=1536, block_size=4MiB, max_bat_entries=1).
        file[512..520].copy_from_slice(b"cxsparse");
        file[512 + 16..512 + 24].copy_from_slice(&1536u64.to_be_bytes()); // bat_offset
        file[512 + 28..512 + 32].copy_from_slice(&1u32.to_be_bytes()); // max_bat_entries
        file[512 + 32..512 + 36].copy_from_slice(&(BLOCK_SIZE as u32).to_be_bytes()); // block_size

        // BAT: entry 0 = sector 4 (byte 2048 = start of block 0).
        file[1536..1540].copy_from_slice(&4u32.to_be_bytes());

        // Block 0 bitmap: 2 sectors × 0xFF (all 512-byte sectors present).
        file[2048..2560].fill(0xFF); // bitmap sector 1
        file[2560..3072].fill(0xFF); // bitmap sector 2

        // Block 0 data: known sentinel. The test asserts this is what we read.
        // With BITMAP_SECTORS=1 (bug), the reader skips only 1 sector and reads
        // bytes [2560..3072) which are 0xFF (bitmap) — mismatch.
        file[3072..3584].fill(0xAB);

        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&file).unwrap();

        let mut reader = VhdReader::open(tmp.path()).expect("open synthetic 4MiB-block vhd");
        let mut buf = [0u8; 512];
        reader.seek(SeekFrom::Start(0)).unwrap();
        reader
            .read_exact(&mut buf)
            .expect("read block 0 data sector 0");
        assert_eq!(
            buf, [0xABu8; 512],
            "with 4 MiB block_size, bitmap is 2 sectors (1024 bytes); \
             BITMAP_SECTORS must not be hardcoded to 1"
        );
    }

    // ── Differential test: bytes must match qemu-img convert -O raw output ────
    //
    // VHD uses CHS geometry, so the virtual size gets rounded from the source.
    // Strategy: raw → VHD → raw_reference (both via qemu-img), then compare
    // our reader output against raw_reference. qemu-img is authoritative for
    // both conversions; we need not predict the CHS-rounded size ourselves.

    #[test]
    fn reads_match_qemu_raw_convert() {
        const QEMU_IMG: &str = "/opt/homebrew/bin/qemu-img";
        if !Path::new(QEMU_IMG).exists() {
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");

        // 1 MiB source with a deterministic non-trivial pattern.
        let size: usize = 1 << 20;
        let source_data: Vec<u8> = (0..size).map(|i| (i ^ (i >> 8)) as u8).collect();
        let raw_path = tmp.path().join("source.raw");
        std::fs::write(&raw_path, &source_data).expect("write raw");

        // raw → VHD (dynamic, qemu default VPC format).
        let vhd_path = tmp.path().join("test.vhd");
        let ok = std::process::Command::new(QEMU_IMG)
            .args([
                "convert",
                "-O",
                "vpc",
                raw_path.to_str().unwrap(),
                vhd_path.to_str().unwrap(),
            ])
            .status()
            .expect("spawn qemu-img")
            .success();
        assert!(ok, "qemu-img raw→vpc failed");

        // VHD → reference raw (qemu-img resolves CHS rounding authoritatively).
        let ref_path = tmp.path().join("reference.raw");
        let ok = std::process::Command::new(QEMU_IMG)
            .args([
                "convert",
                "-O",
                "raw",
                vhd_path.to_str().unwrap(),
                ref_path.to_str().unwrap(),
            ])
            .status()
            .expect("spawn qemu-img")
            .success();
        assert!(ok, "qemu-img vpc→raw failed");
        let ref_data = std::fs::read(&ref_path).expect("read reference raw");

        let mut reader = VhdReader::open(&vhd_path).expect("open vhd");
        let vhd_size = reader.virtual_disk_size() as usize;
        assert_eq!(
            vhd_size,
            ref_data.len(),
            "virtual_disk_size must match qemu-img reference raw size"
        );

        // Sample every 64 KiB (covers block boundaries) plus near-end.
        let step = 65536usize;
        let mut offset = 0usize;
        while offset < vhd_size {
            let len = 512.min(vhd_size - offset);
            let mut buf = vec![0u8; len];
            reader.seek(SeekFrom::Start(offset as u64)).expect("seek");
            reader.read_exact(&mut buf).expect("read");
            assert_eq!(
                buf,
                ref_data[offset..offset + len],
                "byte mismatch at offset {offset:#x}",
            );
            offset += step;
        }
        if vhd_size >= 512 {
            let end = vhd_size - 512;
            let mut buf = vec![0u8; 512];
            reader
                .seek(SeekFrom::Start(end as u64))
                .expect("seek near-end");
            reader.read_exact(&mut buf).expect("read near-end");
            assert_eq!(buf, ref_data[end..end + 512], "byte mismatch near end");
        }
    }

    // ── Corpus differential tests: real qemu-img generated VHDs ──────────────

    fn corpus_vhd_matches_raw(corpus: &Path) {
        const QEMU_IMG: &str = "/opt/homebrew/bin/qemu-img";
        if !Path::new(QEMU_IMG).exists() || !corpus.exists() {
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        let ref_path = tmp.path().join("reference.raw");
        let ok = std::process::Command::new(QEMU_IMG)
            .args([
                "convert",
                "-O",
                "raw",
                corpus.to_str().unwrap(),
                ref_path.to_str().unwrap(),
            ])
            .status()
            .expect("spawn qemu-img")
            .success();
        assert!(ok, "qemu-img convert failed for {}", corpus.display());
        let ref_data = std::fs::read(&ref_path).expect("read raw");

        let mut reader = VhdReader::open(corpus).expect("open");
        let vhd_size = reader.virtual_disk_size() as usize;
        // qemu's vpc driver computes total_sectors = file_size / 512 for fixed
        // VHDs, treating the 512-byte footer as a trailing data sector.
        // Our reader follows the spec: virtual_disk_size = current_size (data only).
        // Accept ref_data being exactly vhd_size OR vhd_size + 512.
        assert!(
            ref_data.len() == vhd_size || ref_data.len() == vhd_size + 512,
            "unexpected ref raw size {} vs vhd_size {} for {}",
            ref_data.len(),
            vhd_size,
            corpus.display(),
        );
        let cmp_size = vhd_size; // never compare footer bytes

        let step = 65536usize;
        let mut offset = 0usize;
        while offset < cmp_size {
            let len = 512.min(cmp_size - offset);
            let mut buf = vec![0u8; len];
            reader.seek(SeekFrom::Start(offset as u64)).expect("seek");
            reader.read_exact(&mut buf).expect("read");
            assert_eq!(
                buf,
                ref_data[offset..offset + len],
                "byte mismatch at {offset:#x} in {}",
                corpus.display()
            );
            offset += step;
        }
    }

    #[test]
    fn corpus_minimal_vhd_reads_match_qemu_raw_convert() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/minimal.vhd");
        corpus_vhd_matches_raw(&p);
    }

    #[test]
    fn corpus_fixed_vhd_reads_match_qemu_raw_convert() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/fixed.vhd");
        corpus_vhd_matches_raw(&p);
    }

    #[test]
    fn corpus_dfvfs_ntfs_fixed_vhd_reads_match_qemu_raw_convert() {
        // ntfs_fixed.vhd was created by Windows (creator_app = "win ", version 0x000A0000
        // = Windows 10 / Hyper-V). It is a fixed-type VHD with an NTFS filesystem,
        // sourced from the dfvfs project (Apache-2.0):
        // https://github.com/log2timeline/dfvfs/raw/main/test_data/ntfs-fixed.vhd
        // SHA-256: 797a3a1ffb1966b634bef79bf4b1e93641545cce8560b1f81d8d2c3f84b00de2
        // This is NOT QEMU-generated, providing independent cross-implementation validation.
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/ntfs_fixed.vhd");
        corpus_vhd_matches_raw(&p);
    }
}
