//! VHD footer parsing (MS-VHD §2.1).
//!
//! The footer is a 512-byte structure at the end of every VHD file.
//! Fixed disks also have a copy at byte 0 of the file.
//! Dynamic disks have a copy at byte 0 and the real footer at the very end.

use crate::error::{Result, VhdError};

pub const FOOTER_SIZE: usize = 512;
pub const COOKIE: &[u8; 8] = b"conectix";
pub const CURRENT_VERSION: u32 = 0x0001_0000;

/// VHD disk type codes (§2.1, DiskType field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskType {
    Fixed = 2,
    Dynamic = 3,
    // Differencing = 4 — rejected at open time
}

/// Parsed VHD footer fields relevant to container reading.
#[derive(Debug, Clone)]
pub struct VhdFooter {
    pub disk_type: DiskType,
    pub current_size: u64, // virtual disk size in bytes
    pub data_offset: u64,  // offset to dynamic header (0xFFFF... for fixed)
}

impl VhdFooter {
    /// Parse the last 512 bytes of `data` as a VHD footer.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < FOOTER_SIZE {
            return Err(VhdError::FileTooSmall);
        }
        let footer = &data[data.len() - FOOTER_SIZE..];

        // Cookie: bytes 0–7
        if &footer[0..8] != COOKIE {
            return Err(VhdError::BadCookie);
        }

        // Version: bytes 12–15
        let version = u32::from_be_bytes(footer[12..16].try_into().unwrap());
        if version != CURRENT_VERSION {
            return Err(VhdError::UnsupportedVersion(version));
        }

        // DataOffset: bytes 16–23
        let data_offset = u64::from_be_bytes(footer[16..24].try_into().unwrap());

        // OriginalSize / CurrentSize: bytes 32–47
        let current_size = u64::from_be_bytes(footer[40..48].try_into().unwrap());

        // DiskType: bytes 60–63
        let disk_type_raw = u32::from_be_bytes(footer[60..64].try_into().unwrap());
        let disk_type = match disk_type_raw {
            2 => DiskType::Fixed,
            3 => DiskType::Dynamic,
            4 => return Err(VhdError::DifferencingNotSupported),
            other => return Err(VhdError::UnknownDiskType(other)),
        };

        // Checksum: bytes 64–67
        let stored_checksum = u32::from_be_bytes(footer[64..68].try_into().unwrap());
        let computed = checksum(footer);
        if stored_checksum != computed {
            return Err(VhdError::ChecksumMismatch {
                expected: stored_checksum,
                actual: computed,
            });
        }

        Ok(VhdFooter {
            disk_type,
            current_size,
            data_offset,
        })
    }
}

/// One's-complement checksum over the footer with the checksum field zeroed.
fn checksum(footer: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    for (i, &byte) in footer.iter().enumerate() {
        // Skip the checksum field itself (bytes 64–67)
        if (64..68).contains(&i) {
            continue;
        }
        sum = sum.wrapping_add(u32::from(byte));
    }
    !sum
}

// ── Test helpers ─────────────────────────────────────────────────────────────

/// Build a minimal valid Fixed VHD footer for testing.
///
/// Sets the cookie, version, current_size, disk_type=Fixed, data_offset=0xFFFF,
/// and a valid checksum. All other fields are zeroed.
#[cfg(any(test, feature = "test-helpers"))]
pub fn test_fixed_footer(virtual_size: u64) -> Vec<u8> {
    let mut footer = vec![0u8; FOOTER_SIZE];

    // Cookie
    footer[0..8].copy_from_slice(COOKIE);
    // Features: reserved (0x0000_0002)
    footer[8..12].copy_from_slice(&0x0000_0002u32.to_be_bytes());
    // FileFormatVersion
    footer[12..16].copy_from_slice(&CURRENT_VERSION.to_be_bytes());
    // DataOffset: 0xFFFF_FFFF_FFFF_FFFF for Fixed
    footer[16..24].copy_from_slice(&0xFFFF_FFFF_FFFF_FFFFu64.to_be_bytes());
    // OriginalSize
    footer[32..40].copy_from_slice(&virtual_size.to_be_bytes());
    // CurrentSize
    footer[40..48].copy_from_slice(&virtual_size.to_be_bytes());
    // DiskType: Fixed = 2
    footer[60..64].copy_from_slice(&2u32.to_be_bytes());
    // Checksum (computed with checksum field zeroed)
    let cs = checksum(&footer);
    footer[64..68].copy_from_slice(&cs.to_be_bytes());

    footer
}
