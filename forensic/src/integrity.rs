//! Forensic integrity analysis of the VHD footer (MS-VHD §2.1).
//!
//! Field offsets are per Microsoft's *Virtual Hard Disk Image Format
//! Specification*, cross-checked against microsoft/azure-vhd-utils and
//! libyal/libvhdi: Cookie@0, Version@12, DataOffset@16, OriginalSize@40,
//! CurrentSize@48, DiskGeometry@56, DiskType@60, Checksum@64, SavedState@84.
//! All multi-byte fields are big-endian. Findings are observations
//! ("consistent with"), never verdicts.

use forensicnomicon::report::{Category, Severity};

/// The VHD footer is a fixed 512-byte structure at the end of every VHD file.
pub const FOOTER_SIZE: usize = 512;
const COOKIE: &[u8; 8] = b"conectix";
const CURRENT_VERSION: u32 = 0x0001_0000;
const FIXED_DATA_OFFSET: u64 = 0xFFFF_FFFF_FFFF_FFFF;

// Footer field offsets (spec, big-endian).
const OFF_COOKIE: usize = 0;
const OFF_VERSION: usize = 12;
const OFF_DATA_OFFSET: usize = 16;
const OFF_DISK_TYPE: usize = 60;
const OFF_CHECKSUM: usize = 64;
const OFF_SAVED_STATE: usize = 84;

/// A footer-level integrity or structure anomaly. Each variant carries the
/// offending value verbatim (the "show the unrecognized value" rule).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VhdIntegrityAnomaly {
    /// File is shorter than a 512-byte footer — truncated or not a VHD.
    FooterTruncated { len: usize },
    /// Footer cookie is not `conectix`.
    FooterCookieInvalid { found: [u8; 8] },
    /// Stored footer checksum does not match the recomputed value.
    FooterChecksumMismatch { stored: u32, computed: u32 },
    /// File format version is not 1.0 (`0x0001_0000`).
    FileFormatVersionUnexpected { found: u32 },
    /// Disk type is not a defined value (2 Fixed, 3 Dynamic, 4 Differencing;
    /// 0 None is tolerated).
    DiskTypeUnknown { found: u32 },
    /// The image is flagged as being in a saved (suspended) state.
    SavedStateSet,
    /// `DataOffset` is inconsistent with the disk type (Fixed must be
    /// `0xFFFF_FFFF_FFFF_FFFF`; Dynamic/Differencing must point into the file).
    DataOffsetInconsistent { disk_type: u32, data_offset: u64 },
}

impl VhdIntegrityAnomaly {
    fn severity(&self) -> Severity {
        match self {
            Self::FooterTruncated { .. }
            | Self::FooterCookieInvalid { .. }
            | Self::FooterChecksumMismatch { .. } => Severity::High,
            Self::FileFormatVersionUnexpected { .. }
            | Self::DiskTypeUnknown { .. }
            | Self::DataOffsetInconsistent { .. } => Severity::Medium,
            Self::SavedStateSet => Severity::Low,
        }
    }

    fn category(&self) -> Category {
        match self {
            // Image completeness / authenticity.
            Self::FooterTruncated { .. } | Self::FooterChecksumMismatch { .. } => {
                Category::Integrity
            }
            Self::FooterCookieInvalid { .. }
            | Self::FileFormatVersionUnexpected { .. }
            | Self::DiskTypeUnknown { .. }
            | Self::SavedStateSet
            | Self::DataOffsetInconsistent { .. } => Category::Structure,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::FooterTruncated { .. } => "VHD-FOOTER-TRUNCATED",
            Self::FooterCookieInvalid { .. } => "VHD-FOOTER-COOKIE-INVALID",
            Self::FooterChecksumMismatch { .. } => "VHD-FOOTER-CHECKSUM-MISMATCH",
            Self::FileFormatVersionUnexpected { .. } => "VHD-FORMAT-VERSION-UNEXPECTED",
            Self::DiskTypeUnknown { .. } => "VHD-DISK-TYPE-UNKNOWN",
            Self::SavedStateSet => "VHD-SAVED-STATE",
            Self::DataOffsetInconsistent { .. } => "VHD-DATA-OFFSET-INCONSISTENT",
        }
    }

    fn significance(&self) -> String {
        match self {
            Self::FooterTruncated { len } => format!(
                "VHD file is {len} bytes — too small to contain the 512-byte footer; \
                 the image is truncated or not a VHD"
            ),
            Self::FooterCookieInvalid { found } => format!(
                "footer cookie is {:?} (hex {}), not 'conectix' — the trailing 512 bytes \
                 are not a valid VHD footer",
                String::from_utf8_lossy(found),
                hex8(*found)
            ),
            Self::FooterChecksumMismatch { stored, computed } => format!(
                "footer checksum 0x{stored:08x} does not match the recomputed 0x{computed:08x} \
                 — consistent with tampering or corruption of the footer"
            ),
            Self::FileFormatVersionUnexpected { found } => {
                format!("file format version is 0x{found:08x}, not 0x00010000 (VHD 1.0)")
            }
            Self::DiskTypeUnknown { found } => format!(
                "disk type {found} is not a defined VHD type (2 Fixed, 3 Dynamic, 4 Differencing)"
            ),
            Self::SavedStateSet => "the SavedState flag is set — the image was captured while \
                 the VM was in a saved (suspended) state"
                .to_string(),
            Self::DataOffsetInconsistent {
                disk_type,
                data_offset,
            } => format!(
                "DataOffset 0x{data_offset:016x} is inconsistent with disk type {disk_type} \
                 (Fixed must be 0xFFFFFFFFFFFFFFFF; Dynamic/Differencing must point into the file)"
            ),
        }
    }
}

impl forensicnomicon::report::Observation for VhdIntegrityAnomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity())
    }
    fn category(&self) -> Category {
        self.category()
    }
    fn code(&self) -> &'static str {
        self.code()
    }
    fn note(&self) -> String {
        self.significance()
    }
}

/// Audit the trailing VHD footer of `data` for integrity and structure
/// anomalies. Panic-free and read-only; returns every anomaly found.
#[must_use]
pub fn audit(data: &[u8]) -> Vec<VhdIntegrityAnomaly> {
    let mut out = Vec::new();
    let Some(footer) = data.get(data.len().saturating_sub(FOOTER_SIZE)..) else {
        out.push(VhdIntegrityAnomaly::FooterTruncated { len: data.len() });
        return out;
    };
    if footer.len() < FOOTER_SIZE {
        out.push(VhdIntegrityAnomaly::FooterTruncated { len: data.len() });
        return out;
    }

    // Cookie @0.
    if footer.get(OFF_COOKIE..OFF_COOKIE + 8) != Some(COOKIE.as_slice()) {
        let mut found = [0u8; 8];
        if let Some(s) = footer.get(OFF_COOKIE..OFF_COOKIE + 8) {
            found.copy_from_slice(s);
        }
        out.push(VhdIntegrityAnomaly::FooterCookieInvalid { found });
    }

    // Checksum @64 — one's-complement over the footer with the field zeroed.
    let stored = be_u32(footer, OFF_CHECKSUM);
    let computed = footer_checksum(footer);
    if stored != computed {
        out.push(VhdIntegrityAnomaly::FooterChecksumMismatch { stored, computed });
    }

    // File format version @12.
    let version = be_u32(footer, OFF_VERSION);
    if version != CURRENT_VERSION {
        out.push(VhdIntegrityAnomaly::FileFormatVersionUnexpected { found: version });
    }

    // Disk type @60 — 0 None (tolerated), 2 Fixed, 3 Dynamic, 4 Differencing.
    let disk_type = be_u32(footer, OFF_DISK_TYPE);
    if !matches!(disk_type, 0 | 2 | 3 | 4) {
        out.push(VhdIntegrityAnomaly::DiskTypeUnknown { found: disk_type });
    }

    // DataOffset @16 vs disk type: Fixed must be the all-ones sentinel;
    // Dynamic/Differencing must point into the file (not the sentinel).
    let data_offset = be_u64(footer, OFF_DATA_OFFSET);
    let inconsistent = match disk_type {
        2 => data_offset != FIXED_DATA_OFFSET,
        3 | 4 => data_offset == FIXED_DATA_OFFSET,
        _ => false,
    };
    if inconsistent {
        out.push(VhdIntegrityAnomaly::DataOffsetInconsistent {
            disk_type,
            data_offset,
        });
    }

    // SavedState @84.
    if footer.get(OFF_SAVED_STATE).copied().unwrap_or(0) != 0 {
        out.push(VhdIntegrityAnomaly::SavedStateSet);
    }

    out
}

// ── panic-free byte readers ───────────────────────────────────────────────────

fn be_u32(buf: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = buf.get(off..off + 4) {
        b.copy_from_slice(s);
    }
    u32::from_be_bytes(b)
}

fn be_u64(buf: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    if let Some(s) = buf.get(off..off + 8) {
        b.copy_from_slice(s);
    }
    u64::from_be_bytes(b)
}

fn hex8(b: [u8; 8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// One's-complement checksum over the footer with the checksum field zeroed
/// (MS-VHD §2.1). Byte-wise sum; the size of elements is one byte.
fn footer_checksum(footer: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    for (i, &byte) in footer.iter().enumerate() {
        if (OFF_CHECKSUM..OFF_CHECKSUM + 4).contains(&i) {
            continue;
        }
        sum = sum.wrapping_add(u32::from(byte));
    }
    !sum
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a spec-correct 512-byte footer (independent of vhd-core's helper,
    /// which encodes the size fields at the wrong offsets). Cookie is valid; the
    /// checksum is computed LAST over the final bytes so single-field tests do not
    /// also trip the checksum check.
    fn footer(version: u32, disk_type: u32, data_offset: u64, saved_state: u8) -> Vec<u8> {
        let mut f = vec![0u8; FOOTER_SIZE];
        f[OFF_COOKIE..OFF_COOKIE + 8].copy_from_slice(COOKIE);
        f[OFF_VERSION..OFF_VERSION + 4].copy_from_slice(&version.to_be_bytes());
        f[OFF_DATA_OFFSET..OFF_DATA_OFFSET + 8].copy_from_slice(&data_offset.to_be_bytes());
        f[OFF_DISK_TYPE..OFF_DISK_TYPE + 4].copy_from_slice(&disk_type.to_be_bytes());
        f[OFF_SAVED_STATE] = saved_state;
        let cs = footer_checksum(&f);
        f[OFF_CHECKSUM..OFF_CHECKSUM + 4].copy_from_slice(&cs.to_be_bytes());
        f
    }

    /// A valid fixed-disk footer: version 1.0, type Fixed, `DataOffset` all-ones.
    fn valid_fixed() -> Vec<u8> {
        footer(CURRENT_VERSION, 2, FIXED_DATA_OFFSET, 0)
    }

    fn has(anoms: &[VhdIntegrityAnomaly], code: &str) -> bool {
        anoms.iter().any(|a| a.code() == code)
    }

    #[test]
    fn valid_fixed_footer_has_no_anomalies() {
        assert!(audit(&valid_fixed()).is_empty());
    }

    #[test]
    fn file_below_footer_size_is_truncated() {
        let anoms = audit(&[0u8; 100]);
        assert_eq!(
            anoms,
            vec![VhdIntegrityAnomaly::FooterTruncated { len: 100 }]
        );
    }

    #[test]
    fn bad_cookie_is_detected() {
        let mut f = valid_fixed();
        f[0] = b'X';
        assert!(has(&audit(&f), "VHD-FOOTER-COOKIE-INVALID"));
    }

    #[test]
    fn checksum_mismatch_is_detected() {
        let mut f = valid_fixed();
        // Flip a reserved byte AFTER the checksum was computed → stored != recomputed.
        f[200] ^= 0xFF;
        assert!(has(&audit(&f), "VHD-FOOTER-CHECKSUM-MISMATCH"));
    }

    #[test]
    fn unexpected_version_is_detected() {
        let f = footer(0x0002_0000, 2, FIXED_DATA_OFFSET, 0);
        assert!(has(&audit(&f), "VHD-FORMAT-VERSION-UNEXPECTED"));
    }

    #[test]
    fn unknown_disk_type_is_detected() {
        let f = footer(CURRENT_VERSION, 99, FIXED_DATA_OFFSET, 0);
        assert!(has(&audit(&f), "VHD-DISK-TYPE-UNKNOWN"));
    }

    #[test]
    fn saved_state_is_detected() {
        let f = footer(CURRENT_VERSION, 2, FIXED_DATA_OFFSET, 1);
        assert!(has(&audit(&f), "VHD-SAVED-STATE"));
    }

    #[test]
    fn fixed_disk_with_non_sentinel_data_offset_is_inconsistent() {
        let f = footer(CURRENT_VERSION, 2, 0x1000, 0);
        assert!(has(&audit(&f), "VHD-DATA-OFFSET-INCONSISTENT"));
    }

    #[test]
    fn dynamic_disk_with_sentinel_data_offset_is_inconsistent() {
        let f = footer(CURRENT_VERSION, 3, FIXED_DATA_OFFSET, 0);
        assert!(has(&audit(&f), "VHD-DATA-OFFSET-INCONSISTENT"));
    }
}
