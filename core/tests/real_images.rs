//! Integration tests against committed VHD real-image corpus.
//!
//! All fixtures are in `tests/data/` — provenance in `tests/data/README.md`.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");

// ── minimal.vhd (dynamic, ~1 MiB virtual) ────────────────────────────────────

#[test]
fn minimal_vhd_virtual_disk_size() {
    let path = format!("{DATA_DIR}/minimal.vhd");
    let reader = vhd::VhdReader::open(Path::new(&path)).expect("minimal.vhd must open");
    // qemu-img rounds up to a VHD cylinder boundary; the resulting virtual size
    // is 1,079,296 bytes (2108 sectors) rather than the nominal 1 MiB (2048 sectors).
    assert_eq!(
        reader.virtual_disk_size(),
        1_079_296,
        "minimal.vhd: qemu-img rounds to CHS boundary → 1_079_296 bytes"
    );
}

#[test]
fn minimal_vhd_sector0_is_zeros() {
    let path = format!("{DATA_DIR}/minimal.vhd");
    let mut reader = vhd::VhdReader::open(Path::new(&path)).expect("open");
    let mut buf = [0xFFu8; 512];
    reader.seek(SeekFrom::Start(0)).expect("seek");
    reader.read_exact(&mut buf).expect("read sector 0");
    assert_eq!(
        buf, [0u8; 512],
        "empty dynamic VHD — sector 0 must be all zeros"
    );
}

// ── fixed.vhd (fixed, ~1 MiB virtual) ────────────────────────────────────────

#[test]
fn fixed_vhd_virtual_disk_size() {
    let path = format!("{DATA_DIR}/fixed.vhd");
    let reader = vhd::VhdReader::open(Path::new(&path)).expect("fixed.vhd must open");
    // Same CHS rounding as minimal.vhd — both were created with qemu-img 1M.
    assert_eq!(
        reader.virtual_disk_size(),
        1_079_296,
        "fixed.vhd: qemu-img rounds to CHS boundary → 1_079_296 bytes"
    );
}

#[test]
fn fixed_vhd_sector0_is_zeros() {
    let path = format!("{DATA_DIR}/fixed.vhd");
    let mut reader = vhd::VhdReader::open(Path::new(&path)).expect("open");
    let mut buf = [0xFFu8; 512];
    reader.seek(SeekFrom::Start(0)).expect("seek");
    reader.read_exact(&mut buf).expect("read sector 0");
    assert_eq!(
        buf, [0u8; 512],
        "fixed VHD with no filesystem — sector 0 must be all zeros"
    );
}

// ── ntfs_fixed.vhd (fixed, 4 MiB, NTFS filesystem) ───────────────────────────

#[test]
fn ntfs_fixed_vhd_opens_and_has_nonzero_size() {
    let path = format!("{DATA_DIR}/ntfs_fixed.vhd");
    let reader = vhd::VhdReader::open(Path::new(&path)).expect("ntfs_fixed.vhd must open");
    assert!(
        reader.virtual_disk_size() > 0,
        "ntfs_fixed.vhd virtual_disk_size must be > 0"
    );
}

#[test]
fn ntfs_fixed_vhd_seek_and_read_stable() {
    let path = format!("{DATA_DIR}/ntfs_fixed.vhd");
    let mut reader = vhd::VhdReader::open(Path::new(&path)).expect("open");
    let mut a = [0u8; 512];
    reader.seek(SeekFrom::Start(0)).expect("seek");
    reader.read_exact(&mut a).expect("first read");
    let mut b = [0u8; 512];
    reader.seek(SeekFrom::Start(0)).expect("seek");
    reader.read_exact(&mut b).expect("second read");
    assert_eq!(a, b, "repeated reads at offset 0 must be identical");
}
