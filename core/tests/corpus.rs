#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use vhd::VhdReader;

fn corpus_dir() -> Option<PathBuf> {
    std::env::var("CORPUS_DIR").ok().map(PathBuf::from)
}

#[test]
fn corpus_dynamic_vhd_opens_and_has_nonzero_size() {
    let Some(dir) = corpus_dir() else { return };
    let path = dir.join("dynamic.vhd");
    if !path.exists() {
        return;
    }
    let reader = VhdReader::open(&path).expect("open dynamic.vhd");
    assert!(
        reader.virtual_disk_size() > 0,
        "virtual_disk_size must be > 0"
    );
}

#[test]
fn corpus_dynamic_vhd_read_is_stable() {
    let Some(dir) = corpus_dir() else { return };
    let path = dir.join("dynamic.vhd");
    if !path.exists() {
        return;
    }
    let mut reader = VhdReader::open(&path).expect("open");
    let mut buf = [0u8; 512];
    reader.seek(SeekFrom::Start(0)).expect("seek");
    reader.read_exact(&mut buf).expect("read sector 0");
    assert_eq!(
        buf, [0u8; 512],
        "sector 0 of an empty dynamic VHD must be all zeros"
    );
}

#[test]
fn corpus_fixed_vhd_opens_and_has_nonzero_size() {
    let Some(dir) = corpus_dir() else { return };
    let path = dir.join("fixed.vhd");
    if !path.exists() {
        return;
    }
    let reader = VhdReader::open(&path).expect("open fixed.vhd");
    assert!(
        reader.virtual_disk_size() > 0,
        "virtual_disk_size must be > 0"
    );
}
