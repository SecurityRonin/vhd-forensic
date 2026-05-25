#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::{Read, Seek, SeekFrom};
use vhd::VhdReader;

fuzz_target!(|data: &[u8]| {
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let path = dir.path().join("fuzz.vhd");
    if std::fs::write(&path, data).is_err() {
        return;
    }
    if let Ok(mut reader) = VhdReader::open(&path) {
        let size = reader.virtual_disk_size();
        if size > 0 {
            let _ = reader.seek(SeekFrom::Start(0));
            let mut buf = [0u8; 512];
            let _ = reader.read(&mut buf);
        }
    }
});
