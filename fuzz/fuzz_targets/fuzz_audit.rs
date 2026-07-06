#![no_main]
//! Fuzz the vhd-forensic footer audit — it must never panic on arbitrary bytes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = vhd_forensic::audit(data);
});
