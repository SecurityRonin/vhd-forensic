#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Forensic integrity analyzer for legacy VHD (Virtual PC / Hyper-V) disk images.
//!
//! `vhd-core` is a happy-path reader: it validates-and-discards the footer's
//! integrity fields (cookie, checksum) and *rejects* malformed or unsupported
//! images, so a forensic auditor cannot see tampering or corruption through it.
//! This crate parses the footer **raw**, at the documented spec offsets, and
//! reports anomalies as `forensicnomicon::report` findings — the reader/analyzer
//! split used across the fleet (see ntfs-forensic, vhdx-forensic).
//!
//! `audit(&image_bytes)` returns typed [`VhdIntegrityAnomaly`] values; each
//! implements `forensicnomicon::report::Observation`, so `.to_finding(source)`
//! yields a canonical `Finding`.

pub mod integrity;

pub use integrity::{audit, VhdIntegrityAnomaly, FOOTER_SIZE};
