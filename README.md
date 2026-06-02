[![Crates.io](https://img.shields.io/crates/v/vhd.svg)](https://crates.io/crates/vhd)
[![Docs.rs](https://img.shields.io/docsrs/vhd)](https://docs.rs/vhd)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/vhd/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/vhd/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Pure-Rust read-only legacy VHD disk image reader — fixed and dynamic disk types.**

Decodes the MS-VHD container format (Virtual PC, Virtual Server, Hyper-V Generation-1) and exposes a `Read + Seek` interface over the virtual sector stream. Supports both Fixed (raw sector data + footer) and Dynamic (BAT-addressed block data) disk types. Zero unsafe code, no C bindings.

```toml
[dependencies]
vhd = "0.1"
```

---

## Usage

### Open a VHD and read sectors

```rust
use vhd::VhdReader;
use std::io::{Read, Seek, SeekFrom};

let mut reader = VhdReader::open("disk.vhd")?;

println!("Virtual disk size: {} bytes", reader.virtual_disk_size());
println!("Disk type: {:?}", reader.disk_type());

// Read the first sector
let mut sector = [0u8; 512];
reader.read_exact(&mut sector)?;

// Seek anywhere
reader.seek(SeekFrom::Start(1_048_576))?;
```

### Pass to a filesystem crate

`VhdReader` implements `Read + Seek`, so it drops directly into any crate that accepts a reader:

```rust
use vhd::VhdReader;

let reader = VhdReader::open("disk.vhd")?;
// e.g. ext4fs_forensic::Filesystem::open(reader)?;
```

---

## Supported formats

| Format | Supported |
|--------|:---------:|
| Fixed disk (raw sectors + footer) | ✓ |
| Dynamic disk (Block Allocation Table) | ✓ |
| Differencing disk (parent chain) | not planned |

Read-only. Differencing disks require parent locator resolution which is out of scope for a forensic reader. For Hyper-V Generation-2 and Azure virtual disks use the [`vhdx`](https://github.com/SecurityRonin/vhdx) crate.

---

## Related crates

### Container readers

| Crate | Format | Notes |
|-------|--------|-------|
| [`ewf`](https://github.com/SecurityRonin/ewf) | E01 / EWF / Ex01 | Dominant professional forensic acquisition format |
| [`aff4`](https://github.com/SecurityRonin/aff4) | AFF4 v1 | Evimetry / aff4-imager forensic disk images with Map streams |
| [`vmdk`](https://github.com/SecurityRonin/vmdk) | VMware VMDK | Monolithic sparse disk images from VMware Workstation / ESXi |
| [`vhdx`](https://github.com/SecurityRonin/vhdx) | Microsoft VHDX | Hyper-V, Windows 8+, WSL2, Azure disk container |
| [`qcow2`](https://github.com/SecurityRonin/qcow2) | QCOW2 v2/v3 | QEMU / KVM / libvirt disk images |
| [`ufed`](https://github.com/SecurityRonin/ufed) | Cellebrite UFED | Physical mobile device dumps with UFD XML segment mapping |
| [`dd`](https://github.com/SecurityRonin/dd) | Raw / flat / gz | dd, dcfldd, and gzip-wrapped raw images |
| [`iso9660-forensic`](https://github.com/SecurityRonin/iso9660-forensic) | ISO 9660 | Optical disc images: multi-session, UDF bridge, Rock Ridge, Joliet, El Torito |
| [`dmg`](https://github.com/SecurityRonin/dmg) | Apple DMG / UDIF | macOS disk images with koly trailer, mish block tables, zlib decompression |
| [`dar`](https://github.com/SecurityRonin/dar) | DAR archive | Disk ARchiver archives with catalog index and CRC32 validation |

### Forensic analysers

| Crate | Format | Notes |
|-------|--------|-------|
| [`ewf-forensic`](https://github.com/SecurityRonin/ewf-forensic) | E01 | Structural integrity audit, Adler-32 / MD5 hash verification, and in-memory repair |
| [`vhdx-forensic`](https://github.com/SecurityRonin/vhdx-forensic) | VHDX | Forensic integrity analyser and in-memory repair tool for VHDX containers |

---

[Privacy Policy](https://securityronin.github.io/vhd/privacy/) · [Terms of Service](https://securityronin.github.io/vhd/terms/) · © 2026 Security Ronin Ltd
