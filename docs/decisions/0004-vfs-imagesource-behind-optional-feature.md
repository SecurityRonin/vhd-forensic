# 4. `forensic-vfs` `ImageSource` adapter behind an optional `vfs` feature

Date: 2026-07-24
Status: Accepted

## Context

The fleet's VFS policy (`~/src/ronin-issen/CLAUDE.md`, "VFS & Universal
Container Abstraction") says a consumer that reads an evidence image must go
through the abstraction, never a per-format container crate. `forensic-vfs`
defines the `ImageSource` positioned-byte edge (`read_at`), so that a whole
stack — e.g. `E01 → GPT → NTFS` — reads as one `Arc<dyn ImageSource>` shared by
many workers. For a VHD to participate, `vhd-core` must be able to present a
decoded VHD as an `ImageSource`.

But `VhdReader` is a `Read + Seek` cursor: a read advances an internal position,
so it needs `&mut self`, whereas `ImageSource::read_at` is `&self` and must be
`Send + Sync`. And most consumers of `vhd-core` want only the reader and should
not be forced to pull `forensic-vfs`.

## Decision

Provide a `VhdSource` adapter that implements `forensic_vfs::ImageSource`, gated
behind an optional **`vfs`** Cargo feature (`core/Cargo.toml`:
`vfs = ["dep:forensic-vfs"]`, `forensic-vfs = { version = "0.3", optional =
true }`). `core/Cargo.toml` labels the feature "(ADR 0004)"; the
`core/src/lib.rs` `#[cfg(feature = "vfs")] pub mod vfs;` gate carries no such
comment.

Implementation (`core/src/vfs.rs`): `VhdSource` holds the `VhdReader` behind a
**poison-recovering `Mutex`**; `read_at` seeks then reads under the lock — the
same technique the sibling VHDX/VMDK adapters use. The virtual disk size is
recorded once at construction for `len()`.

Development history: RED `381f042` ("VhdSource ImageSource cross-checked vs
reader's Read path"), GREEN `e9f9ccc`; published dep bumps `160d517`
(forensic-vfs 0.2) and `341deb6` (forensic-vfs 0.3).

## Consequences

- The default `vhd-core` build stays dependency-light (just `thiserror`); only a
  caller that opts into `vfs` pulls `forensic-vfs`.
- Reads through `VhdSource` **serialize through the mutex** — correct and
  `Send + Sync`, at the cost of no intra-source read parallelism. Documented on
  the type. The poison-recovering lock means one panicking reader does not wedge
  the source.
- The adapter is validated by cross-checking `read_at` output against the
  reader's own `Read` path (the `vfs` test module).
- A VHD can now be composed into a `forensic-vfs` stack like the other container
  formats, satisfying the "consumer depends on the abstraction, not the format"
  rule.
