# 7. `CurrentSize` from footer offset 48, validated against an independent oracle

Date: 2026-07-24
Status: Accepted

## Context

The MS-VHD footer (§2.1) stores two virtual-size fields in big-endian:
**`OriginalSize` at offset 40** (size at creation) and **`CurrentSize` at offset
48** (the current/readable virtual size). They differ only when a disk is
resized after creation, so reading the wrong one is *masked* on every
un-resized image — a latent bug that passes synthetic tests encoded to the same
mistake (the "LZNT1 trap").

`vhd-core` originally read the virtual size from offset 40, returning
`OriginalSize` — wrong on any resized disk.

## Decision

- Read `current_size` from footer bytes **48..56**; read `original_size` from
  **40..48**; all footer integers are **big-endian** (`core/src/footer.rs`
  `VhdFooter`, offsets cross-checked against `microsoft/azure-vhd-utils` and
  `libyal/libvhdi`). The offset constants are duplicated verbatim in the
  analyzer (`OFF_ORIGINAL_SIZE = 40`, `OFF_CURRENT_SIZE = 48` in
  `forensic/src/integrity.rs`).
- Expose **both** sizes on the reader: `virtual_disk_size()` (CurrentSize @48)
  and `original_size()` (OriginalSize @40); their inequality means the disk was
  resized (commit `131035c`).
- Emit a **`VHD-SIZE-RESIZED`** finding (History, Low) when
  `OriginalSize != CurrentSize` (commits `aee681a` RED / `756d257` GREEN).

Development history: the offset was corrected under TDD — RED `d2c9bdb`
("current_size must come from footer offset 48, not 40"), GREEN `0f66393`.

## Consequences

- **Tier-2 validation against an independent oracle:** the offset-48 fix was
  driven and confirmed by `original-size-mismatch.vhd` — a **synthetic Tier-2**
  fixture (a real qemu dynamic VHD with **only** `OriginalSize`@40 hand-injected
  to a distinct value, leaving `CurrentSize`@48 and the BAT at qemu's 2 MiB), not
  a real resized disk. `qemu-img info` independently reports its virtual size as
  2,123,776 bytes — a value we never authored — so it is a genuine
  value-producing decoder cross-checked by an independent oracle, but at Tier-2
  (we chose and hand-edited the scenario). The genuine **Tier-1** dfvfs images
  (`ntfs_dynamic.vhd`, `ntfs_fixed.vhd`) are un-resized (`OriginalSize ==
  CurrentSize`; `core/tests/real_images.rs` `real_vhd_original_equals_current`),
  so they corroborate the reader's size broadly but do **not** themselves
  exercise the 40-vs-48 distinction. On every real VHD `libyal/libvhdi` confirms
  the reader (commits `0e63210`, `a9b4050`; `docs/validation.md`). This validates
  against real artifacts + an independent oracle, not self-authored fixtures.
- Because both crates own their offsets independently (ADR 0002), a future spec
  correction must be applied in both; here the analyzer already encoded 48.
- The resize signal is surfaced forensically rather than silently normalized.
