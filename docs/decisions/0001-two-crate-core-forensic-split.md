# 1. Two-crate workspace: `vhd-core` reader + `vhd-forensic` analyzer

Date: 2026-07-24
Status: Accepted

## Context

The repository parses the legacy MS-VHD (Virtual PC / Hyper-V Generation-1)
disk-image container. Two distinct consumers exist: a general Rust caller that
wants to *read* a VHD's virtual sector stream, and a DFIR analyst who wants to
*audit* a VHD's footer for tampering and structural anomalies. A single crate
serving both would force the reader to carry a `forensicnomicon` dependency it
does not need, and would blur "read valid data robustly" against "surface the
broken structure a robust reader hides".

The fleet constitution (`~/src/ronin-issen/CLAUDE.md`, "Crate-structure
standard — reader/analyzer split") fixes the layout for every format: one
workspace repo `<x>-forensic`, a `core/` member (the raw reader) and a
`forensic/` member (the anomaly auditor). `vhdx-forensic` and `ntfs-forensic`
are the reference implementations.

## Decision

Split the repo into a two-member Cargo workspace (`Cargo.toml`:
`members = ["core", "forensic"]`):

- **`core/` → `vhd-core`** — the read-only MS-VHD container reader
  (`core/src/lib.rs`), exposing `Read + Seek` over the virtual sector stream. No
  findings, no `forensicnomicon`.
- **`forensic/` → `vhd-forensic`** — the footer integrity analyzer
  (`forensic/src/integrity.rs`), emitting `forensicnomicon::report` findings.

The split was performed in commit `d4b623d` ("split into core/ (vhd-core) —
align to the `<x>-core`/`<x>-forensic` layout"), moving `vhd/` → `core/` and
preparing the `forensic/` member. Shared fields (`version`, `edition`,
`rust-version`, `license`, `repository`, lints) are inherited from
`[workspace.package]` / `[workspace.lints]` so a bump is one edit (commit
`a28db19`).

## Consequences

- A downstream reader depends only on `vhd-core` and pays no analyzer cost; an
  analyst depends on `vhd-forensic` and gets graded findings.
- The two crates version and release in lockstep off the workspace version
  (`0.1.3` at time of writing).
- New format-family repos in the fleet mirror this exact layout, so the shape is
  learn-once.
- Naming and dependency-direction follow-ons are recorded in ADR 0002
  (analyzer's dependency direction) and ADR 0003 (crate naming / collision).
