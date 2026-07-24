# 6. Format scope: read-only Fixed + Dynamic; Differencing rejected

Date: 2026-07-24
Status: Accepted

## Context

The MS-VHD specification defines three disk types: Fixed (type 2), Dynamic
(type 3), and Differencing (type 4). Differencing disks store only the delta
from a parent VHD and require resolving a **parent locator** (a path/GUID chain
to the parent image) before their contents can be reconstructed — a materially
larger problem than reading a self-contained image. As a forensic reader the
crate is also read-only: it must never write the source evidence.

## Decision

- Support **reading** Fixed and Dynamic disks; **reject** Differencing at open
  time. `core/src/footer.rs` defines `DiskType { Fixed = 2, Dynamic = 3 }` with
  the comment "`Differencing = 4` — rejected at open time", and
  `core/src/error.rs` carries `DifferencingNotSupported`. The module doc in
  `core/src/lib.rs` states "Differencing disks are rejected (parent locator
  resolution is out of scope)".
- The reader is **strictly read-only** — `VhdReader` exposes only `Read + Seek`
  and size accessors; there is no write path.
- Fixed = raw sector data + trailing footer; Dynamic = BAT-addressed sparse
  blocks (`core/src/dynamic.rs`), with the bitmap size **computed** from
  `block_size` per the spec/QEMU `vpc.c` formula (commit `fac0aa4`, fixing a
  hardcoded-1 bug that misread 4 MiB-block VHDs).

## Consequences

- The analyzer does **not** emit a differencing-specific finding. Its integrity
  audit *tolerates* disk type 4 as a known value (`forensic/src/integrity.rs`
  `matches!(disk_type, 0 | 2 | 3 | 4)` → no `DiskTypeUnknown`), so a well-formed
  differencing footer (type 4, `DataOffset` pointing into the file) produces zero
  anomalies — `VHD-DATA-OFFSET-INCONSISTENT` fires only when a type 3/4 footer
  carries the all-ones *sentinel* (a malformed footer), not for a valid
  differencing disk. Surfacing "this image is a differencing disk" is deferred
  work, not a shipped capability.
- Parent-locator resolution and multi-level differencing chains are deferred; if
  needed later they are an additive feature, not a rewrite.
- Read-only-by-construction keeps the crate safe to point at live evidence.
