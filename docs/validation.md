# Validation

Correctness is proven against **independent oracles and real-world artifacts**, not
against fixtures we authored ourselves — the self-authored-fixture trap is exactly
how the reader bug below survived until this pass.

## Reader correctness — real qemu-img images, oracle = qemu-img

`vhd-core` is validated against real VHDs minted by `qemu-img` (v11), with
`qemu-img info`'s reported virtual size as the independent ground truth. Fixtures
live in `core/tests/data/` (provenance + mint commands in that folder's `README.md`).

| Fixture | Type | Oracle (qemu-img virtual size) | What it proves |
|---|---|---|---|
| `minimal.vhd` | dynamic | 1,079,296 B | reader opens a real dynamic VHD; virtual size matches qemu-img |
| `fixed.vhd` | fixed | ~1 MiB | fixed-disk footer path |
| `original-size-mismatch.vhd` | dynamic | 2,123,776 B | reader returns **CurrentSize** (offset 48), not OriginalSize |

### The `current_size` offset bug (found and fixed this pass)

Spec research (Microsoft's Virtual Hard Disk Image Format Specification,
cross-checked against `microsoft/azure-vhd-utils` and `libyal/libvhdi`) established
the footer layout: **OriginalSize @40, CurrentSize @48**. `vhd-core` had been reading
`current_size` from **offset 40** — returning OriginalSize. It was masked because
un-resized disks have `OriginalSize == CurrentSize`, *and* because the test fixtures
encoded the same wrong offset, so the suite was green while the reader was wrong.

The fix was validated with an **independent oracle**: `original-size-mismatch.vhd`
is a real qemu VHD whose `CurrentSize` (offset 48) is left untouched at qemu's
2,123,776, with only `OriginalSize` (offset 40) injected to a distinct 1,061,888.
`qemu-img info` reports 2,123,776 — a value we never authored. The reader must match
it. Before the fix it returned 1,061,888; after, 2,123,776. This is a value-producing
decoder cross-checked by a tool that decodes the same bytes independently.

## Panic-free posture — fuzzing + no-panic tests

`vhd-core` and `vhd-forensic` parse attacker-controllable images, so they meet the
Paranoid Gatekeeper standard: `unsafe_code = forbid`, `clippy::unwrap_used`/`expect_used
= deny`, bounded readers (out-of-range ⇒ 0), and `usize::try_from` + `checked_add`/
`checked_mul` on every offset/length from the image.

- **Adversarial unit tests:** a malicious footer `data_offset` or `max_bat_entries`
  used to overflow `start + size` / `start + entries*4` (panic in debug; in release it
  wrapped past the bounds check, admitting a 16 GiB allocation). Tests now assert these
  return `BatOutOfBounds`, never panic.
- **Fuzzing** (`fuzz/`, nightly cargo-fuzz, run by `fuzz.yml` — 45 s smoke per target on
  push/PR, 10 min on schedule):
  - `fuzz_open` drives `VhdReader::open` over arbitrary bytes.
  - `fuzz_audit` drives `vhd_forensic::audit` over arbitrary bytes.
  - Local smoke: **fuzz_audit 8.1 M executions, fuzz_open 52 K executions — no panic or
    crash**, confirming the bounded-reader + checked-arithmetic hardening.

## Analyzer correctness — spec-derived fixtures

`vhd-forensic::audit` is tested against footers built to the **spec offsets**
(independent of the reader's construction), covering each anomaly: truncation, cookie
≠ `conectix`, one's-complement checksum mismatch, unexpected format version, undefined
disk type, saved-state flag, and `DataOffset` inconsistent with the disk type. The
checksum algorithm is the MS-VHD one's-complement sum; offsets are the same
spec-verified offsets used to find the reader bug.
