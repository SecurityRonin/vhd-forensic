# Validation

Correctness is proven against **independent oracles and real-world artifacts**, not
against fixtures we authored ourselves — the self-authored-fixture trap is exactly
how the reader bug below survived until this pass.

## Reader correctness

The reader's one value-producing output — `virtual_disk_size` — is cross-checked
against an independent oracle at two tiers. Fixtures live in `core/tests/data/`
(provenance + mint commands / download URLs + hashes in that folder's `README.md`).

**Tier-1 — third-party real-world artifacts.** Real Windows-authored VHDs from
log2timeline/dfvfs (Apache-2.0), with an independent tool reporting the answer key:

| Fixture | Type | Oracle | Result |
|---|---|---|---|
| `ntfs_dynamic.vhd` (dfvfs) | dynamic | `qemu-img info -f vpc` → **4,194,304 B** | reader reads **4,194,304** — exact match, no fudge |
| `ntfs_fixed.vhd` (dfvfs) | fixed | qemu raw-convert reconciliation | reader matches (with the documented fixed-VHD footer-as-sector ±512 caveat) |

Neither the artifact nor the size was authored by us — the artifact is dfvfs's, the
answer key is qemu-img's. Dynamic VHDs give qemu a clean read, so `ntfs_dynamic.vhd`
is the clean Tier-1 anchor.

### Reference-implementation cross-check — libvhdi (`vhdiinfo`)

The strongest oracle is **libvhdi** (Joachim Metz's reference VHD library, the one
Plaso/dfvfs use), built from the 20251119 release. `vhdiinfo` media-size vs vhd-core:

| Image | vhd-core | libvhdi | qemu-img | Verdict |
|---|---|---|---|---|
| `ntfs_dynamic.vhd` (real) | 4,194,304 | 4,194,304 | 4,194,304 | **all three agree** |
| `ntfs_fixed.vhd` (real) | 4,194,304 | **4,194,304** | 4,194,816 (raw) | vhd-core matches the *reference*; qemu's raw read counts the footer as a sector |
| `minimal.vhd` | 1,079,296 | 1,079,296 | 1,079,296 | agree |
| `original-size-mismatch.vhd` (synthetic) | 2,123,776 (`CurrentSize`@48) | **1,061,888 (`OriginalSize`@40)** | 2,123,776 | the two references *disagree* — see below |

On **every real VHD, libvhdi confirms vhd-core** — and on the fixed image vhd-core
matches libvhdi *more closely than qemu* (qemu's raw-mode read over-counts by the
512-byte footer).

The disagreement is only on the synthetic `original-size-mismatch.vhd`, and it is
instructive: I hand-edited **only** `OriginalSize`@40, leaving `CurrentSize`@48 and
the dynamic-header BAT at qemu's 2 MiB. **vhd-core and qemu report `CurrentSize`@48
(2,123,776) — which equals the BAT capacity, i.e. the bytes you can actually read;
libvhdi reports `OriginalSize`@40 (1,061,888), the creation-time size.** For a
*reader* exposing the virtual sector stream, the readable capacity (`CurrentSize`,
matching the BAT) is the correct size — reading `OriginalSize` on a grown disk would
truncate. So vhd-core's choice is right for its contract; libvhdi's `media size` is a
different quantity (nominal creation size). Honest caveat: this synthetic image is an
*inconsistent* state a real tool never emits (a real resize updates both fields and
the header together), so it does not by itself adjudicate the semantics — the real-VHD
agreement above is what carries the correctness claim.

Reproduce: build `libvhdi` (`./configure && make`), then
`vhditools/vhdiinfo core/tests/data/ntfs_dynamic.vhd` → `Media size: 4194304`.

**Tier-2 — real qemu-minted images, qemu-img as oracle.** Genuine `qemu-img` (v11)
output whose ground truth qemu-img itself reports:

| Fixture | Type | Oracle (qemu-img) | What it proves |
|---|---|---|---|
| `minimal.vhd` | dynamic | 1,079,296 B | reader opens a dynamic VHD; size matches |
| `fixed.vhd` | fixed | ~1 MiB | fixed-disk footer path |
| `original-size-mismatch.vhd` | dynamic | 2,123,776 B | reader returns **CurrentSize** (offset 48), not OriginalSize |

The **`current_size` offset bug** (below) was caught with `original-size-mismatch.vhd`
(Tier-2) and independently corroborated by the Tier-1 dfvfs images.

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
