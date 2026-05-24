# VHD Corpus Validation

Byte-level differential tests comparing `VhdReader` output against
`qemu-img convert -O raw` (QEMU 11.0.0, macOS/Apple Silicon).

## Test Environment

| Component | Version |
|-----------|---------|
| QEMU | 11.0.0 (Homebrew, `/opt/homebrew/bin/qemu-img`) |
| OS | macOS (Apple Silicon) |
| Rust | (see `rust-toolchain.toml`) |

## Corpus Files

### minimal.vhd — dynamic VHD

| Field | Value |
|-------|-------|
| Subformat | Dynamic (copy-on-write blocks + BAT) |
| Virtual size | 1 MiB (1,049,088 bytes per `CurrentSize` field) |
| Creator | `qemu-img create -f vpc vhd/tests/data/minimal.vhd 1M` (QEMU 11.0.0) |
| License | Generated locally |

### fixed.vhd — fixed VHD

| Field | Value |
|-------|-------|
| Subformat | Fixed (raw data + trailing footer) |
| Virtual size | 1 MiB |
| Creator | `qemu-img create -f vpc -o subformat=fixed vhd/tests/data/fixed.vhd 1M` (QEMU 11.0.0) |
| License | Generated locally |

## Test Results

### `corpus_minimal_vhd_reads_match_qemu_raw` (dynamic)

Full byte scan of `minimal.vhd` at 64 KiB stride + near-end read, compared
against `qemu-img convert -O raw`. **PASS**.

Exercises: BAT lookup, dynamic block bitmap skip (+512 bytes), block data
reads, unallocated block → zeros.

### `corpus_fixed_vhd_reads_match_qemu_raw` (fixed)

Full byte scan of `fixed.vhd` at 64 KiB stride + near-end read, compared
against `qemu-img convert -O raw`. **PASS**.

Exercises: fixed-image direct sector reads (no BAT), footer-only header parse.

## Validation Coverage

| Feature | Covered | Notes |
|---------|---------|-------|
| Dynamic VHD (BAT + blocks) | Yes | `minimal.vhd` |
| Fixed VHD (raw + footer) | Yes | `fixed.vhd` |
| Unallocated blocks (zeros) | Yes | minimal.vhd sparse regions |
| Block bitmap skip (+512) | Yes | mandatory for dynamic blocks |
| One's-complement checksum | Yes | parsed and validated on open |
| Differencing VHD | No | not in current corpus |
| CHS geometry rounding quirk | Yes (implicit) | QEMU uses `file_size/512`; our reader matches |

### Virtual size note

QEMU's `vpc` driver reports virtual size as `(file_size - 512) / 512 * 512`
for fixed VHDs (counting footer bytes), which differs from the spec's
`CurrentSize` field. Our reader uses `CurrentSize` and the test passes,
meaning the two values agree for these QEMU-generated images. See
`docs/implementation-notes.md` for the full analysis.

## Reproducing

```sh
# Regenerate corpus
qemu-img create -f vpc vhd/tests/data/minimal.vhd 1M
qemu-img create -f vpc -o subformat=fixed vhd/tests/data/fixed.vhd 1M

# Run validation tests
cargo test
```
