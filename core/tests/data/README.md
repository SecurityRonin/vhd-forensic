# tests/data — VHD Real-Image Corpus

Integration test fixtures and fuzz seed corpus.
`fuzz/corpus/fuzz_open/` symlinks here; files are not duplicated.

## Files

All images generated locally with `qemu-img 11.0.0` on macOS (Apple Silicon).

| File | Subformat | Virtual size | Notes |
|------|-----------|-------------|-------|
| `minimal.vhd` | dynamic | ~1 MiB | Primary integration test seed |
| `fixed.vhd` | fixed | ~1 MiB | Fixed-size VHD footer variant |

## Regenerating

```sh
qemu-img create -f vpc tests/data/minimal.vhd 1M
qemu-img create -f vpc -o subformat=fixed tests/data/fixed.vhd 1M
```
