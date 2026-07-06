# tests/data — VHD Real-Image Corpus

Integration test fixtures and fuzz seed corpus.
`fuzz/corpus/fuzz_open/` symlinks here; files are not duplicated.

## Files

All images generated locally with `qemu-img 11.0.0` on macOS (Apple Silicon).

| File | Subformat | Virtual size | Notes |
|------|-----------|-------------|-------|
| `minimal.vhd` | dynamic | ~1 MiB | Primary integration test seed |
| `fixed.vhd` | fixed | ~1 MiB | Fixed-size VHD footer variant |
| `original-size-mismatch.vhd` | dynamic | current 2,123,776 / original 1,061,888 | `OriginalSize@40` ≠ `CurrentSize@48`. Real qemu VHD with only `OriginalSize` injected; **qemu-img reports 2,123,776** (the `CurrentSize@48` oracle). Reader must return the current size. md5 `a5461b3043a067a079e9191f5da2e9b9` |

## Regenerating

```sh
qemu-img create -f vpc tests/data/minimal.vhd 1M
qemu-img create -f vpc -o subformat=fixed tests/data/fixed.vhd 1M
```

`original-size-mismatch.vhd` is a real qemu dynamic VHD whose `CurrentSize` (footer
offset 48 — reported by `qemu-img info` as 2,123,776) is left untouched, with only
`OriginalSize` (offset 40) injected to a distinct `1,061,888` in both footer copies
and the footer checksums recomputed. `qemu-img` is the independent oracle for the
current/virtual size, so the reader's `virtual_disk_size()` must match it. Mint with:

```sh
qemu-img create -f vpc tests/data/original-size-mismatch.vhd 2M
python3 - <<'PY'
import struct
p = "tests/data/original-size-mismatch.vhd"
d = bytearray(open(p, "rb").read())
def checksum(f):
    s = sum(b for i, b in enumerate(f) if not 64 <= i < 68) & 0xFFFFFFFF
    return (~s) & 0xFFFFFFFF
def patch(buf, base):
    f = buf[base:base + 512]
    curr = struct.unpack(">Q", f[48:56])[0]      # untouched CurrentSize (offset 48)
    f[40:48] = struct.pack(">Q", curr // 2)       # inject a distinct OriginalSize
    f[64:68] = b"\x00\x00\x00\x00"
    f[64:68] = struct.pack(">I", checksum(f))
    buf[base:base + 512] = f
patch(d, 0)                # front footer copy (dynamic VHD)
patch(d, len(d) - 512)     # trailing footer (authoritative)
open(p, "wb").write(d)
PY
```
