# VHD Implementation Notes

Developer notes capturing format quirks, spec contradictions, and empirically verified
behaviour. Intended for future contributors and as a basis for upstream spec clarifications.

---

## 1. CHS geometry rounding and the `current_size` / `file_size` split

**The single most confusing aspect of fixed VHDs.**

### What the spec says

MS-VHD §2.1 `CurrentSize` field:

> Current size of the virtual disk. This field is always a multiple of the sector size
> (512 bytes). This is the current size of the disk, in bytes.

The footer `CurrentSize` (bytes 40–47) is the canonical virtual disk size. Reads must
stop at this boundary regardless of the on-disk file size.

### What QEMU does (block/vpc.c)

QEMU's vpc driver computes `total_sectors` differently for fixed disks:

```c
/* Fixed type disk uses: total_sectors = file_size / 512 */
total_sectors = bs->total_sectors;
```

For a fixed VHD with 1 MiB of data, the file is 1,049,088 bytes:
- 1,048,576 bytes of sector data
- 512 bytes of footer at the end

QEMU computes `total_sectors = 1,049,088 / 512 = 2,049`, treating the trailing footer
as a data sector. This yields a `raw` output 512 bytes larger than `CurrentSize`.

### Empirical confirmation

Our differential tests against `qemu-img convert -O raw` for corpus fixed VHDs expose
this discrepancy. Our `corpus_vhd_matches_raw` helper therefore accepts:

```rust
assert!(
    ref_data.len() == vhd_size || ref_data.len() == vhd_size + 512,
    "unexpected ref raw size {} vs vhd_size {}",
    ref_data.len(), vhd_size,
);
```

We compare only `vhd_size` bytes and never read the footer as data, which is correct
per the spec.

### Upstream PR opportunity

`block/vpc.c` in QEMU would benefit from a comment at the `total_sectors` assignment:

> For fixed VHDs, `total_sectors = file_size / 512` includes the trailing 512-byte
> footer. This means `qemu-img convert -O raw` produces `CurrentSize + 512` bytes
> for a fixed VHD. The spec-correct virtual disk size is the `CurrentSize` field
> in the footer, not derived from file size.

---

## 2. Dynamic VHD block bitmap

Every data block in a dynamic VHD is preceded by a **sector bitmap**. The bitmap
records which sectors within the block have been written.

### Spec (MS-VHD §2.3)

> Each block is prefaced with a bitmap section. The number of sectors in the bitmap
> is always one sector (512 bytes) for backward compatibility.

Despite the block size being configurable (default 2 MiB = 4,096 sectors), the bitmap
is always exactly **1 sector = 512 bytes** (covering up to 512 × 8 = 4,096 sectors).

### Implementation consequence

The BAT entry gives a sector offset to the start of the block (bitmap + data). To read
data bytes, skip the bitmap sector:

```rust
let block_file_offset = u64::from(bat_entry) * 512 + BITMAP_SECTORS * 512;
//                                                    ^^^^^^^^^^^^^^^^^^^^^^^^
//                                                    always +512 bytes
let offset_in_block = virtual_byte % block_size;
Ok(Some(block_file_offset + offset_in_block))
```

**Common pitfall:** treating the BAT entry as a direct data offset (missing the +512
bitmap skip) causes the first 512 bytes of every block to read bitmap bytes as sector
data — wrong data with no error.

---

## 3. Footer layout by disk type

| Disk Type | Byte 0..511 | Main structure | Footer (end) |
|-----------|-------------|----------------|--------------|
| Fixed | Copy of footer | Sector data (aligned sectors) | Footer copy |
| Dynamic | Copy of footer | Dynamic header (512) → BAT → data blocks | Footer copy |

- **Fixed**: the "first" footer copy at byte 0 exists for resilience; the authoritative
  footer is always at `file_size - 512`.
- **Dynamic**: byte 0 = footer copy; byte 512 = dynamic header (cookie `"cxsparse"`);
  the BAT and data blocks follow; the authoritative footer is at `file_size - 512`.

Our parser always reads the trailing footer (`data[data.len() - FOOTER_SIZE..]`).

---

## 4. One's-complement checksum

The footer checksum at bytes 64–67 is computed as:

```
checksum = ~( sum of all footer bytes with bytes 64–67 zeroed )
```

This is a **one's complement** (bitwise NOT), not two's complement. The sum is a simple
byte sum with no carry (wrapping addition). Writers must zero bytes 64–67 before
computing the checksum.

---

## 5. Differencing disks (type 4)

Differencing disks embed a `ParentLocator` pointing to a parent VHD. Reads to
unallocated blocks must be forwarded to the parent chain (which may be arbitrarily
deep) rather than returning zeros.

This implementation rejects type-4 images at `open()` with `VhdError::DifferencingNotSupported`.
Implementing differencing correctly requires:
- Resolving parent locator platform codes (W2ku, W2ru for Unicode/relative paths)
- Following an arbitrary chain depth
- Knowing which blocks are present in each overlay

**Returning zeros for unallocated blocks in a differencing disk is silently wrong.**

---

## Upstream PR candidates

| Project | File | Suggested change |
|---------|------|-----------------|
| QEMU | `block/vpc.c` | Add comment at `total_sectors` for fixed VHDs explaining the footer-as-sector discrepancy vs. spec `CurrentSize` |
| MS-VHD spec | §2.3 | Clarify that the bitmap is always 1 sector regardless of block size, with explicit example for 2 MiB blocks |
