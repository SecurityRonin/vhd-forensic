# vhd-forensic

Legacy **VHD** (Virtual PC / Virtual Server / Hyper-V Gen-1) forensic tooling in
pure Rust, split the fleet way:

- **`vhd-core`** — a read-only reader: opens Fixed and Dynamic VHDs and exposes the
  virtual sector stream as `Read + Seek`. Imports as `vhd`.
- **`vhd-forensic`** — an integrity **analyzer**: parses the footer *raw* (which the
  reader validates-and-discards) and reports tamper / structural anomalies as
  `forensicnomicon::report` findings.

```rust
// Analyze a VHD footer for integrity anomalies.
for anomaly in vhd_forensic::audit(&image_bytes) {
    let finding = anomaly.to_finding(source);  // forensicnomicon Finding
}
```

Trust but verify: panic-free (bounded readers, no `unwrap` in production, fuzzed),
and validated against real qemu-img images with an independent oracle — see
[Validation](validation.md).

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · © 2026 Security Ronin Ltd
