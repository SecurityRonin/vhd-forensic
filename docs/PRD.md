# vhd-forensic — Purpose & Scope

This is a **library** (a fleet container reader + integrity analyzer), not an
examiner-run tool. It has no CLI, GUI, or MCP server of its own; the end-user
surface is the fleet CLI (`disk4n6` / Issen), which links these crates.

**What it is.** Two crates that together read and audit the legacy MS-VHD
(Virtual PC / Virtual Server / Hyper-V Generation-1) disk-image container:

- **`vhd-core`** — a pure-Rust, read-only container reader that exposes a
  `Read + Seek` view (and, under the `vfs` feature, a `forensic-vfs`
  `ImageSource`) over the virtual sector stream of Fixed and Dynamic VHDs.
- **`vhd-forensic`** — a footer integrity analyzer that parses the 512-byte
  footer raw at the documented spec offsets and reports tamper / structural
  anomalies as `forensicnomicon::report::Finding` values.

**In scope.** Fixed and Dynamic disk reading; footer cookie / checksum /
version / disk-type / data-offset / saved-state / resize auditing; big-endian
MS-VHD footer and dynamic-header/BAT parsing; presenting a decoded VHD as an
`ImageSource` for `forensic-vfs` composition.

**Out of scope (non-goals).** Differencing disks and parent-locator resolution;
writing or repairing VHDs (strictly read-only); filesystem interpretation of the
decoded sectors (a downstream filesystem crate's job); the VHDX format (a
separate `vhdx-forensic` repo); any interactive front-end.

**Users.** Fleet orchestration and other Rust code that needs to decode a VHD or
grade its footer — not a human running a binary. Design rationale for the split,
naming, safety posture, format scope, and the offset-48 fix is recorded in
[`docs/decisions/`](docs/decisions/).

**Validation.** Correctness is proven against real `qemu-img` images and
reconciled with `libyal/libvhdi` as independent oracles, and the parsers are
fuzzed (`fuzz_open`, `fuzz_audit`). See
[Validation](https://securityronin.github.io/vhd-forensic/validation/).
