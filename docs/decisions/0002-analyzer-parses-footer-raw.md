# 2. `vhd-forensic` parses the footer raw and does not depend on `vhd-core`

Date: 2026-07-24
Status: Accepted

## Context

`vhd-core` is a happy-path reader. To open a VHD it validates the footer's
integrity fields and *rejects* anything malformed or unsupported: a bad cookie
(`VhdError::BadCookie`), a checksum mismatch (`VhdError::ChecksumMismatch`), an
unexpected version, a differencing disk, an unknown disk type
(`core/src/error.rs`). Those are exactly the conditions a forensic auditor must
*see and report*, not have rejected. Routing an audit through the reader's API
would hide the tampering it is hunting for.

The constitution's binding design principle ("`-forensic` is NOT required to
depend on `-core` — it may need to go lower") anticipates this: build
`-forensic` on `-core` only when `-core`'s API exposes everything the audit
needs; otherwise parse the raw structure directly. `ewf-forensic` (consumes only
`ewf::sections`) and `ntfs-forensic` (takes raw `&[u8]`) are the fleet
precedents.

## Decision

`vhd-forensic` parses the trailing 512-byte footer **raw**, at the documented
MS-VHD big-endian offsets, and depends **only** on `forensicnomicon` — not on
`vhd-core`. Evidence:

- `forensic/Cargo.toml` `[dependencies]` lists exactly `forensicnomicon = "1"`;
  there is no `vhd-core` entry.
- `forensic/src/integrity.rs` declares its own field-offset constants
  (`OFF_COOKIE = 0`, `OFF_VERSION = 12`, `OFF_DATA_OFFSET = 16`,
  `OFF_ORIGINAL_SIZE = 40`, `OFF_CURRENT_SIZE = 48`, `OFF_DISK_TYPE = 60`,
  `OFF_CHECKSUM = 64`, `OFF_SAVED_STATE = 84`) and its own bounded `be_u32`
  reader, independent of the reader's parser.
- `forensic/src/lib.rs` states the rationale in its module doc: "`vhd-core` is a
  happy-path reader … so a forensic auditor cannot see tampering or corruption
  through it. This crate parses the footer **raw** …".
- `audit()` returns anomalies (`FooterCookieInvalid`, `FooterChecksumMismatch`,
  etc.) for precisely the states the reader rejects — introduced in commit
  `b6fb76f`.

## Consequences

- The analyzer can grade a checksum mismatch or a bad cookie that the reader
  would refuse to open — the whole point of a forensic pass.
- Each anomaly variant carries the offending value verbatim
  (`FooterCookieInvalid { found: [u8; 8] }`, `FooterChecksumMismatch { stored,
  computed }`), honouring the "show the unrecognized value" robustness rule.
- The footer field offsets are duplicated between reader and analyzer by design
  (each owns its parse), so a spec correction must be applied in both — see ADR
  0007 for the offset-48 case, which touched the reader; the analyzer already
  encoded `OFF_CURRENT_SIZE = 48`.
- Findings are observations ("consistent with"), never verdicts, per the
  reporting model.
