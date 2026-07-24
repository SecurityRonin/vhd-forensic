# 8. Declared MSRV floor of 1.85, verified below the dev-toolchain pin

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy (`~/src/ronin-issen/CLAUDE.md` and
`CLAUDE.core.md`, "Rust MSRV & Toolchain Policy") separates the **dev toolchain**
(pinned to current stable, one version fleet-wide) from the **declared MSRV**
(`rust-version`, a downstream-facing promise). Published libraries keep a low,
CI-verified MSRV rather than tracking the pin, so the reader can be reused by
third parties on older toolchains.

Here the dev toolchain is pinned to `1.96.0` (`rust-toolchain.toml`), while the
crates are libraries meant for reuse.

## Decision

Declare **`rust-version = "1.85"`** once at the workspace level
(`Cargo.toml` `[workspace.package]`), inherited by both `vhd-core` and
`vhd-forensic`, and verify it in CI with a dedicated job (`ci.yml`: `msrv` job,
`name: MSRV (1.85)`, `dtolnay/rust-toolchain@…#1.85`). The floor is deliberately
below the `1.96.0` dev pin so the promise is a real guarantee, not a restatement
of the pin.

## Consequences

- A `1.85` build is CI-enforced on every push, so the promise cannot silently
  regress.
- Raising the floor later narrows the crates' audience and is treated as a
  near-breaking change requiring an explicit reason.
- The specific choice of `1.85` (rather than the fleet's usual `1.75`/`1.80`
  library floor) is **rationale reconstructed from structure; original intent
  not recovered in available history** — no commit explains why `1.85` was
  selected. The observable constraint is the `edition = "2021"` + `thiserror 2`
  + `forensic-vfs 0.3` dependency set, but which of these (if any) forced the
  floor is not documented; the value is simply the CI-verified floor as it
  stands.
