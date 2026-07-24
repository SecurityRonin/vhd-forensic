# 5. `forbid(unsafe)` + panic-free Paranoid Gatekeeper posture

Date: 2026-07-24
Status: Accepted

## Context

Both crates parse **untrusted, attacker-controllable disk images**. The fleet's
"Security & Robustness Standard — Paranoid Gatekeeper" is mandatory for every
`*-core` / `*-forensic` crate: never panic, never read out of bounds, never
trust a length field. Unlike the mmap readers (`ewf`, `memory-forensic`) that
need a bounded `unsafe`, a VHD is decoded from a `Read + Seek` cursor and a byte
slice, so no `unsafe` is required at all — the strongest posture (`forbid`) is
achievable and badge-able.

## Decision

- **`unsafe_code = "forbid"`** at the workspace level (`Cargo.toml`
  `[workspace.lints.rust]`), inherited by both members. The README carries the
  `unsafe: forbidden` badge.
- **Panic-free lints:** `clippy::unwrap_used = "deny"` and
  `clippy::expect_used = "deny"` in `[workspace.lints.clippy]`; tests re-allow
  them via `#![cfg_attr(test, allow(...))]` and `clippy.toml`
  (`allow-unwrap-in-tests`, `allow-expect-in-tests`).
- **Bounded readers:** integer fields are read through helpers that return `0`
  on an out-of-range slice rather than panicking — `core/src/read.rs` (`be_u32`,
  `be_u64` using `buf.get(off..off+n)`) and the analyzer's own bounded `be_u32`
  in `forensic/src/integrity.rs`.
- **Checked arithmetic on image-derived offsets:** BAT and block offsets use
  `checked_add`/`checked_mul` (commit `8b62b17`, "checked arithmetic on
  attacker-controlled BAT offsets"), and `block_size == 0` is rejected to
  prevent a divide-by-zero (`VhdError::InvalidBlockSize`, commit `01948f6`).
- **Fuzzing:** two `cargo-fuzz` targets — `fuzz_open` (reader) and `fuzz_audit`
  (analyzer) — over arbitrary bytes (`fuzz/Cargo.toml`, `fuzz.yml`, commit
  `1e858fc`).

The posture was consolidated in commit `3d4eecf` ("panic-free posture — bounded
readers + workspace lints").

## Consequences

- Zero `unsafe`, no C bindings — the reader cannot reintroduce the
  memory-corruption class by construction, and the claim is compiler-proved.
- Robustness is claimed as **fuzzed** (measured — the README cites 8.1 M /
  52 K local executions with no panic) plus **panic-free by lint** (the static
  posture), the paired form the fleet README standard requires.
- `core/src/read.rs` hand-rolls two big-endian bounded readers rather than
  depending on the fleet `safe-read` crate. Rationale reconstructed from
  structure; original intent not recovered in available history — the observable
  effect is that the default `vhd-core` build stays dependency-light (only
  `thiserror`) and pulls no reader crate, whereas `safe-read` becomes available
  transitively only under the `vfs` feature via `forensic-vfs`.
