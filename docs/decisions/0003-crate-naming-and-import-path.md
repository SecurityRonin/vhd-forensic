# 3. Crate naming: package `vhd-core`, import path `vhd`, repo `vhd-forensic`

Date: 2026-07-24
Status: Accepted

## Context

The fleet's crate-naming grammar (`~/src/ronin-issen/CLAUDE.md`, "Crate naming
grammar") makes this a **Pattern A** single-format repo: exactly two crates,
`<x>-core` (reader) and `<x>-forensic` (analyzer), in a repo named
`<x>-forensic`. Two naming pressures apply here:

1. The bare crate name `vhd` on crates.io must not be assumed free, and a
   `-core` suffix self-describes the reader on the registry.
2. Consumers should still write idiomatic `use vhd::…`, not `use vhd_core::…`.

The repo was originally a single crate simply named `vhd`; the git history shows
the rename and repo re-point as deliberate fleet-alignment steps.

## Decision

- Publish the reader as package **`vhd-core`** with **`[lib] name = "vhd"`**
  (`core/Cargo.toml`), so it is self-describing on crates.io yet imports as
  `use vhd::VhdReader`. This mirrors `vhdx-core`/`vhdx-forensic`.
- Name the analyzer package **`vhd-forensic`** (`forensic/Cargo.toml`).
- Name the repository **`SecurityRonin/vhd-forensic`** (the analyzer is the
  headline even though the repo also holds the reader).

Evidence:

- `core/Cargo.toml`: `name = "vhd-core"`, `[lib] name = "vhd"`,
  `documentation = "https://docs.rs/vhd"`.
- Commit `d4b623d`: "rename it vhd-core with `[lib] name = "vhd"` (imports
  unchanged)".
- Commit `4d1767c`: "repoint repository to SecurityRonin/vhd-forensic (fleet
  `<x>-forensic` repo naming)".

## Consequences

- Registry search and `cargo add vhd-core` are unambiguous; source stays
  `use vhd::…`.
- The fuzz crate references the reader by both names to keep the split explicit:
  `vhd = { path = "../core", package = "vhd-core" }` (`fuzz/Cargo.toml`).
- README badges and `cargo add` lines point at `vhd-core` / `vhd-forensic`, not
  the pre-split `vhd` crate (rewritten in commit `745dcc4`).
- Any future rename must respect the crates.io 72-hour window; the names are
  settled here before first publish.
