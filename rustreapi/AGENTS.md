# rustreapi guide for AI agents

Rules for Rust code in the `rustreapi/` workspace, in addition to the
top-level `AGENTS.md` (commit messages, review and push rules apply
unchanged).  See `README.md` here for setup and integration tests.

## Layout

- Cargo workspace in `rustreapi/Cargo.toml`: `rustreapi` (the safe API),
  `lustreapi-sys`, `lnetconfig-sys` and `changelog-sys` (bindgen
  bindings generated from each crate's `wrapper.h` at build time),
  `lnetconfig`, `cstrbuf` and `lu-version`.
- The toolchain is pinned in `rust-toolchain`.  Lints come from the
  `ci_clippy` alias in `.cargo/config.toml` (denies `unwrap_used` and all
  warnings), the rustflags in `.cargo/ci.toml` (`-D unreachable-pub`)
  and `.clippy.toml`.  `[workspace.lints]` in `Cargo.toml` is not yet
  inherited by the crates.  A crate that must break a lint by design has
  a crate-level `#![allow(...)]` in `lib.rs`, as the `-sys` crates do.

## Checks

```bash
just check      # fmt (rewrites files), machete, spelling, clippy, tests
```

- `Cargo.lock` is not tracked and the `ci_*` aliases use `--locked`, so
  run `cargo generate-lockfile` first in a fresh checkout.

- Run `cargo check` and `cargo clippy` early and often.
- Integration tests (`cargo test --test layout_test --test hsm_test`)
  need a mounted Lustre filesystem, so run them on a test VM, never on
  the development host (`rustreapi-test.sh` sets up their environment).
- Prefer `insta` snapshot assertions (`assert_snapshot!`,
  `assert_debug_snapshot!`) over asserting parts of the output.

## Errors and state

- Encode unknown or missing states in the types.  No `unwrap()` (clippy
  denies it outside tests), no `unreachable!()`, no silent `Default`,
  no `.unwrap_or("")`.
- Use `thiserror` with distinct error variants so callers can tell the
  causes apart; don't fold several sources into `Error::Variant(String)`.
- Return `Result` rather than `Option` when a missing value is
  unexpected.
- Return an error for bad input from code we control; log and continue
  for errors from remote or external input.
- Enums for closed sets.  No indexing that can panic in library code
  (tests may index).
- Choose the data structure whose invariants fit (`BTreeSet` for ordered
  operations, and so on).

## Naming, modules and imports

These apply to new code.  When editing an existing file, follow its
style rather than mixing the two in one file.

- Short binding names in the style `x` for one item and `xs` for a
  collection; descriptive names for functions and types.
- New modules use `foo.rs` plus a `foo/` directory, not `foo/mod.rs`.
- Minimal visibility: items are private or `pub(crate)` unless they are
  part of the API.  Fields and variants of a `pub` item may be `pub`.
- Merge crate imports into one `use crate::{a, b, c};` with no blank
  lines between imports.  Tests import with `crate::`, not `super::`.
- Import a trait used only for its methods as `use Trait as _;`.

## Style

- Terse comments (`///`, `//!`, `//`, `/* */`), only where the reason is
  not obvious.  Never narrate what the code does.
- Numeric literals with separators: `1_000_000`, `1_u64`.
- Discard a value with `_ = expr;`.  RAII guards get a real name and an
  explicit `drop(name)` where they are released; `let _name = expr;` is
  acceptable when the release is at the end of the function, with a
  comment naming the resource.
- `vec![]` rather than `Vec::new()`.
- Inline format arguments (`"{x}"`), but don't add a `let` only to
  satisfy the lint; positional arguments are fine for expressions.
- Concrete types rather than ad-hoc `serde_json::json!` values.
- No dead code, and no backward-compatibility shims for unreleased code.

## Dependencies

- Crate `Cargo.toml` files inherit package fields from the workspace
  field by field (`edition.workspace = true`, `version.workspace = true`,
  ...) and use `dep.workspace = true` where the workspace pins a
  dependency.
- Add the newest published version of a new dependency, and check that
  `cargo machete` reports no unused ones.
