# `rustreapi`

Rust-friendly, curated interface for `lustreapi`.

## Examples

### Create a striped file.

```rust
use rustreapi::OpenOptions;

fn main() {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .stripe_count(2)
        .stripe_size(1024 * 1024)
        .mode(0o600)
        .pool("ssd_pool")
        .open("/mnt/lustre/file.txt");
}
```

### Create a file with multiple extensible components.

This creates a 4 component file with two extensible components.

```rust
use rustreapi::Layout;

fn main() {
    let end: [u64; 4] = [
        10 << 20, // 10 MiB
        1 << 30,  // 1 GiB
        10 << 30, // 10 GiB
        lustreapi_sys::LUSTRE_EOF as u64,
    ];
    let start: [u64; 4] = [0, end[0], end[1], end[2]];

    let layout = Layout::new();

    layout
        // Comp 0
        .stripe_count(1)?
        .comp_extent(start[0], end[0])?

        // Comp 1
        .comp_add()?
        .stripe_count(4)?
        .comp_extent(start[1], end[1])?
        .comp_flags(CompEntryFlags::Extension)?
        .layout.extension_size(64 << 20)?

        // Zero-length Comp 2
        .comp_add()?
        .comp_extent(start[2], start[2])?

        // Extendable Comp 3
        .comp_add()?
        .comp_extent(start[2], end[3])?
        .comp_flags(CompEntryFlags::Extension)?;

    let file = layout.create(PathName::new("test.dat"))?;
}
```

## Dev Setup

Currently we only support Linux development environments because we depend on
`lustreapi` being available.

1. Install `lustre-client-devel` package.
2. Install  [Rust](https://rustup.rs/)
3. Extra tools for development
   ```console
       dnf install -y llvm-devel clang-devel rpm-build npm
   ```
4. Clone this repo locally.
5. Install tools: `cargo install_tools`
6. Install spellcheck:
   ```console
   cargo install_spellcheck
   ```
7. Install pre-commit hook:
   ```console
   cargo install_rusty_hook
   rusty-hook init
   ```

## Setup for Integration Tests

The layout and `HSM` integration tests are based on the lustre `llapi_*` tests,
and requires a Lustre filesystem, as
well as some setup and environment variables.

### Setup

- Enable HSM coordinator
    - `lctl set_param mdt.*.hsm_control enabled`
- Create a pool
    - `lctl pool_new lustre.testp`

### Environment Variables

- `LUSTRE_DIR=/mnt/lustre`
- `TEST_DIR=/mnt/lustre/test-dir`
    - make sure this directory exists
    - after mkdir, do  `lfs setstripe -C $TEST_DIR` to reset to default stripe
- `POOL=testp`

### Run Integration Tests

```shell
cargo test --test hsm_test --test layout_test
```
