// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use lustreapi_sys::{LLAPI_LAYOUT_DEFAULT, *};
use rand::prelude::*;
use rustreapi::{
    CompEntryFlags, CompUse, Fid, Layout, LayoutGetFlags, LustrePath, OpenOptions, ost_count,
};
use std::{
    env, fs,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    process::Command,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

static T0_SIZE: u64 = 1024 * 1024;
static T0_COUNT: u64 = 2;
static T0_FILE: &str = "layout_test";
static T0_INDEX: u64 = 1;
#[test]
fn test0_write_read_attributes() -> Result<()> {
    let pool = lustre_pool();

    let l = Layout::new();

    l.stripe_size(T0_SIZE)?
        .stripe_count(T0_COUNT)?
        .ost_index(0, T0_INDEX)?
        .pool_name(&pool)?;

    assert_eq!(l.get_stripe_size()?, T0_SIZE);
    assert_eq!(l.get_stripe_count()?, T0_COUNT);
    assert_eq!(l.get_pool_name()?, pool);
    assert_eq!(l.get_ost_index(0)?, T0_INDEX);

    Ok(())
}

fn new_file_path() -> PathBuf {
    let mut path =
        PathBuf::from(env::var("TEST_DIR").unwrap_or("/mnt/lustre/layout_test".to_string()));

    let mut rng = rand::rng();
    path.push(format!("{}_{:x}", T0_FILE, rng.random::<u32>()));
    path
}

/*
* Returns a new directory path with a unique name based on the prefix.
*/
fn new_dir_path(prefix: &str) -> PathBuf {
    let mut path =
        PathBuf::from(env::var("TEST_DIR").unwrap_or("/mnt/lustre/layout_test".to_string()));

    let mut rng = rand::rng();
    path.push(format!("{}_{:x}", prefix, rng.random::<u32>()));
    path
}

fn create_t0_file() -> Result<PathBuf> {
    let pool = lustre_pool();

    let l = Layout::new();

    l.stripe_size(T0_SIZE)?
        .stripe_count(T0_COUNT)?
        .ost_index(0, T0_INDEX)?
        .pool_name(&pool)?;

    let path = new_file_path();
    let _file = l.create(&path)?;
    Ok(path)
}

fn lustre_dir() -> PathBuf {
    match LustrePath::parse(&env::var("LUSTRE_DIR").unwrap_or("/mnt/lustre".to_string())) {
        Ok(x) => x.as_ref().to_path_buf(),
        Err(e) => {
            panic!("Failed to parse LUSTRE_DIR: {e:?}");
        }
    }
}

fn lustre_pool() -> String {
    std::env::var("POOL").unwrap_or_else(|_| "testpool".to_string())
}

fn lfs_path() -> String {
    std::env::var("LFS").unwrap_or_else(|_| "/usr/bin/lfs".to_string())
}

#[test]
fn test1_read_file_by_path() -> Result<()> {
    let path = create_t0_file()?;

    let v = rustreapi::get_layout(&path, LayoutGetFlags::NONE)?;

    let x = v.first().ok_or("Layout not found")?;

    insta::assert_debug_snapshot!(x.stripe_count, @"2");
    insta::assert_debug_snapshot!(x.stripe_size, @"1048576");
    insta::assert_debug_snapshot!(x.pool_name, @r#"
    Some(
        "testp",
    )
    "#);
    insta::assert_debug_snapshot!(x.osts[0], @"1");
    fs::remove_file(&path)?;

    Ok(())
}

#[test]
fn test2_read_file_by_fd() -> Result<()> {
    let path = create_t0_file()?;
    let file = fs::File::open(&path)?;

    let v = rustreapi::get_layout_fd(&file, LayoutGetFlags::NONE)?;
    let x = v.first().ok_or("Layout not found")?;

    insta::assert_debug_snapshot!(x.stripe_count, @"2");
    insta::assert_debug_snapshot!(x.stripe_size, @"1048576");
    insta::assert_debug_snapshot!(x.pool_name, @r#"
    Some(
        "testp",
    )
    "#);
    insta::assert_debug_snapshot!(x.osts[0], @"1");

    fs::remove_file(&path)?;

    Ok(())
}

#[test]
fn test3_read_file_by_fid() -> Result<()> {
    let lustre_dir = lustre_dir();

    let path = create_t0_file()?;

    let fid = Fid::with_path(&path)?;

    let v = rustreapi::get_layout_fid(&lustre_dir, fid, LayoutGetFlags::NONE)?;
    let x = v.first().ok_or("Layout not found")?;

    insta::assert_debug_snapshot!(x.stripe_count, @"2");
    insta::assert_debug_snapshot!(x.stripe_size, @"1048576");
    insta::assert_debug_snapshot!(x.pool_name, @r#"
    Some(
        "testp",
    )
    "#);
    insta::assert_debug_snapshot!(x.osts[0], @"1");

    fs::remove_file(&path)?;

    Ok(())
}

#[test]
fn test4_verify_compat_with_lfs_setstripe() -> Result<()> {
    let pool = std::env::var("POOL").unwrap_or("testpool".to_string());
    let path = new_file_path();

    let output = Command::new("lfs")
        .arg("setstripe")
        .arg("-c")
        .arg("2")
        .arg("-S")
        .arg("2M")
        .arg("-i")
        .arg("1")
        .arg("-p")
        .arg(&pool)
        .arg(&path)
        .output()?;

    assert!(output.status.success());

    let v = rustreapi::get_layout(&path, LayoutGetFlags::NONE)?;
    let x = v.first().ok_or("Layout not found")?;

    insta::assert_debug_snapshot!(x.stripe_count, @"2");
    insta::assert_debug_snapshot!(x.stripe_size, @"2097152");
    insta::assert_debug_snapshot!(x.pool_name, @r#"
    Some(
        "testp",
    )
    "#);
    insta::assert_debug_snapshot!(x.osts[0], @"1");
    fs::remove_file(path)?;
    Ok(())
}

#[test]
fn test5_file_not_exist() {
    let path = new_file_path();

    match rustreapi::get_layout(&path, LayoutGetFlags::NONE) {
        Err(rustreapi::Error::MsgErrno(_, err)) => {
            assert_eq!(err, nix::errno::Errno::ENOENT)
        }
        e => panic!("expected ENOENT, got {:?}", e),
    }
}

#[test]
fn test7_get_path_access_error() {
    // need to seteuid() to a non-root user
    // initial attempt at this didn't work, lookup by path succeded after seteduid().
}

#[test]
fn test8_default_layout_for_generic_file() -> Result<()> {
    let path = new_file_path();
    let file = fs::File::create(&path)?;
    drop(file);
    let default_stripe = if cfg!(feature = "LUSTRE_2_17") {
        4 * 1024 * 1024
    } else {
        1024 * 1024
    };
    let l = rustreapi::Layout::with_path(&path, LayoutGetFlags::NONE)?;
    assert_eq!(l.get_stripe_count().ok(), Some(1));
    assert_eq!(l.get_stripe_size().ok(), Some(default_stripe));
    assert_eq!(l.get_pool_name().ok(), Some(String::from("")));
    assert_eq!(l.get_stripe_pattern().ok(), Some(0));
    fs::remove_file(path)?;
    Ok(())
}

#[test]
fn test9_verify_pattern_errors() -> Result<()> {
    let l = Layout::new();

    match l.stripe_pattern(lustreapi_sys::LLAPI_LAYOUT_INVALID) {
        Err(rustreapi::Error::Errno(err)) => {
            assert_eq!(err, nix::errno::Errno::EOPNOTSUPP)
        }
        e => panic!("expected EOPNOTSUPP, got {:?}", e),
    }

    let result = l.stripe_pattern(LLAPI_LAYOUT_DEFAULT);
    assert!(result.is_ok());

    let result = l.stripe_pattern(u64::from(lustreapi_sys::LLAPI_LAYOUT_MDT));
    assert!(result.is_ok());

    let result = l.stripe_pattern(u64::from(lustreapi_sys::LLAPI_LAYOUT_RAID0));
    assert!(result.is_ok());

    Ok(())
}

#[test]
fn test10_verify_stripe_count_errors() {
    let l = Layout::new();

    match l.stripe_count(lustreapi_sys::LLAPI_LAYOUT_INVALID) {
        Err(rustreapi::Error::Errno(err)) => {
            assert_eq!(err, nix::errno::Errno::EINVAL)
        }
        e => panic!("expected EINVAL, got {:?}", e),
    }

    match l.stripe_count(u64::from(lustreapi_sys::LOV_MAX_STRIPE_COUNT) + 1) {
        Err(rustreapi::Error::Errno(err)) => {
            assert_eq!(err, nix::errno::Errno::EINVAL)
        }
        e => panic!("expected EINVAL, got {:?}", e),
    }
}

#[test]
fn test11_verify_stripe_size_errors() {
    let l = Layout::new();

    match l.stripe_size(lustreapi_sys::LLAPI_LAYOUT_INVALID) {
        Err(rustreapi::Error::Errno(err)) => {
            assert_eq!(err, nix::errno::Errno::EINVAL)
        }
        e => panic!("expected EINVAL, got {:?}", e),
    }

    // why isn't this defined?
    const MAX_STRIPE_SIZE: u64 = 1 << 32;

    match l.stripe_size(MAX_STRIPE_SIZE + 1) {
        Err(rustreapi::Error::Errno(err)) => {
            assert_eq!(err, nix::errno::Errno::EINVAL)
        }
        e => panic!("expected EINVAL, got {:?}", e),
    }

    match l.stripe_size(1024 * 1024 - 1) {
        Err(rustreapi::Error::Errno(err)) => {
            assert_eq!(err, nix::errno::Errno::EINVAL)
        }
        e => panic!("expected EINVAL, got {:?}", e),
    }

    match l.stripe_size(1024) {
        Err(rustreapi::Error::Errno(err)) => {
            assert_eq!(err, nix::errno::Errno::EINVAL)
        }
        e => panic!("expected EINVAL, got {:?}", e),
    }
}

#[test]
fn test12_verify_pool_name_errors() {
    let l = Layout::new();

    match l.pool_name("0123456789abdefg") {
        Err(rustreapi::Error::Errno(err)) => {
            assert_eq!(err, nix::errno::Errno::EINVAL)
        }
        e => panic!("expected EINVAL, got {:?}", e),
    }
}

#[test]
fn test13_ost_index_errors() -> Result<()> {
    let l = Layout::new();

    let count = 2;

    match l.ost_index(0, lustreapi_sys::LLAPI_LAYOUT_INVALID) {
        Err(rustreapi::Error::Errno(err)) => {
            assert_eq!(err, nix::errno::Errno::EINVAL)
        }
        e => panic!("expected EINVAL, got {:?}", e),
    }

    match l.ost_index(0, 1000000) {
        Err(rustreapi::Error::Errno(err)) => {
            assert_eq!(err, nix::errno::Errno::EINVAL)
        }
        e => panic!("expected EINVAL, got {:?}", e),
    }

    let l = Layout::new();
    let result = l.stripe_count(count);
    assert!(result.is_ok());

    match l.get_ost_index(0) {
        Err(rustreapi::Error::Errno(err)) => {
            assert_eq!(err, nix::errno::Errno::EINVAL)
        }
        e => panic!("expected EINVAL, got {:?}", e),
    }

    let l = Layout::new();
    let path = new_file_path();
    l.stripe_count(count)?;
    let file = l.create(&path)?;
    drop(file);

    let l = Layout::with_path(&path, LayoutGetFlags::NONE)?;
    let result = l.get_ost_index(0);
    assert!(result.is_ok());

    match l.get_ost_index(count + 1) {
        Err(rustreapi::Error::Errno(err)) => {
            assert_eq!(err, nix::errno::Errno::EINVAL)
        }
        e => panic!("expected EINVAL, got {:?}", e),
    }
    fs::remove_file(&path)?;
    Ok(())
}

#[test]
fn test14_file_create_errors() -> Result<()> {
    let l = Layout::new();
    let lustre_dir = lustre_dir();

    match l.create(&lustre_dir) {
        Err(rustreapi::Error::MsgErrno(_, err)) => {
            assert_eq!(err, nix::errno::Errno::EEXIST)
        }
        e => panic!("expected EEXIST, got {:?}", e),
    }

    match l.create(&PathBuf::from("/tmp/not-lustre.txt")) {
        Err(rustreapi::Error::MsgErrno(_, err)) => {
            assert_eq!(err, nix::errno::Errno::ENOTTY)
        }
        e => panic!("expected ENOTTY, got {:?}", e),
    }
    fs::remove_file("/tmp/not-lustre.txt")?;
    Ok(())
}

#[test]
fn test15_cant_change_existing() -> Result<()> {
    let l = Layout::new();
    let path = new_file_path();
    let file = l.stripe_count(2)?.create(&path)?;
    drop(file);

    let l = Layout::new();
    let file = l.stripe_count(1)?.open(&path)?;
    drop(file);

    let l = Layout::with_path(&path, LayoutGetFlags::NONE)?;
    assert_eq!(l.get_stripe_count()?, 2);
    Ok(())
}

#[test]
fn test15b_can_change_existing() -> Result<()> {
    let path = new_file_path();
    let _file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .lov_delay(true)
        .open(&path)?;

    let file = Layout::new()
        .stripe_count(3)?
        .stripe_size(512 * 1024)?
        .open(&path)?;

    drop(file);

    let l = Layout::with_path(&path, LayoutGetFlags::NONE)?;
    assert_eq!(l.get_stripe_count()?, 3);
    assert_eq!(l.get_stripe_size()?, 512 * 1024);
    Ok(())
}

// this test is similar to test_default_values as we are not testing NULL layout,
#[test]
fn test16_default_stripe_attributes_applied() -> Result<()> {
    let deflayout = Layout::new();
    let stripe_size = Layout::get_stripe_size(&deflayout)?;
    assert_eq!(
        stripe_size, LLAPI_LAYOUT_DEFAULT,
        "Failed to get stripe size for default"
    );

    let stripe_count = Layout::get_stripe_count(&deflayout)?;
    assert_eq!(
        stripe_count, LLAPI_LAYOUT_DEFAULT,
        "Failed to get stripe count for default"
    );

    drop(deflayout);

    Ok(())
}

/* needs version of Lustre containing LU-18972 to be able to run this test. */
#[test]
#[cfg(feature = "LUSTRE_2_16")]
fn test17_layout_wide_uses_all_osts() -> Result<()> {
    let path = new_file_path();

    let layout = Layout::new();
    layout.stripe_count(unsafe { llapi_LAYOUT_WIDE_MIN() })?;

    let file = layout.create(&path)?;
    drop(file);

    let file = layout.open(&path)?;
    let ost_count_all = ost_count(&LustrePath::parse("/mnt/lustre")?)?;
    drop(file);

    let file_layout = Layout::with_path(&path, LayoutGetFlags::EXPECTED)?;
    let stripe_count = file_layout.get_stripe_count()?;

    assert!(
        stripe_count.abs_diff(ost_count_all as u64) <= 1,
        "stripe_count {} differs from ost_count {} by more than 1",
        stripe_count,
        ost_count_all
    );

    Ok(())
}

#[test]
fn test18_pool_name_notation() -> Result<()> {
    let path = new_file_path();
    let poolname = lustre_pool();

    let pool_with_fsname = format!("lustre.{}", poolname);

    let layout = Layout::new();
    layout.pool_name(&pool_with_fsname)?;

    // Verify the pool name was set correctly (should strip fsname prefix)
    let retrieved_pool = layout.get_pool_name()?;
    assert_eq!(
        retrieved_pool, poolname,
        "Pool name mismatch: {} != {}",
        retrieved_pool, poolname
    );

    let file = layout.create(&path)?;
    drop(file);

    let file_layout = Layout::with_path(&path, LayoutGetFlags::NONE)?;
    let file_pool = file_layout.get_pool_name()?;
    assert_eq!(
        file_pool, poolname,
        "File pool name mismatch: {} != {}",
        file_pool, poolname
    );

    Ok(())
}

#[test]
fn test22_file_create_mode_correctly_applied() -> Result<()> {
    let path = new_file_path();
    let mode_in = 0o640;

    // Save original umask and set restrictive umask
    let original_umask = unsafe { libc::umask(0o022) };

    let layout = Layout::new();
    let file = layout.create_with_mode(&path, mode_in)?;

    unsafe { libc::umask(original_umask) };

    let metadata = file.metadata()?;
    let mode_out = metadata.mode() & 0o7777; // (equivalent to ~S_IFMT)

    drop(file);

    assert_eq!(
        mode_in, mode_out as i32,
        "Mode mismatch: expected 0o{:o}, got 0o{:o}",
        mode_in, mode_out
    );

    Ok(())
}

#[test]
fn test24_layout_get_expected_works_with_existing_file() -> Result<()> {
    let path = new_file_path();

    //(equivalent to open() with O_CREAT)
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .mode(0o640)
        .open(&path)?;

    drop(file);

    let layout = Layout::with_path(&path, LayoutGetFlags::EXPECTED)?;

    let count = layout.get_stripe_count()?;
    assert_ne!(
        count, LLAPI_LAYOUT_DEFAULT,
        "Expected literal stripe count value, got default"
    );

    let size = layout.get_stripe_size()?;
    assert_ne!(
        size, LLAPI_LAYOUT_DEFAULT,
        "Expected literal stripe size value, got default"
    );

    let pattern = layout.get_stripe_pattern()?;
    assert_ne!(
        pattern, LLAPI_LAYOUT_DEFAULT,
        "Expected literal stripe pattern value, got default"
    );

    Ok(())
}

#[test]
fn test26_layout_get_expected_partially_specified_parent() -> Result<()> {
    const T26_STRIPE_SIZE: u64 = 1048576 * 4; // 4MB

    let dir = new_dir_path("test26");

    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750))?;

    // could be problematic on test systems if lfs is defined elsewhere.
    let output = Command::new(&lfs_path())
        .args(&[
            "setstripe",
            "-S",
            &T26_STRIPE_SIZE.to_string(),
            dir.to_str().unwrap(),
        ])
        .output()?;

    assert!(
        output.status.success(),
        "lfs setstripe command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Get layout with EXPECTED flag - should combine specified stripe size with defaults
    let layout = Layout::with_path(&dir, LayoutGetFlags::EXPECTED)?;

    let count = layout.get_stripe_count()?;
    assert_ne!(
        count, LLAPI_LAYOUT_DEFAULT,
        "Expected literal stripe count value, got default"
    );

    // Verify stripe size matches what we set
    let size = layout.get_stripe_size()?;
    assert_eq!(
        size, T26_STRIPE_SIZE,
        "Expected stripe size {}, got {}",
        T26_STRIPE_SIZE, size
    );

    let pattern = layout.get_stripe_pattern()?;
    assert_ne!(
        pattern, LLAPI_LAYOUT_DEFAULT,
        "Expected literal stripe pattern value, got default"
    );

    Ok(())
}

/* llapi_layout_stripe_count_get returns LLAPI_LAYOUT_WIDE for a directory
 * with a stripe_count of -1.
 */
#[test]
#[cfg(feature = "LUSTRE_2_16")]
fn test28_layout_wide_stripe_count() -> Result<()> {
    let dir = new_dir_path("test28");

    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750))?;

    let output = Command::new(&lfs_path())
        .args(&["setstripe", "-c", "-1", dir.to_str().unwrap()])
        .output()?;

    assert!(
        output.status.success(),
        "lfs setstripe command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let layout = Layout::with_path(&dir, LayoutGetFlags::NONE)?;

    let count = layout.get_stripe_count()?;
    let expected_wide = unsafe { llapi_LAYOUT_WIDE_MIN() };

    assert_eq!(
        count, expected_wide,
        "Expected LLAPI_LAYOUT_WIDE ({}), got count = {}",
        expected_wide, count
    );

    Ok(())
}

#[test]
fn test30_composite_file_traverse() -> Result<()> {
    let end: [u64; 3] = [
        64 * 1024 * 1024,
        1024 * 1024 * 1024,
        lustreapi_sys::LUSTRE_EOF as u64,
    ];
    let start: [u64; 3] = [0, end[0], end[1]];
    let path = new_file_path();

    let l = Layout::new();
    l.stripe_count(1)?;

    // attempt to add component without extent will fail
    match l.comp_add() {
        Err(rustreapi::Error::MsgErrno(_, err)) => {
            assert_eq!(err, nix::errno::Errno::EINVAL)
        }
        e => panic!("expected EINVAL, got {:?}", e),
    }

    l.comp_extent(start[0], end[0])?
        .comp_add()?
        .comp_extent(start[1], end[1])?
        .comp_add()?
        .comp_extent(start[2], end[2])?;

    let file = l.create(&path)?;

    drop(file);

    let l = Layout::with_path(&path, LayoutGetFlags::NONE)?;
    let (s, e) = l.get_comp_extent()?;
    assert_eq!(s, start[2]);
    assert_eq!(e, end[2]);

    l.comp_use(CompUse::First)?;

    // attempt to delete non-tail component will fail
    match l.comp_del() {
        Err(rustreapi::Error::MsgErrno(_, err)) => {
            assert_eq!(err, nix::errno::Errno::EINVAL)
        }
        e => panic!("expected EINVAL, got {:?}", e),
    }

    let (s, e) = l.get_comp_extent()?;
    assert_eq!(s, start[0]);
    assert_eq!(e, end[0]);

    l.comp_use(CompUse::Next)?;
    assert_eq!(l.get_comp_extent()?, (start[1], end[1]));

    l.comp_use(CompUse::Next)?;
    assert_eq!(l.get_comp_extent()?, (start[2], end[2]));

    let result = l.comp_del();
    assert!(result.is_ok());

    fs::remove_file(&path)?;
    Ok(())
}

#[test]
fn test31_manipulate_components_on_file() -> Result<()> {
    let end: [u64; 3] = [
        64 * 1024 * 1024,
        1024 * 1024 * 1024,
        lustreapi_sys::LUSTRE_EOF as u64,
    ];
    let start: [u64; 3] = [0, end[0], end[1]];
    let path = new_file_path();

    let file = Layout::new()
        .stripe_count(1)?
        .comp_extent(start[0], end[0])?
        .create(&path)?;
    drop(file);

    Layout::new()
        .stripe_count(2)?
        .comp_extent(start[1], end[1])?
        .file_comp_add(&path)?;

    let layout = Layout::with_path(&path, LayoutGetFlags::NONE)?;

    let mut i = 0;
    let mut id: [u32; 2] = [0; 2];

    for l in layout.iter() {
        assert_eq!(l.get_comp_extent()?, (start[i], end[i]));
        id[i] = l.get_comp_id()?;
        i += 1;
    }

    for l in layout.iter_reverse() {
        i -= 1;
        assert_eq!(l.get_comp_extent()?, (start[i], end[i]));
        assert_eq!(l.get_comp_id()?, id[i]);
    }

    match Layout::file_comp_del(&path, id[0]) {
        Err(rustreapi::Error::MsgErrno(_, err)) => {
            assert_eq!(err, nix::errno::Errno::EINVAL)
        }
        e => panic!("expected EINVAL, got {:?}", e),
    }

    let result = Layout::file_comp_del(&path, id[1]);
    assert!(result.is_ok());

    Ok(())
}

#[test]
fn test34_extending_layouts() -> Result<()> {
    let path = new_file_path();
    let end: [u64; 4] = [
        10 << 20,
        1 << 30,
        10 << 30,
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
        .stripe_count(1)?
        .comp_extent(start[1], end[1])?
        .comp_flags(CompEntryFlags::Extension)?;

    match layout.extension_size(32 << 20) {
        Err(rustreapi::Error::MsgErrno(_, err)) => {
            assert_eq!(err, nix::errno::Errno::EINVAL)
        }
        e => panic!("expected EINVAL, got {:?}", e),
    }

    match layout.extension_size(5 << 40) {
        Err(rustreapi::Error::MsgErrno(_, err)) => {
            assert_eq!(err, nix::errno::Errno::EINVAL)
        }
        e => panic!("expected EINVAL, got {:?}", e),
    }
    layout.extension_size(64 << 20)?;

    // Broken Comp 2
    layout
        .comp_add()?
        .comp_extent(start[2], end[2])?
        // this flag is invalid but can't be checked until file is created
        .comp_flags(CompEntryFlags::Extension)?;

    match layout.create(&path) {
        Err(rustreapi::Error::MsgErrno(_, err)) => {
            assert_eq!(err, nix::errno::Errno::EINVAL)
        }
        e => panic!("expected EINVAL, got {:?}", e),
    }

    layout.comp_del()?;
    // Zero-length Comp 2
    layout
        .comp_add()?
        .comp_extent(start[2], start[2])?
        // Extendable Comp 3
        .comp_add()?
        .comp_extent(start[2], end[3])?
        .comp_flags(CompEntryFlags::Extension)?;

    let result = layout.create(&path);
    assert!(result.is_ok());

    let layout = Layout::with_path(&path, LayoutGetFlags::NONE)?;

    layout.sanity(false, false)?;

    Ok(())
}

#[test]
fn test35_all_paths_at_single_file() -> Result<()> {
    use std::fs::File;

    let path = create_t0_file()?;
    let lustre_path = lustre_dir();
    let mount_file = File::open(&lustre_path)?;
    let test_file = File::open(&path)?;
    let fid = Fid::with_fd(&test_file)?;

    let all_paths = fid.all_paths_at(&mount_file)?;
    assert_eq!(
        all_paths.len(),
        1,
        "Should have exactly one path for single file"
    );

    assert_eq!(
        all_paths[0].file_name(),
        path.file_name(),
        "Returned filename should match expected"
    );

    fs::remove_file(&path)?;
    Ok(())
}

#[test]
fn test36_all_paths_convenience_method() -> Result<()> {
    let path = create_t0_file()?;
    let lustre_path = lustre_dir();
    let mount_path = LustrePath::parse(lustre_path.to_str().unwrap())?;
    let test_file = std::fs::File::open(&path)?;
    let fid = Fid::with_fd(&test_file)?;

    let all_paths = fid.all_paths(&mount_path)?;
    assert!(!all_paths.is_empty(), "Should have at least one path");

    fs::remove_file(&path)?;
    Ok(())
}

#[test]
fn test37_all_paths_consistency_with_path_at() -> Result<()> {
    use std::fs::File;

    let path = create_t0_file()?;
    let lustre_path = lustre_dir();
    let mount_file = File::open(&lustre_path)?;
    let test_file = File::open(&path)?;
    let fid = Fid::with_fd(&test_file)?;

    let single_path = fid.path_at(&mount_file)?;
    let all_paths = fid.all_paths_at(&mount_file)?;

    assert!(
        !all_paths.is_empty(),
        "all_paths should return at least one path"
    );
    assert_eq!(
        single_path, all_paths[0],
        "First path from all_paths_at should match path_at result"
    );

    fs::remove_file(&path)?;
    Ok(())
}

#[test]
fn test38_all_paths_with_hard_links() -> Result<()> {
    use std::fs::{File, hard_link};

    let original_path = create_t0_file()?;
    let lustre_path = lustre_dir();
    let mount_file = File::open(&lustre_path)?;

    // Create two hard links to the original file
    let link1_path = new_file_path();
    let link2_path = new_file_path();
    hard_link(&original_path, &link1_path)?;
    hard_link(&original_path, &link2_path)?;

    let test_file = File::open(&original_path)?;
    let fid = Fid::with_fd(&test_file)?;

    let all_paths = fid.all_paths_at(&mount_file)?;
    assert_eq!(
        all_paths.len(),
        3,
        "Should have exactly three paths for file with two hard links"
    );

    // Extract filenames from all paths
    let mut returned_filenames: Vec<_> = all_paths.iter().map(|p| p.file_name()).collect();
    returned_filenames.sort();

    let mut expected_filenames = vec![
        original_path.file_name(),
        link1_path.file_name(),
        link2_path.file_name(),
    ];
    expected_filenames.sort();

    assert_eq!(
        returned_filenames, expected_filenames,
        "All hard link paths should be returned"
    );

    // Clean up all files
    fs::remove_file(&original_path)?;
    fs::remove_file(&link1_path)?;
    fs::remove_file(&link2_path)?;
    Ok(())
}
