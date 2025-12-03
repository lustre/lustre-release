// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use crate::changelog::{ChangelogBuilder, ChangelogExtraFlag, ChangelogFlag};

#[test]
fn test_changelog_flags() {
    // Test individual flags
    assert_eq!(ChangelogFlag::Follow.bits(), 1);
    assert_eq!(ChangelogFlag::Block.bits(), 2);
    assert_eq!(ChangelogFlag::JobId.bits(), 4);
    assert_eq!(ChangelogFlag::ExtraFlags.bits(), 8);

    #[cfg(feature = "LUSTRE_2_16")]
    assert_eq!(ChangelogFlag::NidBe.bits(), 16);

    // Test flag combinations
    let combined = ChangelogFlag::Follow | ChangelogFlag::Block;
    assert_eq!(combined.bits(), 3);
    assert!(combined.contains(ChangelogFlag::Follow));
    assert!(combined.contains(ChangelogFlag::Block));
    assert!(!combined.contains(ChangelogFlag::JobId));
}

#[test]
fn test_changelog_extra_flags() {
    // Test individual extra flags
    assert_eq!(ChangelogExtraFlag::UidGid.bits(), 1);
    assert_eq!(ChangelogExtraFlag::Nid.bits(), 2);
    assert_eq!(ChangelogExtraFlag::OpenMode.bits(), 4);
    assert_eq!(ChangelogExtraFlag::Xattr.bits(), 8);

    // Test extra flag combinations
    let combined = ChangelogExtraFlag::UidGid | ChangelogExtraFlag::Nid;
    assert_eq!(combined.bits(), 3);
    assert!(combined.contains(ChangelogExtraFlag::UidGid));
    assert!(combined.contains(ChangelogExtraFlag::Nid));
    assert!(!combined.contains(ChangelogExtraFlag::OpenMode));
}

#[test]
fn test_changelog_builder_new() {
    let builder = ChangelogBuilder::new();
    // We can't test much without actually connecting, but we can verify
    // the builder interface works
    let _builder = builder
        .device("test-MDT0000")
        .flags(ChangelogFlag::Follow)
        .extra_flags(ChangelogExtraFlag::UidGid)
        .start_record(12345);
}

#[test]
fn test_changelog_builder_default() {
    let builder1 = ChangelogBuilder::new();
    let builder2 = ChangelogBuilder::default();
    // Can't directly compare builders, but ensure both compile
    drop(builder1);
    drop(builder2);
}

#[test]
fn test_changelog_builder_connect_no_device() {
    let builder = ChangelogBuilder::new().flags(ChangelogFlag::Follow);
    let result = builder.connect();
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("device name must be specified")
    );
}

#[test]
fn test_flag_debug() {
    // Test debug formatting
    let flag = ChangelogFlag::Follow | ChangelogFlag::Block;
    let debug_str = format!("{:?}", flag);
    assert!(debug_str.contains("Follow"));
    assert!(debug_str.contains("Block"));

    let extra_flag = ChangelogExtraFlag::UidGid | ChangelogExtraFlag::Nid;
    let debug_str = format!("{:?}", extra_flag);
    assert!(debug_str.contains("UidGid"));
    assert!(debug_str.contains("Nid"));
}

#[test]
fn test_flag_none() {
    let no_flags = ChangelogFlag::none();
    assert_eq!(no_flags.bits(), 0);
    assert!(!no_flags.contains(ChangelogFlag::Follow));

    let no_extra_flags = ChangelogExtraFlag::none();
    assert_eq!(no_extra_flags.bits(), 0);
    assert!(!no_extra_flags.contains(ChangelogExtraFlag::UidGid));
}

#[test]
fn test_flag_all() {
    let all_flags = ChangelogFlag::all_bits();
    assert!(all_flags.contains(ChangelogFlag::Follow));
    assert!(all_flags.contains(ChangelogFlag::Block));
    assert!(all_flags.contains(ChangelogFlag::JobId));
    assert!(all_flags.contains(ChangelogFlag::ExtraFlags));
    #[cfg(feature = "LUSTRE_2_16")]
    assert!(all_flags.contains(ChangelogFlag::NidBe));

    let all_extra_flags = ChangelogExtraFlag::all_bits();
    assert!(all_extra_flags.contains(ChangelogExtraFlag::UidGid));
    assert!(all_extra_flags.contains(ChangelogExtraFlag::Nid));
    assert!(all_extra_flags.contains(ChangelogExtraFlag::OpenMode));
    assert!(all_extra_flags.contains(ChangelogExtraFlag::Xattr));
}
