// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use bitmask_enum::bitmask;
use changelog_sys::*;
use serde::{Deserialize, Serialize};

/// Changelog send flags for controlling changelog behavior.
#[bitmask(u32)]
#[bitmask_config(vec_debug, flags_iter)]
#[derive(Serialize, Deserialize)]
pub enum ChangelogFlag {
    /// Follow mode: continue receiving new records as they are generated
    Follow = CHANGELOG_FLAG_FOLLOW,
    /// Block mode: block when no records are available instead of returning immediately
    Block = CHANGELOG_FLAG_BLOCK,
    /// Include job ID information in records
    JobId = CHANGELOG_FLAG_JOBID,
    /// Include extra flags information in records
    ExtraFlags = CHANGELOG_FLAG_EXTRA_FLAGS,
    /// Use extended Nid format (available on Lustre 2.16+)
    #[cfg(feature = "LUSTRE_2_16")]
    NidBe = CHANGELOG_FLAG_NID_BE,
    #[cfg(not(feature = "LUSTRE_2_16"))]
    NidBe,
}

/// Extra flags for requesting additional extension data in changelog records.
#[bitmask(u32)]
#[bitmask_config(vec_debug, flags_iter)]
#[derive(Serialize, Deserialize)]
pub enum ChangelogExtraFlag {
    /// Include UID/GID information in records
    UidGid = CHANGELOG_EXTRA_FLAG_UIDGID,
    /// Include client NID information in records
    Nid = CHANGELOG_EXTRA_FLAG_NID,
    /// Include open mode information in records
    OpenMode = CHANGELOG_EXTRA_FLAG_OMODE,
    /// Include extended attribute information in records
    Xattr = CHANGELOG_EXTRA_FLAG_XATTR,
}
