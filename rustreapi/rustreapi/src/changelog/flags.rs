// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use bitflags::bitflags;
use changelog_sys::*;

bitflags! {
    /// Changelog send flags for controlling changelog behavior.
    #[repr(transparent)]
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default, serde::Serialize, serde::Deserialize)]
    pub struct ChangelogFlag: u32 {
        /// Follow mode: continue receiving new records as they are generated
        const Follow     = CHANGELOG_FLAG_FOLLOW;
        /// Block mode: block when no records are available instead of returning immediately
        const Block      = CHANGELOG_FLAG_BLOCK;
        /// Include job ID information in records
        const JobId      = CHANGELOG_FLAG_JOBID;
        /// Include extra flags information in records
        const ExtraFlags = CHANGELOG_FLAG_EXTRA_FLAGS;
        /// Use extended Nid format (available on Lustre 2.16+)
        #[cfg(feature = "LUSTRE_2_16")]
        const NidBe      = CHANGELOG_FLAG_NID_BE;
    }

    /// Extra flags for requesting additional extension data in changelog records.
    #[repr(transparent)]
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default, serde::Serialize, serde::Deserialize)]
    pub struct ChangelogExtraFlag: u32 {
        /// Include UID/GID information in records
        const UidGid   = CHANGELOG_EXTRA_FLAG_UIDGID;
        /// Include client NID information in records
        const Nid      = CHANGELOG_EXTRA_FLAG_NID;
        /// Include open mode information in records
        const OpenMode = CHANGELOG_EXTRA_FLAG_OMODE;
        /// Include extended attribute information in records
        const Xattr    = CHANGELOG_EXTRA_FLAG_XATTR;
    }
}
