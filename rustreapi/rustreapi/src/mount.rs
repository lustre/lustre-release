// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use crate::{Error, ObdUuid};
use cstrbuf::CStrBuf;
use lustreapi_sys::{
    LL_STATFS_LMV, LL_STATFS_LOV, LOV_ALL_STRIPES, llapi_obd_fstatfs, llapi_search_mounts,
    obd_statfs, obd_uuid,
};
use nix::errno::Errno;
use std::{
    ffi::CString,
    fmt,
    fs::File,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

/// Lustre filesystem mount discovery and statistics collection.
///
/// This module provides functionality for discovering and collecting detailed statistics
/// from Lustre filesystem mounts, including individual component information for
/// MDTs and OSTs.
///
/// The primary entry point is [`MountStats`], which provides methods to discover
/// all Lustre mounts on the system and collect statistics about
/// their components and overall filesystem status.
///
/// # Discovery Process
///
/// The discovery process works in two phases:
/// 1. **Mount Discovery**: Uses `llapi_search_mounts` to find all Lustre mount points
/// 2. **Component Collection**: For each mount, queries individual MDTs and OSTs
///
/// # Component Statistics
///
/// For each component, the following information is collected:
/// - Block statistics (total, free, available space)
/// - Inode statistics (total, free inodes)
/// - Component UUID and identification
/// - Component status (active/inactive)
///
/// # Usage Patterns
///
/// The typical usage involves calling [`discover_mounts`](#method.discover_mounts) to get
/// all Lustre mounts, or [`collect_lustre_mounts`](#method.collect_lustre_mounts) for
/// a specific filesystem.
///
/// # Error Handling
///
/// Component queries may fail for various reasons (inactive components, temporary
/// failures, etc.). The implementation handles these scenarios:
/// - Inactive components are included with error status
/// - Temporary failures trigger retries
/// - Unexpected errors are logged but don't stop collection
///
/// # Examples
///
/// ```no_run
/// # use rustreapi::MountStats;
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Discover all Lustre mounts on the system
/// let mounts = MountStats::discover_mounts()?;
///
/// for mount in &mounts {
///     println!("Mount: {}", mount.info.mount_point.display());
///     let stats = &mount.stats;
///     println!("  Available space: {} bytes", stats.bavail * stats.bsize);
///     if let Some(inodes) = &stats.inodes {
///         println!("  Available inodes: {}", inodes.favail);
///     }
/// }
///
/// // Collect mounts for a specific filesystem
/// let specific_mounts = MountStats::collect_lustre_mounts("/mnt/lustre", "testfs")?;
/// println!("Found {} components for testfs", specific_mounts.len());
///
/// Ok(())
/// # }
/// ```
///
/// # Component Types
///
/// The returned [`Mount`] entries include different types:
/// - Individual MDT entries (one per metadata target)
/// - Individual OST entries (one per object storage target)
/// - Filesystem summary entry (aggregated statistics)
///
/// Each component type can be distinguished by examining the `fs_label` field
/// and `dev.major` field in the mount information.
#[derive(Debug)]
pub enum LustreQueryResult {
    Success(obd_statfs, obd_uuid),
    /// `ENODATA` - component exists but is inactive
    Inactive(obd_statfs, obd_uuid),
    /// `EAGAIN` - Temporary failure, should retry with next index
    RetryNext,
    /// `ENODEV` - No more components available
    NoMoreComponents,
}

#[derive(Debug, Clone, Copy)]
enum ComponentStatus {
    Active,
    Inactive,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum Statfs {
    NONE = 0,
    LMV = LL_STATFS_LMV,
    LOV = LL_STATFS_LOV,
}

impl fmt::Display for Statfs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Statfs::NONE => "NONE",
            Statfs::LMV => "MDT",
            Statfs::LOV => "OST",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct MountStats;

#[derive(Debug, PartialEq, Eq)]
pub struct DeviceId {
    pub major: u32,
    pub minor: u32,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Inodes {
    pub files: u64,
    pub ffree: u64,
    pub favail: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Mount {
    pub info: MountInfo,
    pub fs_label: Option<String>,
    pub stats: Stats,
    pub uuid: Option<String>,
    pub part_uuid: Option<String>,
}
#[derive(Debug, PartialEq, Eq)]
pub struct MountInfo {
    pub id: u32,
    pub parent: u32,
    pub dev: DeviceId,
    pub root: PathBuf,
    pub mount_point: PathBuf,
    pub fs: String,
    pub fs_type: String,
    pub bound: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Stats {
    pub bsize: u64,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub inodes: Option<Inodes>,
}
impl MountStats {
    pub fn discover_mounts() -> Result<Vec<Mount>, Error> {
        let mut lustre_mounts = Vec::new();
        let mut index = 0;
        let path = PathBuf::new();

        while let Some((mntdir_str, fsname_str)) = MountStats::search_mounts(&path, index)? {
            // Found a mount
            if !mntdir_str.is_empty() {
                let mut fs_mounts = MountStats::collect_lustre_mounts(&mntdir_str, &fsname_str)?;
                lustre_mounts.append(&mut fs_mounts);
            }
            index += 1;
        }

        Ok(lustre_mounts)
    }

    pub fn collect_lustre_mounts(mntdir: &str, fsname: &str) -> Result<Vec<Mount>, Error> {
        let mut mounts = Vec::new();

        let file = File::open(mntdir)?;

        // Create individual MDT entries
        Self::collect_component_mounts(&file, Statfs::LMV, mntdir, fsname, &mut mounts)?;

        // Create individual OST entries
        Self::collect_component_mounts(&file, Statfs::LOV, mntdir, fsname, &mut mounts)?;

        // Create aggregated client mount entry (filesystem summary)
        let client_mount = Self::create_client_mount(mntdir, fsname)?;
        mounts.push(client_mount);

        Ok(mounts)
    }

    pub fn search_mounts(path: &Path, index: i32) -> Result<Option<(String, String)>, Error> {
        let path_str = path.to_str().ok_or_else(|| Error::InvalidPath {
            path: path.to_path_buf().into_boxed_path(),
        })?;

        let c_path = CString::new(path_str)?;

        let mut mntdir = CStrBuf::new(4096);
        let mut fsname = CStrBuf::new(256);

        let result = unsafe {
            llapi_search_mounts(
                c_path.as_ptr(),
                index,
                mntdir.as_mut_ptr(),
                fsname.as_mut_ptr(),
            )
        };

        match result {
            0 => {
                // Found a mount - convert buffers to strings
                let mntdir_str = mntdir.to_string();
                let fsname_str = fsname.to_string();
                Ok(Some((mntdir_str?, fsname_str?)))
            }
            -19 => Ok(None), // ENODEV - no more mounts
            other => Err(Error::MountSearchError {
                index,
                errno: Errno::from_raw(-other),
            }),
        }
    }

    pub fn query_lustre_component<F: AsRawFd>(
        fd: &F,
        stat_type: Statfs,
        index: u32,
    ) -> Result<LustreQueryResult, Error> {
        let mut stat_buf = obd_statfs::default();
        let mut uuid_buf = obd_uuid::default();

        let rc = unsafe {
            llapi_obd_fstatfs(
                fd.as_raw_fd(),
                stat_type as u32,
                index,
                &mut stat_buf,
                &mut uuid_buf,
            )
        };

        match rc {
            0 => Ok(LustreQueryResult::Success(stat_buf, uuid_buf)),
            -61 => Ok(LustreQueryResult::Inactive(stat_buf, uuid_buf)),
            -11 => Ok(LustreQueryResult::RetryNext),
            -19 => Ok(LustreQueryResult::NoMoreComponents),
            other => Err(Error::LustreStatfs {
                stat: stat_type,
                index,
                source: Errno::from_raw(-other),
            }),
        }
    }

    fn collect_component_mounts<F: AsRawFd>(
        fd: &F,
        stat_type: Statfs,
        mntdir: &str,
        fsname: &str,
        mounts: &mut Vec<Mount>,
    ) -> Result<(), Error> {
        let mut index = 0;
        while index < LOV_ALL_STRIPES {
            match Self::query_lustre_component(fd, stat_type, index)? {
                LustreQueryResult::NoMoreComponents => {
                    break;
                }
                LustreQueryResult::RetryNext => {
                    index += 1;
                    continue;
                }
                LustreQueryResult::Success(stat_buf, uuid_buf) => {
                    let obd_uuid = ObdUuid::new(uuid_buf);
                    let mount = Self::create_component_mount(
                        mntdir,
                        fsname,
                        &stat_buf,
                        &obd_uuid,
                        stat_type,
                        index,
                        ComponentStatus::Active,
                    )?;
                    mounts.push(mount);
                }
                LustreQueryResult::Inactive(stat_buf, uuid_buf) => {
                    let obd_uuid = ObdUuid::new(uuid_buf);
                    let mount = Self::create_component_mount(
                        mntdir,
                        fsname,
                        &stat_buf,
                        &obd_uuid,
                        stat_type,
                        index,
                        ComponentStatus::Inactive,
                    )?;
                    mounts.push(mount);
                }
            }
            index += 1;
        }
        Ok(())
    }

    fn create_component_mount(
        mntdir: &str,
        fsname: &str,
        stat_buf: &obd_statfs,
        uuid: &ObdUuid,
        stat_type: Statfs,
        index: u32,
        status: ComponentStatus,
    ) -> crate::Result<Mount> {
        let uuid_str = uuid.as_string();

        let component_name = if uuid_str.is_empty() {
            format!("{stat_type}:{index:04x}")
        } else {
            uuid_str.clone()
        };

        // Create a unique mount point path for this component
        let component_mount_point = PathBuf::from(format!("{mntdir}[{stat_type}:{index}]"));

        let mount_info = MountInfo {
            id: 0,
            parent: 0,
            dev: DeviceId {
                major: match stat_type {
                    Statfs::LMV => 1, // MDT
                    Statfs::LOV => 2, // OST
                    Statfs::NONE => 0,
                },
                minor: index,
            },
            fs: component_name,
            fs_type: "lustre".to_string(),
            mount_point: component_mount_point,
            bound: false,
            root: Default::default(),
        };

        let stats = match status {
            ComponentStatus::Active => Stats {
                bsize: u64::from(stat_buf.os_bsize),
                blocks: stat_buf.os_blocks,
                bfree: stat_buf.os_bfree,
                bavail: stat_buf.os_bavail,
                inodes: if matches!(stat_type, Statfs::LMV)
                    || (matches!(stat_type, Statfs::LOV) && stat_buf.os_files > 0)
                {
                    Some(Inodes {
                        files: stat_buf.os_files,
                        ffree: stat_buf.os_ffree,
                        favail: stat_buf.os_ffree,
                    })
                } else {
                    None
                },
            },
            ComponentStatus::Inactive => {
                return Err(Error::ComponentInactive {
                    component_type: { stat_type },
                    index,
                });
            }
        };

        let mount = Mount {
            info: mount_info,
            stats,
            fs_label: Some(format!("{fsname}-{stat_type}")),
            uuid: if uuid_str.is_empty() {
                None
            } else {
                Some(uuid_str)
            },
            part_uuid: None,
        };

        Ok(mount)
    }

    fn create_client_mount(mntdir: &str, fsname: &str) -> Result<Mount, Error> {
        let file = File::open(mntdir)?;

        let mut total_blocks = 0u64;
        let mut total_bfree = 0u64;
        let mut total_bavail = 0u64;
        let mut total_files = 0u64;
        let mut total_ffree = 0u64;
        let mut bsize = 4096u32;
        let mut ost_count = 0;

        // Get OST stats for space
        let ost_uuids = Self::component_stats(&file, Statfs::LOV, |stat_buf| {
            total_blocks += stat_buf.os_blocks;
            total_bfree += stat_buf.os_bfree;
            total_bavail += stat_buf.os_bavail;
            if bsize == 4096 {
                bsize = stat_buf.os_bsize;
            }
            ost_count += 1;
        })?;

        // Get MDT stats for inode information
        let mdt_uuids = Self::component_stats(&file, Statfs::LMV, |stat_buf| {
            total_files += stat_buf.os_files;
            total_ffree += stat_buf.os_ffree;
        })?;

        // Early return with specific error if no valid components found
        if total_blocks == 0 || ost_count == 0 {
            return Err(Error::InsufficientComponents {
                filesystem: fsname.to_string(),
                ost_count,
                total_blocks,
            });
        }

        // Create a combined UUID string from the first OST or MDT UUID if available
        let filesystem_uuid = ost_uuids
            .first()
            .or_else(|| mdt_uuids.first())
            .map(|uuid| uuid.as_string())
            .filter(|s| !s.is_empty());

        let mount_info = MountInfo {
            id: 0,
            parent: 0,
            dev: DeviceId { major: 0, minor: 0 },
            fs: "filesystem_summary".to_string(),
            fs_type: "lustre".to_string(),
            mount_point: PathBuf::from(mntdir),
            bound: false,
            root: Default::default(),
        };

        let stats = Stats {
            bsize: u64::from(bsize),
            blocks: total_blocks,
            bfree: total_bfree,
            bavail: total_bavail,
            inodes: if total_files > 0 {
                Some(Inodes {
                    files: total_files,
                    ffree: total_ffree,
                    favail: total_ffree,
                })
            } else {
                None
            },
        };

        let mount = Mount {
            info: mount_info,
            stats,
            fs_label: Some(format!("Lustre-{fsname}")),
            uuid: filesystem_uuid,
            part_uuid: None,
        };

        Ok(mount)
    }

    fn component_stats<F, H>(
        fd: &F,
        stat_type: Statfs,
        mut stats_handler: H,
    ) -> Result<Vec<ObdUuid>, Error>
    where
        F: AsRawFd,
        H: FnMut(&obd_statfs),
    {
        let mut uuids = Vec::new();
        let mut index = 0;

        while index < LOV_ALL_STRIPES {
            match Self::query_lustre_component(fd, stat_type, index)? {
                LustreQueryResult::NoMoreComponents => {
                    break;
                }
                LustreQueryResult::RetryNext => {
                    index += 1;
                    continue;
                }
                LustreQueryResult::Success(stat_buf, uuid_buf) => {
                    stats_handler(&stat_buf);
                    let obd_uuid = ObdUuid::new(uuid_buf);
                    uuids.push(obd_uuid);
                }
                LustreQueryResult::Inactive(_, uuid_buf) => {
                    // Inactive component - still collect UUID but don't aggregate stats
                    let obd_uuid = ObdUuid::new(uuid_buf);
                    uuids.push(obd_uuid);
                }
            }
            index += 1;
        }

        Ok(uuids)
    }
}
