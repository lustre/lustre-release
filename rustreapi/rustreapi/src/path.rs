// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use crate::{
    Error,
    Error::{MsgErrno, NotLustreFileSystem},
    MountStats,
    error::cvt_lz_m,
};
use cstrbuf::CStrBuf;
use lustreapi_sys::llapi_get_fsname;
use nix::errno;
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fmt::{Display, Formatter},
    fs::File,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LustrePath {
    path: PathBuf,
}

/// Represents a validated path to a Lustre filesystem.
///
/// `LustrePath` encapsulates an absolute path to a Lustre filesystem mount point or a location within
/// a Lustre filesystem. It validates that the path actually points to a Lustre filesystem
/// during creation, providing early failure for operations that require Lustre-specific
/// functionality.
///
/// This type serves as a prerequisite for many Lustre operations and provides
/// safety by ensuring operations are only performed on valid Lustre paths.
///
/// # Creating a `LustrePath`
///
/// The primary way to create a `LustrePath` is through the [`parse`](#method.parse) method,
/// which validates that the provided path points to a Lustre filesystem.
///
/// # Usage with Lustre APIs
///
/// Once created, a `LustrePath` can be used with various Lustre operations like:
/// - Getting filesystem information (OST count, MDT count)
/// - Opening files with specific Lustre parameters
/// - Working with Lustre file identifiers (FIDs)
///
/// # Trait Implementations
///
/// `LustrePath` implements:
/// - `Display` for string representation
/// - `AsRef<Path>` for easy use with standard path operations
/// - `Serialize` and `Deserialize` for serialization support
///
/// # Examples
///
/// ```no_run
/// # use rustreapi::{LustrePath, Result};
/// # fn example() -> Result<()> {
/// // Create a validated Lustre path
/// let lustre_path = LustrePath::parse("/mnt/lustre")?;
///
/// // Use it to open a file handle to the Lustre mount point
/// let file = lustre_path.open()?;
/// # Ok(())
/// # }
/// ```
impl LustrePath {
    /// Parses a path string into a validated Lustre filesystem path.
    ///
    /// This method validates that the provided path points to a Lustre filesystem
    /// by attempting to retrieve the Lustre filesystem name using `llapi_get_fsname`.
    /// The path is canonicalized before validation.
    ///
    /// # Arguments
    ///
    /// * `path` - A string representing a path to a Lustre filesystem
    ///
    /// # Returns
    ///
    /// * `Ok(LustrePath)` - A validated Lustre filesystem path
    /// * `Err` - If the path is not a Lustre filesystem or other errors occur
    /// ```
    pub fn parse(path: &str) -> crate::Result<LustrePath> {
        let path = Path::new(path).canonicalize()?;
        let cstr = CString::new(path.as_os_str().as_encoded_bytes())?;
        let mut buf = CStrBuf::new(256);
        let _result = unsafe {
            cvt_lz_m(
                llapi_get_fsname(cstr.as_ptr(), buf.as_mut_ptr(), buf.buffer_len()),
                "llapi_get_fsname".to_string(),
            )
            .map_err(|e| match e {
                MsgErrno(_, errno::Errno::ENOTTY) => {
                    NotLustreFileSystem(path.to_string_lossy().to_string())
                }
                e => e,
            })?
        };

        Ok(LustrePath { path })
    }
    ///
    /// Opens this Lustre path as a file.
    ///
    /// This is a convenience method that attempts to open the path represented by
    /// this `LustrePath` and provides Lustre-specific error handling.
    ///
    /// # Returns
    ///
    /// * `Ok(File)` - A file handle for the opened Lustre path
    /// * `Err` - If opening the path fails, wrapped in a `LustreRootOpenError` with path details
    /// ```
    pub fn open(&self) -> crate::Result<File> {
        let file = match File::open(self) {
            Ok(file) => file,
            Err(e) => return Err(Error::LustreRootOpenError(self.clone(), e)),
        };

        Ok(file)
    }

    /// Finds a Lustre mount point by filesystem name.
    ///
    /// This function searches through all Lustre mounts on the system to find
    /// a mount point for the specified filesystem name. It looks for client mounts
    /// with `fs_label` matching the pattern `"Lustre-{fs_name}"`.
    ///
    /// # Arguments
    ///
    /// * `fs_name` - The name of the Lustre filesystem to search for
    ///
    /// # Returns
    ///
    /// * `Ok(LustrePath)` - A validated Lustre path to the filesystem mount point
    /// * `Err` - If the filesystem is not found or other errors occur
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rustreapi::{LustrePath, Result};
    /// # fn example() -> Result<()> {
    /// // Find mount point for filesystem named "lustre01"
    /// let mount_path = LustrePath::find_mount_by_fsname("lustre01")?;
    /// println!("Found mount at: {}", mount_path);
    /// # Ok(())
    /// # }
    /// ```
    pub fn find_mount_by_fsname(fs_name: &str) -> crate::Result<LustrePath> {
        let mounts = MountStats::discover_mounts()?;

        let expected_label = format!("Lustre-{}", fs_name);

        for mount in mounts {
            if let Some(ref fs_label) = mount.fs_label
                && fs_label == &expected_label
            {
                return Ok(LustrePath {
                    path: mount.info.mount_point,
                });
            }
        }

        Err(Error::FilesystemNotFound {
            filesystem: fs_name.to_string(),
        })
    }
}

impl Display for LustrePath {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path.display())
    }
}

impl AsRef<Path> for LustrePath {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}
