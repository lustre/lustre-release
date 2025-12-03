// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use std::ffi::CString;

use super::{
    error::{ChangelogError, Result as ChangelogResult},
    flags::{ChangelogExtraFlag, ChangelogFlag},
    reader::ChangelogReader,
};
use crate::error::cvt_nz;
use changelog_sys::*;

/// Builder for configuring and connecting to a Lustre changelog.
///
/// This builder provides a fluent interface for configuring changelog parameters
/// before establishing a connection.
///
/// # Example
/// ```rust,no_run
/// use rustreapi::changelog::{ChangelogBuilder, ChangelogFlag, ChangelogExtraFlag};
///
/// let reader = ChangelogBuilder::new()
///     .device("lustre-MDT0000")
///     .flags(ChangelogFlag::Follow | ChangelogFlag::Block)
///     .extra_flags(ChangelogExtraFlag::UidGid | ChangelogExtraFlag::Nid)
///     .start_record(0)
///     .connect()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct ChangelogBuilder {
    device: Option<String>,
    flags: ChangelogFlag,
    extra_flags: Option<ChangelogExtraFlag>,
    start_record: i64,
}

impl ChangelogBuilder {
    /// Create a new changelog builder with default settings.
    pub fn new() -> Self {
        Self {
            device: None,
            flags: ChangelogFlag::none(),
            extra_flags: None,
            start_record: 0,
        }
    }

    /// Set the MDT device name to connect to.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use rustreapi::changelog::ChangelogBuilder;
    /// let builder = ChangelogBuilder::new().device("lustre-MDT0000");
    /// ```
    pub fn device<S: Into<String>>(mut self, device: S) -> Self {
        self.device = Some(device.into());
        self
    }

    /// Set the changelog flags.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use rustreapi::changelog::{ChangelogBuilder, ChangelogFlag};
    /// let builder = ChangelogBuilder::new()
    ///     .flags(ChangelogFlag::Follow | ChangelogFlag::Block);
    /// ```
    pub fn flags(mut self, flags: ChangelogFlag) -> Self {
        self.flags = flags;
        self
    }

    /// Set the extra flags for requesting additional extension data.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use rustreapi::changelog::{ChangelogBuilder, ChangelogExtraFlag};
    /// let builder = ChangelogBuilder::new()
    ///     .extra_flags(ChangelogExtraFlag::UidGid | ChangelogExtraFlag::Nid);
    /// ```
    pub fn extra_flags(mut self, extra_flags: ChangelogExtraFlag) -> Self {
        self.extra_flags = Some(extra_flags);
        self
    }

    /// Set the starting record index.
    ///
    /// Records with indices less than this value will be skipped.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use rustreapi::changelog::ChangelogBuilder;
    /// let builder = ChangelogBuilder::new().start_record(12345);
    /// ```
    pub fn start_record(mut self, start_record: i64) -> Self {
        self.start_record = start_record;
        self
    }

    /// Establish a connection to the changelog and return a reader.
    ///
    /// This method will call `llapi_changelog_start` followed by
    /// `llapi_changelog_set_xflags` if extra flags are configured.
    ///
    /// # Errors
    /// Returns an error if:
    /// - No device was specified
    /// - The changelog connection could not be established
    /// - Setting extra flags failed
    pub fn connect(self) -> ChangelogResult<ChangelogReader> {
        let device = self.device.ok_or(ChangelogError::MissingDevice)?;

        let device_cstr =
            CString::new(device.clone()).map_err(|e| ChangelogError::InvalidDevice {
                device: device.clone(),
                source: e,
            })?;

        let mut priv_ptr: *mut std::os::raw::c_void = std::ptr::null_mut();

        // Start the changelog connection
        unsafe {
            cvt_nz(llapi_changelog_start(
                &mut priv_ptr,
                self.flags.bits(),
                device_cstr.as_ptr(),
                self.start_record as std::os::raw::c_longlong,
            ))
            .map_err(|e| ChangelogError::StartFailed {
                device: device.clone(),
                source: Box::new(e),
            })?;
        }

        if priv_ptr.is_null() {
            return Err(ChangelogError::StartInvalidResult {
                device: device.clone(),
            });
        }

        // Set extra flags if specified
        if let Some(extra_flags) = self.extra_flags {
            unsafe {
                cvt_nz(llapi_changelog_set_xflags(priv_ptr, extra_flags.bits())).map_err(|e| {
                    // Clean up the connection on error
                    let mut cleanup_ptr = priv_ptr;
                    let _ = llapi_changelog_fini(&mut cleanup_ptr);
                    ChangelogError::SetExtraFlagsFailed {
                        device: device.clone(),
                        source: Box::new(e),
                    }
                })?;
            }
        }

        Ok(ChangelogReader::new(priv_ptr, device, self.flags))
    }
}

impl Default for ChangelogBuilder {
    fn default() -> Self {
        Self::new()
    }
}
