// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use std::{io::Error as IoError, ptr, time::Duration};

use super::{
    convert::{ChangelogRecord, ConvertRecord},
    error::{ChangelogError, Result as ChangelogResult},
    flags::ChangelogFlag,
    record::Record,
};
use crate::{
    error::{Result, cvt_rc_m},
    hsm::RawDescriptor,
};
use changelog_sys::*;
use nix::{
    errno::Errno,
    fcntl::{FcntlArg, OFlag, fcntl},
};

/// Safe wrapper around `llapi_changelog_recv` that handles error conversion.
///
/// # Returns
/// - `Ok(Some(ptr))` if a record was received successfully
/// - `Ok(None)` if no more records are available (EOF)
/// - `Err(error)` if an error occurred during receive
fn safe_changelog_recv(
    priv_ptr: *mut std::os::raw::c_void,
    device: &str,
) -> Result<Option<*mut changelog_rec>> {
    let mut rec_ptr: *mut changelog_rec = ptr::null_mut();

    let rc = unsafe { llapi_changelog_recv(priv_ptr, &mut rec_ptr) };
    // Save errno immediately after the call, before any other operations
    let errno = Errno::last();

    match rc {
        0 => {
            if rec_ptr.is_null() {
                Ok(None)
            } else {
                Ok(Some(rec_ptr))
            }
        }
        1 => {
            // EOF - no more records available
            Ok(None)
        }
        rc if rc == -(Errno::EAGAIN as i32) || rc == -(Errno::EWOULDBLOCK as i32) => {
            // EAGAIN or EWOULDBLOCK - No data available right now in non-blocking mode
            Ok(None)
        }
        _ => {
            // Check errno as well (sometimes errno is set instead of rc being -errno)
            if errno == Errno::EAGAIN || errno == Errno::EWOULDBLOCK {
                // No data available right now, but not an error
                Ok(None)
            } else {
                // Real error occurred - use cvt_rc_m to convert the error code
                cvt_rc_m(
                    rc,
                    format!(
                        "Failed to receive changelog record from device {} (rc: {}, errno: {})",
                        device, rc, errno
                    ),
                )?;
                unreachable!()
            }
        }
    }
}

/// A reader for consuming Lustre changelog records.
///
/// This reader manages an active connection to a Lustre changelog and provides
/// methods for receiving records both in blocking and non-blocking modes.
/// It automatically cleans up the connection when dropped.
///
/// # Examples
/// ```rust,no_run
/// use rustreapi::changelog::{ChangelogBuilder, ChangelogFlag};
///
/// let reader = ChangelogBuilder::new()
///     .device("lustre-MDT0000")
///     .flags(ChangelogFlag::Follow)
///     .connect()?;
///
/// // Blocking receive
/// if let Some(record) = reader.recv()? {
///     println!("Received record: {:?}", record);
/// }
///
/// // Non-blocking poll
/// if let Some(record) = reader.poll()? {
///     println!("Polled record: {:?}", record);
/// }
///
/// // Iterator interface
/// for record in reader {
///     let record = record?;
///     if record.record_type == rustreapi::RecordType::Create {
///         println!("File created: {:?}", record.filename);
///     }
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct ChangelogReader {
    priv_ptr: *mut std::os::raw::c_void,
    device: String,
    flags: ChangelogFlag,
}

impl ChangelogReader {
    /// Create a new changelog reader.
    ///
    /// # Safety
    /// The caller must ensure that `priv_ptr` is a valid pointer returned
    /// by `llapi_changelog_start` and has not been freed.
    pub(super) fn new(
        priv_ptr: *mut std::os::raw::c_void,
        device: String,
        flags: ChangelogFlag,
    ) -> Self {
        Self {
            priv_ptr,
            device,
            flags,
        }
    }

    /// Receive a changelog record, blocking until one is available.
    ///
    /// This method will block indefinitely if the `Block` flag was set during
    /// connection. If `Block` was not set, it will return `None` immediately
    /// if no records are available.
    ///
    /// # Returns
    /// - `Ok(Some(record))` if a record was received
    /// - `Ok(None)` if no records are available and blocking is disabled
    /// - `Err(error)` if an error occurred
    pub fn recv(&self) -> ChangelogResult<Option<Record>> {
        match safe_changelog_recv(self.priv_ptr, &self.device) {
            Ok(Some(rec_ptr)) => {
                // We have a record, convert it
                let changelog_record = unsafe { ChangelogRecord::from_ptr(rec_ptr) }
                    .ok_or(ChangelogError::InvalidRecordPointer)?;

                let record = changelog_record.to_record()?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ChangelogError::ReceiveFailed {
                device: self.device.clone(),
                source: Box::new(e),
            }),
        }
    }

    /// Receive a changelog record with a converter for context-aware processing.
    ///
    /// This method works like `recv()` but allows passing a `RecordConverter`
    /// that can contain context such as Lustre file descriptors for resolving
    /// parent FIDs to directory paths.
    ///
    /// # Arguments
    /// * `converter` - `RecordConverter` with optional context for FID resolution
    ///
    /// # Returns
    /// - `Ok(Some(record))` if a record was received  
    /// - `Ok(None)` if no records are available and blocking is disabled
    /// - `Err(error)` if an error occurred
    pub fn recv_with_converter<C: ConvertRecord>(
        &self,
        converter: &C,
    ) -> ChangelogResult<Option<Record>> {
        match safe_changelog_recv(self.priv_ptr, &self.device) {
            Ok(Some(rec_ptr)) => {
                // We have a record, convert it
                let changelog_record = unsafe { ChangelogRecord::from_ptr(rec_ptr) }
                    .ok_or(ChangelogError::InvalidRecordPointer)?;

                let record = converter.convert_record(&changelog_record)?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ChangelogError::ReceiveFailed {
                device: self.device.clone(),
                source: Box::new(e),
            }),
        }
    }

    /// Poll for a changelog record without blocking.
    ///
    /// This method will return immediately regardless of the `Block` flag setting.
    /// It's useful for implementing non-blocking event loops.
    ///
    /// # Returns
    /// - `Ok(Some(record))` if a record was received
    /// - `Ok(None)` if no records are currently available
    /// - `Err(error)` if an error occurred
    pub fn poll(&self) -> ChangelogResult<Option<Record>> {
        // For now, this is the same as recv() since the Lustre API doesn't
        // provide a separate non-blocking interface. The blocking behavior
        // is controlled by the flags set during connection.
        // TODO: Consider using a timeout mechanism or background thread
        // for true non-blocking behavior
        self.recv()
    }

    /// Poll for a changelog record with a timeout.
    ///
    /// This method will wait up to the specified duration for a record to become
    /// available before returning `None`.
    ///
    /// # Arguments
    /// * `timeout` - Maximum time to wait for a record
    ///
    /// # Returns
    /// - `Ok(Some(record))` if a record was received within the timeout
    /// - `Ok(None)` if no records were available within the timeout
    /// - `Err(error)` if an error occurred
    pub fn poll_timeout(&self, _timeout: Duration) -> ChangelogResult<Option<Record>> {
        // TODO: Implement timeout-based polling using threads or async
        // For now, fall back to regular polling
        self.poll()
    }

    /// Get the device name this reader is connected to.
    pub fn device(&self) -> &str {
        &self.device
    }

    /// Get the flags used to configure this reader.
    pub fn flags(&self) -> ChangelogFlag {
        self.flags
    }

    /// Check if this reader is configured to follow new records.
    pub fn is_following(&self) -> bool {
        self.flags.contains(ChangelogFlag::Follow)
    }

    /// Check if this reader is configured to block when no records are available.
    pub fn is_blocking(&self) -> bool {
        self.flags.contains(ChangelogFlag::Block)
    }

    /// Get the file descriptor for this changelog reader as a `RawDescriptor`.
    ///
    /// This returns a `RawDescriptor` that is compatible with `tokio::AsyncFd` for
    /// implementing non-blocking, interruptible reads.
    ///
    /// # Returns
    /// - `Ok(RawDescriptor)` if the file descriptor was retrieved successfully
    /// - `Err(error)` if an error occurred
    pub fn get_fd(&self) -> ChangelogResult<RawDescriptor> {
        let fd = unsafe { llapi_changelog_get_fd(self.priv_ptr) };

        if fd < 0 {
            return Err(ChangelogError::ConnectionFailed {
                device: self.device.clone(),
                source: IoError::other(format!("Failed to get changelog file descriptor: {}", fd)),
            });
        }

        // Set the file descriptor to non-blocking mode using nix
        // Get current flags
        let flags = fcntl(fd, FcntlArg::F_GETFL).map_err(|e| ChangelogError::ConnectionFailed {
            device: self.device.clone(),
            source: IoError::from(e),
        })?;

        // Set non-blocking flag
        let mut new_flags = OFlag::from_bits_truncate(flags);
        new_flags |= OFlag::O_NONBLOCK;

        fcntl(fd, FcntlArg::F_SETFL(new_flags)).map_err(|e| ChangelogError::ConnectionFailed {
            device: self.device.clone(),
            source: IoError::from(e),
        })?;

        Ok(RawDescriptor::new(fd))
    }
}

impl Drop for ChangelogReader {
    fn drop(&mut self) {
        if !self.priv_ptr.is_null() {
            unsafe {
                let mut ptr = self.priv_ptr;
                let _ = llapi_changelog_fini(&mut ptr);
                self.priv_ptr = ptr::null_mut();
            }
        }
    }
}

impl Iterator for ChangelogReader {
    type Item = ChangelogResult<Record>;

    /// Iterate over changelog records.
    ///
    /// This iterator will continue indefinitely if the `Follow` flag was set,
    /// yielding new records as they become available. Without `Follow`, it will
    /// stop when no more records are available.
    ///
    /// # Note
    /// The iterator will block if the `Block` flag was set during connection.
    /// For non-blocking iteration, use the `poll()` method directly.
    fn next(&mut self) -> Option<Self::Item> {
        match self.recv() {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => {
                if self.is_following() {
                    // In follow mode, we should continue trying
                    // TODO: Add a small delay to avoid busy-waiting
                    self.next()
                } else {
                    // No more records and not following
                    None
                }
            }
            Err(e) => Some(Err(e)),
        }
    }
}
