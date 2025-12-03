// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use super::{
    error::{ChangelogError, Result},
    record::Record,
};
use crate::{Fid, RecordType};
use changelog_sys::*;
use chrono::{DateTime, Utc};
use lnetconfig::SimpleNid;
use serde::{Deserialize, Serialize};
use std::{ffi::CStr, fs::File};

/// Trait for converting raw changelog records to structured `Record` types.
///
/// This trait allows for different conversion strategies and makes the system
/// more flexible and testable. Users can implement custom converters with
/// different behaviors, such as custom time formatting, field filtering, or
/// validation rules.
///
/// # Examples
///
/// ```rust,no_run
/// use rustreapi::changelog::{ConvertRecord, ChangelogRecord, Record, ChangelogResult};
/// use rustreapi::RecordType;
///
/// struct SimpleConverter;
///
/// impl ConvertRecord for SimpleConverter {
///     fn convert_record(&self, changelog_record: &ChangelogRecord) -> ChangelogResult<Record> {
///         // Custom conversion logic here
///         // For example, always use UTC time format
///         # Ok(Record {
///         #     record_type: RecordType::Create,
///         #     index: 0,
///         #     prev: 0,
///         #     time: "2025-01-01T00:00:00Z".to_string(),
///         #     target_fid: None,
///         #     parent_fid: None,
///         #     parent_dir: None,
///         #     filename: None,
///         #     uid: None,
///         #     gid: None,
///         #     client_nid: None,
///         #     job_id: None,
///         #     open_flags: None,
///         #     extra_flags: None,
///         #     marker_flags: None,
///         #     source_name: None,
///         #     source_fid: None,
///         #     source_parent_fid: None,
///         #     source_path: None,
///         #     xattr_name: None,
///         # })
///     }
/// }
///
/// // Usage:
/// let converter = SimpleConverter;
/// // let record = changelog_record.to_record_with(&converter)?;
/// ```
pub trait ConvertRecord {
    /// Converts a raw changelog record to a structured `Record`.
    fn convert_record(&self, changelog_record: &ChangelogRecord) -> Result<Record>;
}

/// Format for timestamp representation in records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimeFormat {
    /// Unix timestamp (seconds since epoch) as string
    Unix,
    /// ISO 8601 formatted string in local time without timezone (e.g., "2025-08-25T12:34:56")
    Iso8601Local,
    /// ISO 8601 formatted string assuming UNIX timestamp is in UTC (e.g., "2025-08-25T12:34:56Z")
    #[default]
    Iso8601Utc,
}

/// Represents different NID formats that can be present in changelog records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClientNid {
    /// Simple `lnet_nid_t` format (when `CLFE_NID_BE` is not set)
    Simple(SimpleNid), // Size of changelog_ext_nid.cr_nid
                       // Extended `struct lnet_nid` format (when `CLFE_NID_BE` is set)
                       // Currently represented as raw bytes until proper bindings are available
                       // Extended(lnetconfig::ExtendedNid), // Size of changelog_ext_nid
}

/// Builder for configuring a `RecordConverter`.
///
/// # Examples
/// ```rust,no_run
/// # use rustreapi::changelog::RecordConverterBuilder;
/// # use rustreapi::LustrePath;
/// # fn example() -> rustreapi::Result<()> {
/// let fd = LustrePath::parse("/mnt/lustre")?.open()?;
/// let converter = RecordConverterBuilder::new()
///     .lustre_fd(fd)
///     .resolve_fids(true)
///     .build();
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default)]
pub struct RecordConverterBuilder {
    lustre_fd: Option<File>,
    resolve_fids: bool,
    time_format: TimeFormat,
}

impl RecordConverterBuilder {
    /// Creates a new builder with default settings.
    pub fn new() -> Self {
        Self {
            lustre_fd: None,
            resolve_fids: false,
            time_format: TimeFormat::Unix, // Default to Unix timestamp for backward compatibility
        }
    }

    /// Sets the Lustre file descriptor for path resolution.
    pub fn lustre_fd(mut self, fd: File) -> Self {
        self.lustre_fd = Some(fd);
        self
    }

    pub fn resolve_fids(mut self, resolve: bool) -> Self {
        self.resolve_fids = resolve;
        self
    }

    /// Sets the time format for timestamps in records.
    ///
    /// By default, Unix timestamps are used. Set to `TimeFormat::Iso8601Local`
    /// to get ISO 8601 formatted strings in local time without timezone indicator.
    pub fn time_format(mut self, format: TimeFormat) -> Self {
        self.time_format = format;
        self
    }

    /// Builds the `RecordConverter` with the configured options.
    pub fn build(self) -> RecordConverter {
        RecordConverter {
            lustre_fd: self.lustre_fd,
            resolve_fids: self.resolve_fids,
            time_format: self.time_format,
        }
    }
}

/// Converts changelog records to structured `Record` types with optional context.
///
/// The converter holds context like Lustre file descriptors that can be used
/// to enhance records with additional information like resolved directory paths.
#[derive(Debug)]
pub struct RecordConverter {
    lustre_fd: Option<File>,
    resolve_fids: bool,
    time_format: TimeFormat,
}

impl ConvertRecord for RecordConverter {
    /// Converts a raw changelog record to a structured `Record`.
    fn convert_record(&self, changelog_record: &ChangelogRecord) -> Result<Record> {
        let record_type = changelog_record.record_type();

        // Check for unsupported record types
        if let RecordType::Unknown(_) = record_type {
            return Err(ChangelogError::UnsupportedRecordType { record_type });
        }

        // Extract common fields
        let (uid, gid) = changelog_record
            .uid_gid()
            .map(|(u, g)| (Some(u), Some(g)))
            .unwrap_or((None, None));

        let parent_fid = changelog_record.parent_fid();
        let parent_fid = if parent_fid.is_empty() {
            None
        } else {
            Some(parent_fid)
        };

        // Extract target_fid for all record types
        let target_fid = if record_type == RecordType::Mark {
            // CL_MARK uses marker_flags instead of target_fid
            None
        } else {
            let fid = changelog_record
                .target_fid()
                .ok_or(ChangelogError::MissingTargetFid { record_type })?;
            if fid.is_empty() { None } else { Some(fid) }
        };

        let filename = if let Some(mut parent) = self.resolve_fid(parent_fid.as_ref())
            && let Some(name) = changelog_record.filename()
        {
            parent.push(name);
            Some(parent.to_string_lossy().to_string())
        } else {
            self.resolve_all_targets(target_fid.as_ref())
                .or(changelog_record.filename())
        };

        // Extract type-specific fields
        let (marker_flags, source_fid, source_parent_fid, source_path, xattr_name) =
            match record_type {
                RecordType::Mark => {
                    let marker_flags = changelog_record.marker_flags();
                    (marker_flags, None, None, None, None)
                }
                RecordType::Rename => {
                    let rename_data = changelog_record.rename_data();
                    let (source_fid, source_parent_fid) = match rename_data {
                        Some((sf, spf)) => (Some(sf), Some(spf)),
                        None => (None, None),
                    };
                    let source_path = if let Some(name) = changelog_record.source_name()
                        && let Some(mut dir) = self.resolve_fid(source_parent_fid.as_ref())
                    {
                        dir.push(name);
                        Some(dir.to_string_lossy().to_string())
                    } else {
                        changelog_record.source_name()
                    };

                    (None, source_fid, source_parent_fid, source_path, None)
                }
                RecordType::Setxattr | RecordType::Getxattr => {
                    let xattr_name = changelog_record.xattr_name();
                    (None, None, None, None, xattr_name)
                }
                _ => {
                    // All other record types have no type-specific fields
                    (None, None, None, None, None)
                }
            };

        Ok(Record {
            record_type,
            index: changelog_record.index(),
            prev: changelog_record.prev(),
            time: self.format_time(changelog_record.time())?,
            parent_fid,
            parent_dir: None,
            target_fid,
            filename,
            uid,
            gid,
            client_nid: changelog_record.client_nid(),
            job_id: changelog_record.job_id(),
            open_flags: changelog_record.open_flags(),
            extra_flags: changelog_record.extra_flags(),
            marker_flags,
            source_fid,
            source_name: None,
            source_parent_fid,
            source_path,
            xattr_name,
        })
    }
}

impl RecordConverter {
    /// Creates a new converter with no context.
    pub fn new() -> Self {
        Self {
            lustre_fd: None,
            resolve_fids: false,
            time_format: TimeFormat::Unix,
        }
    }

    /// Creates a new converter with a Lustre file descriptor for path resolution.
    pub fn with_lustre_fd(lustre_fd: File) -> Self {
        Self {
            lustre_fd: Some(lustre_fd),
            resolve_fids: true,
            time_format: TimeFormat::Unix,
        }
    }

    /// Creates a new builder for configuring a converter.
    pub fn builder() -> RecordConverterBuilder {
        RecordConverterBuilder::new()
    }

    /// Helper function to format time according to the configured format
    fn format_time(&self, lustre_time: u64) -> Result<String> {
        match self.time_format {
            TimeFormat::Unix => Ok(lustre_time.to_string()),
            TimeFormat::Iso8601Local => {
                // Lustre time format: upper bits are seconds, lower 30 bits are nanoseconds
                let seconds = (lustre_time >> 30) as i64;
                let nanoseconds = (lustre_time & ((1 << 30) - 1)) as u32;

                match DateTime::<Utc>::from_timestamp(seconds, nanoseconds) {
                    Some(dt) => {
                        let local = dt.with_timezone(&chrono::Local);
                        Ok(local.to_rfc3339_opts(chrono::SecondsFormat::Nanos, false))
                    }
                    None => Err(ChangelogError::InvalidTimeFormat {
                        timestamp: lustre_time,
                    }),
                }
            }
            TimeFormat::Iso8601Utc => {
                // Lustre time format: upper bits are seconds, lower 30 bits are nanoseconds
                let seconds = (lustre_time >> 30) as i64;
                let nanoseconds = (lustre_time & ((1 << 30) - 1)) as u32;

                match DateTime::<Utc>::from_timestamp(seconds, nanoseconds) {
                    Some(dt) => Ok(dt.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)),
                    None => Err(ChangelogError::InvalidTimeFormat {
                        timestamp: lustre_time,
                    }),
                }
            }
        }
    }

    fn resolve_all_targets(&self, fid: Option<&Fid>) -> Option<String> {
        if self.resolve_fids {
            self.resolve_fid(fid)
                .map(|p| p.to_string_lossy().to_string())
        } else {
            None
        }
    }

    fn resolve_fid(&self, fid: Option<&Fid>) -> Option<std::path::PathBuf> {
        if self.resolve_fids
            && let Some(fid) = fid
            && !fid.is_empty()
            && let Some(fd) = &self.lustre_fd
            && let Ok(path) = fid.path_at(fd)
        {
            Some(path)
        } else {
            None
        }
    }
}

impl Default for RecordConverter {
    fn default() -> Self {
        Self::new()
    }
}

/// A safe wrapper around a raw changelog record.
///
/// This type owns the changelog record and automatically frees it when dropped.
/// The record is allocated by `llapi_changelog_recv()` and freed by `llapi_changelog_free()`.
pub struct ChangelogRecord {
    inner: *mut changelog_rec,
}

impl ChangelogRecord {
    /// Creates a new `ChangelogRecord` from a raw pointer allocated by `llapi_changelog_recv()`.
    ///
    /// This takes ownership of the allocated record and will automatically free it when dropped.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `rec` points to valid memory containing
    /// a properly initialized `changelog_rec` structure that was allocated
    /// by `llapi_changelog_recv()`.
    pub unsafe fn from_ptr(rec: *mut changelog_rec) -> Option<Self> {
        if rec.is_null() {
            None
        } else {
            Some(Self { inner: rec })
        }
    }

    /// Gets a reference to the inner changelog record.
    fn inner(&self) -> &changelog_rec {
        unsafe { &*self.inner }
    }

    /// Gets the record type.
    pub fn record_type(&self) -> RecordType {
        RecordType::from(self.inner().cr_type)
    }

    /// Gets the record index.
    pub fn index(&self) -> u64 {
        self.inner().cr_index
    }

    /// Gets the previous record index.
    pub fn prev(&self) -> u64 {
        self.inner().cr_prev
    }

    /// Gets the record timestamp.
    pub fn time(&self) -> u64 {
        self.inner().cr_time
    }

    /// Gets the record flags.
    pub fn flags(&self) -> i32 {
        i32::from(self.inner().cr_flags)
    }

    /// Gets the parent FID.
    pub fn parent_fid(&self) -> Fid {
        Fid::from(self.inner().cr_pfid)
    }

    /// Gets the target FID. Returns None for `CL_MARK` records which use `cr_markerflags` instead.
    pub fn target_fid(&self) -> Option<Fid> {
        if self.record_type() == RecordType::Mark {
            None // CL_MARK uses cr_markerflags, not cr_tfid
        } else {
            let tfid = unsafe { &self.inner().__bindgen_anon_1.cr_tfid };
            Some(Fid::from(*tfid))
        }
    }

    /// Gets the marker flags for `CL_MARK` records. Returns None for other record types.
    pub fn marker_flags(&self) -> Option<u32> {
        if self.record_type() == RecordType::Mark {
            Some(unsafe { self.inner().__bindgen_anon_1.cr_markerflags })
        } else {
            None
        }
    }

    /// Gets the `filename` associated with this changelog record, if any.
    pub fn filename(&self) -> Option<String> {
        let name_ptr = unsafe { changelog_rec_name(self.inner) };
        if name_ptr.is_null() {
            return None;
        }

        let name_len = self.inner().cr_namelen as usize;
        if name_len == 0 {
            return None;
        }

        let slice = unsafe { std::slice::from_raw_parts(name_ptr as *const u8, name_len) };
        match CStr::from_bytes_until_nul(slice) {
            Ok(cstr) => cstr.to_str().ok().map(|s| s.to_owned()),
            Err(_) => String::from_utf8_lossy(slice).into_owned().into(),
        }
    }

    /// Gets the source `filename` for rename operations.
    pub fn source_name(&self) -> Option<String> {
        // Check if this is a rename operation
        if (self.flags() & CLF_RENAME) == 0 {
            return None;
        }

        let sname_ptr = unsafe { changelog_rec_sname(self.inner) };
        if sname_ptr.is_null() {
            return None;
        }

        let sname_len = unsafe { changelog_rec_snamelen(self.inner) } as usize;
        if sname_len == 0 {
            return None;
        }

        let slice = unsafe { std::slice::from_raw_parts(sname_ptr as *const u8, sname_len) };
        match CStr::from_bytes_until_nul(slice) {
            Ok(cstr) => cstr.to_str().ok().map(|s| s.to_owned()),
            Err(_) => String::from_utf8_lossy(slice).into_owned().into(),
        }
    }

    /// Gets the extra flags, if the `CLF_EXTRA_FLAGS` flag is set.
    pub fn extra_flags(&self) -> Option<u64> {
        if (self.flags() & CLF_EXTRA_FLAGS) != 0 {
            let extra_flags_ptr = unsafe { changelog_sys::changelog_rec_extra_flags(self.inner) };
            if !extra_flags_ptr.is_null() {
                Some(unsafe { (*extra_flags_ptr).cr_extra_flags })
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Gets the UID and GID from the `UIDGID` extension, if present.
    pub fn uid_gid(&self) -> Option<(u64, u64)> {
        // Check if UIDGID extension is present
        let extra_flags = self.extra_flags()?;
        if (extra_flags & u64::from(CLFE_UIDGID)) == 0 {
            return None;
        }

        let uidgid_ptr = unsafe { changelog_rec_uidgid(self.inner) };
        if !uidgid_ptr.is_null() {
            unsafe { Some(((*uidgid_ptr).cr_uid, (*uidgid_ptr).cr_gid)) }
        } else {
            None
        }
    }

    /// Gets the client NID from the NID extension, if present.
    pub fn client_nid(&self) -> Option<ClientNid> {
        // Check if NID extension is present
        let extra_flags = self.extra_flags()?;
        if (extra_flags & u64::from(CLFE_NID)) == 0 {
            return None;
        }

        let nid_ptr = unsafe { changelog_rec_nid(self.inner) };
        if nid_ptr.is_null() {
            return None;
        }

        // #[cfg(feature = "LUSTRE_2_16")]
        // // Check if NID_BE flag is set to determine format
        // if (extra_flags & u64::from(CLFE_NID_BE)) != 0 {
        //     // Extended format: the entire changelog_ext_nid structure contains struct lnet_nid
        //     let nid = nid_ptr as *const lnetconfig::lnet_nid;
        //     Some(ClientNid::Extended(ExtendedNid::new(unsafe { *nid })))
        // } else

        let nid = unsafe { (*nid_ptr).cr_nid as lnetconfig::lnet_nid_t };
        // Simple format: cr_nid field contains lnet_nid_t
        Some(ClientNid::Simple(SimpleNid::new(nid)))
    }

    /// Gets the open flags from the OPEN extension, if present.
    pub fn open_flags(&self) -> Option<u32> {
        // Check if OPEN extension is present
        let extra_flags = self.extra_flags()?;
        if (extra_flags & u64::from(CLFE_OPEN)) == 0 {
            return None;
        }

        let open_ptr = unsafe { changelog_rec_openmode(self.inner) };
        if !open_ptr.is_null() {
            Some(unsafe { (*open_ptr).cr_openflags })
        } else {
            None
        }
    }

    /// Gets the job ID from the JOBID extension, if present.
    pub fn job_id(&self) -> Option<String> {
        // Check if JOBID flag is set
        if (self.flags() & CLF_JOBID) == 0 {
            return None;
        }

        let jobid_ptr = unsafe { changelog_rec_jobid(self.inner) };
        if !jobid_ptr.is_null() {
            let jobid_bytes = unsafe { &(*jobid_ptr).cr_jobid };
            let cstr = unsafe { CStr::from_ptr(jobid_bytes.as_ptr()) };
            if let Ok(s) = cstr.to_str()
                && !s.is_empty()
            {
                Some(s.to_owned())
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Gets the rename extension data, if present.
    pub fn rename_data(&self) -> Option<(Fid, Fid)> {
        // Check if this is a rename operation
        if (self.flags() & CLF_RENAME) == 0 {
            return None;
        }

        let rename_ptr = unsafe { changelog_rec_rename(self.inner) };
        if !rename_ptr.is_null() {
            unsafe {
                let source_fid = Fid::from((*rename_ptr).cr_sfid);
                let source_parent_fid = Fid::from((*rename_ptr).cr_spfid);
                Some((source_fid, source_parent_fid))
            }
        } else {
            None
        }
    }

    /// Gets the `xattr` name from the `XATTR` extension, if present.
    pub fn xattr_name(&self) -> Option<String> {
        // Check if XATTR extension is present
        let extra_flags = self.extra_flags()?;
        if (extra_flags & u64::from(CLFE_XATTR)) == 0 {
            return None;
        }

        let xattr_ptr = unsafe { changelog_rec_xattr(self.inner) };
        if !xattr_ptr.is_null() {
            let xattr_bytes = unsafe { &(*xattr_ptr).cr_xattr };
            let cstr = unsafe { CStr::from_ptr(xattr_bytes.as_ptr()) };
            if let Ok(s) = cstr.to_str()
                && !s.is_empty()
            {
                Some(s.to_owned())
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Converts this changelog record to a structured `Record` using the default converter.
    pub fn to_record(&self) -> Result<Record> {
        let converter = RecordConverter::new();
        converter.convert_record(self)
    }

    /// Converts this changelog record to a structured `Record` using a custom converter.
    pub fn to_record_with<C: ConvertRecord>(&self, converter: &C) -> Result<Record> {
        converter.convert_record(self)
    }
}

impl Drop for ChangelogRecord {
    fn drop(&mut self) {
        unsafe {
            let mut rec_ptr = self.inner;
            llapi_changelog_free(&mut rec_ptr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    /// Allocates a `changelog_rec` on the heap for testing.
    /// The returned pointer can be safely passed to `ChangelogRecord::from_ptr()`
    /// and will be properly freed by `llapi_changelog_free()` when dropped.
    fn alloc_test_changelog_rec() -> *mut changelog_rec {
        let size = size_of::<changelog_rec>();
        let ptr = unsafe { libc::calloc(1, size) as *mut changelog_rec };
        if ptr.is_null() {
            panic!("Failed to allocate memory for test");
        }
        ptr
    }

    #[test]
    fn test_convert_null() {
        let result = unsafe { ChangelogRecord::from_ptr(ptr::null_mut()) };
        assert!(result.is_none());
    }

    #[test]
    fn test_convert_wrong_type() {
        unsafe {
            let rec_ptr = alloc_test_changelog_rec();
            (*rec_ptr).cr_type = CL_MKDIR as u32;

            // Set a non-empty target FID
            (*rec_ptr).__bindgen_anon_1.cr_tfid.f_seq = 0x200000007;
            (*rec_ptr).__bindgen_anon_1.cr_tfid.f_oid = 1;
            (*rec_ptr).__bindgen_anon_1.cr_tfid.f_ver = 0;

            let changelog_record = ChangelogRecord::from_ptr(rec_ptr).unwrap();
            let converter = RecordConverter::new();
            let result = converter.convert_record(&changelog_record);
            // Should succeed for MKDIR record type
            assert!(result.is_ok());
            // ChangelogRecord will automatically free the memory when dropped
        }
    }

    #[test]
    fn test_builder() {
        // Test builder with default settings
        let converter = RecordConverterBuilder::new().build();
        assert!(converter.lustre_fd.is_none());
        assert!(!converter.resolve_fids);
        assert_eq!(converter.time_format, TimeFormat::Unix);

        // Test builder with parent resolution disabled
        let converter = RecordConverterBuilder::new().resolve_fids(false).build();
        assert!(converter.lustre_fd.is_none());
        assert!(!converter.resolve_fids);

        // Test builder with ISO 8601 UTC time format
        let converter = RecordConverterBuilder::new()
            .time_format(TimeFormat::Iso8601Utc)
            .build();
        assert_eq!(converter.time_format, TimeFormat::Iso8601Utc);

        // Test that builder() method on RecordConverter works
        let converter = RecordConverter::builder().resolve_fids(false).build();
        assert!(!converter.resolve_fids);
    }

    #[test]
    fn test_time_format() {
        // Test with Lustre packed timestamp format:
        // Upper bits (>> 30) = seconds, lower 30 bits = nanoseconds
        // 1234567890 seconds << 30 | 123456789 nanoseconds
        let lustre_timestamp = (1234567890u64 << 30) | 123456789u64;

        let converter_unix = RecordConverter::builder()
            .time_format(TimeFormat::Unix)
            .build();
        assert_eq!(
            converter_unix.format_time(lustre_timestamp).unwrap(),
            lustre_timestamp.to_string()
        );

        let converter_utc = RecordConverter::builder()
            .time_format(TimeFormat::Iso8601Utc)
            .build();
        assert_eq!(
            converter_utc.format_time(lustre_timestamp).unwrap(),
            "2009-02-13T23:31:30.123456789Z"
        );

        let converter_local = RecordConverter::builder()
            .time_format(TimeFormat::Iso8601Local)
            .build();
        let result = converter_local.format_time(lustre_timestamp).unwrap();
        // Check that it includes nanoseconds and doesn't have 'Z' suffix
        assert!(result.contains("2009-02-13T") || result.contains("2009-02-14T"));
        assert!(result.contains(".123456789"));
        assert!(!result.contains("Z")); // Should not have timezone indicator
    }

    #[test]
    fn test_convert_basic_create() {
        unsafe {
            let rec_ptr = alloc_test_changelog_rec();

            // Initialize the record
            (*rec_ptr).cr_type = CL_CREATE as u32;
            (*rec_ptr).cr_index = 12345;
            (*rec_ptr).cr_prev = 12344;
            (*rec_ptr).cr_time = 1234567890;
            (*rec_ptr).cr_namelen = 0; // No filename

            // Set some basic FIDs
            (*rec_ptr).cr_pfid.f_seq = 0x200000007;
            (*rec_ptr).cr_pfid.f_oid = 1;
            (*rec_ptr).cr_pfid.f_ver = 0;

            (*rec_ptr).__bindgen_anon_1.cr_tfid.f_seq = 0x200000007;
            (*rec_ptr).__bindgen_anon_1.cr_tfid.f_oid = 2;
            (*rec_ptr).__bindgen_anon_1.cr_tfid.f_ver = 0;

            let changelog_record = ChangelogRecord::from_ptr(rec_ptr).unwrap();
            let converter = RecordConverter::new();
            let result = converter.convert_record(&changelog_record);
            assert!(result.is_ok());

            let record = result.unwrap();
            assert_eq!(record.record_type, RecordType::Create);
            assert_eq!(record.index, 12345);
            assert_eq!(record.prev, 12344);
            assert_eq!(record.time, "1234567890");
            assert_eq!(record.parent_fid.as_ref().unwrap().oid(), 1);
            assert_eq!(record.target_fid.as_ref().unwrap().oid(), 2);
            assert!(record.filename.is_none());
            assert!(record.uid.is_none());
            assert!(record.gid.is_none());
            assert!(record.client_nid.is_none());
            assert!(record.job_id.is_none());
            assert!(record.open_flags.is_none());
            assert!(record.extra_flags.is_none());
            assert!(record.parent_dir.is_none());
            // ChangelogRecord will automatically free the memory when dropped
        }
    }

    #[test]
    fn test_convert_close() {
        unsafe {
            let rec_ptr = alloc_test_changelog_rec();

            // Initialize the record
            (*rec_ptr).cr_type = CL_CLOSE as u32;
            (*rec_ptr).cr_index = 54321;
            (*rec_ptr).cr_prev = 54320;
            (*rec_ptr).cr_time = (1234567890u64 << 30) | 987654321u64; // Lustre packed time format
            (*rec_ptr).cr_namelen = 0; // No filename

            // Set some basic FIDs
            (*rec_ptr).cr_pfid.f_seq = 0x200000007;
            (*rec_ptr).cr_pfid.f_oid = 1;
            (*rec_ptr).cr_pfid.f_ver = 0;

            (*rec_ptr).__bindgen_anon_1.cr_tfid.f_seq = 0x200000007;
            (*rec_ptr).__bindgen_anon_1.cr_tfid.f_oid = 3;
            (*rec_ptr).__bindgen_anon_1.cr_tfid.f_ver = 0;

            let changelog_record = ChangelogRecord::from_ptr(rec_ptr).unwrap();
            let converter = RecordConverter::new();
            let result = converter.convert_record(&changelog_record);
            assert!(result.is_ok());

            let record = result.unwrap();
            assert_eq!(record.record_type, RecordType::Close);
            assert_eq!(record.index, 54321);
            assert_eq!(record.prev, 54320);
            // Time should be the raw packed value as string since we're using Unix format
            assert_eq!(
                record.time,
                ((1234567890u64 << 30) | 987654321u64).to_string()
            );
            assert_eq!(record.parent_fid.as_ref().unwrap().oid(), 1);
            assert_eq!(record.target_fid.as_ref().unwrap().oid(), 3);
            assert_eq!(record.filename, None);

            // ChangelogRecord will automatically free the memory when dropped
        }
    }

    #[test]
    fn test_convert_record_trait() {
        unsafe {
            let rec_ptr = alloc_test_changelog_rec();
            (*rec_ptr).cr_type = CL_CREATE as u32;

            // Set a non-empty target FID
            (*rec_ptr).__bindgen_anon_1.cr_tfid.f_seq = 0x200000007;
            (*rec_ptr).__bindgen_anon_1.cr_tfid.f_oid = 2;
            (*rec_ptr).__bindgen_anon_1.cr_tfid.f_ver = 0;

            let changelog_record = ChangelogRecord::from_ptr(rec_ptr).unwrap();

            // Test using trait method directly
            let converter = RecordConverter::new();
            let result = converter.convert_record(&changelog_record);
            assert!(result.is_ok());

            // Test using to_record_with method
            let result2 = changelog_record.to_record_with(&converter);
            assert!(result2.is_ok());

            // Both should produce the same result
            let record1 = result.unwrap();
            let record2 = result2.unwrap();
            assert_eq!(record1.record_type, record2.record_type);
            assert_eq!(record1.index, record2.index);
        }
    }
}
