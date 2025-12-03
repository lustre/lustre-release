// SPDX-License-Identifier: MIT

// Copyright (c) 2025. DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use super::convert::ClientNid;
use crate::Fid;
use changelog_sys::*;
use serde::{Deserialize, Serialize};

/// Represents the different types of changelog records.
///
/// Each variant corresponds to a specific operation that can be recorded
/// in the Lustre changelog system. Order matches the C constants exactly.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum RecordType {
    /// None value (`CL_NONE` = -1)
    None,
    /// Mark operation (`CL_MARK` = 0)
    Mark,
    /// File/directory creation (`CL_CREATE` = 1)
    Create,
    /// Directory creation (`CL_MKDIR` = 2)
    Mkdir,
    /// Hard link creation (`CL_HARDLINK` = 3)
    Hardlink,
    /// Soft link creation (`CL_SOFTLINK` = 4)
    Softlink,
    /// Special file creation (`CL_MKNOD` = 5)
    Mknod,
    /// File/directory deletion (`CL_UNLINK` = 6)
    Unlink,
    /// Directory removal (`CL_RMDIR` = 7)
    Rmdir,
    /// File/directory rename (`CL_RENAME` = 8)
    Rename,
    /// Extended operation (`CL_EXT` = 9)
    Ext,
    /// File open (`CL_OPEN` = 10)
    Open,
    /// File close (`CL_CLOSE` = 11)
    Close,
    /// Layout change (`CL_LAYOUT` = 12)
    Layout,
    /// File truncation (`CL_TRUNC` = 13)
    Trunc,
    /// Metadata change (`CL_SETATTR` = 14)
    Setattr,
    /// Extended attribute setting (`CL_SETXATTR` = 15)
    Setxattr,
    /// HSM operation (`CL_HSM` = 16)
    Hsm,
    /// Modify time update (`CL_MTIME` = 17)
    Mtime,
    /// Change time update (`CL_CTIME` = 18)
    Ctime,
    /// Access time update (`CL_ATIME` = 19)
    Atime,
    /// Migration operation (`CL_MIGRATE` = 20)
    Migrate,
    /// File lock read/write (`CL_FLRW` = 21)
    Flrw,
    /// Re-sync operation (`CL_RESYNC` = 22)
    Resync,
    /// Extended attribute retrieval (`CL_GETXATTR` = 23)
    Getxattr,
    /// Directory open (`CL_DN_OPEN` = 24)
    DnOpen,
    /// Last valid record type (`CL_LAST` = 25)
    Last,
    /// Unknown or unsupported record type
    Unknown(u32),
}

impl From<u32> for RecordType {
    fn from(value: u32) -> Self {
        match value {
            x if x == CL_NONE as u32 => RecordType::None,
            x if x == CL_MARK as u32 => RecordType::Mark,
            x if x == CL_CREATE as u32 => RecordType::Create,
            x if x == CL_MKDIR as u32 => RecordType::Mkdir,
            x if x == CL_HARDLINK as u32 => RecordType::Hardlink,
            x if x == CL_SOFTLINK as u32 => RecordType::Softlink,
            x if x == CL_MKNOD as u32 => RecordType::Mknod,
            x if x == CL_UNLINK as u32 => RecordType::Unlink,
            x if x == CL_RMDIR as u32 => RecordType::Rmdir,
            x if x == CL_RENAME as u32 => RecordType::Rename,
            x if x == CL_EXT as u32 => RecordType::Ext,
            x if x == CL_OPEN as u32 => RecordType::Open,
            x if x == CL_CLOSE as u32 => RecordType::Close,
            x if x == CL_LAYOUT as u32 => RecordType::Layout,
            x if x == CL_TRUNC as u32 => RecordType::Trunc,
            x if x == CL_SETATTR as u32 => RecordType::Setattr,
            x if x == CL_SETXATTR as u32 => RecordType::Setxattr,
            x if x == CL_HSM as u32 => RecordType::Hsm,
            x if x == CL_MTIME as u32 => RecordType::Mtime,
            x if x == CL_CTIME as u32 => RecordType::Ctime,
            x if x == CL_ATIME as u32 => RecordType::Atime,
            x if x == CL_MIGRATE as u32 => RecordType::Migrate,
            x if x == CL_FLRW as u32 => RecordType::Flrw,
            x if x == CL_RESYNC as u32 => RecordType::Resync,
            x if x == CL_GETXATTR as u32 => RecordType::Getxattr,
            x if x == CL_DN_OPEN as u32 => RecordType::DnOpen,
            x if x == CL_LAST as u32 => RecordType::Last,
            other => RecordType::Unknown(other),
        }
    }
}

impl From<RecordType> for u32 {
    fn from(value: RecordType) -> Self {
        match value {
            RecordType::None => CL_NONE as u32,
            RecordType::Mark => CL_MARK as u32,
            RecordType::Create => CL_CREATE as u32,
            RecordType::Mkdir => CL_MKDIR as u32,
            RecordType::Hardlink => CL_HARDLINK as u32,
            RecordType::Softlink => CL_SOFTLINK as u32,
            RecordType::Mknod => CL_MKNOD as u32,
            RecordType::Unlink => CL_UNLINK as u32,
            RecordType::Rmdir => CL_RMDIR as u32,
            RecordType::Rename => CL_RENAME as u32,
            RecordType::Ext => CL_EXT as u32,
            RecordType::Open => CL_OPEN as u32,
            RecordType::Close => CL_CLOSE as u32,
            RecordType::Layout => CL_LAYOUT as u32,
            RecordType::Trunc => CL_TRUNC as u32,
            RecordType::Setattr => CL_SETATTR as u32,
            RecordType::Setxattr => CL_SETXATTR as u32,
            RecordType::Hsm => CL_HSM as u32,
            RecordType::Mtime => CL_MTIME as u32,
            RecordType::Ctime => CL_CTIME as u32,
            RecordType::Atime => CL_ATIME as u32,
            RecordType::Migrate => CL_MIGRATE as u32,
            RecordType::Flrw => CL_FLRW as u32,
            RecordType::Resync => CL_RESYNC as u32,
            RecordType::Getxattr => CL_GETXATTR as u32,
            RecordType::DnOpen => CL_DN_OPEN as u32,
            RecordType::Last => CL_LAST as u32,
            RecordType::Unknown(val) => val,
        }
    }
}

impl RecordType {
    /// Returns the string representation of the changelog record type.
    pub fn as_string(&self) -> String {
        match self {
            RecordType::None => "NONE".to_string(),
            RecordType::Mark => "MARK".to_string(),
            RecordType::Create => "CREATE".to_string(),
            RecordType::Mkdir => "MKDIR".to_string(),
            RecordType::Hardlink => "HARDLINK".to_string(),
            RecordType::Softlink => "SOFTLINK".to_string(),
            RecordType::Mknod => "MKNOD".to_string(),
            RecordType::Unlink => "UNLINK".to_string(),
            RecordType::Rmdir => "RMDIR".to_string(),
            RecordType::Rename => "RENAME".to_string(),
            RecordType::Ext => "EXT".to_string(),
            RecordType::Open => "OPEN".to_string(),
            RecordType::Close => "CLOSE".to_string(),
            RecordType::Layout => "LAYOUT".to_string(),
            RecordType::Trunc => "TRUNC".to_string(),
            RecordType::Setattr => "SETATTR".to_string(),
            RecordType::Setxattr => "SETXATTR".to_string(),
            RecordType::Hsm => "HSM".to_string(),
            RecordType::Mtime => "MTIME".to_string(),
            RecordType::Ctime => "CTIME".to_string(),
            RecordType::Atime => "ATIME".to_string(),
            RecordType::Migrate => "MIGRATE".to_string(),
            RecordType::Flrw => "FLRW".to_string(),
            RecordType::Resync => "RESYNC".to_string(),
            RecordType::Getxattr => "GETXATTR".to_string(),
            RecordType::DnOpen => "DN_OPEN".to_string(),
            RecordType::Last => "LAST".to_string(),
            RecordType::Unknown(x) => format!("UNKNOWN({})", x),
        }
    }

    /// Returns the string representation using the C library function.
    pub fn to_c_string(self) -> String {
        let type_val: u32 = self.into();
        unsafe {
            let c_str = changelog_type2str(type_val as i32);
            if c_str.is_null() {
                format!("UNKNOWN({})", type_val)
            } else {
                std::ffi::CStr::from_ptr(c_str)
                    .to_string_lossy()
                    .to_string()
            }
        }
    }
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

/// Represents a changelog record with unified fields for all operation types.
///
/// This structure contains all fields that may be present in any changelog record type.
/// Fields that are not applicable to a specific record type will be `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The type of changelog operation
    pub record_type: RecordType,
    /// Record index in the changelog
    pub index: u64,
    /// Previous record index
    pub prev: u64,
    /// Timestamp of the operation
    pub time: String,

    // Core FID fields
    /// Target file/directory FID (not present in `CL_MARK` records)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_fid: Option<Fid>,
    /// Parent directory FID (None if empty or not applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_fid: Option<Fid>,
    /// Resolved parent directory path (when available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_dir: Option<String>,
    /// File name associated with the operation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,

    // Extension fields (available in most record types)
    /// User ID from `UIDGID` extension
    pub uid: Option<u64>,
    /// Group ID from `UIDGID` extension  
    pub gid: Option<u64>,
    /// Client NID from NID extension
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_nid: Option<ClientNid>,
    /// Job ID from JOBID extension
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    /// Open flags from OPEN extension
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_flags: Option<u32>,
    /// Extra flags
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_flags: Option<u64>,

    // Type-specific fields
    /// Marker flags (`CL_MARK` records only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marker_flags: Option<u32>,
    /// Source file name for rename operations (`CL_RENAME` only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_name: Option<String>,
    /// Source FID for rename operations (`CL_RENAME` only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_fid: Option<Fid>,
    /// Source parent FID for rename operations (`CL_RENAME` only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_parent_fid: Option<Fid>,
    /// Resolved source parent directory path (`CL_RENAME` only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    /// Extended attribute name (`CL_SETXATTR`/`CL_GETXATTR` only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xattr_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnetconfig::{SimpleNid, lnet_nid_t};

    #[test]
    fn test_changelog_record_type_conversions() {
        let create_type = RecordType::Create;
        let create_val: u32 = create_type.into();
        let back_to_type = RecordType::from(create_val);
        assert_eq!(create_type, back_to_type);
    }

    #[test]
    fn test_changelog_record_type_display() {
        assert_eq!(RecordType::Create.to_string(), "CREATE");
        assert_eq!(RecordType::Unlink.to_string(), "UNLINK");
        assert_eq!(RecordType::Unknown(999).to_string(), "UNKNOWN(999)");
    }

    #[test]
    fn test_changelog_record_type_c_string() {
        let create_type = RecordType::Create;
        let c_string = create_type.to_c_string();
        assert!(!c_string.is_empty());
    }

    #[test]
    fn test_record_create() {
        let parent_fid = Fid::new(0x100, 0x1, 0x0);
        let target_fid = Some(Fid::new(0x200, 0x2, 0x0));

        let record = Record {
            record_type: RecordType::Create,
            index: 123,
            prev: 122,
            time: "1640995200".to_string(),
            parent_fid: Some(parent_fid),
            parent_dir: None,
            target_fid,
            filename: Some("test.txt".to_string()),
            uid: Some(1000),
            gid: Some(1000),
            client_nid: Some(ClientNid::Simple(SimpleNid::new(
                2533274790395904 as lnet_nid_t,
            ))),
            job_id: Some("job123".to_string()),
            open_flags: None,
            extra_flags: None,
            marker_flags: None,
            source_name: None,
            source_fid: None,
            source_parent_fid: None,
            source_path: None,
            xattr_name: None,
        };

        assert_eq!(record.record_type, RecordType::Create);
        assert_eq!(record.index, 123);
        assert_eq!(record.filename.as_deref(), Some("test.txt"));
        assert_eq!(record.uid, Some(1000));
        assert_eq!(record.gid, Some(1000));
        assert_eq!(record.job_id.as_deref(), Some("job123"));
    }

    #[test]
    fn test_record_mkdir() {
        let parent_fid = Fid::new(0x100, 0x1, 0x0);
        let target_fid = Some(Fid::new(0x300, 0x3, 0x0));

        let record = Record {
            record_type: RecordType::Mkdir,
            index: 124,
            prev: 123,
            time: "1640995300".to_string(),
            parent_fid: Some(parent_fid),
            parent_dir: None,
            target_fid,
            filename: Some("testdir".to_string()),
            uid: None,
            gid: None,
            client_nid: None,
            job_id: None,
            open_flags: None,
            extra_flags: None,
            marker_flags: None,
            source_name: None,
            source_fid: None,
            source_parent_fid: None,
            source_path: None,
            xattr_name: None,
        };

        assert_eq!(record.record_type, RecordType::Mkdir);
        assert_eq!(record.index, 124);
        assert_eq!(record.filename.as_deref(), Some("testdir"));
    }

    #[test]
    fn test_record_serialization() {
        let parent_fid = Fid::new(0x100, 0x1, 0x0);
        let target_fid = Some(Fid::new(0x200, 0x2, 0x0));

        let record = Record {
            record_type: RecordType::Unlink,
            index: 125,
            prev: 124,
            time: "1640995400".to_string(),
            parent_fid: Some(parent_fid),
            parent_dir: None,
            target_fid,
            filename: Some("deleted.txt".to_string()),
            uid: None,
            gid: None,
            client_nid: None,
            job_id: None,
            open_flags: None,
            extra_flags: None,
            marker_flags: None,
            source_name: None,
            source_fid: None,
            source_parent_fid: None,
            source_path: None,
            xattr_name: None,
        };

        // Test basic record properties
        assert_eq!(record.record_type, RecordType::Unlink);
        assert_eq!(record.index, 125);
        assert_eq!(record.prev, 124);
        assert_eq!(record.time, "1640995400");
        assert_eq!(record.filename.as_deref(), Some("deleted.txt"));
    }

    #[test]
    fn test_record_with_extensions() {
        let parent_fid = Fid::new(0x100, 0x1, 0x0);
        let target_fid = Some(Fid::new(0x200, 0x2, 0x0));

        // Test record with all extension fields populated
        let record = Record {
            record_type: RecordType::Create,
            index: 126,
            prev: 125,
            time: "1640995500".to_string(),
            parent_fid: Some(parent_fid),
            parent_dir: None,
            target_fid,
            filename: Some("extended.txt".to_string()),
            uid: Some(1001),
            gid: Some(1001),
            client_nid: Some(ClientNid::Simple(SimpleNid::new(
                2533274790395904 as lnet_nid_t,
            ))),
            job_id: Some("job456".to_string()),
            open_flags: Some(0o644),
            extra_flags: Some(0x1000),
            marker_flags: None,
            source_name: None,
            source_fid: None,
            source_parent_fid: None,
            source_path: None,
            xattr_name: None,
        };

        assert_eq!(record.uid, Some(1001));
        assert_eq!(record.gid, Some(1001));
        assert_eq!(
            record.client_nid,
            Some(ClientNid::Simple(SimpleNid::new(
                2533274790395904 as lnet_nid_t
            )))
        );
        assert_eq!(record.job_id.as_deref(), Some("job456"));
        assert_eq!(record.open_flags, Some(0o644));
        assert_eq!(record.extra_flags, Some(0x1000));
    }
}
