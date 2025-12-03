// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use crate::{
    Error, LustrePath,
    error::{Result, cvt_lz_m, cvt_nz, cvt_rc_m},
};
use lustreapi_sys::{
    llapi_fd2fid, llapi_fid2path_at, llapi_open_by_fid_at, llapi_path2fid, lu_fid,
};

use cstrbuf::CStrBuf;
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fmt::{self, Display, Formatter},
    fs::File,
    os::fd::{AsRawFd, FromRawFd},
    path::{Path, PathBuf},
    ptr,
};

pub const MAX_PATH_LEN: usize = 4096;

/// A Lustre File Identifier (FID) that uniquely identifies files in a Lustre filesystem.
///
/// A FID consists of three components:
/// - `seq`: A 64-bit sequence number identifying the target
/// - `oid`: A 32-bit object ID within that sequence
/// - `ver`: A 32-bit version number
///
/// # Features
///
/// This implementation provides:
/// - Conversion to/from Lustre's native `lu_fid` struct
/// - Serialization and deserialization through Serde
/// - String parsing and formatting with `[0xSEQ:0xOID:0xVER]` syntax
/// - Methods to obtain `FIDs` from file paths or descriptors
/// - Opening files using their FID
///
/// # Examples
///
/// ```
/// use rustreapi::Fid;
///
/// // Create a FID directly
/// let fid = Fid::new(0xCAFE, 0x11, 0x22);
///
/// // Parse from string representation
/// let parsed = Fid::parse("[0xCAFE:0x11:0x22]").unwrap();
/// assert_eq!(fid, parsed);
///
/// // Get string representation
/// assert_eq!(fid.to_string(), "[0xCAFE:0x11:0x22]");
/// ```
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub struct Fid {
    seq: u64,
    oid: u32,
    ver: u32,
}

impl Serialize for Fid {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Fid {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Fid::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Constructors and utility methods for `Fid`.
impl Fid {
    /// Creates a new FID with the specified sequence, object ID, and version numbers.
    ///
    /// # Arguments
    ///
    /// * `seq` - The 64-bit sequence number
    /// * `oid` - The 32-bit object ID
    /// * `ver` - The 32-bit version number
    pub fn new(seq: u64, oid: u32, ver: u32) -> Self {
        Self { oid, seq, ver }
    }

    /// Retrieves the FID for a file referenced by an open file descriptor.
    ///
    /// This method obtains the Lustre File Identifier (FID) for a file that has already
    /// been opened, using its file descriptor. The file must be on a Lustre filesystem.
    ///
    /// # Arguments
    ///
    /// * `fd` - Any type that implements `AsRawFd`, typically a `File` or file descriptor wrapper
    ///
    /// # Returns
    ///
    /// * `Ok(Fid)` - The FID of the file if successful
    /// * `Err` - If the file descriptor is invalid or the file is not on a Lustre filesystem
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use std::error::Error;
    /// # use std::fs::File;
    /// # fn example() -> Result<(), Box<dyn Error>> {
    /// use rustreapi::Fid;
    ///
    /// // Open a file on a Lustre filesystem
    /// let file = File::open("/mnt/lustre/myfile.txt")?;
    ///
    /// // Get its FID
    /// let fid = Fid::with_fd(&file)?;
    /// println!("File FID: {}", fid);
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_fd<Fd: AsRawFd>(fd: &Fd) -> Result<Self> {
        let mut fid = lu_fid::default();
        unsafe { cvt_nz(llapi_fd2fid(fd.as_raw_fd(), &mut fid as *mut lu_fid))? }
        Ok(fid.into())
    }

    /// Retrieves the FID for a file at the specified path.
    ///
    /// This method obtains the Lustre File Identifier (FID) for a file using its path.
    /// It internally calls the Lustre API function `llapi_path2fid()`.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to a file on a Lustre filesystem
    ///
    /// # Returns
    ///
    /// * `Ok(Fid)` - The FID of the file if successful
    /// * `Err` - If the path is invalid or not on a Lustre filesystem
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use std::error::Error;
    /// # fn example() -> Result<(), Box<dyn Error>> {
    /// use rustreapi::Fid;
    ///
    /// let fid = Fid::with_path("/mnt/lustre/myfile.txt")?;
    /// println!("File FID: {}", fid);
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut fid = lu_fid::default();
        let cstr = CString::new(path.as_ref().to_string_lossy().to_string())?;
        unsafe { cvt_nz(llapi_path2fid(cstr.as_ptr(), &mut fid as *mut lu_fid))? }
        Ok(fid.into())
    }

    /// Converts this `Fid` to Lustre's native `lu_fid` structure.
    ///
    /// This is useful when interfacing with the Lustre API functions
    /// that require the native FID representation.
    ///
    /// # Returns
    ///
    /// A new `lu_fid` instance containing the same sequence, object ID and version.
    pub fn to_lu_fid(&self) -> lu_fid {
        lu_fid {
            f_seq: self.seq,
            f_oid: self.oid,
            f_ver: self.ver,
        }
    }
}

impl From<lu_fid> for Fid {
    fn from(fid: lu_fid) -> Self {
        Self {
            seq: fid.f_seq,
            oid: fid.f_oid,
            ver: fid.f_ver,
        }
    }
}

impl From<changelog_sys::lu_fid> for Fid {
    fn from(fid: changelog_sys::lu_fid) -> Self {
        Self {
            seq: fid.f_seq,
            oid: fid.f_oid,
            ver: fid.f_ver,
        }
    }
}

impl From<Fid> for lu_fid {
    fn from(fid: Fid) -> Self {
        lu_fid {
            f_seq: fid.seq,
            f_oid: fid.oid,
            f_ver: fid.ver,
        }
    }
}

impl Fid {
    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn oid(&self) -> u32 {
        self.oid
    }

    pub fn ver(&self) -> u32 {
        self.ver
    }

    /// Checks if the FID is empty (all components are zero).
    ///
    /// Returns `true` if `seq`, `oid`, and `ver` are all 0, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustreapi::Fid;
    ///
    /// let empty_fid = Fid::new(0, 0, 0);
    /// assert!(empty_fid.is_empty());
    ///
    /// let non_empty_fid = Fid::new(1, 0, 0);
    /// assert!(!non_empty_fid.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.seq == 0 && self.oid == 0 && self.ver == 0
    }

    /// Opens a file identified by this FID through a Lustre filesystem descriptor.
    ///
    /// # Arguments
    ///
    /// * `lustre_fd` - An open file descriptor for a Lustre filesystem mount point
    /// * `flags` - The open flags to use, defaults to `O_RDONLY` when set to 0
    ///
    /// # Returns
    ///
    /// * `Ok(File)` - The opened file handle
    /// * `Err` - If the file cannot be opened using this FID
    pub fn open_at<Fd: AsRawFd>(&self, lustre_fd: &Fd, flags: i32) -> Result<File> {
        let fd = lustre_fd.as_raw_fd();
        let flags = if flags == 0 { libc::O_RDONLY } else { flags };

        unsafe {
            cvt_lz_m(
                llapi_open_by_fid_at(fd, &self.to_lu_fid(), flags),
                "open_at".to_string(),
            )
            .map(|fd| File::from_raw_fd(fd))
        }
    }

    /// Resolves this FID to its first path in the filesystem using a file descriptor
    /// for the Lustre mount path..
    ///
    /// This method converts a FID to its corresponding path in the Lustre filesystem
    /// by querying the Lustre MDS. It requires an open file descriptor to a Lustre
    /// mount point.
    ///
    /// # Arguments
    ///
    /// * `lustre_fd` - An open file descriptor to a Lustre filesystem mount point
    ///
    /// # Returns
    ///
    /// * `Ok(PathBuf)` - The path corresponding to this FID within the filesystem
    /// * `Err` - If the path lookup fails (e.g., if the FID doesn't exist in this filesystem)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use std::error::Error;
    /// # use std::fs::File;
    /// # fn example() -> Result<(), Box<dyn Error>> {
    /// use rustreapi::{Fid, LustrePath};
    ///
    /// // Open a file descriptor to the Lustre mount
    /// let mount_path = LustrePath::parse("/mnt/lustre")?;
    /// let mount_file = File::open(&mount_path)?;
    ///
    /// // Get the FID for a specific file
    /// let fid = Fid::with_path(mount_path.as_ref().join("my_file.txt"))?;
    ///
    /// // Convert the FID back to a path
    /// let path = fid.path_at(&mount_file)?;
    /// println!("FID resolves to path: {}", path.display());
    /// # Ok(())
    /// # }
    pub fn path_at<Fd: AsRawFd>(&self, lustre_fd: &Fd) -> Result<PathBuf> {
        let mut path = CStrBuf::new(MAX_PATH_LEN);
        unsafe {
            cvt_rc_m(
                llapi_fid2path_at(
                    lustre_fd.as_raw_fd(),
                    &self.to_lu_fid(),
                    path.as_mut_ptr(),
                    path.buffer_len() as i32,
                    ptr::null_mut(),
                    ptr::null_mut(),
                ),
                "path_at".to_string(),
            )?
        };

        Ok(Path::new(&path).to_owned())
    }

    /// Resolves this FID to its path in the filesystem using a Lustre mount path.
    ///
    /// This method is a convenience wrapper around `path_at()` that automatically
    /// opens the provided Lustre path before resolving the FID to a path.
    ///
    /// # Arguments
    ///
    /// * `path` - A `LustrePath` representing a Lustre filesystem mount point
    ///
    /// # Returns
    ///
    /// * `Ok(PathBuf)` - The path corresponding to this FID within the filesystem
    /// * `Err` - If opening the mount path fails or if the path lookup fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use std::error::Error;
    /// # fn example() -> Result<(), Box<dyn Error>> {
    /// use rustreapi::{Fid, LustrePath};
    ///
    /// // Parse a Lustre mount path
    /// let mount_path = LustrePath::parse("/mnt/lustre")?;
    ///
    /// // Get the FID for a specific file
    /// let fid = Fid::with_path(mount_path.as_ref().join("my_file.txt"))?;
    ///
    /// // Convert the FID back to a path
    /// let path = fid.path(&mount_path)?;
    /// println!("FID resolves to path: {}", path.display());
    /// # Ok(())
    /// # }
    /// ```
    pub fn path(&self, path: &LustrePath) -> Result<PathBuf> {
        let file = path.open()?;
        self.path_at(&file)
    }

    /// Resolves this FID to all of its paths (hard links) in the filesystem using a file descriptor.
    ///
    /// This method converts a FID to all corresponding paths in the Lustre filesystem
    /// by iterating through all hard links using the Lustre MDS. It requires an open
    /// file descriptor to a Lustre mount point.
    ///
    /// # Arguments
    ///
    /// * `lustre_fd` - An open file descriptor to a Lustre filesystem mount point
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<PathBuf>)` - All paths corresponding to this FID within the filesystem
    /// * `Err` - If the path lookup fails (e.g., if the FID doesn't exist in this filesystem)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use std::error::Error;
    /// # use std::fs::File;
    /// # fn example() -> Result<(), Box<dyn Error>> {
    /// use rustreapi::{Fid, LustrePath};
    ///
    /// // Open a file descriptor to the Lustre mount
    /// let mount_path = LustrePath::parse("/mnt/lustre")?;
    /// let mount_file = File::open(&mount_path)?;
    ///
    /// // Get the FID for a specific file
    /// let fid = Fid::with_path(mount_path.as_ref().join("my_file.txt"))?;
    ///
    /// // Get all paths (hard links) for this FID
    /// let paths = fid.all_paths_at(&mount_file)?;
    /// for path in paths {
    ///     println!("FID has hard link: {}", path.display());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn all_paths_at<Fd: AsRawFd>(&self, lustre_fd: &Fd) -> Result<Vec<PathBuf>> {
        let mut paths = Vec::new();
        let mut linkno: libc::c_int = 0;
        // Safety limit to prevent infinite loops, not sure if this needs to be > 1000?
        const MAX_LINKS: i32 = 1000;

        loop {
            if linkno >= MAX_LINKS {
                break;
            }

            let mut path = CStrBuf::new(MAX_PATH_LEN);
            let mut current_linkno = linkno;

            let rc = unsafe {
                llapi_fid2path_at(
                    lustre_fd.as_raw_fd(),
                    &self.to_lu_fid(),
                    path.as_mut_ptr(),
                    path.buffer_len() as i32,
                    ptr::null_mut(),
                    &mut current_linkno,
                )
            };

            if rc == 0 {
                // Success - add this path to our collection
                let path_buf = Path::new(&path).to_owned();

                // Avoid adding duplicate paths
                if !paths.contains(&path_buf) {
                    paths.push(path_buf);
                }

                linkno += 1;

                // If current_linkno didn't change or is invalid, we might be done
                if current_linkno < linkno {
                    break;
                }
            } else {
                // Error occurred - if we have no paths yet, this is a real error
                if paths.is_empty() {
                    cvt_rc_m(rc, "all_paths_at".to_string())?;
                }
                // Otherwise, we've likely exhausted all available links
                break;
            }
        }

        Ok(paths)
    }

    /// Resolves this FID to all of its paths (hard links) in the filesystem using a Lustre mount path.
    ///
    /// This method is a convenience wrapper around `all_paths_at()` that automatically
    /// opens the provided Lustre path before resolving the FID to all paths.
    ///
    /// # Arguments
    ///
    /// * `path` - A `LustrePath` representing a Lustre filesystem mount point
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<PathBuf>)` - All paths corresponding to this FID within the filesystem
    /// * `Err` - If opening the mount path fails or if the path lookup fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use std::error::Error;
    /// # fn example() -> Result<(), Box<dyn Error>> {
    /// use rustreapi::{Fid, LustrePath};
    ///
    /// // Parse a Lustre mount path
    /// let mount_path = LustrePath::parse("/mnt/lustre")?;
    ///
    /// // Get the FID for a specific file
    /// let fid = Fid::with_path(mount_path.as_ref().join("my_file.txt"))?;
    ///
    /// // Get all paths (hard links) for this FID
    /// let paths = fid.all_paths(&mount_path)?;
    /// for path in paths {
    ///     println!("FID has hard link: {}", path.display());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn all_paths(&self, path: &LustrePath) -> Result<Vec<PathBuf>> {
        let file = path.open()?;
        self.all_paths_at(&file)
    }

    /// Parses a string representation of a Lustre FID into a `Fid` struct.
    ///
    /// The string must contain three hexadecimal components in the format:
    /// `[0xSEQ:0xOID:0xVER]` or `0xSEQ:0xOID:0xVER` (without brackets).
    ///
    /// # Arguments
    ///
    /// * `orig` - A string slice containing the FID representation.
    ///
    /// # Returns
    ///
    /// A `Result<Fid>` containing the parsed `Fid` or an error.
    ///
    /// # Errors
    ///
    /// Returns an error in the following cases:
    /// - If the string doesn't contain exactly 3 components separated by colons
    /// - If any component doesn't start with "0x" prefix
    /// - If any component contains invalid hexadecimal digits
    /// - If the sequence component overflows `u64`
    /// - If the OID or version component overflows `u32`
    ///
    /// # Examples
    ///
    /// ```
    /// use rustreapi::Fid;
    ///
    /// let fid = Fid::parse("[0xCAFE:0x11:0x22]").unwrap();
    /// assert_eq!(fid.to_string(), "[0xCAFE:0x11:0x22]");
    ///
    /// let fid = Fid::parse("0x123:0x12:0x34").unwrap();
    /// assert_eq!(fid.to_string(), "[0x123:0x12:0x34]");
    /// ```
    pub fn parse(orig: &str) -> Result<Fid> {
        let s = orig.trim();

        let s = if s.starts_with('[') && s.ends_with(']') {
            &s[1..s.len() - 1] // Remove the optional surrounding brackets
        } else {
            s
        };

        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 3 {
            if !parts[0].starts_with("0x") {
                return Err(Error::InvalidFidFormat {
                    str: orig.to_string(),
                });
            }
            let seq =
                u64::from_str_radix(&parts[0][2..], 16).map_err(|e| Error::ParseFidError {
                    original: orig.to_string(),
                    part: parts[0][2..].to_string(),
                    err: e,
                })?;

            if !parts[1].starts_with("0x") {
                return Err(Error::InvalidFidFormat {
                    str: orig.to_string(),
                });
            }
            let oid =
                u32::from_str_radix(&parts[1][2..], 16).map_err(|e| Error::ParseFidError {
                    original: orig.to_string(),
                    part: parts[1][2..].to_string(),
                    err: e,
                })?;

            if !parts[2].starts_with("0x") {
                return Err(Error::InvalidFidFormat {
                    str: orig.to_string(),
                });
            }
            let ver =
                u32::from_str_radix(&parts[2][2..], 16).map_err(|e| Error::ParseFidError {
                    original: orig.to_string(),
                    part: parts[2][2..].to_string(),
                    err: e,
                })?;
            return Ok(Fid { seq, oid, ver });
        }

        Err(Error::InvalidFidFormat {
            str: orig.to_string(),
        })
    }
}

impl Display for Fid {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "[0x{:X}:0x{:X}:0x{:X}]", self.seq, self.oid, self.ver)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_fid_into() {
        let raw_fid = lu_fid::default();
        let f: Fid = raw_fid.into();
        assert_eq!(f.seq, 0);
        assert_eq!(format!("{f}"), "[0x0:0x0:0x0]");
    }

    #[test]
    fn test_fid_display() {
        let f = Fid::new(16, 256, 1024);
        assert_eq!(format!("{f}"), "[0x10:0x100:0x400]");
    }

    #[test]
    fn test_fid_is_empty() {
        // Test empty FID
        let empty_fid = Fid::new(0, 0, 0);
        assert!(empty_fid.is_empty());

        // Test non-empty FIDs
        let fid1 = Fid::new(1, 0, 0);
        assert!(!fid1.is_empty());

        let fid2 = Fid::new(0, 1, 0);
        assert!(!fid2.is_empty());

        let fid3 = Fid::new(0, 0, 1);
        assert!(!fid3.is_empty());

        let fid4 = Fid::new(123, 456, 789);
        assert!(!fid4.is_empty());
    }

    #[test]
    fn test_lu_fid_into() {
        let fid = Fid::new(123, 456, 789);
        let raw_fid: lu_fid = fid.into();
        let f_seq = raw_fid.f_seq;
        assert_eq!(f_seq, 123);
        let f_oid = raw_fid.f_oid;
        assert_eq!(f_oid, 456);
        let f_ver = raw_fid.f_ver;
        assert_eq!(f_ver, 789);
    }
    #[test]
    fn test_fid_from() {
        let raw_fid = lu_fid {
            f_seq: 32,
            f_oid: 64,
            f_ver: 128,
        };
        let f = Fid::from(raw_fid);
        let ptr = ptr::addr_of!(raw_fid.f_ver);
        let ver = unsafe { ptr.read() };

        assert_eq!(f.ver, ver);
    }

    #[test]
    fn test_fid_parse() {
        let str = "[0xCAFE:0x11:0x22]";
        let fid = Fid::parse(str).expect("Fid should be valid.");
        assert_eq!(str, fid.to_string());
    }

    #[test]
    fn invalid_fid_missing_one() {
        let str = "[0x12:0x34]";
        let result = Fid::parse(str);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(
                e.to_string(),
                Error::InvalidFidFormat {
                    str: str.to_string(),
                }
                .to_string(),
            );
        }
    }

    #[test]
    fn invalid_fid_empty_seq() {
        let str = "[0x:0x12:0x34]";
        let result = Fid::parse(str);
        assert!(result.is_err());
        if let Err(e) = result {
            insta::assert_debug_snapshot!(e.to_string(), @r#""parse fid error in [0x:0x12:0x34] '': cannot parse integer from empty string""#);
        }
    }

    #[test]
    fn invalid_fid_bad_seq() {
        let str = "[fid:0x12:0x34]";
        let result = Fid::parse(str);
        match result {
            Err(e) => {
                insta::assert_debug_snapshot!(e.to_string(), @r#""invalid fid format: '[fid:0x12:0x34]'""#);
            }
            Ok(f) => {
                panic!("Parsed a bad fid: {f}");
            }
        }
    }

    #[test]
    fn invalid_fid_bad_seq2() {
        let str = "[0xnotvalid:0x12:0x34]";
        let result = Fid::parse(str);
        match result {
            Err(e) => {
                insta::assert_debug_snapshot!(e.to_string(), @r#""parse fid error in [0xnotvalid:0x12:0x34] 'notvalid': invalid digit found in string""#);
            }
            Ok(f) => {
                panic!("Parsed a bad fid: {f}");
            }
        }
    }

    #[test]
    fn invalid_fid_empty_oid() {
        let str = "[0x123:0x:0x34]";
        let result = Fid::parse(str);
        match result {
            Err(e) => {
                insta::assert_debug_snapshot!(e.to_string(), @r#""parse fid error in [0x123:0x:0x34] '': cannot parse integer from empty string""#);
            }
            Ok(f) => {
                panic!("Parsed a bad fid: {f}");
            }
        }
    }

    #[test]
    fn invalid_fid_bad_oid() {
        let str = "[0x123:fid:0x34]";
        let result = Fid::parse(str);
        match result {
            Err(e) => {
                insta::assert_debug_snapshot!(e.to_string(), @r#""invalid fid format: '[0x123:fid:0x34]'""#);
            }
            Ok(f) => {
                panic!("Parsed a bad fid: {f}");
            }
        }
    }

    #[test]
    fn invalid_fid_bad_oid2() {
        let str = "[0x123:0xinvalid:0x34]";
        let result = Fid::parse(str);
        match result {
            Err(e) => {
                insta::assert_debug_snapshot!(e.to_string(), @r#""parse fid error in [0x123:0xinvalid:0x34] 'invalid': invalid digit found in string""#);
            }
            Ok(f) => {
                panic!("Parsed a bad fid: {f}");
            }
        }
    }

    #[test]
    fn invalid_fid_oid_overflow() {
        let str = "[0x123:0xffffffffffff:0x34]";
        let result = Fid::parse(str);
        match result {
            Err(e) => {
                insta::assert_debug_snapshot!(e.to_string(), @r#""parse fid error in [0x123:0xffffffffffff:0x34] 'ffffffffffff': number too large to fit in target type""#);
            }
            Ok(f) => {
                panic!("Parsed a bad fid: {f}");
            }
        }
    }

    #[test]
    fn invalid_fid_empty_ver() {
        let str = "[0x123:0x12:0x]";
        let result = Fid::parse(str);
        match result {
            Err(e) => {
                insta::assert_debug_snapshot!(e.to_string(), @r#""parse fid error in [0x123:0x12:0x] '': cannot parse integer from empty string""#);
            }
            Ok(f) => {
                panic!("Parsed a bad fid: {f}");
            }
        }
    }

    #[test]
    fn invalid_fid_bad_ver() {
        let str = "[0x123:0x313:fid]";
        let result = Fid::parse(str);
        match result {
            Err(e) => {
                insta::assert_debug_snapshot!(e.to_string(), @r#""invalid fid format: '[0x123:0x313:fid]'""#);
            }
            Ok(f) => {
                panic!("Parsed a bad fid: {f}");
            }
        }
    }

    #[test]
    fn invalid_fid_bad_ver2() {
        let str = "[0x123:0x33:0xinvalid]";
        let result = Fid::parse(str);
        match result {
            Err(e) => {
                insta::assert_debug_snapshot!(e.to_string(), @r#""parse fid error in [0x123:0x33:0xinvalid] 'invalid': invalid digit found in string""#);
            }
            Ok(f) => {
                panic!("Parsed a bad fid: {f}");
            }
        }
    }

    #[test]
    fn invalid_fid_ver_overflow() {
        let str = "[0x123:0x34:0xffffffffffff]";
        let result = Fid::parse(str);
        match result {
            Err(e) => {
                insta::assert_debug_snapshot!(e.to_string(), @r#""parse fid error in [0x123:0x34:0xffffffffffff] 'ffffffffffff': number too large to fit in target type""#);
            }
            Ok(f) => {
                panic!("Parsed a bad fid: {f}");
            }
        }
    }

    #[test]
    fn invalid_fid_empty() {
        let str = "";
        let result = Fid::parse(str);
        match result {
            Err(e) => {
                insta::assert_debug_snapshot!(e.to_string(), @r#""invalid fid format: ''""#);
            }
            Ok(f) => {
                panic!("Parsed a bad fid: {f}");
            }
        }
    }

    #[test]
    fn fid_no_brackets() {
        let str = "0x123:0x12:0x34";
        let result = Fid::parse(str);
        assert!(result.is_ok());
        if let Ok(fid) = result {
            assert_eq!(fid.seq, 0x123);
            assert_eq!(fid.oid, 0x12);
            assert_eq!(fid.ver, 0x34);
        }
    }

    #[test]
    fn fid_no_brackets_with_spaces() {
        let str = " 0x123 : 0x12 : 0x34 ";
        let result = Fid::parse(str);
        match result {
            Err(e) => {
                insta::assert_debug_snapshot!(e.to_string(), @r#""parse fid error in  0x123 : 0x12 : 0x34  '123 ': invalid digit found in string""#);
            }
            Ok(f) => {
                panic!("Parsed a bad fid: {f}");
            }
        }
    }

    #[test]
    fn too_many_parts() {
        let str = "[0x123:0x12:0x34:0x56]";
        let result = Fid::parse(str);
        match result {
            Err(e) => {
                insta::assert_debug_snapshot!(e.to_string(), @r#""invalid fid format: '[0x123:0x12:0x34:0x56]'""#);
            }
            Ok(f) => {
                panic!("Parsed a bad fid: {f}");
            }
        }
    }
}
