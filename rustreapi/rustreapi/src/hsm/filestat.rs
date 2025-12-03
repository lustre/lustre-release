// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use crate::{Fid, LovPattern};
use cstrbuf::CStrBuf;
use libc::{S_IFREG, S_IRGRP, S_IROTH, S_IRUSR, S_IWUSR};
use lustreapi_sys::*;
use nix::unistd::{getegid, geteuid};
use std::{
    fmt,
    path::Path,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// A Rust-idiomatic representation of file stat information
///
/// This struct provides a safe interface for working with file
/// metadata using Rust's native types instead of raw C types. It automatically
/// handles conversion to the underlying `libc::stat` structure when needed.
/// It is recommended to use `StatBuilder` and not this directly.
///
/// # Examples
///
/// ```
/// # use rustreapi::hsm::Stat;
/// # use std::time::SystemTime;
/// let stat = Stat {
///     uid: 1000,
///     gid: 1000,
///     mode: 0o644,
///     size: 1024,
///     atime: SystemTime::now(),
///     mtime: SystemTime::now(),
///     ctime: SystemTime::now(),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct Stat {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub size: u64,
    pub atime: SystemTime,
    pub mtime: SystemTime,
    pub ctime: SystemTime,
}

impl Default for Stat {
    fn default() -> Self {
        let now = SystemTime::now();
        Self {
            uid: geteuid().as_raw(),
            gid: getegid().as_raw(),
            mode: S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH, // 0644, regular file
            size: 0,
            atime: now,
            mtime: now,
            ctime: now,
        }
    }
}

impl Stat {
    /// Convert System Time to time spec
    fn sys_to_timespec(time: SystemTime) -> timespec {
        let duration = time
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0)); // Handle time before epoch

        timespec {
            tv_sec: duration.as_secs() as i64,
            tv_nsec: i64::from(duration.subsec_nanos()),
        }
    }

    /// Convert to the raw lib c stat struct
    fn to_raw_stat(&self) -> stat {
        let atime = Self::sys_to_timespec(self.atime);
        let mtime = Self::sys_to_timespec(self.mtime);
        let ctime = Self::sys_to_timespec(self.ctime);

        stat {
            st_dev: 0,
            st_ino: 0,
            st_nlink: 1,
            st_mode: self.mode,
            st_uid: self.uid,
            st_gid: self.gid,
            st_rdev: 0,
            st_size: self.size as i64,
            st_blksize: 0,
            st_blocks: 0,
            st_atim: atime,
            st_mtim: mtime,
            st_ctim: ctime,
            // pad and glibc_reserved fields differ between platforms
            // using default values to ensure compatibility for now.
            ..Default::default()
        }
    }
}

/// Builder for creating Stat instances
pub struct StatBuilder {
    inner: Result<Stat, Box<dyn std::error::Error + Send + Sync>>,
}

/// Builder for creating Stat instances with Rust types
///
/// This builder provides a clean interface for creating file stat information
/// using Rust's native types like `SystemTime` instead of raw C types like `timespec`.
/// It follows the same builder pattern where only the final `build()`
/// method returns a `Result`.
///
/// # Examples
///
/// ```
/// # use rustreapi::hsm::StatBuilder;
/// # use std::time::{SystemTime, UNIX_EPOCH, Duration};
/// # fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
/// let stat = StatBuilder::new()
///     .uid(1000)
///     .gid(1000)
///     .mode(0o644)
///     .size(2048)
///     .mtime(SystemTime::now())
///     .build()?;
/// # Ok(())
/// # }
/// ```
impl StatBuilder {
    /// Create a new StatBuilder with default values
    pub fn new() -> Self {
        Self {
            inner: Ok(Stat::default()),
        }
    }

    /// Set the user ID
    pub fn uid(self, uid: u32) -> Self {
        self.and_then(move |mut stat| {
            stat.uid = uid;
            Ok(stat)
        })
    }

    /// Set the group ID
    pub fn gid(self, gid: u32) -> Self {
        self.and_then(move |mut stat| {
            stat.gid = gid;
            Ok(stat)
        })
    }

    /// Set the file mode
    pub fn mode(self, mode: u32) -> Self {
        self.and_then(move |mut stat| {
            stat.mode = mode;
            Ok(stat)
        })
    }

    /// Set the file size
    pub fn size(self, size: u64) -> Self {
        self.and_then(move |mut stat| {
            stat.size = size;
            Ok(stat)
        })
    }

    /// Set the access time
    pub fn atime(self, atime: SystemTime) -> Self {
        self.and_then(move |mut stat| {
            stat.atime = atime;
            Ok(stat)
        })
    }

    /// Set the modification time
    pub fn mtime(self, mtime: SystemTime) -> Self {
        self.and_then(move |mut stat| {
            stat.mtime = mtime;
            Ok(stat)
        })
    }

    /// Set the creation time
    pub fn ctime(self, ctime: SystemTime) -> Self {
        self.and_then(move |mut stat| {
            stat.ctime = ctime;
            Ok(stat)
        })
    }

    /// Build the final Stat
    pub fn build(self) -> Result<Stat, Box<dyn std::error::Error + Send + Sync>> {
        self.inner
    }

    // Private helper method for chaining operations
    fn and_then<F>(self, func: F) -> Self
    where
        F: FnOnce(Stat) -> Result<Stat, Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            inner: self.inner.and_then(func),
        }
    }
}

impl Default for StatBuilder {
    fn default() -> Self {
        Self::new()
    }
}
struct HsmStubData {
    dst: CStrBuf,
    archive: i32,
    stat: Option<Stat>,
    stripe_size: u64,
    stripe_offset: i32,
    stripe_count: i32,
    stripe_pattern: LovPattern,
    pool_name: Option<CStrBuf>,
}

/// This builder conforms to a pattern where individual setter methods
/// don't return `Result` and only the final `create()` method returns
/// a `Result`. This allows for clean, fluent chaining without error
/// handling interrupting the builder flow.
///
/// # Examples
///
/// ```no_run
/// # use rustreapi::hsm::HsmFileStub;
/// # use std::time::SystemTime;
/// # fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
/// let fid = HsmFileStub::new("/path/to/file")
///     .archive(1)
///     .pool("my_pool")
///     .uid(1000)
///     .gid(1000)
///     .size(1024)
///     .mtime(SystemTime::now())
///     .stripe_size(2 << 20)
///     .create()?;
/// # Ok(())
/// # }
/// ```
pub struct HsmFileStub {
    inner: Result<HsmStubData, Box<dyn std::error::Error + Send + Sync>>,
}

impl fmt::Display for HsmFileStub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            Ok(data) => {
                let dst_str = data
                    .dst
                    .to_str()
                    .expect("Destination path should be valid UTF-8");

                let pool_str = match &data.pool_name {
                    Some(p) => p.to_str().expect("Pool name should be valid UTF-8"),
                    None => "None",
                };

                let stat_info = match &data.stat {
                    Some(stat) => format!(
                        "uid: {}, gid: {}, mode: 0o{:o}, size: {}, atime: {:?}, mtime: {:?}, ctime: {:?}",
                        stat.uid,
                        stat.gid,
                        stat.mode,
                        stat.size,
                        stat.atime,
                        stat.mtime,
                        stat.ctime,
                    ),
                    None => "default".to_string(),
                };

                write!(
                    f,
                    "HsmStub {{\n  dst: \"{dst_str}\",\n  archive: {},\n  stat: [{}],\n  stripe_size: {},\n  stripe_offset: {},\n  stripe_count: {},\n  stripe_pattern: {},\n  pool_name: \"{}\",\n}}",
                    data.archive,
                    stat_info,
                    data.stripe_size,
                    data.stripe_offset,
                    data.stripe_count,
                    data.stripe_pattern,
                    pool_str,
                )
            }
            Err(e) => write!(f, "HsmStub {{ error: {e} }}"),
        }
    }
}

impl HsmFileStub {
    /// Creates a new HsmFileStub builder. Any initialization
    /// errors are stored internally and will be returned by create().
    pub fn new<P: AsRef<Path>>(dst: P) -> Self {
        let result = (|| -> Result<HsmStubData, Box<dyn std::error::Error + Send + Sync>> {
            let dst = CStrBuf::from_path(dst)?;

            Ok(HsmStubData {
                dst,
                archive: 0,
                stat: None,
                stripe_size: 1 << 20,
                stripe_offset: -1,
                stripe_count: 1,
                stripe_pattern: 0,
                pool_name: None,
            })
        })();

        Self { inner: result }
    }

    /// Set the archive ID.
    pub fn archive(self, archive: i32) -> Self {
        self.and_then(move |mut data| {
            data.archive = archive;
            Ok(data)
        })
    }

    /// Get the stat struct if the builder is in a valid state.
    pub fn stat(self, stat: Stat) -> Self {
        self.and_then(move |mut data| {
            data.stat = Some(stat);
            Ok(data)
        })
    }

    /// Set UID (modifies stat attribute directly)
    pub fn uid(self, uid: u32) -> Self {
        self.and_then(move |mut data| {
            let mut stat = data.stat.unwrap_or_default();
            stat.uid = uid;
            data.stat = Some(stat);
            Ok(data)
        })
    }

    /// Set GID (modifies stat attribute directly)
    pub fn gid(self, gid: u32) -> Self {
        self.and_then(move |mut data| {
            let mut stat = data.stat.unwrap_or_default();
            stat.gid = gid;
            data.stat = Some(stat);
            Ok(data)
        })
    }

    /// Set mode (modifies stat attribute directly)
    pub fn mode(self, mode: u32) -> Self {
        self.and_then(move |mut data| {
            let mut stat = data.stat.unwrap_or_default();
            stat.mode = mode;
            data.stat = Some(stat);
            Ok(data)
        })
    }

    /// Set file size (modifies stat attribute directly)
    pub fn size(self, size: u64) -> Self {
        self.and_then(move |mut data| {
            let mut stat = data.stat.unwrap_or_default();
            stat.size = size;
            data.stat = Some(stat);
            Ok(data)
        })
    }

    /// Set mtime (modifies stat attribute directly)
    pub fn mtime(self, mtime: SystemTime) -> Self {
        self.and_then(move |mut data| {
            let mut stat = data.stat.unwrap_or_default();
            stat.mtime = mtime;
            data.stat = Some(stat);
            Ok(data)
        })
    }

    /// Set atime (modifies stat attribute directly)
    pub fn atime(self, atime: SystemTime) -> Self {
        self.and_then(move |mut data| {
            let mut stat = data.stat.unwrap_or_default();
            stat.atime = atime;
            data.stat = Some(stat);
            Ok(data)
        })
    }

    /// Set ctime (modifies stat attribute directly)
    pub fn ctime(self, ctime: SystemTime) -> Self {
        self.and_then(move |mut data| {
            let mut stat = data.stat.unwrap_or_default();
            stat.ctime = ctime;
            data.stat = Some(stat);
            Ok(data)
        })
    }

    /// Set stripe size.
    pub fn stripe_size(self, size: u64) -> Self {
        self.and_then(move |mut data| {
            data.stripe_size = size;
            Ok(data)
        })
    }

    /// Set stripe offset.
    pub fn stripe_offset(self, offset: i32) -> Self {
        self.and_then(move |mut data| {
            data.stripe_offset = offset;
            Ok(data)
        })
    }

    /// Set stripe count.
    pub fn stripe_count(self, count: i32) -> Self {
        self.and_then(move |mut data| {
            data.stripe_count = count;
            Ok(data)
        })
    }

    /// Set stripe pattern.
    pub fn stripe_pattern(self, pattern: LovPattern) -> Self {
        self.and_then(move |mut data| {
            data.stripe_pattern = pattern;
            Ok(data)
        })
    }

    /// Set pool name.
    pub fn pool(self, pool_name: &str) -> Self {
        self.and_then(move |mut data| {
            data.pool_name = Some(CStrBuf::from_str(pool_name)?);
            Ok(data)
        })
    }

    /// Creates the HSM stub. This is where all accumulated errors are handled.
    pub fn create(self) -> Result<Fid, Box<dyn std::error::Error + Send + Sync>> {
        let data = self.inner?; // Handle any builder errors first

        let newfid: Fid = Default::default();

        // Use provided stat or create defaults
        let stat = data.stat.unwrap_or_default();
        let raw_stat = stat.to_raw_stat();

        let pool_ptr = match &data.pool_name {
            Some(p) => p.as_ptr() as *mut std::os::raw::c_char,
            None => std::ptr::null_mut(),
        };

        let rc = unsafe {
            llapi_hsm_import(
                data.dst.as_ptr(),
                data.archive,
                &raw_stat,
                data.stripe_size,
                data.stripe_offset,
                data.stripe_count,
                data.stripe_pattern,
                pool_ptr,
                &mut lu_fid::from(newfid),
            )
        };

        if rc == 0 {
            Ok(newfid)
        } else {
            Err(format!("llapi_hsm_import failed with code: {rc}").into())
        }
    }

    // Private helper method for chaining operations on the inner Result
    fn and_then<F>(self, func: F) -> Self
    where
        F: FnOnce(HsmStubData) -> Result<HsmStubData, Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            inner: self.inner.and_then(func),
        }
    }
}
