// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

#![doc = include_str!("../doc/api.md")]

mod error;
mod fid;
mod layout;

pub mod changelog;
pub mod hsm;
mod mount;
mod path;

use crate::error::{Error::MsgErrno, cvt_lz, cvt_lz_m, cvt_nz, cvt_rc_m};
pub use changelog::{
    ChangelogBuilder, ChangelogExtraFlag, ChangelogFlag, ChangelogReader, ChangelogRecord,
    ClientNid, Record, RecordType,
};
pub use cstrbuf::CStrBuf;
pub use error::{Error, Result};
pub use fid::*;
pub use layout::*;

use libc::{c_char, mode_t};
use lustreapi_sys::*;
pub use mount::*;
use nix::errno;
pub use path::LustrePath;
use std::{
    ffi::{CStr, CString},
    fmt::{Display, Formatter},
    fs::File,
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd},
        raw::c_int,
    },
    path::Path,
    ptr,
    ptr::addr_of_mut,
};

// Constants
#[cfg(not(feature = "LUSTRE_2_14"))]
#[allow(non_snake_case)]
pub fn LAYOUT_WIDE_MIN() -> u64 {
    unsafe { llapi_LAYOUT_WIDE_MIN() }
}

#[cfg(not(feature = "LUSTRE_2_14"))]
#[allow(non_snake_case)]
pub fn LAYOUT_WIDE_MAX() -> u64 {
    unsafe { llapi_LAYOUT_WIDE_MAX() }
}

#[cfg(not(feature = "LUSTRE_2_14"))]
#[allow(non_snake_case)]
pub fn OVERSTRIPE_COUNT_MIN() -> u64 {
    unsafe { llapi_OVERSTRIPE_COUNT_MIN() }
}

#[cfg(not(feature = "LUSTRE_2_14"))]
#[allow(non_snake_case)]
pub fn OVERSTRIPE_COUNT_MAX() -> u64 {
    unsafe { llapi_OVERSTRIPE_COUNT_MAX() }
}

#[cfg(feature = "LUSTRE_2_17")]
pub type LovPattern = u32; // TODO: should an enum based on lov_pattern
#[cfg(not(feature = "LUSTRE_2_17"))]
pub type LovPattern = i32;

#[allow(non_snake_case)]
pub fn O_LOV_DELAY_CREATE() -> i32 {
    unsafe { llapi_O_LOV_DELAY_CREATE() }
}

/// `OpenOptions` is used to configure the options for opening a file in Lustre.
#[derive(Clone, Debug)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
    lov_delay: bool,
    mode: mode_t,
    stripe_size: u64,
    stripe_offset: i32,
    stripe_count: i32,
    stripe_pattern: LovPattern,
    pool: Option<String>,
    mdt: Option<i32>,
    layout: Option<Layout>,
}

impl OpenOptions {
    pub fn new() -> Self {
        Self {
            read: false,
            write: false,
            append: false,
            truncate: false,
            create: false,
            create_new: false,
            lov_delay: false,
            mode: 0o644,
            stripe_size: 0,
            stripe_offset: 0,
            stripe_count: 0,
            stripe_pattern: 0,
            pool: None,
            mdt: None,
            layout: None,
        }
    }
    pub fn read(&mut self, read: bool) -> &mut Self {
        self.read = read;
        self
    }
    pub fn write(&mut self, write: bool) -> &mut Self {
        self.write = write;
        self
    }

    pub fn create(&mut self, create: bool) -> &mut Self {
        self.create = create;
        self
    }

    pub fn create_new(&mut self, create_new: bool) -> &mut Self {
        self.create_new = create_new;
        self
    }

    pub fn lov_delay(&mut self, lov_delay: bool) -> &mut Self {
        self.lov_delay = lov_delay;
        self
    }
    pub fn mode(&mut self, mode: mode_t) -> &mut Self {
        self.mode = mode;
        self
    }
    pub fn mdt_idx(&mut self, mdtidx: i32) -> &mut Self {
        self.mdt = Some(mdtidx);
        self
    }

    pub fn pool(&mut self, pool: Option<String>) -> &mut Self {
        self.pool = pool;
        self
    }

    pub fn layout(&mut self, layout: Layout) -> &mut Self {
        self.layout = Some(layout);
        self
    }

    pub fn stripe_size(&mut self, stripe_size: u64) -> &mut Self {
        self.stripe_size = stripe_size;
        self
    }

    pub fn stripe_offset(&mut self, stripe_offset: i32) -> &mut Self {
        self.stripe_offset = stripe_offset;
        self
    }
    pub fn stripe_count(&mut self, stripe_count: i32) -> &mut Self {
        self.stripe_count = stripe_count;
        self
    }

    pub fn stripe_pattern(&mut self, stripe_pattern: LovPattern) -> &mut Self {
        self.stripe_pattern = stripe_pattern;
        self
    }

    fn get_access_mode(&self) -> Result<i32> {
        match (self.read, self.write, self.append) {
            (true, false, false) => Ok(libc::O_RDONLY),
            (false, true, false) => Ok(libc::O_WRONLY),
            (true, true, false) => Ok(libc::O_RDWR),
            (false, _, true) => Ok(libc::O_WRONLY | libc::O_APPEND),
            (true, _, true) => Ok(libc::O_RDWR | libc::O_APPEND),
            (false, false, false) => Err(MsgErrno(
                "incorrect access mode".to_string(),
                errno::Errno::EINVAL,
            )),
        }
    }

    fn get_creation_mode(&self) -> Result<i32> {
        match (self.write, self.append) {
            (true, false) => {}
            (false, false) => {
                if self.truncate || self.create || self.create_new {
                    return Err(MsgErrno(
                        "must set write or append".to_string(),
                        errno::Errno::EINVAL,
                    ));
                }
            }
            (_, true) => {
                if self.truncate && !self.create_new {
                    return Err(MsgErrno(
                        "truncate and exclusive set".to_string(),
                        errno::Errno::EINVAL,
                    ));
                }
            }
        }

        Ok(match (self.create, self.truncate, self.create_new) {
            (false, false, false) => 0,
            (true, false, false) => libc::O_CREAT,
            (false, true, false) => libc::O_TRUNC,
            (true, true, false) => libc::O_CREAT | libc::O_TRUNC,
            (_, _, true) => libc::O_CREAT | libc::O_EXCL,
        })
    }

    /// Initializes an allocated but uninitialized `llapi_stripe_param`.
    /// The caller is responsible allocating and dropping.
    fn get_stripe_param(&self, param: *mut llapi_stripe_param) {
        let pool = if let Some(pool) = self.pool.as_ref() {
            pool.as_bytes().as_ptr() as *mut c_char
        } else {
            ptr::null_mut::<c_char>()
        };
        unsafe {
            // ptr::write() sets the value without dropping the previous value.
            addr_of_mut!((*param).lsp_stripe_size).write(self.stripe_size);
            addr_of_mut!((*param).lsp_pool).write(pool);
            addr_of_mut!((*param).lsp_stripe_offset).write(self.stripe_offset);
            addr_of_mut!((*param).lsp_stripe_pattern).write(self.stripe_pattern);
            addr_of_mut!((*param).lsp_stripe_count).write(self.stripe_count);
            // It appears lustre uses these internally
            addr_of_mut!((*param).lsp_is_specific).write(false);
            addr_of_mut!((*param).lsp_is_create).write(false);
            addr_of_mut!((*param).lsp_max_inherit).write(0);
            addr_of_mut!((*param).lsp_max_inherit_rr).write(0);
            addr_of_mut!((*param).lsp_osts).write(Default::default());
        }
    }

    fn get_lov_delay(&self) -> i32 {
        if self.lov_delay {
            O_LOV_DELAY_CREATE()
        } else {
            0
        }
    }

    pub fn open(&mut self, path: &Path) -> Result<File> {
        // Assume create if not specified

        if !self.create_new {
            self.create = true;
        }
        let access_mode = self.get_access_mode()?;
        let creation_mode = self.get_creation_mode()?;
        let flags = access_mode | creation_mode;

        let cpath = CString::new(path.to_string_lossy().to_string())?;

        if self.lov_delay {
            let flags = flags | self.get_lov_delay();
            // If lov_delay is set, we need to use O_LOV_DELAY_CREATE
            return unsafe {
                cvt_lz_m(
                    llapi_layout_file_open(cpath.as_ptr(), flags, self.mode, ptr::null_mut()),
                    cpath.to_string_lossy().to_string(),
                )
                .map(|fd| File::from_raw_fd(fd))
            };
        }

        // TODO: remove param and just use layout, at least when
        // llapi_create_volatile_layout is available
        if let Some(ref layout) = self.layout {
            return unsafe {
                cvt_lz_m(
                    llapi_layout_file_open(cpath.as_ptr(), flags, self.mode, layout.as_lu_layout()),
                    cpath.to_string_lossy().to_string(),
                )
                .map(|fd| File::from_raw_fd(fd))
            };
        }

        let mut param: MaybeUninit<llapi_stripe_param> = MaybeUninit::zeroed();
        self.get_stripe_param(param.as_mut_ptr());
        let param = unsafe { param.assume_init() };

        unsafe {
            cvt_lz_m(
                llapi_file_open_param(
                    cpath.as_ptr(),
                    flags,
                    self.mode,
                    &param as *const llapi_stripe_param,
                ),
                cpath.to_string_lossy().to_string(),
            )
            .map(|fd| File::from_raw_fd(fd))
        }
    }

    pub fn volatile(&mut self, dir: &Path) -> Result<File> {
        self.create_new(true);
        self.write(true);

        let access_mode = self.get_access_mode()?;
        let creation_mode = self.get_creation_mode()?;
        let flags = access_mode | creation_mode;

        let mut param: MaybeUninit<llapi_stripe_param> = MaybeUninit::zeroed();
        self.get_stripe_param(param.as_mut_ptr());
        let param = unsafe { param.assume_init() };

        let cpath = dir.as_os_str().as_encoded_bytes().as_ptr() as *const c_char;

        let fd = unsafe {
            cvt_lz(llapi_create_volatile_param(
                cpath,
                self.mdt.unwrap_or(-1),
                flags,
                self.mode,
                &param as *const llapi_stripe_param,
            ))?
        };
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self::new()
    }
}

pub fn file_get_mdtidx(name: &Path) -> Result<i32> {
    let mut mdtidx = c_int::default();
    let h = File::open(name).map_err(|err| {
        MsgErrno(
            name.to_string_lossy().to_string(),
            errno::Errno::try_from(err).unwrap_or(errno::Errno::EINVAL),
        )
    })?;
    let fd = h.as_raw_fd();
    let rc = unsafe {
        let rc = llapi_file_fget_mdtidx(fd, &mut mdtidx);
        if rc != 0 {
            println!("get_mdtidx failed: {rc}");
        }
        rc
    };
    drop(h);
    cvt_nz(rc)?;
    Ok(mdtidx)
}

pub fn open_by_fid_at(lustre_fd: &File, fid: &Fid, flags: i32) -> Result<File> {
    let fd = lustre_fd.as_raw_fd();
    let flags = if flags == 0 { libc::O_RDONLY } else { flags };

    unsafe {
        cvt_lz_m(
            llapi_open_by_fid_at(fd, &fid.to_lu_fid(), flags),
            "open_by_fid".to_string(),
        )
        .map(|fd| File::from_raw_fd(fd))
    }
}

pub fn ost_count(lustre_path: &LustrePath) -> Result<i32> {
    let file = File::open(lustre_path.as_ref())?;
    let mut count = 0;
    unsafe {
        cvt_rc_m(
            llapi_lov_get_uuids(file.as_raw_fd(), ptr::null_mut(), &mut count),
            "get_lmv_uuids".to_string(),
        )?;
    }
    Ok(count)
}

#[cfg(feature = "LUSTRE_2_14")]
pub fn mdt_count(lustre_path: &LustrePath) -> Result<i32> {
    let file = lustre_path.open()?;
    let mut count = 0;
    unsafe {
        cvt_rc_m(
            llapi_lmv_get_uuids(file.as_raw_fd(), ptr::null_mut(), &mut count),
            "get_lov_uuids".to_string(),
        )?;
    }

    Ok(count)
}

#[repr(transparent)]
#[derive(Debug, Default, Clone)]
pub struct ObdUuid {
    inner: obd_uuid,
}

impl Display for ObdUuid {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str().expect("should be valid UTF-8"))
    }
}

impl ObdUuid {
    pub fn new(uuid: obd_uuid) -> Self {
        ObdUuid { inner: uuid }
    }

    pub fn as_str(&self) -> Result<&str> {
        let mut index = 0;
        // The `uuid` buffer in `obd_uuid` is a `char` array that may contain
        // an embedded nul. This like because the library function has truncated the
        // `uuid` from the rest of the string in the buffer. :(
        for (n, c) in self.inner.uuid.iter().enumerate() {
            if *c == 0 {
                index = n;
                break;
            }
        }

        let s = &self.inner.uuid[0..index];

        let cstr = unsafe { CStr::from_ptr(s.as_ptr() as *const c_char) };

        Ok(cstr.to_str()?)
    }

    pub fn as_string(&self) -> String {
        self.as_str().unwrap_or("").to_string()
    }
}

pub fn get_lov_uuids(lustre_path: &LustrePath) -> Result<Vec<ObdUuid>> {
    let file = lustre_path.open()?;
    let mut count = ost_count(lustre_path)?;
    let uuids = vec![ObdUuid::default(); count as usize];
    unsafe {
        cvt_rc_m(
            llapi_lov_get_uuids(
                file.as_raw_fd(),
                uuids.as_ptr() as *mut obd_uuid,
                &mut count,
            ),
            "get_lmv_uuids".to_string(),
        )?;
    }
    Ok(uuids)
}

#[cfg(feature = "LUSTRE_2_14")]
pub fn get_lmv_uuids(lustre_path: &LustrePath) -> Result<Vec<ObdUuid>> {
    let file = File::open(lustre_path.as_ref())?;
    let mut count = mdt_count(lustre_path)?;
    let uuids = vec![ObdUuid::default(); count as usize];
    unsafe {
        cvt_rc_m(
            llapi_lmv_get_uuids(
                file.as_raw_fd(),
                uuids.as_ptr() as *mut obd_uuid,
                &mut count,
            ),
            "get_lmv_uuids".to_string(),
        )?;
    }
    Ok(uuids)
}

#[cfg(test)]
mod tests {
    // use super::*;

    #[test]
    fn it_works() {}
}
