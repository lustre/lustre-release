// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use crate::{
    Error, Fid,
    error::{Result, cvt_lz_m, cvt_nz, cvt_nz_m},
};
use cstrbuf::CStrBuf;
use lustreapi_sys::*;
use nix::errno;
use std::{
    ffi::CString,
    fmt,
    fmt::Display,
    fs::File,
    os::fd::{AsRawFd, FromRawFd},
    path::Path,
};

use bitmask_enum::bitmask;

#[cfg(not(feature = "LUSTRE_2_14"))]
#[repr(u32)]
#[derive(Clone)]
pub enum LayoutGetFlags {
    NONE = 0,
    EXPECTED = LLAPI_LAYOUT_GET_EXPECTED,
    COPY = LLAPI_LAYOUT_GET_COPY,
    CHECK = LLAPI_LAYOUT_GET_CHECK,
}

#[cfg(feature = "LUSTRE_2_14")]
#[repr(u32)]
#[derive(Clone)]
pub enum LayoutGetFlags {
    NONE = 0,
    EXPECTED = 0x1,
}

#[repr(u32)]
#[derive(Clone)]
pub enum CompUse {
    First = LLAPI_LAYOUT_COMP_USE_FIRST,
    Last = LLAPI_LAYOUT_COMP_USE_LAST,
    Next = LLAPI_LAYOUT_COMP_USE_NEXT,
    Prev = LLAPI_LAYOUT_COMP_USE_PREV,
}

#[cfg(not(feature = "LUSTRE_2_14"))]
#[bitmask(u32)]
#[bitmask_config(vec_debug, flags_iter)]
pub enum CompEntryFlags {
    Stale = LCME_FL_STALE,
    PrefRd = LCME_FL_PREF_RD,
    PrefWr = LCME_FL_PREF_WR,
    PrefRW = LCME_FL_PREF_RW,
    Offline = LCME_FL_OFFLINE,
    Init = LCME_FL_INIT,
    NoSync = LCME_FL_NOSYNC,
    Extension = LCME_FL_EXTENSION,
    Parity = LCME_FL_PARITY,
    Compress = LCME_FL_COMPRESS,
    Partial = LCME_FL_PARTIAL,
    NoCompr = LCME_FL_NOCOMPR,
    Neg = LCME_FL_NEG,
}

#[cfg(feature = "LUSTRE_2_14")]
#[bitmask(u32)]
#[bitmask_config(vec_debug, flags_iter)]
pub enum CompEntryFlags {
    Stale = LCME_FL_STALE,
    PrefRd = LCME_FL_PREF_RD,
    PrefWr = LCME_FL_PREF_WR,
    PrefRW = LCME_FL_PREF_RW,
    Offline = LCME_FL_OFFLINE,
    Init = LCME_FL_INIT,
    NoSync = LCME_FL_NOSYNC,
    Extension = LCME_FL_EXTENSION,
    Compress = LCME_FL_COMPRESS,
    Partial = LCME_FL_PARTIAL,
    NoCompr = LCME_FL_NOCOMPR,
    Neg = LCME_FL_NEG,
}

impl Default for CompEntryFlags {
    fn default() -> Self {
        CompEntryFlags::none()
    }
}
impl Display for CompEntryFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v: Vec<&str> = CompEntryFlags::flags()
            .filter(|&(_, value)| self.contains(*value))
            .map(|(name, _)| *name)
            .collect();

        if v.is_empty() {
            write!(f, "Uninit")?;
        } else {
            write!(f, "{}", v.join(", "))?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Layout {
    layout: *mut llapi_layout,
}

impl Drop for Layout {
    fn drop(&mut self) {
        unsafe { llapi_layout_free(self.layout) }
    }
}

impl Layout {
    pub fn new() -> Self {
        let layout = unsafe { llapi_layout_alloc() };

        // Rust considers allocation failures unrecoverable
        assert!(!layout.is_null());

        Self { layout }
    }

    pub fn as_lu_layout(&self) -> *mut llapi_layout {
        self.layout
    }
    pub fn with_path(name: &Path, flags: LayoutGetFlags) -> Result<Layout> {
        let name = name.as_os_str();
        let cstr = CString::new(name.as_encoded_bytes())?;
        let ll = unsafe { llapi_layout_get_by_path(cstr.as_ptr(), flags as u32) };
        if ll.is_null() {
            return Err(Error::MsgErrno(
                name.to_string_lossy().to_string(),
                errno::Errno::last(),
            ));
        }
        Ok(Layout { layout: ll })
    }

    pub fn with_fd(file: &File, flags: LayoutGetFlags) -> Result<Layout> {
        let fd = file.as_raw_fd();
        unsafe {
            let ll = llapi_layout_get_by_fd(fd, flags as u32);
            if ll.is_null() {
                Err(Error::MsgErrno(
                    "llapi_layout_get_by_fd".to_string(),
                    errno::Errno::last(),
                ))
            } else {
                Ok(Layout { layout: ll })
            }
        }
    }

    pub fn with_fid(path: &Path, fid: Fid, flags: LayoutGetFlags) -> Result<Layout> {
        let cstr = CString::new(path.as_os_str().as_encoded_bytes())?;

        let ll = unsafe { llapi_layout_get_by_fid(cstr.as_ptr(), &fid.to_lu_fid(), flags as u32) };
        if ll.is_null() {
            return Err(Error::MsgErrno(
                "llapi_layout_get_by_fid".to_string(),
                errno::Errno::last(),
            ));
        }
        Ok(Layout { layout: ll })
    }
}

impl Default for Layout {
    fn default() -> Self {
        Self::new()
    }
}

// Builder and getter methods for Layout and Components
// TODO: Change getters to return Option<T> instead of Result<T>.
impl Layout {
    pub fn get_stripe_count(&self) -> Result<u64> {
        let mut num = std::os::raw::c_ulong::default();

        unsafe { cvt_nz(llapi_layout_stripe_count_get(self.layout, &mut num))? };

        Ok(num)
    }

    pub fn get_stripe_size(&self) -> Result<u64> {
        let mut num = std::os::raw::c_ulong::default();

        unsafe { cvt_nz(llapi_layout_stripe_size_get(self.layout, &mut num))? };

        Ok(num)
    }

    pub fn get_stripe_pattern(&self) -> Result<u64> {
        let mut num = std::os::raw::c_ulong::default();

        unsafe { cvt_nz(llapi_layout_pattern_get(self.layout, &mut num))? };

        Ok(num)
    }

    pub fn get_ost_index(&self, stripe: u64) -> Result<u64> {
        let mut num = std::os::raw::c_ulong::default();

        unsafe { cvt_nz(llapi_layout_ost_index_get(self.layout, stripe, &mut num))? };

        Ok(num)
    }
    pub fn get_pool_name(&self) -> Result<String> {
        let mut cbuf = CStrBuf::new(256);
        unsafe {
            cvt_nz(llapi_layout_pool_name_get(
                self.layout,
                cbuf.as_mut_ptr(),
                cbuf.buffer_len() - 1,
            ))?
        };
        cbuf.into_string().map_err(Error::StringConversionError)
    }

    pub fn get_flags(&self) -> Result<u32> {
        let mut flags = std::os::raw::c_uint::default();

        unsafe { cvt_nz(llapi_layout_flags_get(self.layout, &mut flags))? };

        Ok(flags)
    }

    pub fn get_comp_flags(&self) -> Result<CompEntryFlags> {
        let mut flags = std::os::raw::c_uint::default();

        unsafe { cvt_nz(llapi_layout_comp_flags_get(self.layout, &mut flags))? };

        Ok(flags.into())
    }

    pub fn get_mirror_count(&self) -> Result<u16> {
        let mut count = std::os::raw::c_ushort::default();

        unsafe { cvt_nz(llapi_layout_mirror_count_get(self.layout, &mut count))? };

        Ok(count)
    }

    pub fn get_comp_extent(&self) -> Result<(u64, u64)> {
        let mut start = std::os::raw::c_ulong::default();
        let mut end = std::os::raw::c_ulong::default();

        unsafe {
            cvt_nz(llapi_layout_comp_extent_get(
                self.layout,
                &mut start,
                &mut end,
            ))?
        };

        Ok((start, end))
    }

    pub fn get_comp_id(&self) -> Result<u32> {
        let mut id = std::os::raw::c_uint::default();

        unsafe { cvt_nz(llapi_layout_comp_id_get(self.layout, &mut id))? };

        Ok(id)
    }
    pub fn stripe_count(&self, stripe_count: u64) -> Result<&Self> {
        unsafe { cvt_nz(llapi_layout_stripe_count_set(self.layout, stripe_count))? };
        Ok(self)
    }

    pub fn stripe_size(&self, stripe_size: u64) -> Result<&Self> {
        unsafe { cvt_nz(llapi_layout_stripe_size_set(self.layout, stripe_size))? };
        Ok(self)
    }

    pub fn stripe_pattern(&self, stripe_pattern: u64) -> Result<&Self> {
        unsafe { cvt_nz(llapi_layout_pattern_set(self.layout, stripe_pattern))? };
        Ok(self)
    }

    pub fn ost_index(&self, index: i32, ost: u64) -> Result<&Self> {
        unsafe { cvt_nz(llapi_layout_ost_index_set(self.layout, index, ost))? };
        Ok(self)
    }

    pub fn pool_name(&self, pool_name: &str) -> Result<&Self> {
        let cstr = CString::new(pool_name)?;

        unsafe { cvt_nz(llapi_layout_pool_name_set(self.layout, cstr.as_ptr()))? };
        Ok(self)
    }

    pub fn flags(&self, flags: u32) -> Result<&Self> {
        unsafe { cvt_nz(llapi_layout_flags_set(self.layout, flags))? };
        Ok(self)
    }

    pub fn extension_size(&self, size: u64) -> Result<&Self> {
        unsafe {
            cvt_nz_m(
                llapi_layout_extension_size_set(self.layout, size),
                "extension_size".to_string(),
            )?
        };
        Ok(self)
    }

    pub fn comp_flags(&self, flags: CompEntryFlags) -> Result<&Self> {
        unsafe { cvt_nz(llapi_layout_comp_flags_set(self.layout, u32::from(flags)))? };
        Ok(self)
    }
    pub fn mirror_count(&self, mirror_count: u16) -> Result<&Self> {
        unsafe { cvt_nz(llapi_layout_mirror_count_set(self.layout, mirror_count))? };
        Ok(self)
    }
    pub fn comp_extent(&self, start: u64, end: u64) -> Result<&Self> {
        unsafe {
            cvt_nz_m(
                llapi_layout_comp_extent_set(self.layout, start, end),
                "comp_extent".to_string(),
            )?
        };
        Ok(self)
    }

    pub fn comp_add(&self) -> Result<&Self> {
        unsafe { cvt_nz_m(llapi_layout_comp_add(self.layout), "comp_add".to_string())? };
        Ok(self)
    }

    pub fn comp_del(&self) -> Result<()> {
        unsafe { cvt_nz_m(llapi_layout_comp_del(self.layout), "comp_del".to_string())? };
        Ok(())
    }

    pub fn file_comp_add(&self, path: &Path) -> Result<()> {
        let cpath = CString::new(path.as_os_str().as_encoded_bytes())?;
        unsafe {
            cvt_nz_m(
                llapi_layout_file_comp_add(cpath.as_ptr(), self.layout),
                "comp_add_path".to_string(),
            )?
        };
        Ok(())
    }

    /// Delete component from the file based on the component ID.
    ///
    pub fn file_comp_del(path: &Path, id: u32) -> Result<()> {
        let flags = 0;
        let cpath = CString::new(path.as_os_str().as_encoded_bytes())?;
        unsafe {
            cvt_nz_m(
                llapi_layout_file_comp_del(cpath.as_ptr(), id, flags),
                "comp_del_path".to_string(),
            )?
        };
        Ok(())
    }

    /// Delete one or more components from the file based on the component ID.
    pub fn file_comp_del_flags(path: &Path, flags: CompEntryFlags) -> Result<()> {
        let id = LCME_ID_INVAL;
        let cpath = CString::new(path.as_os_str().as_encoded_bytes())?;
        unsafe {
            cvt_nz_m(
                llapi_layout_file_comp_del(cpath.as_ptr(), id, flags.bits()),
                "comp_del_path".to_string(),
            )?
        };
        Ok(())
    }

    pub fn comp_use(&self, use_: CompUse) -> Result<&Self> {
        unsafe {
            cvt_nz_m(
                llapi_layout_comp_use(self.layout, use_ as u32),
                "comp_use".to_string(),
            )?
        };
        Ok(self)
    }

    pub fn create(&self, path: &Path) -> Result<File> {
        let cpath = CString::new(path.as_os_str().as_encoded_bytes())?;
        unsafe {
            cvt_lz_m(
                llapi_layout_file_create(cpath.as_ptr(), 0, 0o660, self.layout),
                cpath.to_string_lossy().to_string(),
            )
            .map(|fd| File::from_raw_fd(fd))
        }
    }

    pub fn create_with_mode(&self, path: &Path, mode_in: i32) -> Result<File> {
        let cpath = CString::new(path.as_os_str().as_encoded_bytes())?;
        unsafe {
            cvt_lz_m(
                llapi_layout_file_create(cpath.as_ptr(), 0, mode_in, self.layout),
                cpath.to_string_lossy().to_string(),
            )
            .map(|fd| File::from_raw_fd(fd))
        }
    }

    pub fn open(&self, path: &Path) -> Result<File> {
        let cpath = CString::new(path.as_os_str().as_encoded_bytes())?;

        unsafe {
            cvt_lz_m(
                llapi_layout_file_open(cpath.as_ptr(), 0, 0o660, self.layout),
                cpath.to_string_lossy().to_string(),
            )
            .map(|fd| File::from_raw_fd(fd))
        }
    }
    pub fn sanity(&self, incomplete: bool, flr: bool) -> Result<()> {
        unsafe {
            cvt_nz_m(
                llapi_layout_sanity(self.layout, incomplete, flr),
                "sanity".to_string(),
            )?
        };
        Ok(())
    }

    #[cfg(not(feature = "LUSTRE_2_14"))]
    pub fn sanity_v2(&self, incomplete: bool, flr: bool, fsname: String) -> Result<()> {
        use std::os::raw::c_char;

        let fsname = CString::new(fsname)?;
        unsafe {
            cvt_nz_m(
                llapi_layout_v2_sanity(
                    self.layout,
                    incomplete,
                    flr,
                    fsname.as_ptr() as *mut c_char,
                ),
                "sanity_v2".to_string(),
            )?
        };
        Ok(())
    }
}

impl Display for Layout {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for l in self.iter() {
            writeln!(f, "id: {}", l.get_comp_id()?)?;
            writeln!(f, "comp_extent: {:?}", l.get_comp_extent()?)?;
            writeln!(f, "mirror_count: {}", l.get_mirror_count()?)?;
            writeln!(f, "stripe_count: {}", l.get_stripe_count()?)?;
            writeln!(f, "stripe_size: {}", l.get_stripe_size()?)?;
            writeln!(f, "pattern: {}", l.get_stripe_pattern()?)?;
            writeln!(f, "pool_name: {}", l.get_pool_name()?)?;
            writeln!(f, "flags: 0x{:x}", l.get_flags()?)?;

            let comp_flags = l.get_comp_flags()?;
            writeln!(f, "comp_flags: {comp_flags}")?;

            let mut osts = Vec::new();

            for i in 0..l.get_stripe_count()? {
                match l.get_ost_index(i) {
                    Ok(ost) => osts.push(ost),
                    Err(_) => break,
                }
            }

            writeln!(f, "ost_index: {osts:?}")?;

            writeln!(f)?;
        }

        Ok(())
    }
}

/// Iterator for Layout.
/// (experimental)
pub struct LayoutIter<'a> {
    layout: &'a Layout,
    first: bool,
}

impl<'a> Iterator for LayoutIter<'a> {
    type Item = &'a Layout;

    fn next(&mut self) -> Option<Self::Item> {
        if self.first {
            self.first = false;
            return Some(self.layout);
        }
        match self.layout.comp_use(CompUse::Next) {
            Ok(_) => Some(self.layout),
            Err(_) => None,
        }
    }
}

pub struct LayoutIterReverse<'a> {
    layout: &'a Layout,
    first: bool,
}

impl<'a> Iterator for LayoutIterReverse<'a> {
    type Item = &'a Layout;

    fn next(&mut self) -> Option<Self::Item> {
        if self.first {
            self.first = false;
            return Some(self.layout);
        }
        match self.layout.comp_use(CompUse::Prev) {
            Ok(_) => Some(self.layout),
            Err(_) => None,
        }
    }
}
impl Layout {
    /// Returns an iterator over the components of the layout.
    /// This starts with the first component and iterates to the last.
    /// A layout always has at least 1 component, so
    /// this will always return at least one item.
    ///
    /// ```
    /// use rustreapi::Layout;
    ///
    /// let layout = Layout::new();
    /// for l in layout.iter() {
    ///    println!("{}", l.get_stripe_count().unwrap());
    /// }
    /// ```
    pub fn iter(&self) -> LayoutIter<'_> {
        self.comp_use(CompUse::First)
            .expect("Layout should have at least one component."); // First shouldn't fail if it's a valid layout
        LayoutIter {
            layout: self,
            first: true,
        }
    }

    /// Returns an iterator over the components of the layout.
    /// This starts with the last component and iterates to the first.
    /// A layout always has at least 1 component, so
    /// this will always return at least one item.
    pub fn iter_reverse(&self) -> LayoutIterReverse<'_> {
        self.comp_use(CompUse::Last)
            .expect("Layout should have at least one component."); // Last shouldn't fail if it's a valid layout
        LayoutIterReverse {
            layout: self,
            first: true,
        }
    }
}

/// `CompLayout` is a rust version of Lustre's
/// internal `llapi_layout` structure. The goal
/// is to provide a more rust friendly interface
/// for retrieving layout information. However,
/// perhaps the iterator on Layout is good enough
/// and this isn't needed.
///
/// TODO: still in progress
type CompLayout = Vec<SingleLayout>;

#[derive(Default, Debug)]
pub struct SingleLayout {
    pub pattern: u64,
    pub stripe_size: u64,
    pub stripe_count: u64,
    pub osts: Vec<u64>,
    pub mirror_count: u16,
    pub comp_flags: CompEntryFlags,
    pub pool_name: Option<String>,
    pub start: u64,
    pub end: u64,
    comp_id: u32,
    lcmd_flags: u32,
}

impl Display for SingleLayout {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "comp_id: {}\npattern: {}\nstripe_size: {}\nstripe_count: {}\nosts: {:?}\npool_name: {:?}\nstart: {}\nend: {}\nlcmd_flags: {}",
            self.comp_id,
            self.pattern,
            self.stripe_size,
            self.stripe_count,
            self.osts,
            self.pool_name,
            self.start,
            self.end as i64,
            self.lcmd_flags
        )
    }
}

// TODO replace these with a CompLayout::from() or Layout::to_comp_layout()
pub fn get_layout(name: &Path, flags: LayoutGetFlags) -> Result<Vec<SingleLayout>> {
    let ll = Layout::with_path(name, flags)?;
    ll_to_comp_layout(ll)
}

pub fn get_layout_fd(file: &File, flags: LayoutGetFlags) -> Result<Vec<SingleLayout>> {
    let ll = Layout::with_fd(file, flags)?;
    ll_to_comp_layout(ll)
}

pub fn get_layout_fid(path: &Path, fid: Fid, flags: LayoutGetFlags) -> Result<CompLayout> {
    let ll = Layout::with_fid(path, fid, flags)?;
    ll_to_comp_layout(ll)
}

fn ll_to_comp_layout(ll: Layout) -> Result<CompLayout> {
    ll.iter()
        .map(|l| {
            let (start, end) = l.get_comp_extent()?;
            let mut layout = SingleLayout {
                stripe_count: l.get_stripe_count()?,
                stripe_size: l.get_stripe_size()?,
                start,
                end,
                pattern: l.get_stripe_pattern()?,
                comp_id: l.get_comp_id()?,
                lcmd_flags: l.get_flags()?,
                comp_flags: l.get_comp_flags()?,
                mirror_count: l.get_mirror_count()?,

                ..Default::default()
            };

            for i in 0..layout.stripe_count {
                match l.get_ost_index(i) {
                    Ok(ost) => layout.osts.push(ost),
                    Err(_) => break,
                }
            }

            layout.pool_name = match l.get_pool_name() {
                Ok(name) => {
                    if name.is_empty() {
                        None
                    } else {
                        Some(name)
                    }
                }
                Err(err) => {
                    println!("pool name conversion failed: {err:?}");
                    None
                }
            };

            Ok(layout)
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;

    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    #[test]
    fn test_new_layout_iter() {
        let l = Layout::new();
        let mut iter = l.iter();
        // Always at least one component
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_default_values() -> Result<()> {
        let l = Layout::new();
        assert_eq!(l.get_stripe_count()?, LLAPI_LAYOUT_DEFAULT);
        assert_eq!(l.get_stripe_size()?, LLAPI_LAYOUT_DEFAULT);
        assert_eq!(l.get_stripe_pattern()?, LLAPI_LAYOUT_DEFAULT);
        assert_eq!(l.get_pool_name()?, "");
        assert_eq!(l.get_comp_extent()?, (0, LUSTRE_EOF as u64));
        assert_eq!(l.get_comp_id()?, 0);
        assert_eq!(l.get_flags()?, 0);
        Ok(())
    }

    #[test]
    fn test_flags() -> Result<()> {
        let l = Layout::new();
        l.flags(LCME_FL_EXTENSION)?;
        assert_eq!(l.get_flags()?, LCME_FL_EXTENSION);
        Ok(())
    }
}
