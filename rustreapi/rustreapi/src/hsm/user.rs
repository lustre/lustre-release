// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use bitmask_enum::bitmask;
use lustreapi_sys::*;
use serde::{Deserialize, Serialize};
use std::{ffi::CString, fmt, fmt::Display, os::fd::AsRawFd, path::Path};

use crate::{
    Fid, Result,
    error::{cvt_null_mut_m, cvt_nz_m, cvt_rc_m},
    hsm::Extent,
};

#[bitmask(u32)]
#[bitmask_config(vec_debug, flags_iter)]
pub enum HsmState {
    // None = HS_NONE, // a flag for 0 doesn't make sense
    Exists = HS_EXISTS,
    Dirty = HS_DIRTY,
    Released = HS_RELEASED,
    Archived = HS_ARCHIVED,
    NoRelease = HS_NORELEASE,
    NoArchive = HS_NOARCHIVE,
    Lost = HS_LOST,
    PCCRW = HS_PCCRW,
    PCCRO = HS_PCCRO,
}
impl Default for HsmState {
    fn default() -> Self {
        HsmState::none()
    }
}

impl Display for HsmState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v: Vec<&str> = HsmState::flags()
            .filter(|&(_, value)| self.contains(*value))
            .map(|(name, _)| *name)
            .collect();

        if v.is_empty() {
            write!(f, "Empty")?;
        } else {
            write!(f, "{}", v.join(", "))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[repr(u32)]
pub enum UserAction {
    Noop = HUA_NONE,
    Archive = HUA_ARCHIVE,
    Restore = HUA_RESTORE,
    Release = HUA_RELEASE,
    Remove = HUA_REMOVE,
    Cancel = HUA_CANCEL,
}

impl From<u32> for UserAction {
    fn from(action: u32) -> Self {
        match action {
            HUA_NONE => UserAction::Noop,
            HUA_ARCHIVE => UserAction::Archive,
            HUA_RESTORE => UserAction::Restore,
            HUA_RELEASE => UserAction::Release,
            HUA_REMOVE => UserAction::Remove,
            HUA_CANCEL => UserAction::Cancel,
            _ => panic!("Invalid UserAction"),
        }
    }
}

impl Display for UserAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[repr(u32)]
pub enum ProgressState {
    Init = HPS_NONE,
    Waiting = HPS_WAITING,
    Running = HPS_RUNNING,
    Done = HPS_DONE,
}

impl From<u32> for ProgressState {
    fn from(state: u32) -> Self {
        match state {
            HPS_NONE => ProgressState::Init,
            HPS_WAITING => ProgressState::Waiting,
            HPS_RUNNING => ProgressState::Running,
            HPS_DONE => ProgressState::Done,
            _ => panic!("Invalid ProgressState"),
        }
    }
}

impl Display for ProgressState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// HSM request flags from LU-18940
///
/// These flags are used in the `hr_flags` field of `hsm_request` to provide
/// additional context about HSM requests, particularly to indicate when an HSM
/// request is blocking an application.
#[bitmask(u64)]
#[bitmask_config(vec_debug, flags_iter)]
#[derive(Serialize, Deserialize)]
pub enum HsmRequestFlags {
    /// Flag indicating HSM request is blocking an application
    /// This occurs when a process opens a released file and triggers an HSM restore
    Blocking = HSM_REQ_BLOCKING as u64,
}

impl Default for HsmRequestFlags {
    fn default() -> Self {
        HsmRequestFlags::none()
    }
}

impl Display for HsmRequestFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v: Vec<&str> = HsmRequestFlags::flags()
            .filter(|&(_, value)| self.contains(*value))
            .map(|(name, _)| *name)
            .collect();

        if v.is_empty() {
            write!(f, "Empty")?;
        } else {
            write!(f, "{}", v.join(", "))?;
        }
        Ok(())
    }
}

/*
    This struct contains the hus and hca fields.
*/
#[derive(Debug)]
pub struct HsmCurrent {
    pub states: HsmState,
    pub archive_id: u32,
    pub progress_state: ProgressState,
    pub action: UserAction,
    pub extent: Extent,
}

impl HsmCurrent {
    pub fn get(path: &Path) -> Result<Self> {
        let mut hus = hsm_user_state::default();
        let mut hca = hsm_current_action::default();
        let cstr = CString::new(path.as_os_str().as_encoded_bytes())?;

        unsafe {
            cvt_rc_m(
                llapi_hsm_state_get(cstr.as_ptr(), &mut hus as *mut hsm_user_state),
                "Failed to get HSM state".to_string(),
            )?;
            cvt_rc_m(
                llapi_hsm_current_action(cstr.as_ptr(), &mut hca as *mut hsm_current_action),
                "Failed to get current action".to_string(),
            )?;

            Ok(HsmCurrent {
                states: HsmState::from(hus.hus_states),
                archive_id: hus.hus_archive_id,
                progress_state: ProgressState::from(hca.hca_state),
                action: UserAction::from(hca.hca_action),
                extent: Extent {
                    offset: hca.hca_location.offset,
                    length: hca.hca_location.length,
                },
            })
        }
    }

    pub fn set(path_buf: &Path, set: HsmState, clear: HsmState, archive_id: u32) -> Result<()> {
        let cstr = CString::new(path_buf.as_os_str().as_encoded_bytes())?;
        unsafe {
            cvt_rc_m(
                llapi_hsm_state_set(
                    cstr.as_ptr(),
                    u64::from(set.bits()),
                    u64::from(clear.bits()),
                    archive_id,
                ),
                "Failed to set HSM state".to_string(),
            )
        }
    }

    pub fn set_fd<Fd: AsRawFd>(
        fd: &Fd,
        set: HsmState,
        clear: HsmState,
        archive_id: u32,
    ) -> Result<()> {
        unsafe {
            cvt_rc_m(
                llapi_hsm_state_set_fd(
                    fd.as_raw_fd(),
                    u64::from(set.bits()),
                    u64::from(clear.bits()),
                    archive_id,
                ),
                "Failed to set HSM state".to_string(),
            )
        }
    }
}

pub fn user_request_alloc<'a>(
    item_count: usize,
    data_len: usize,
) -> Result<&'a mut hsm_user_request> {
    unsafe {
        cvt_null_mut_m(
            llapi_hsm_user_request_alloc(item_count as i32, data_len as i32),
            "Failed to allocate HSM request".to_string(),
        )
        .map(|ptr| &mut (*ptr))
    }
}

pub fn user_request_free(hur: *mut hsm_user_request) {
    unsafe { libc::free(hur as *mut std::ffi::c_void) }
}
fn send_request(
    action: UserAction,
    path: &Path,
    archive_id: u32,
    flags: HsmRequestFlags,
    fids: Vec<Fid>,
) -> Result<()> {
    let hur = user_request_alloc(fids.len(), 0)?;

    hur.hur_request.hr_action = action as u32;
    hur.hur_request.hr_archive_id = archive_id;
    hur.hur_request.hr_flags = flags.bits();
    hur.hur_request.hr_itemcount = fids.len() as u32;
    hur.hur_request.hr_data_len = 0;

    for (i, fid) in fids.iter().enumerate() {
        let hui = unsafe {
            hur.hur_user_item
                .as_mut_slice(fids.len())
                .get_unchecked_mut(i)
        };
        hui.hui_fid = fid.to_lu_fid();
        hui.hui_extent.offset = 0;
        hui.hui_extent.length = LUSTRE_EOF as u64;
    }

    let result = user_request(path, hur);
    user_request_free(hur);

    result
}
pub fn user_request(path: &Path, hur: &hsm_user_request) -> Result<()> {
    let cstr = CString::new(path.as_os_str().as_encoded_bytes())?;
    unsafe {
        cvt_nz_m(
            llapi_hsm_request(cstr.as_ptr(), hur),
            "Failed to send user request".to_string(),
        )
    }
}

pub fn archive<P: AsRef<Path>>(
    path: P,
    archive_id: u32,
    flags: HsmRequestFlags,
    fids: Vec<Fid>,
) -> Result<()> {
    send_request(UserAction::Archive, path.as_ref(), archive_id, flags, fids)
}

pub fn restore<P: AsRef<Path>>(path: P, flags: HsmRequestFlags, fids: Vec<Fid>) -> Result<()> {
    send_request(UserAction::Restore, path.as_ref(), 0, flags, fids)
}

pub fn release<P: AsRef<Path>>(path: &P, flags: HsmRequestFlags, fids: Vec<Fid>) -> Result<()> {
    send_request(UserAction::Release, path.as_ref(), 0, flags, fids)
}

pub fn cancel<P: AsRef<Path>>(path: P, flags: HsmRequestFlags, fids: Vec<Fid>) -> Result<()> {
    send_request(UserAction::Cancel, path.as_ref(), 0, flags, fids)
}

pub fn remove<P: AsRef<Path>>(path: P, flags: HsmRequestFlags, fids: Vec<Fid>) -> Result<()> {
    send_request(UserAction::Remove, path.as_ref(), 0, flags, fids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hsm_states() {
        let mut states = HsmState::default();
        states |= HsmState::Exists | HsmState::Dirty;
        assert_eq!(states.to_string(), "Exists, Dirty");
    }
}
