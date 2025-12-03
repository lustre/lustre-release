// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

#![allow(nonstandard_style)]

#[cfg(target_os = "linux")]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(target_os = "linux")]
pub type lstat_t = libc::stat64;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    #[cfg(feature = "LUSTRE_2_16")]
    pub fn llapi_LAYOUT_WIDE_MIN() -> libc::c_ulong;

    #[cfg(feature = "LUSTRE_2_16")]
    pub fn llapi_LAYOUT_WIDE_MAX() -> libc::c_ulong;

    #[cfg(feature = "LUSTRE_2_16")]
    pub fn llapi_OVERSTRIPE_COUNT_MIN() -> libc::c_ulong;

    #[cfg(feature = "LUSTRE_2_16")]
    pub fn llapi_OVERSTRIPE_COUNT_MAX() -> libc::c_ulong;

    pub fn llapi_O_LOV_DELAY_CREATE() -> libc::c_int;

    pub fn hai_first__extern(hal: *const hsm_action_list) -> *const hsm_action_item;
    pub fn hai_next__extern(hal: *const hsm_action_item) -> *const hsm_action_item;

    pub fn hal_size__extern(hal: *const hsm_action_list) -> libc::c_ulong;
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        unsafe {
            #[cfg(feature = "LUSTRE_2_16")]
            assert_eq!(llapi_LAYOUT_WIDE_MIN(), 0x1000000000000003);

            #[cfg(feature = "LUSTRE_2_16")]
            assert_eq!(llapi_LAYOUT_WIDE_MAX(), 0x1000000000000022);

            #[cfg(feature = "LUSTRE_2_16")]
            assert_eq!(llapi_OVERSTRIPE_COUNT_MIN(), 0xffffffffffffffff);
            #[cfg(feature = "LUSTRE_2_16")]
            assert_eq!(llapi_OVERSTRIPE_COUNT_MAX(), 0xffffffffffffffe0);

            assert!((llapi_O_LOV_DELAY_CREATE() | 0x2100) == 0x2100);
        }
    }
}
