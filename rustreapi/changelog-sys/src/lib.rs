// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

#![allow(nonstandard_style)]
#![cfg(target_os = "linux")]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_changelog_types_exist() {
        // Just verify that the types are available
        let _size = std::mem::size_of::<changelog_rec>();
        assert!(_size > 0);
    }

    #[test]
    fn test_inline_functions_accessible() {
        unsafe {
            // Test that changelog_type2str is accessible
            let type_str = changelog_type2str(CL_CREATE);
            assert!(!type_str.is_null());

            // Test changelog_rec_offset with valid flags
            let offset = changelog_rec_offset(0, 0);
            assert!(offset >= std::mem::size_of::<changelog_rec>() as u64);

            // These functions are now accessible through bindgen's wrap_static_fns
            // The actual function names don't have _wrapper suffix anymore
        }
    }
}
