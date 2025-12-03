// SPDX-License-Identifier: MIT

// Copyright (c) 2025. DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

mod error;
mod nid;

pub use error::{Error, Result};
pub use lnetconfig_sys::lnet_nid_t;
pub use nid::SimpleNid;

#[cfg(feature = "LUSTRE_2_16")]
mod nid_large;

#[cfg(feature = "LUSTRE_2_16")]
pub use nid_large::LargeNid;

#[cfg(feature = "LUSTRE_2_16")]
pub use lnetconfig_sys::lnet_nid;
