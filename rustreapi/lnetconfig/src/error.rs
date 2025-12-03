// SPDX-License-Identifier: MIT

// Copyright (c) 2025. DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use nix::errno::Errno;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}: {1}")]
    MsgErrno(String, Errno),

    #[error("Nul Error: {0}")]
    StringConversion(#[from] std::ffi::NulError),

    #[error("UTF8 Error: {0}")]
    IntoString(#[from] std::string::FromUtf8Error),

    #[error("NID Conversion Error: {0}")]
    NidConversion(Errno),
}

pub(crate) fn cvt_null_mut_m<T>(t: *mut T, msg: String) -> Result<*mut T> {
    if t.is_null() {
        Err(Error::MsgErrno(msg, Errno::last()))
    } else {
        Ok(t)
    }
}
