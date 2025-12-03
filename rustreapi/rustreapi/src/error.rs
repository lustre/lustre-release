// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use crate::{LustrePath, Statfs};
use nix::errno::Errno;
use std::{ffi::FromBytesWithNulError, path::Path, result};
use thiserror::Error;

pub type Result<T> = result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Not a Lustre filesystem {0}")]
    NotLustreFileSystem(String),

    #[error("Unable to open root: {0}: {1}")]
    LustreRootOpenError(LustrePath, std::io::Error),

    #[error("Allocation error: {0}")]
    AllocError(String),

    #[error("UTF8 Error: {0}")]
    StringConversionError(#[from] std::string::FromUtf8Error),

    #[error("UTF8 Error: {0}")]
    PathConversionError(#[from] core::str::Utf8Error),

    #[error("Invalid path: {0}")]
    UUIDParseError(#[from] FromBytesWithNulError),

    #[error(transparent)]
    Errno(Errno),

    #[error("{0}: {1}")]
    MsgErrno(String, Errno),

    #[error("parse fid error in {original} '{part}': {err}")]
    ParseFidError {
        original: String,
        part: String,
        err: std::num::ParseIntError,
    },

    #[error("invalid fid format: '{str}'")]
    InvalidFidFormat { str: String },

    #[deprecated]
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    NulError(#[from] std::ffi::NulError),

    #[error("Would block")]
    WouldBlock,

    #[error("Lustre stats error. stat_type: {stat} index: {index} source: {source}")]
    LustreStatfs {
        stat: Statfs,
        index: u32,
        source: Errno,
    },

    #[error("Component {component_type} at index {index} is inactive")]
    ComponentInactive { component_type: Statfs, index: u32 },

    #[error(
        "Insufficient components for filesystem {filesystem}: OST count {ost_count}, total blocks {total_blocks}"
    )]
    InsufficientComponents {
        filesystem: String,
        ost_count: u32,
        total_blocks: u64,
    },

    #[error("Mount search error at index {index}: {errno}")]
    MountSearchError { index: i32, errno: Errno },

    #[error("Invalid path: {path}")]
    InvalidPath { path: Box<Path> },

    #[error("Filesystem '{filesystem}' not found in mounted Lustre filesystems")]
    FilesystemNotFound { filesystem: String },
}

impl From<Error> for std::fmt::Error {
    fn from(_err: Error) -> Self {
        std::fmt::Error
    }
}

/// Converts a negative return value from a lustre function as an `Err` variant.
/// Otherwise, returns the value as an `Ok` variant.
pub(crate) fn cvt_lz(t: libc::c_int) -> Result<i32> {
    if t < 0 {
        Err(Error::Errno(Errno::last()))
    } else {
        Ok(t)
    }
}

/// Converts a negative return value from a lustre function as an `Err` variant.
/// Otherwise, returns the value as an `Ok` variant.
/// Adds a message to the error
pub(crate) fn cvt_lz_m(t: libc::c_int, msg: String) -> Result<i32> {
    if t < 0 {
        Err(Error::MsgErrno(msg, Errno::last()))
    } else {
        Ok(t)
    }
}

/// Converts a non-zero return value from a lustre function as an `Err` variant.
pub(crate) fn cvt_nz(t: libc::c_int) -> Result<()> {
    if t != 0 {
        Err(Error::Errno(Errno::last()))
    } else {
        Ok(())
    }
}

/// Converts a non-zero return value from a lustre function as an `Err` variant.
/// Adds a message to the error
pub(crate) fn cvt_nz_m(t: libc::c_int, msg: String) -> Result<()> {
    if t != 0 {
        Err(Error::MsgErrno(msg, Errno::last()))
    } else {
        Ok(())
    }
}

pub(crate) fn cvt_rc_m(t: libc::c_int, msg: String) -> Result<()> {
    if t < 0 {
        match Errno::from_raw(-t) {
            Errno::EAGAIN => Err(Error::WouldBlock),
            _ => Err(Error::MsgErrno(msg, Errno::from_raw(-t))),
        }
    } else {
        Ok(())
    }
}

pub(crate) fn cvt_null_mut_m<T>(t: *mut T, msg: String) -> Result<*mut T> {
    if t.is_null() {
        Err(Error::MsgErrno(msg, Errno::last()))
    } else {
        Ok(t)
    }
}
