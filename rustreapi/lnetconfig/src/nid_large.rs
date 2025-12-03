// SPDX-License-Identifier: MIT

// Copyright (c) 2025. DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use crate::{Error, error::cvt_null_mut_m};
use cstrbuf::CStrBuf;
use lnetconfig_sys::{__kernel_size_t, libcfs_nidstr_r, libcfs_strnid, lnet_nid};
use nix::errno::Errno;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Display;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LargeNid(lnet_nid);

impl LargeNid {
    pub fn new(nid: lnet_nid) -> Self {
        LargeNid(nid)
    }
}

impl Display for LargeNid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match nidstr(&self.0) {
            Ok(s) => write!(f, "{}", s),
            Err(_) => write!(f, "<invalid extended nid>"),
        }
    }
}

impl Serialize for LargeNid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match nidstr(&self.0) {
            Ok(s) => serializer.serialize_str(&s),
            Err(_) => serializer.serialize_str("<invalid extended nid>"),
        }
    }
}

impl<'de> Deserialize<'de> for LargeNid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match strnid(&s) {
            Ok(nid) => Ok(LargeNid(nid)),
            Err(_) => Err(serde::de::Error::custom("invalid extended nid string")),
        }
    }
}

fn nidstr(nid: &lnet_nid) -> crate::Result<String> {
    let mut buf = CStrBuf::new(64);
    let _res = unsafe {
        cvt_null_mut_m(
            libcfs_nidstr_r(nid, buf.as_mut_ptr(), buf.buffer_len() as __kernel_size_t),
            "libcfs_nidstr".to_string(),
        )
    }?;

    buf.into_string().map_err(Error::IntoString)
}

fn strnid(s: &str) -> crate::Result<lnet_nid> {
    let cstr = std::ffi::CString::new(s).map_err(Error::StringConversion)?;
    let mut nid = lnet_nid::default();
    let res = unsafe { libcfs_strnid(&mut nid, cstr.as_ptr()) };
    if res < 0 {
        return Err(Error::NidConversion(Errno::from_raw(-res)));
    }
    Ok(nid)
}

#[cfg(test)]
mod test {
    use super::nidstr;
    use lnetconfig_sys::lnet_nid;

    #[test]
    fn test_nidstr_invalid() {
        let nid = lnet_nid::default();
        let nid_str = nidstr(&nid).unwrap();
        insta::assert_debug_snapshot!(nid_str, @r#""0@<0:0>""#);
    }
}
