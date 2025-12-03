// SPDX-License-Identifier: MIT

// Copyright (c) 2025. DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use crate::{Error, error::cvt_null_mut_m};
use cstrbuf::CStrBuf;
use lnetconfig_sys::{__kernel_size_t, libcfs_nid2str_r, lnet_nid_t};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt::Display;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SimpleNid(lnet_nid_t);

impl SimpleNid {
    pub fn new(nid: lnet_nid_t) -> Self {
        SimpleNid(nid)
    }
}

impl Display for SimpleNid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match nid2str(self.0) {
            Ok(s) => write!(f, "{}", s),
            Err(_) => write!(f, "<invalid nid>"),
        }
    }
}

impl Serialize for SimpleNid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match nid2str(self.0) {
            Ok(s) => serializer.serialize_str(&s),
            Err(_) => serializer.serialize_str("<invalid nid>"),
        }
    }
}

impl<'de> Deserialize<'de> for SimpleNid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match str2nid(&s) {
            Ok(nid) => Ok(SimpleNid::new(nid)),
            Err(_) => Err(serde::de::Error::custom("invalid nid string")),
        }
    }
}

fn nid2str(nid: lnet_nid_t) -> crate::Result<String> {
    let mut buf = CStrBuf::new(64);
    let _res = unsafe {
        cvt_null_mut_m(
            libcfs_nid2str_r(nid, buf.as_mut_ptr(), buf.buffer_len() as __kernel_size_t),
            "libcfs_nid2str".to_string(),
        )
    }?;

    buf.into_string().map_err(Error::IntoString)
}

fn str2nid(s: &str) -> crate::Result<lnet_nid_t> {
    let cstr = std::ffi::CString::new(s).map_err(Error::StringConversion)?;
    let nid = unsafe { lnetconfig_sys::libcfs_str2nid(cstr.as_ptr()) };

    Ok(nid)
}

#[cfg(test)]
mod test {
    use super::nid2str;
    use lnetconfig_sys::lnet_nid_t;
    #[test]
    fn test_nid2str() {
        let nid: lnet_nid_t = 2533274790395904;
        let nid_str = nid2str(nid).unwrap();
        insta::assert_debug_snapshot!(nid_str, @r#""0@lo""#);
    }
}
