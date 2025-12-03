// SPDX-License-Identifier: MIT

// Copyright (c) 2025. DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//! A buffer type for safe interaction with C string APIs.
//!
//! This module provides [`CStrBuf`], a wrapper around a byte vector designed for
//! passing string buffers to C functions that expect `char*` pointers. It handles
//! the common pattern of allocating a buffer, passing it to C code that writes a
//! null-terminated string into it, and then converting the result back to Rust
//! string types.
//!
//! Based on the approach described at:
//! <https://dean.serenevy.net/blog/2021/Feb/c-string-buffers/>
//!
//! # Example
//!
//! ```
//! use cstrbuf::CStrBuf;
//!
//! // Create a buffer for C functions to write into
//! let mut buf = CStrBuf::new(256);
//!
//! // Pass to C function: some_c_function(buf.as_mut_ptr(), buf.buffer_len());
//!
//! // Convert the result to a Rust string
//! let result = buf.to_string().expect("valid UTF-8");
//! ```

use memchr::memchr;
use std::{
    ffi::{CString, NulError, OsStr, c_char},
    os::unix::ffi::OsStrExt,
    path::Path,
    str::FromStr,
};

/// A buffer for C string interoperability.
///
/// `CStrBuf` provides a safe way to allocate buffers that can be passed to C
/// functions expecting `char*` pointers. The buffer tracks its total capacity
/// and can determine the length of any null-terminated string written into it.
pub struct CStrBuf {
    vec: Vec<u8>,
}

impl CStrBuf {
    /// Creates a new buffer of the specified length, initialized to zeros.
    ///
    /// The buffer will contain `len` bytes, all set to 0.
    pub fn new(len: usize) -> Self {
        CStrBuf { vec: vec![0; len] }
    }

    /// Fills the entire buffer with the specified byte value.
    ///
    /// Returns a mutable reference to self for method chaining.
    pub fn fill(&mut self, fill: u8) -> &mut Self {
        self.vec.fill(fill);
        self
    }

    /// Returns a `const` pointer to the buffer for passing to C functions.
    ///
    /// The pointer is valid for the lifetime of the `CStrBuf`.
    pub fn as_ptr(&self) -> *const c_char {
        self.vec.as_ptr() as *const c_char
    }

    /// Returns a mutable pointer to the buffer for passing to C functions.
    ///
    /// The pointer is valid for the lifetime of the `CStrBuf`.
    pub fn as_mut_ptr(&mut self) -> *mut c_char {
        self.vec.as_mut_ptr() as *mut c_char
    }

    /// Returns the total capacity of the buffer in bytes.
    pub fn buffer_len(&self) -> usize {
        self.vec.len()
    }

    /// Returns the length of the null-terminated string in the buffer.
    ///
    /// Scans for the first null byte and returns its index. If no null byte
    /// is found, returns the total buffer length.
    pub fn strlen(&self) -> usize {
        match memchr(0, &self.vec) {
            Some(n) => n,
            None => self.vec.len(),
        }
    }

    /// Consumes the buffer and returns its contents as an owned `String`.
    ///
    /// The string is truncated at the first null byte. Returns an error if
    /// the contents are not valid UTF-8.
    pub fn into_string(mut self) -> Result<String, std::string::FromUtf8Error> {
        let len = self.strlen();
        self.vec.truncate(len);
        String::from_utf8(self.vec)
    }

    /// Returns the buffer contents as an owned `String`.
    ///
    /// The string is truncated at the first null byte. Returns an error if
    /// the contents are not valid UTF-8. Unlike [`into_string`](Self::into_string),
    /// this method clones the data.
    pub fn to_string(&self) -> Result<String, std::string::FromUtf8Error> {
        let len = self.strlen();
        String::from_utf8(self.vec[0..len].to_vec())
    }

    /// Returns the buffer contents as a string slice.
    ///
    /// The slice extends to the first null byte. Returns an error if the
    /// contents are not valid UTF-8.
    pub fn to_str(&self) -> Result<&str, std::str::Utf8Error> {
        let len = self.strlen();
        std::str::from_utf8(&self.vec[0..len])
    }

    /// Returns the buffer contents as an OS string slice.
    ///
    /// The slice extends to the first null byte. On Unix, this is a zero-copy
    /// operation that accepts any byte sequence.
    pub fn to_os_str(&self) -> &OsStr {
        let len = self.strlen();
        OsStr::from_bytes(&self.vec[0..len])
    }

    /// Creates a `CStrBuf` from an OS string.
    ///
    /// Returns an error if the string contains an interior null byte.
    pub fn from_os_str(os_str: &OsStr) -> Result<Self, NulError> {
        let bytes = os_str.as_bytes();
        let cstring = CString::new(bytes.to_vec())?;
        let vec = cstring.into_bytes();
        Ok(Self { vec })
    }

    /// Creates a `CStrBuf` from an owned `String`.
    ///
    /// Returns an error if the string contains an interior null byte.
    pub fn from_string(s: String) -> Result<CStrBuf, NulError> {
        Self::from_str(&s)
    }

    /// Creates a `CStrBuf` from a filesystem path.
    ///
    /// Returns an error if the path contains an interior null byte.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<CStrBuf, NulError> {
        Self::from_os_str(path.as_ref().as_os_str())
    }
}

impl FromStr for CStrBuf {
    type Err = NulError;

    /// Creates a `CStrBuf` from a string slice.
    ///
    /// The buffer will contain the string bytes followed by a null terminator.
    /// Returns an error if the string contains an interior null byte.
    fn from_str(s: &str) -> Result<Self, NulError> {
        let bytes = s.as_bytes();

        let _validation = CString::new(bytes)?;

        let mut vec = Vec::with_capacity(bytes.len() + 1);
        vec.extend_from_slice(bytes);
        vec.push(0); // null terminator

        Ok(Self { vec })
    }
}

impl AsRef<OsStr> for CStrBuf {
    /// Returns the buffer contents as an OS string reference.
    fn as_ref(&self) -> &OsStr {
        self.to_os_str()
    }
}

#[cfg(test)]
mod tests {
    use super::CStrBuf;
    use std::ffi::OsStr;

    #[test]
    fn test_cstrbuf_to_os_str() {
        let mut cbuf = CStrBuf::new(256);
        let s = "hello world";
        let c = s.as_bytes();
        cbuf.vec[0..c.len()].copy_from_slice(c);
        let os_str: &OsStr = cbuf.as_ref();
        assert_eq!(OsStr::new("hello world"), os_str);
    }

    #[test]
    fn test_cstrbuf_to_str() {
        let mut cbuf = CStrBuf::new(256);
        let s = "hello world";
        let c = s.as_bytes();
        cbuf.vec[0..c.len()].copy_from_slice(c);
        assert_eq!(cbuf.strlen(), c.len());
        assert_eq!(cbuf.to_str().expect("String should be valid."), s);
    }

    #[test]
    fn test_cstrbuf_to_string() {
        let mut cbuf = CStrBuf::new(256);
        let s = "hello world";
        let c = s.as_bytes();
        cbuf.vec[0..c.len()].copy_from_slice(c);
        assert_eq!(cbuf.strlen(), c.len());
        assert_eq!(cbuf.to_string().expect("String should be valid."), s);
    }

    #[test]
    fn test_cstrbuf_into_string() {
        let mut cbuf = CStrBuf::new(256);
        let s = "hello world";
        let c = s.as_bytes();
        cbuf.vec[0..c.len()].copy_from_slice(c);
        assert_eq!(cbuf.strlen(), c.len());
        assert_eq!(cbuf.into_string().expect("String should be valid"), s);
    }

    #[test]
    fn test_cstrbuf_as_ptr() {
        let mut cbuf = CStrBuf::new(256);
        let s = "hello world";
        let c = s.as_bytes();
        cbuf.vec[0..c.len()].copy_from_slice(c);
        assert_eq!(cbuf.strlen(), c.len());
        let ptr = cbuf.as_ptr();
        let s2 = unsafe {
            std::ffi::CStr::from_ptr(ptr)
                .to_str()
                .expect("String should be valid.")
        };
        assert_eq!(s2, s);
    }

    #[test]
    fn test_cstrbuf_as_mut_ptr() {
        let mut cbuf = CStrBuf::new(256);
        let s = "hello world";
        let c = s.as_bytes();
        cbuf.vec[0..c.len()].copy_from_slice(c);
        assert_eq!(cbuf.strlen(), c.len());
        let ptr = cbuf.as_mut_ptr();
        let s2 = unsafe {
            std::ffi::CStr::from_ptr(ptr)
                .to_str()
                .expect("String should be valid.")
        };
        assert_eq!(s2, s);
    }

    #[test]
    fn test_cstrbuf_buffer_len() {
        let cbuf = CStrBuf::new(256);
        assert_eq!(cbuf.buffer_len(), 256);
    }

    #[test]
    fn test_cstrbuf_strlen() {
        let mut cbuf = CStrBuf::new(256);
        let s = "hello world";
        let c = s.as_bytes();
        cbuf.vec[0..c.len()].copy_from_slice(c);
        assert_eq!(cbuf.strlen(), c.len());
    }

    #[test]
    fn test_cstrbuf_new() {
        let cbuf = CStrBuf::new(256);
        assert_eq!(cbuf.buffer_len(), 256);
    }
    #[test]
    fn test_cstrbuf_new_0() {
        let cbuf = CStrBuf::new(0);
        assert_eq!(cbuf.buffer_len(), 0);
    }
}
