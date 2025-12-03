// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use std::process::Command;

#[derive(Debug)]
pub struct LustreVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub extra: String,
}

impl LustreVersion {
    fn features(self) {
        assert_eq!(self.major, 2);
        if self.minor < 14 {
            println!(
                "cargo:error=Unsupported Lustre version: minor version must be >= 14, but found {}",
                self.minor
            );
            return;
        }
        if self.minor >= 14 {
            println!(r#"cargo:rustc-cfg=feature="LUSTRE_{}_14""#, self.major);
        }
        if self.minor >= 15 {
            println!(r#"cargo:rustc-cfg=feature="LUSTRE_{}_15""#, self.major);
        }
        if self.minor >= 16 {
            println!(r#"cargo:rustc-cfg=feature="LUSTRE_{}_16""#, self.major);
        }
        if self.minor >= 17 {
            println!(r#"cargo:rustc-cfg=feature="LUSTRE_{}_17""#, self.major);
        }
        if self.minor >= 18 {
            println!(r#"cargo:rustc-cfg=feature="LUSTRE_{}_18""#, self.major);
        }

        if self.patch >= 50 {
            println!(
                r#"cargo:rustc-cfg=feature="LUSTRE_{}_{}""#,
                self.major,
                self.minor + 1
            );
        }
    }
}

pub fn export_features() -> Result<(), String> {
    current()
        .map_err(|e| format!("failed to get Lustre version: {e}"))?
        .features();

    Ok(())
}

/// Detects the installed Lustre filesystem version.
///
/// This function executes the `lfs --version` command and parses the output
/// to extract the major, minor, and patch version numbers of the installed
/// Lustre client.
///
/// # Returns
///
/// A `Result` containing:
/// - `Ok(LustreVersion)`: A struct with major, minor, patch version numbers and extra info if successful
/// - `Err(String)`: An error message describing what went wrong
///
/// # Errors
///
/// Returns an error string in the following cases:
/// - If the Lustre client tools are not installed or the command execution fails
/// - If the version string output doesn't match the expected format
/// - If any version component cannot be parsed as a `u32` number
///
/// # Examples
///
/// ```
/// let version = lu_version::current().expect("should be able to detect Lustre version");
/// println!("Detected Lustre version {}.{}.{}", version.major, version.minor, version.patch);
/// ```
pub fn current() -> Result<LustreVersion, String> {
    let output = Command::new("lfs")
        .arg("--version")
        .output()
        .map_err(|e| format!("lustre client tools should be installed: {e}"))?;

    let s = String::from_utf8_lossy(output.stdout.as_ref());
    let s = s.trim();
    let s = if s.contains("lfs ") { &s[4..] } else { s };

    parse_version(s)
}

fn parse_version(s: &str) -> Result<LustreVersion, String> {
    let re =
        regex::Regex::new(r"^(?<major>[0-9]+)\.(?<minor>[0-9]+)\.(?<patch>[0-9]+)_?(?<extra>.*)$")
            .expect("regex should compile");

    let Some(caps) = re.captures(s.trim()) else {
        return Err(format!("unexpected output from lfs --version: {s}"));
    };

    let major = caps
        .name("major")
        .ok_or("missing major version")?
        .as_str()
        .parse::<u32>()
        .map_err(|e| format!("error in major: {e}"))?;

    let minor = caps
        .name("minor")
        .ok_or("missing minor version")?
        .as_str()
        .parse::<u32>()
        .map_err(|e| format!("error in minor: {e}"))?;

    let patch = caps
        .name("patch")
        .ok_or("missing patch version")?
        .as_str()
        .parse::<u32>()
        .map_err(|e| format!("error in patch: {e}"))?;

    let extra = caps
        .name("extra")
        .ok_or("error parsing extra")?
        .as_str()
        .to_string();

    Ok(LustreVersion {
        major,
        minor,
        patch,
        extra,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic() {
        let version = parse_version("1.2.3");
        assert!(version.is_ok(), "Failed to get Lustre version: {version:?}");
        let version = version.unwrap();
        assert_eq!(version.major, 1);
        assert_eq!(version.minor, 2);
        assert_eq!(version.patch, 3);
        assert_eq!(version.extra, "");
    }

    #[test]
    fn test_extra() {
        let version = parse_version("2.16.55_16_g33442e0");
        assert!(version.is_ok(), "Failed to get Lustre version: {version:?}");
        let version = version.unwrap();
        assert_eq!(version.major, 2);
        assert_eq!(version.minor, 16);
        assert_eq!(version.patch, 55);
        assert_eq!(version.extra, "16_g33442e0");
    }
}
