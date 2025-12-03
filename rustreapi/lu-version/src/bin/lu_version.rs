// SPDX-License-Identifier: MIT

// Copyright (c) 2025. DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

fn main() {
    let version = lu_version::current().expect("should be able to detect Lustre version");
    println!(
        "Detected Lustre version {}.{}.{}",
        version.major, version.minor, version.patch
    );
}
