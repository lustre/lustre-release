// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

fn main() {
    if !cfg!(target_os = "linux") {
        println!("cargo::error=This crate is only supported on Linux");
        return;
    }

    lu_version::export_features().expect("Failed to export features");
}
