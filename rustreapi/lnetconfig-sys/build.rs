// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

fn main() {
    use std::path::Path;

    if !cfg!(target_os = "linux") {
        println!(r#"cargo::error="This crate is only supported on Linux""#);
        return;
    }

    lu_version::export_features().expect("Failed to export features");

    println!("cargo::rustc-link-lib=lnetconfig");
    println!("cargo:rerun-if-changed=wrapper.h");

    let out_dir = std::env::var_os("OUT_DIR").expect("Failed to get OUT_DIR");
    let out_file = Path::new(&out_dir).join("bindings.rs");

    let binding_temp_dir = std::env::temp_dir().join("bindgen");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .constified_enum_module("boolean")
        .derive_default(true)
        .derive_eq(true)
        .derive_partialeq(true)
        .wrap_static_fns(true)
        .wrap_static_fns_path(binding_temp_dir.join("lnetconfig_extern"))
        // Changelog types and structures.
        .allowlist_type("lnet_nid_t")
        .allowlist_type("lnet_nid")
        // Changelog enums
        // Changelog API functions
        // Inline functions
        .allowlist_function("libcfs_nid2str_r")
        .allowlist_function("libcfs_str2nid")
        .allowlist_function("libcfs_nidstr_r")
        .allowlist_function("libcfs_strnid")
        // Constants
        .prepend_enum_name(false)
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_file)
        .expect("Couldn't write bindings!");

    // Compile the generated extern.c file for wrapped static functions
    let extern_c_path = binding_temp_dir.join("lnetconfig_extern.c");
    if extern_c_path.exists() {
        cc::Build::new()
            .file(extern_c_path)
            .include(".") // Add current directory to include path for wrapper.h
            .compile("lnetconfig_extern");
    }
}
