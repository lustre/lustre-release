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

    println!("cargo:rerun-if-changed=wrapper.h");

    let out_dir = std::env::var_os("OUT_DIR").expect("Failed to get OUT_DIR");
    let out_path = Path::new(&out_dir);
    let out_file = out_path.join("bindings.rs");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .constified_enum_module("boolean")
        .derive_default(true)
        .derive_eq(true)
        .derive_partialeq(true)
        .wrap_static_fns(true)
        .wrap_static_fns_path(out_path.join("changelog_extern"))
        // Changelog types and structures.
        .allowlist_type("changelog_rec")
        .allowlist_type("changelog_ext_rename")
        .allowlist_type("changelog_ext_jobid")
        .allowlist_type("changelog_ext_extra_flags")
        .allowlist_type("changelog_ext_uidgid")
        .allowlist_type("changelog_ext_nid")
        .allowlist_type("changelog_ext_openmode")
        .allowlist_type("changelog_ext_xattr")
        // Changelog enums
        .allowlist_type("changelog_rec_type")
        .allowlist_type("changelog_rec_flags")
        .allowlist_type("changelog_rec_extra_flags")
        .allowlist_type("changelog_send_flag")
        .allowlist_type("changelog_send_extra_flag")
        // Changelog API functions
        .allowlist_function("llapi_changelog_start")
        .allowlist_function("llapi_changelog_fini")
        .allowlist_function("llapi_changelog_recv")
        .allowlist_function("llapi_changelog_in_buf")
        .allowlist_function("llapi_changelog_free")
        .allowlist_function("llapi_changelog_get_fd")
        .allowlist_function("llapi_changelog_clear")
        .allowlist_function("llapi_changelog_set_xflags")
        .allowlist_function("llapi_changelog_repack_rec")
        // Inline functions
        .allowlist_function("changelog_type2str")
        .allowlist_function("changelog_rec_offset")
        .allowlist_function("changelog_rec_size")
        .allowlist_function("changelog_rec_varsize")
        .allowlist_function("changelog_rec_name")
        .allowlist_function("changelog_rec_sname")
        .allowlist_function("changelog_rec_snamelen")
        .allowlist_function("changelog_remap_rec")
        .allowlist_function("changelog_rec_rename")
        .allowlist_function("changelog_rec_jobid")
        .allowlist_function("changelog_rec_extra_flags")
        .allowlist_function("changelog_rec_uidgid")
        .allowlist_function("changelog_rec_nid")
        .allowlist_function("changelog_rec_openmode")
        .allowlist_function("changelog_rec_xattr")
        // HSM changelog helper functions
        .allowlist_function("hsm_set_cl_event")
        .allowlist_function("hsm_get_cl_flags")
        .allowlist_function("hsm_set_cl_flags")
        .allowlist_function("hsm_get_cl_error")
        .allowlist_function("hsm_set_cl_error")
        // Constants
        .allowlist_var("CL_.*")
        .allowlist_var("CLF_.*")
        .allowlist_var("CLFE_.*")
        .allowlist_var("CHANGELOG_.*")
        .prepend_enum_name(false)
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_file)
        .expect("Couldn't write bindings!");

    // Compile the generated extern.c file for wrapped static functions
    let extern_c_path = out_path.join("changelog_extern.c");
    if extern_c_path.exists() {
        cc::Build::new()
            .file(extern_c_path)
            .include(".") // Add current directory to include path for wrapper.h
            .compile("changelog_extern");
    }
}
