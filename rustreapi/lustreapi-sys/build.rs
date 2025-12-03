// SPDX-License-Identifier: MIT

// Copyright (c) 2024-2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

fn main() {
    use std::path::Path;

    if !cfg!(target_os = "linux") {
        println!(r#"cargo::error="This crate is only supported on Linux""#);
        return;
    }

    lu_version::export_features().expect("Failed to export features");

    println!("cargo::rustc-link-lib=lustreapi");
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=src/wrapper.c");
    println!("cargo:rerun-if-changed=src/bindings.rs");

    cc::Build::new()
        .file("src/wrapper.c")
        .include(".")
        .compile("wrapper");

    let out_dir = std::env::var_os("OUT_DIR").expect("Failed to get OUT_DIR");
    let out_file = Path::new(&out_dir).join("bindings.rs");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .constified_enum_module("boolean")
        .derive_default(true)
        // not sure if safe to allow these for all, but needed for external use of mount data
        .derive_eq(true)
        .derive_partialeq(true)
        // .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // .wrap_static_fns(true)
        // FID
        .allowlist_type("lu_fid")
        .allowlist_type("lov_user_mds_data_v1")
        .allowlist_type("fid_array")
        .allowlist_var("OBD_MAX_FIDS_IN_ARRAY")
        .allowlist_var("LUSTRE_MAXFSNAME")
        .allowlist_function("llapi_fd2fid")
        .allowlist_function("llapi_path2fid")
        .allowlist_function("llapi_fid_parse")
        .allowlist_function("llapi_open_by_fid_at")
        .allowlist_function("llapi_get_fsname")
        .allowlist_function("llapi_fid2path_at")
        /* Layout */
        .allowlist_item("LLAPI_LAYOUT_.*")
        .allowlist_item("LLAPI_OVERSTRIPE_.*")
        .allowlist_item("LL_STATFS_LMV")
        .allowlist_item("LL_STATFS_LOV")
        .allowlist_item("lov_comp_md_entry_flags")
        .allowlist_item("lcme_id")
        .allowlist_item("lov_comp_md_flags")
        .allowlist_item("LOV_MAX_STRIPE_COUNT")
        .allowlist_item("LOV_ALL_STRIPES.*")
        .allowlist_item("LUSTRE_EOF")
        .constified_enum("llapi_layout_comp_use")
        .allowlist_function("llapi_file_open_param")
        .allowlist_function("llapi_file_fget_mdtidx")
        .allowlist_function("llapi_layout.*")
        .allowlist_function("llapi_create_volatile_param")
        // HSM
        .allowlist_function("llapi_hsm.*")
        .allowlist_var("HSM_REQ_BLOCKING")
        .allowlist_item("hsm_states")
        .allowlist_item("hsm_copytool_action")
        .allowlist_item("hsm_mover_.*")
        .allowlist_item("hsm_user_action")
        .allowlist_item("hsm_progress_states")
        .allowlist_item("HP_FLAG_.*")
        .blocklist_type("lstat_t")
        // Mount data
        .allowlist_function("llapi_search_mounts")
        .allowlist_function("llapi_obd_fstatfs")
        // Misc
        .allowlist_item("llapi_get_obd_count")
        .allowlist_item("llapi_lov_get_uuids")
        .allowlist_item("llapi_lmv_get_uuids")
        .wrap_unsafe_ops(true)
        .prepend_enum_name(false)
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_file)
        .expect("Couldn't write bindings!");
    // handle statics

    //     let obj_path = output_path.join("extern.o");
    //     let lib_path = output_path.join("libextern.a");
    //     cc::Build::new()
    //         .file(std::env::temp_dir().join("bindgen").join("extern.c"))
    //         .include(".")
    //         .compile("extern");
}
