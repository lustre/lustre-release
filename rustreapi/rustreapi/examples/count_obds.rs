// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Example program demonstrating how to use ost_count and mdt_count functions

use rustreapi::{LustrePath, get_lov_uuids, ost_count};
use std::{env, process};

#[cfg(feature = "LUSTRE_2_14")]
use rustreapi::{get_lmv_uuids, mdt_count};

fn main() {
    // Get Lustre path from command line or use default
    let path = env::args().nth(1).unwrap_or_else(|| {
        println!("Usage: count_obds <lustre_path>");
        println!("Using default path: /mnt/lustre");
        "/mnt/lustre".to_string()
    });

    // Parse the path as a LustrePath
    let lustre_path = match LustrePath::parse(&path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {path} is not a valid Lustre path: {e}");
            process::exit(1);
        }
    };

    // Get OST and MDT counts
    match ost_count(&lustre_path) {
        Ok(count) => println!("OST count: {count}"),
        Err(e) => eprintln!("Error getting OST count: {e}"),
    }

    match get_lov_uuids(&lustre_path) {
        Ok(uuids) => {
            println!("LOV UUIDs:");
            for uuid in uuids {
                println!("{uuid}");
            }
        }
        Err(e) => eprintln!("Error getting LOV UUIDs: {e}"),
    }

    #[cfg(feature = "LUSTRE_2_14")]
    match mdt_count(&lustre_path) {
        Ok(count) => println!("MDT count: {count}"),
        Err(e) => eprintln!("Error getting MDT count: {e}"),
    }

    #[cfg(feature = "LUSTRE_2_14")]
    match get_lmv_uuids(&lustre_path) {
        Ok(uuids) => {
            println!("LMV UUIDs:");
            for uuid in uuids {
                println!("{uuid}");
            }
        }
        Err(e) => eprintln!("Error getting LOV UUIDs: {e}"),
    }
}
