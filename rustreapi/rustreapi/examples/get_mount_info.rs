// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use rustreapi::MountStats;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mounts = MountStats::discover_mounts()?;

    for mount in &mounts {
        println!("Mount: {}", mount.info.mount_point.display());
        let stats = &mount.stats;
        println!("  Available space: {} bytes", stats.bavail * stats.bsize);
        if let Some(inodes) = &stats.inodes {
            println!("  Available inodes: {}", inodes.favail);
        }
    }

    Ok(())
}
