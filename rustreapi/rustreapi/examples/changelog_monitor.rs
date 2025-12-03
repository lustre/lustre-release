// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use chrono::{DateTime, Utc};
use clap::Parser;
use rustreapi::{
    LustrePath, Record,
    changelog::{
        ChangelogBuilder, ChangelogExtraFlag, ChangelogFlag, ChangelogReader, RecordConverter,
        RecordConverterBuilder, TimeFormat,
    },
};
use serde::{Deserialize, Serialize};
use std::{thread, time::Duration};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Monitor Lustre changelog records from multiple MDTs and output as JSON
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Lustre filesystem name
    #[arg(short, long)]
    fsname: String,

    /// List of MDT indices to monitor (e.g., 0,1,2). If not specified, defaults to MDT0 only.
    #[arg(short, long, value_delimiter = ',')]
    mdts: Option<Vec<u32>>,

    /// Starting record index (default: 0 for latest)
    #[arg(short, long, default_value = "0")]
    start_record: i64,

    /// Enable follow mode to continue monitoring for new records
    #[arg(short = 'F', long, default_value = "false")]
    follow: bool,

    /// Enable blocking mode when no records are available
    #[arg(short, long, default_value = "false")]
    block: bool,

    /// Disable job ID information in records (enabled by default)
    #[arg(long, default_value = "false")]
    no_jobid: bool,

    /// Disable UID/GID information in records (enabled by default)
    #[arg(long, default_value = "false")]
    no_uidgid: bool,

    /// Include client NID information in records
    #[arg(short, long, default_value = "false")]
    no_nid: bool,

    /// Include open mode information in records
    #[arg(short, long, default_value = "false")]
    openmode: bool,

    /// Include extended attribute information in records
    #[arg(short, long, default_value = "false")]
    xattr: bool,

    /// Maximum number of records to process before exiting (0 = unlimited)
    #[arg(short = 'c', long, default_value = "0")]
    count: u64,

    /// Verbose output for debugging
    #[arg(short, long, default_value = "false")]
    verbose: bool,

    /// Time format for timestamps: `"unix"` (default), `"local"`, `"utc"`
    #[arg(long, default_value = "unix", value_parser = ["unix", "local", "utc"])]
    time_format: String,

    /// Resolve parent paths for FIDs (requires Lustre mount access)
    #[arg(short, long, default_value = "false")]
    resolve_parent: bool,
}

/// A changelog record with its source MDT information
#[derive(Debug, Serialize, Deserialize)]
struct ChangelogOutput {
    /// The MDT device name this record came from
    mdt: String,
    /// The actual changelog record
    record: Record,
    /// Timestamp when this record was processed
    timestamp: DateTime<Utc>,
}

/// Reader state for a single MDT
struct MdtReader {
    device: String,
    reader: ChangelogReader,
    converter: RecordConverter,
}

impl MdtReader {
    fn new(fsname: &str, mdt_index: u32, args: &Args) -> Result<Self> {
        let device = format!("{}-MDT{:04x}", fsname, mdt_index);

        if args.verbose {
            eprintln!("Connecting to MDT device: {}", device);
        }

        // Build changelog flags - always set essential flags for proper operation
        let mut flags = ChangelogFlag::ExtraFlags;

        // Include JobId unless explicitly disabled
        if !args.no_jobid {
            flags |= ChangelogFlag::JobId;
        }

        if args.follow {
            flags |= ChangelogFlag::Follow;
        }
        if args.block {
            flags |= ChangelogFlag::Block;
        }

        // Build extra flags - include UID/GID by default unless disabled
        let mut extra_flags = ChangelogExtraFlag::none();
        if !args.no_uidgid {
            extra_flags |= ChangelogExtraFlag::UidGid;
        }

        if !args.no_nid {
            extra_flags |= ChangelogExtraFlag::Nid;
        }
        if args.openmode {
            extra_flags |= ChangelogExtraFlag::OpenMode;
        }
        if args.xattr {
            extra_flags |= ChangelogExtraFlag::Xattr;
        }

        let mut builder = ChangelogBuilder::new()
            .device(&device)
            .flags(flags)
            .start_record(args.start_record);

        if extra_flags.bits() != 0 {
            builder = builder.extra_flags(extra_flags);
        }

        let reader = builder
            .connect()
            .map_err(|e| format!("Failed to connect to {}: {}", device, e))?;

        // Try to get Lustre mount point for FID path resolution
        let mut converter_builder = RecordConverterBuilder::new();

        // Configure time format based on arguments
        let time_format = match args.time_format.as_str() {
            "local" => TimeFormat::Iso8601Local,
            "utc" => TimeFormat::Iso8601Utc,
            "unix" => TimeFormat::Unix,
            _ => {
                return Err(format!(
                    "Invalid time format '{}'. Valid options are: unix, local, utc",
                    args.time_format
                )
                .into());
            }
        };
        converter_builder = converter_builder.time_format(time_format);

        match LustrePath::find_mount_by_fsname(fsname) {
            Ok(lustre_path) => {
                if args.verbose {
                    eprintln!("Found Lustre mount at: {}", lustre_path);
                }
                match lustre_path.open() {
                    Ok(fd) => {
                        converter_builder = converter_builder.lustre_fd(fd);
                    }
                    Err(e) => {
                        if args.verbose {
                            eprintln!("Could not open Lustre mount: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                if args.verbose {
                    eprintln!("Could not find Lustre mount for {}: {}", fsname, e);
                }
            }
        }

        let converter = converter_builder.build();

        if args.verbose {
            eprintln!("Successfully connected to {}", device);
        }

        Ok(Self {
            device,
            reader,
            converter,
        })
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Default to MDT0 if no MDTs specified
    let mdts = args.mdts.clone().unwrap_or_else(|| vec![0]);

    if args.verbose {
        eprintln!("Starting changelog monitor for filesystem: {}", args.fsname);
        eprintln!("Monitoring MDTs: {:?}", mdts);
    }

    // For this example, we'll monitor MDTs sequentially
    // In a production implementation, you'd want parallel monitoring
    let mut readers = Vec::new();

    for &mdt_index in &mdts {
        match MdtReader::new(&args.fsname, mdt_index, &args) {
            Ok(reader) => {
                readers.push(reader);
            }
            Err(e) => {
                if args.verbose {
                    eprintln!("Warning: Failed to connect to MDT{:04x}: {}", mdt_index, e);
                } else if mdts.len() == 1 {
                    // If only one MDT was specified and it failed, that's an error
                    eprintln!(
                        "Failed to connect to {}-MDT{:04x}: {}",
                        args.fsname, mdt_index, e
                    );
                } else {
                    // Multiple MDTs specified, just note which ones failed
                    eprintln!(
                        "Warning: {}-MDT{:04x} has no changelog consumer",
                        args.fsname, mdt_index
                    );
                }
                // Propagate the error - don't continue with other MDTs
                return Err(e);
            }
        }
    }

    if readers.is_empty() {
        return Err("No MDTs could be connected".into());
    }

    if args.verbose {
        eprintln!("Successfully connected to {} MDTs", readers.len());
    }

    // Monitor records from all readers
    let mut total_records = 0u64;
    let start_time = Utc::now();

    loop {
        let mut any_activity = false;

        for mdt_reader in &readers {
            // Try to get a record from this MDT
            match mdt_reader.reader.recv_with_converter(&mdt_reader.converter) {
                Ok(Some(record)) => {
                    any_activity = true;
                    total_records += 1;

                    let output = ChangelogOutput {
                        mdt: mdt_reader.device.clone(),
                        record,
                        timestamp: Utc::now(),
                    };

                    // Output as JSON
                    match serde_json::to_string(&output) {
                        Ok(json) => println!("{}", json),
                        Err(e) => {
                            eprintln!("Failed to serialize record to JSON: {}", e);
                        }
                    }

                    // Check if we've hit the record limit
                    if args.count > 0 && total_records >= args.count {
                        if args.verbose {
                            eprintln!("Reached record limit of {}", args.count);
                        }
                        return Ok(());
                    }
                }
                Ok(None) => {
                    // No records available from this MDT
                }
                Err(e) => {
                    if args.verbose {
                        eprintln!("Error reading from {}: {}", mdt_reader.device, e);
                    }
                    // For non-verbose mode, we'll skip logging repeated errors
                    // since they're likely due to the MDT not having a changelog consumer
                }
            }
        }

        // If we're not following and no activity, exit
        if !args.follow && !any_activity {
            if args.verbose {
                eprintln!("No more records available, exiting");
            }
            break;
        }

        // If no activity and we're following, sleep briefly to avoid busy waiting
        if !any_activity {
            thread::sleep(Duration::from_millis(100));
        }
    }

    if args.verbose {
        let duration = Utc::now().signed_duration_since(start_time).num_seconds();
        eprintln!(
            "Processed {} records in {} seconds",
            total_records, duration
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_parsing() {
        // Test basic argument parsing
        let args = Args::parse_from(["changelog_monitor", "--fsname", "lustre", "--mdts", "0,1,2"]);

        assert_eq!(args.fsname, "lustre");
        assert_eq!(args.mdts, Some(vec![0, 1, 2]));
        assert_eq!(args.start_record, 0);
        assert!(!args.follow);
    }

    #[test]
    fn test_args_with_flags() {
        let args = Args::parse_from([
            "changelog_monitor",
            "--fsname",
            "test",
            "--mdts",
            "0",
            "--follow",
            "--block",
            "--no-jobid",
            "--no-uidgid",
            "--count",
            "100",
            "--time-format",
            "local",
        ]);

        assert_eq!(args.fsname, "test");
        assert_eq!(args.mdts, Some(vec![0]));
        assert!(args.follow);
        assert!(args.block);
        assert!(args.no_jobid);
        assert!(args.no_uidgid);
        assert_eq!(args.count, 100);
        assert_eq!(args.time_format, "local");
    }

    #[test]
    fn test_args_default_mdt() {
        // Test that default behavior works without specifying MDTs
        let args = Args::parse_from(["changelog_monitor", "--fsname", "lustre"]);

        assert_eq!(args.fsname, "lustre");
        assert_eq!(args.mdts, None); // Should default to None, then be converted to vec![0]
        assert_eq!(args.start_record, 0);
        assert!(!args.follow);
        assert_eq!(args.time_format, "unix"); // Should default to unix
    }

    #[test]
    fn test_time_format_options() {
        let args_unix = Args::parse_from([
            "changelog_monitor",
            "--fsname",
            "lustre",
            "--time-format",
            "unix",
        ]);
        assert_eq!(args_unix.time_format, "unix");

        let args_local = Args::parse_from([
            "changelog_monitor",
            "--fsname",
            "lustre",
            "--time-format",
            "local",
        ]);
        assert_eq!(args_local.time_format, "local");

        let args_utc = Args::parse_from([
            "changelog_monitor",
            "--fsname",
            "lustre",
            "--time-format",
            "utc",
        ]);
        assert_eq!(args_utc.time_format, "utc");
    }
}
