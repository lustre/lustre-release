// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use libc::off_t;
use lustreapi_sys::LLAPI_LAYOUT_RAID0;
use polling::{Event, Events};
use rand::Rng;
use rustreapi::{Error, Fid, Layout, LayoutGetFlags, LovPattern, LustrePath, hsm::*};
use sequential_test::{parallel, sequential};
use std::{
    env, fs,
    fs::File,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, Error>;

const TEST_FILE: &str = "test_hsm_file";
fn new_file_path() -> PathBuf {
    let mut path =
        PathBuf::from(env::var("TEST_DIR").unwrap_or("/mnt/lustre/layout_test".to_string()));

    let mut rng = rand::rng();
    path.push(format!("{}_{:x}", TEST_FILE, rng.random::<u32>()));
    path
}

fn get_lustre_dir() -> LustrePath {
    match LustrePath::parse(&env::var("LUSTRE_DIR").unwrap_or("/mnt/lustre".to_string())) {
        Ok(x) => x,
        Err(e) => {
            panic!("Failed to parse LUSTRE_DIR: {e:?}");
        }
    }
}

fn lustre_pool() -> String {
    std::env::var("POOL").unwrap_or_else(|_| "testpool".to_string())
}

#[test]
#[sequential]
fn test1_register() {
    let lustre_dir = get_lustre_dir();

    let mut ct = match Copytool::builder().register(&lustre_dir) {
        Ok(r) => r,
        Err(e) => {
            panic!("Failed to register copytool: {e:?}");
        }
    };

    drop(ct);
}

#[test]
#[sequential]
fn test2_reregister() {
    let lustre_dir = get_lustre_dir();

    let mut ct1 = match Copytool::builder().register(&lustre_dir) {
        Ok(r) => r,
        Err(e) => {
            panic!("Failed to register copytool: {e:?}");
        }
    };

    let mut ct2 = match Copytool::builder().register(&lustre_dir) {
        Ok(r) => r,
        Err(e) => {
            panic!("Failed to register copytool: {e:?}");
        }
    };

    drop(ct2);
    drop(ct1);
}

#[test]
#[sequential]
fn test3_register_bad_parms() {
    let lustre_dir = get_lustre_dir();
    let result = Copytool::builder().archives(vec![-1]).register(&lustre_dir);
    insta::assert_debug_snapshot!(result);

    let result = LustrePath::parse("/tmp/");
    insta::assert_debug_snapshot!(result);
}

#[test]
#[sequential]
fn test5_non_blocking_receive() {
    let lustre_dir = get_lustre_dir();

    let mut ct = match Copytool::builder().non_blocking(true).register(&lustre_dir) {
        Ok(r) => r,
        Err(e) => {
            panic!("Failed to register copytool: {e:?}");
        }
    };

    for _i in 1..1000 {
        match ct.receive() {
            Err(Error::WouldBlock) => {
                continue;
            }
            e => {
                panic!("Unexpected result: {:?}", e);
            }
        }
    }
    drop(ct);
}

#[test]
#[sequential]
fn test7_polling() {
    let lustre_dir = get_lustre_dir();

    let mut ct = match Copytool::builder()
        .non_blocking(false)
        .register(&lustre_dir)
    {
        Ok(r) => r,
        Err(e) => {
            panic!("Failed to register copytool: {e:?}");
        }
    };

    let fd = ct.raw_fd().expect("Failed to get copytool fd");

    let poller = polling::Poller::new().expect("Poller creation failed");
    let key = 1;
    unsafe {
        poller
            .add(fd.as_raw_fd(), Event::readable(key))
            .expect("Poller add failed");
    }

    let mut events = Events::new();
    let result = poller.wait(&mut events, Some(Duration::from_secs(1)));
    assert!(result.is_ok());

    drop(ct);
}

fn create_test_file(length: usize) -> (PathBuf, File) {
    let path = new_file_path();
    let f = File::options()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .expect("File creation should work.");
    nix::unistd::ftruncate(&f, length as off_t).expect("Could not truncate file");
    (path, f)
}

#[test]
#[parallel]
fn test50_hsm_state_get() {
    let (path, f) = create_test_file(1024 * 1024);

    let result = HsmCurrent::get(&path);
    assert!(result.is_ok());
    fs::remove_file(&path).expect("File should be removed.");
}

#[test]
#[parallel]
fn test51_hsm_state_set() {
    let (path, f) = create_test_file(1024 * 1024);

    for i in 1..48 {
        let result = HsmCurrent::set_fd(&f, HsmState::Exists, HsmState::none(), i);
        assert!(result.is_ok());

        if let Ok(result) = HsmCurrent::get(&path) {
            assert_eq!(result.states, HsmState::Exists);
            assert_eq!(result.archive_id, i);
        } else {
            panic!("Failed to get HSM info");
        }
    }

    let result = HsmCurrent::set(&path, HsmState::Archived, HsmState::none(), 64);
    assert!(result.is_ok());

    let result = HsmCurrent::get(&path);
    insta::assert_debug_snapshot!(result);
    fs::remove_file(&path).expect("File should be removed.");
}

#[test]
#[parallel]
fn test52_hsm_current_action() {
    let (path, f) = create_test_file(1024 * 1024);
    drop(f);

    let result = HsmCurrent::get(&path);
    insta::assert_debug_snapshot!(result);
    fs::remove_file(&path).expect("File should be removed.");
}

fn archive_helper(length: usize, progress_cb: fn(&mut ActionProgress, u64) -> ()) -> Result<()> {
    let lustre_dir = get_lustre_dir();
    let (path, f) = create_test_file(length);
    let ct = Copytool::builder().register(&lustre_dir)?;

    let result = archive(&path, 1, HsmRequestFlags::none(), vec![Fid::with_fd(&f)?]);
    assert!(result.is_ok());

    let Ok(hal) = ct.receive() else {
        panic!("Failed to receive HAL");
    };

    assert_eq!(hal.len(), 1);

    for hai in hal.iter() {
        assert_eq!(hai.action, CopytoolAction::Archive);
        let mut ca = ProgressBuilder::action_begin(&ct, &hai, 0)?;

        progress_cb(&mut ca, length as u64);

        let current = HsmCurrent::get(&path)?;
        assert_eq!(current.progress_state, ProgressState::Running);
        assert_eq!(current.action, UserAction::Archive);

        ca.end(hai.extent, 0, 0)?;
    }

    fs::remove_file(path)?;
    Ok(())
}

#[test]
#[sequential]
fn test100_archive() {
    let result = archive_helper(100, |ca: &mut ActionProgress, length: u64| {});
    if result.is_err() {
        panic!("Failed to archive: {:?}", result);
    }
}

#[test]
#[sequential]
fn test101_progress_every_byte() {
    let result = archive_helper(1024, |ca: &mut ActionProgress, length: u64| {
        let mut offset: u64 = 0;
        let mut remaining = length;
        while remaining > 0 {
            let extent = Extent { offset, length: 1 };
            let result = ca.progress(extent, length, 0);
            assert!(result.is_ok());
            offset += 1;
            remaining -= 1;
        }
    });
    if result.is_err() {
        panic!("Failed to archive: {:?}", result);
    }
}

#[test]
#[sequential]
fn test102_progress_every_byte_backwards() {
    let result = archive_helper(1024, |ca: &mut ActionProgress, length: u64| {
        let mut offset: u64 = 0;
        let mut remaining = length;
        while remaining > 0 {
            remaining -= 1;
            let extent = Extent {
                offset: remaining,
                length: 1,
            };
            let result = ca.progress(extent, length, 0);
            assert!(result.is_ok());
        }
    });

    if result.is_err() {
        panic!("Failed to archive: {:?}", result);
    }
}

#[test]
#[sequential]
fn test103_archive_one_report() {
    let result = archive_helper(1024, |ca: &mut ActionProgress, length: u64| {
        let extent = Extent {
            offset: 0,
            length: length,
        };
        let result = ca.progress(extent, length, 0);
        assert!(result.is_ok());
    });
    if result.is_err() {
        panic!("Failed to archive: {:?}", result);
    }
}

#[test]
#[sequential]
fn test104_archive_two_reports() {
    let result = archive_helper(1024, |ca: &mut ActionProgress, length: u64| {
        let extent = Extent {
            offset: 0,
            length: length / 2,
        };
        let result = ca.progress(extent, length, 0);
        assert!(result.is_ok());

        let extent = Extent {
            offset: length / 2,
            length: length / 2,
        };
        let result = ca.progress(extent, length, 0);
        assert!(result.is_ok());
    });
    if result.is_err() {
        panic!("Failed to archive: {:?}", result);
    }
}

#[test]
#[sequential]
fn test105_archive_bogus_report() {
    let result = archive_helper(1024, |ca: &mut ActionProgress, length: u64| {
        let extent = Extent {
            offset: 2 * length,
            length: 10 * length,
        };
        let result = ca.progress(extent, length, 0);
        assert!(result.is_ok());
    });
    if result.is_err() {
        panic!("Failed to archive: {:?}", result);
    }
}

#[test]
#[sequential]
fn test106_archive_empty_report() {
    let result = archive_helper(1024, |ca: &mut ActionProgress, length: u64| {
        let extent = Extent {
            offset: 0,
            length: 0,
        };
        let result = ca.progress(extent, length, 0);
        assert!(result.is_ok());
    });
    if result.is_err() {
        panic!("Failed to archive: {:?}", result);
    }
}

#[test]
#[sequential]
fn test107_archive_bogus2_report() {
    let result = archive_helper(1024, |ca: &mut ActionProgress, length: u64| {
        let offset = -1;
        let extent = Extent {
            offset: offset as u64,
            length: 10,
        };
        let result = ca.progress(extent, length, 0);
        insta::assert_debug_snapshot!(result, @r###"
Err(
    MsgErrno(
        "Failed to update copy action progress",
        EINVAL,
    ),
)
"###);
    });
    if result.is_err() {
        panic!("Failed to archive: {:?}", result);
    }
}

#[test]
#[sequential]
fn test108_archive_same_report() {
    let result = archive_helper(1024, |ca: &mut ActionProgress, length: u64| {
        let reports = 10;

        for report_num in 0..reports {
            let extent = Extent {
                offset: 0,
                length: length / 2,
            };

            let result = ca.progress(extent, length, 0);
            assert!(result.is_ok());

            if result.is_err() {
                panic!("Failed to archive: {:?} #{}", result, report_num);
            }
        }
    });
}

#[test]
#[sequential]
fn test109_archive_one_report_large_number() {
    let result = archive_helper(1024, |ca: &mut ActionProgress, length: u64| {
        let extent = Extent {
            offset: 0,
            length: std::u64::MAX,
        };
        let result = ca.progress(extent, std::u64::MAX, 0);
        assert!(result.is_ok());
    });
    if result.is_err() {
        panic!("Failed to archive: {:?}", result);
    }
}

#[test]
#[sequential]
fn test110_archive_different_reports() {
    let result = archive_helper(1024, |ca: &mut ActionProgress, length: u64| {
        let reports = 10;

        for rep_num in 0..reports {
            let extent = Extent {
                offset: rep_num * length / 10,
                length: length / 10,
            };

            let result = ca.progress(extent, length, 0);
            assert!(result.is_ok());

            if result.is_err() {
                panic!("Failed to archive: {:?} #{}", result, rep_num);
            }
        }
    });
}

#[test]
#[sequential]
fn test111_archive_different_reports_reverse() {
    let result = archive_helper(1024, |ca: &mut ActionProgress, length: u64| {
        let reports = 10;

        for rep_num in 0..reports {
            let extent = Extent {
                offset: (reports - rep_num) * length / 10,
                length: length / 10,
            };

            let result = ca.progress(extent, length, 0);
            assert!(result.is_ok());

            if result.is_err() {
                panic!("Failed to archive: {:?} #{}", result, rep_num);
            }
        }
    });
}

#[test]
#[sequential]
fn test112_archive_different_reports_duplicated() {
    let result = archive_helper(1024, |ca: &mut ActionProgress, length: u64| {
        let reports = 10;

        for rep_num in 0..reports {
            let extent = Extent {
                offset: rep_num * length / 10,
                length: length / 10,
            };

            let result = ca.progress(extent, length, 0);
            assert!(result.is_ok());

            if result.is_err() {
                panic!("Failed to archive: {:?} #{}", result, rep_num);
            }
        }

        for rep_num in 0..reports {
            let extent = Extent {
                offset: rep_num * length / 10,
                length: length / 10,
            };

            let result = ca.progress(extent, length, 0);
            assert!(result.is_ok());

            if result.is_err() {
                panic!("Failed to archive: {:?} #{}", result, rep_num);
            }
        }
    });
}

#[test]
#[sequential]
fn test113_archive_reports_overlapping_coverage() {
    let result = archive_helper(1024, |ca: &mut ActionProgress, length: u64| {
        let reports = 10;

        for rep_num in 0..reports {
            let extent = Extent {
                offset: rep_num * length / 10,
                length: 2 * length / 10,
            };

            let result = ca.progress(extent, length, 0);
            assert!(result.is_ok());

            if result.is_err() {
                panic!("Failed to archive: {:?} #{}", result, rep_num);
            }
        }
    });
}

fn mover_helper(length: usize, progress_cb: fn(&mut ActionProgress, u64) -> ()) -> Result<()> {
    let lustre_dir = get_lustre_dir();
    let (path, f) = create_test_file(length);
    let ct = Copytool::builder().register(&lustre_dir)?;

    let mover = Mover::builder().register(&lustre_dir)?;

    let result = archive(&path, 1, HsmRequestFlags::none(), vec![Fid::with_fd(&f)?]);
    assert!(result.is_ok());

    let Ok(hal) = ct.receive() else {
        panic!("Failed to receive HAL");
    };

    assert_eq!(hal.len(), 1);

    for hai in hal.iter() {
        assert_eq!(hai.action, CopytoolAction::Archive);

        let mut ca = ProgressBuilder::action_begin(&mover, &hai, 0)?;

        progress_cb(&mut ca, length as u64);

        let current = HsmCurrent::get(&path)?;
        assert_eq!(current.progress_state, ProgressState::Running);
        assert_eq!(current.action, UserAction::Archive);

        ca.end(hai.extent, 0, 0)?;
    }

    drop(mover);
    drop(ct);

    fs::remove_file(path)?;
    Ok(())
}

#[test]
#[sequential]
fn test199_mover_create() {
    let lustre_dir = get_lustre_dir();

    let mover = Mover::builder()
        .register(&lustre_dir)
        .expect("Mover should be registered");
    drop(mover)
}
#[test]
#[sequential]
fn test200_mover_archive() {
    let result = mover_helper(100, |ca: &mut ActionProgress, length: u64| {});
    if result.is_err() {
        panic!("Failed to archive: {:?}", result);
    }
}

#[test]
#[sequential]
fn test201_mover_progress_every_byte() {
    let result = mover_helper(1024, |ca: &mut ActionProgress, length: u64| {
        let mut offset: u64 = 0;
        let mut remaining = length;
        while remaining > 0 {
            let extent = Extent { offset, length: 1 };
            let result = ca.progress(extent, length, 0);
            assert!(result.is_ok());
            offset += 1;
            remaining -= 1;
        }
    });
    if result.is_err() {
        panic!("Failed to archive: {:?}", result);
    }
}

#[test]
#[sequential]
fn test202_mover_progress_every_byte_backwards() {
    let result = mover_helper(1024, |ca: &mut ActionProgress, length: u64| {
        let mut offset: u64 = 0;
        let mut remaining = length;
        while remaining > 0 {
            remaining -= 1;
            let extent = Extent {
                offset: remaining,
                length: 1,
            };
            let result = ca.progress(extent, length, 0);
            assert!(result.is_ok());
        }
    });

    if result.is_err() {
        panic!("Failed to archive: {:?}", result);
    }
}

#[test]
#[sequential]
fn test204_move_two_reports() {
    let file1 = mover_helper(100, |ca: &mut ActionProgress, length: u64| {});

    if file1.is_err() {
        panic!("Failed to archive: {:?}", file1);
    }
    let file2 = mover_helper(100, |ca: &mut ActionProgress, length: u64| {});

    if file2.is_err() {
        panic!("Failed to archive: {:?}", file2);
    }
}

#[test]
#[sequential]
fn test206_move_empty_file() {
    let file1 = mover_helper(0, |ca: &mut ActionProgress, length: u64| {});

    if file1.is_err() {
        panic!("Failed to archive: {:?}", file1);
    }
}

#[test]
#[sequential]
fn test209_move_large_file() {
    let large_size = 1_000_000_000; // 1 GB

    let result = mover_helper(large_size, |ca: &mut ActionProgress, length: u64| {});

    if result.is_err() {
        panic!("Failed to archive: {:?}", result);
    }
}

#[test]
#[sequential]
fn test210_move_different_reports() {
    for i in 1..10 {
        let result = mover_helper(i * 1000, |ca: &mut ActionProgress, length: u64| {});

        if result.is_err() {
            panic!("Failed to archive: {:?}", result);
        }
    }
}

#[test]
#[sequential]
fn test300_new_default_stub() {
    let path = new_file_path();

    // Create stub with all default values - no ? operators needed until create()
    let stub = HsmFileStub::new(&path);

    // Test the Display output contains expected structure
    let display_output = format!("{}", stub);

    // Verify it contains the expected fields and reasonable values
    assert!(display_output.contains("HsmStub {"));
    assert!(display_output.contains(&format!("dst: \"{}\"", path.to_string_lossy())));
    assert!(display_output.contains("archive: 0"));
    assert!(display_output.contains("stripe_size: 1048576")); // 1MB
    assert!(display_output.contains("stripe_offset: -1"));
    assert!(display_output.contains("stripe_count: 1"));
    assert!(display_output.contains("stripe_pattern: 0"));
    assert!(display_output.contains("pool_name: \"None\""));

    // Create the stub - only one ? needed at the end
    let result = stub.create();
    println!("result: {:?}", result);

    assert!(result.is_ok());

    fs::remove_file(&path).expect("File should be removed.");
}

#[test]
#[sequential]
fn test301_set_archive() {
    let path = new_file_path();
    let archive_id = 42;

    let stub = HsmFileStub::new(&path).archive(archive_id);

    let display = format!("{}", stub);
    assert!(display.contains(&format!("archive: {}", archive_id)));

    let result = stub.create();
    assert!(result.is_ok());

    let hsm = HsmCurrent::get(&path).unwrap();
    assert_eq!(hsm.archive_id, archive_id as u32);

    fs::remove_file(&path).expect("File should be removed.");
}

#[test]
#[sequential]
fn test302_set_uid() {
    let path = new_file_path();
    let custom_uid = 1001;

    let stub = HsmFileStub::new(&path).uid(custom_uid);

    let display = format!("{}", stub);
    assert!(display.contains(&format!("uid: {}", custom_uid)));

    let result = stub.create();
    assert!(result.is_ok());

    let metadata = fs::metadata(&path).unwrap();
    assert_eq!(metadata.uid(), custom_uid);

    fs::remove_file(&path).expect("File should be removed.");
}

#[test]
#[sequential]
fn test303_set_mode() {
    let path = new_file_path();
    let custom_mode = 0o755;

    let stub = HsmFileStub::new(&path).mode(custom_mode);

    let display = format!("{}", stub);
    assert!(display.contains(&format!("mode: 0o{:o}", custom_mode)));

    let result = stub.create();
    assert!(result.is_ok());

    let metadata = fs::metadata(&path).unwrap();
    assert_eq!(metadata.mode() & 0o777, custom_mode as u32);

    fs::remove_file(&path).expect("File should be removed.");
}

#[test]
#[sequential]
fn test304_set_mtime() {
    let path = new_file_path();
    let custom_time = UNIX_EPOCH + Duration::from_secs(1234567890);

    let stub = HsmFileStub::new(&path).mtime(custom_time);

    let display = format!("{}", stub);
    assert!(display.contains("mtime:"));

    let result = stub.create();
    assert!(result.is_ok());

    let metadata = fs::metadata(&path).unwrap();
    assert_eq!(metadata.modified().unwrap(), custom_time);

    fs::remove_file(&path).expect("File should be removed.");
}

#[test]
#[sequential]
fn test305_set_stripe_size() {
    let path = new_file_path();
    let custom_size = 2 * 1024 * 1024; // 2MB

    let stub = HsmFileStub::new(&path).stripe_size(custom_size);

    let display = format!("{}", stub);
    assert!(display.contains(&format!("stripe_size: {}", custom_size)));

    let result = stub.create();
    assert!(result.is_ok());

    let layout = Layout::with_path(&path, LayoutGetFlags::NONE).unwrap();
    assert_eq!(layout.get_stripe_size().unwrap(), custom_size);

    fs::remove_file(&path).expect("File should be removed.");
}

#[test]
#[sequential]
fn test309_set_pool() {
    let path = new_file_path();
    let pool = lustre_pool();

    let stub = HsmFileStub::new(&path).pool(&pool);

    let display = format!("{}", stub);
    assert!(display.contains(&format!("pool_name: \"{}\"", pool)));

    let result = stub.create();
    assert!(result.is_ok());

    let layout = Layout::with_path(&path, LayoutGetFlags::NONE).unwrap();
    assert_eq!(layout.get_pool_name().unwrap(), pool);

    fs::remove_file(&path).expect("File should be removed.");
}

#[test]
#[sequential]
fn test310_set_full_stat_with_builder() {
    let path = new_file_path();
    let custom_time = SystemTime::now();

    // Using the StatBuilder for more complex stat configuration
    let custom_stat = StatBuilder::new()
        .uid(1002)
        .gid(1003)
        .mode(0o644)
        .size(4096)
        .atime(custom_time)
        .mtime(custom_time)
        .ctime(custom_time)
        .build()
        .unwrap();

    let stub = HsmFileStub::new(&path).stat(custom_stat.clone());

    let display = format!("{}", stub);
    assert!(display.contains(&format!("uid: {}", custom_stat.uid)));
    assert!(display.contains(&format!("gid: {}", custom_stat.gid)));
    assert!(display.contains(&format!("mode: 0o{:o}", custom_stat.mode)));
    assert!(display.contains(&format!("size: {}", custom_stat.size)));

    let result = stub.create();
    assert!(result.is_ok());

    let metadata = fs::metadata(&path).unwrap();
    assert_eq!(metadata.uid(), custom_stat.uid);
    assert_eq!(metadata.gid(), custom_stat.gid);
    assert_eq!(metadata.mode() & 0o777, (custom_stat.mode & 0o777) as u32);
    assert_eq!(metadata.size(), custom_stat.size);

    fs::remove_file(&path).expect("File should be removed.");
}

#[test]
#[sequential]
fn test311_full_custom_create_and_verify() {
    let path = new_file_path();
    let archive_id = 99;
    let custom_uid = 1004;
    let custom_mode = 0o600;
    let custom_size = 8192;
    let custom_stripe_size = 4 * 1024 * 1024;
    let custom_stripe_offset = 3;
    let custom_stripe_count = 2;
    let custom_stripe_pattern = LLAPI_LAYOUT_RAID0 as LovPattern;
    let pool = lustre_pool();

    let stub = HsmFileStub::new(&path)
        .archive(archive_id)
        .uid(custom_uid)
        .gid(1005)
        .mode(custom_mode)
        .size(custom_size)
        .stripe_size(custom_stripe_size)
        .stripe_offset(custom_stripe_offset)
        .stripe_count(custom_stripe_count)
        .stripe_pattern(custom_stripe_pattern)
        .pool(&pool);

    let result = stub.create();
    assert!(result.is_ok());

    // Verify HSM
    let hsm = HsmCurrent::get(&path).unwrap();
    assert_eq!(hsm.archive_id, archive_id as u32);

    // Verify stat attributes
    let metadata = fs::metadata(&path).unwrap();
    assert_eq!(metadata.uid(), custom_uid);
    assert_eq!(metadata.gid(), 1005);
    assert_eq!(metadata.mode() & 0o777, custom_mode as u32);
    assert_eq!(metadata.size(), custom_size);

    // Verify layout/stripe
    let layout = Layout::with_path(&path, LayoutGetFlags::NONE).unwrap();
    assert_eq!(layout.get_stripe_size().unwrap(), custom_stripe_size);
    assert_eq!(
        layout.get_stripe_count().unwrap(),
        custom_stripe_count as u64
    );
    assert_eq!(layout.get_pool_name().unwrap(), pool);

    fs::remove_file(&path).expect("File should be removed.");
}

/// Test for HSM request flags functionality (LU-18940)
/// This test verifies the HSM Request Flags enum and its blocking flag
fn blocking_restore_helper() -> Result<()> {
    use rustreapi::{
        Fid,
        hsm::{
            ActionHeader, Copytool, CopytoolAction, HsmCurrent, HsmRequestFlags, HsmState,
            ProgressBuilder, restore,
        },
    };
    let lustre_dir = get_lustre_dir();
    let (path, f) = create_test_file(1024 * 1024);
    let ct = Copytool::builder()
        .archives(vec![1])
        .register(&lustre_dir)?;

    let fid = Fid::with_fd(&f)?;
    archive(&path, 1, HsmRequestFlags::none(), vec![fid])?;

    let hal = ct.receive()?;
    for hai in hal.iter() {
        let mut ca = ProgressBuilder::action_begin(&ct, &hai, 0)?;
        ca.end(hai.extent, 0, 0)?;
    }

    let _ = HsmCurrent::set(&path, HsmState::Released, HsmState::none(), 1);

    // Test restore with blocking flag
    restore(&path, HsmRequestFlags::Blocking, vec![fid])?;

    let blocking_hal = ct.receive()?;

    // Test ActionHeader conversion and blocking flag check BEFORE processing
    // We need to collect the actions first since ActionList is consumed by conversion
    let action_items: Vec<_> = blocking_hal.iter().collect();
    let hal = ActionHeader::from(blocking_hal);

    // Verify the blocking flag is properly set
    assert!(hal.flags.contains(HsmRequestFlags::Blocking));
    assert_eq!(hal.actions.len(), action_items.len());

    // Verify action types match
    for (header_action, original_action) in hal.actions.iter().zip(action_items.iter()) {
        assert_eq!(header_action.action, original_action.action);
        assert_eq!(header_action.action, CopytoolAction::Restore);
    }

    fs::remove_file(&path)?;
    Ok(())
}

#[test]
#[sequential]
fn test320_hsm_blocking_with_released_file() {
    use rustreapi::hsm::HsmRequestFlags;

    // Test the blocking flag constants and enum
    let blocking_flags = HsmRequestFlags::Blocking;
    assert_eq!(blocking_flags.bits(), 0x0004);

    fn get_priority(flags: HsmRequestFlags) -> (&'static str, u8) {
        if flags.contains(HsmRequestFlags::Blocking) {
            ("HIGH_PRIORITY", 1) // User waiting
        } else {
            ("NORMAL_PRIORITY", 5) // Background
        }
    }

    let (blocking_pri, blocking_level) = get_priority(HsmRequestFlags::Blocking);
    let (normal_pri, normal_level) = get_priority(HsmRequestFlags::none());

    assert_eq!(blocking_pri, "HIGH_PRIORITY");
    assert_eq!(blocking_level, 1);
    assert_eq!(normal_pri, "NORMAL_PRIORITY");
    assert_eq!(normal_level, 5);

    // Test with live Lustre environment
    blocking_restore_helper().expect("HSM blocking test should succeed");
}
