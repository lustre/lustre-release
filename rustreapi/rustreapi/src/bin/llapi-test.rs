// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use clap::Parser;
use rustreapi::{Error, Layout, LayoutGetFlags, SingleLayout, file_get_mdtidx, get_layout};
use std::{fmt, io::Write, path::PathBuf};

#[derive(Parser, Debug)]
#[clap(version, about, name = "walk")]
struct Args {
    #[clap(default_value = "./testfile")]
    path: PathBuf,
    #[clap(short, long)]
    create: bool,
}

struct LayoutList(Vec<SingleLayout>);

impl fmt::Display for LayoutList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for layout in &self.0 {
            write!(f, "{layout}\n\n")?;
        }
        Ok(())
    }
}

fn main() {
    match run() {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), Error> {
    let args = Args::parse();
    if args.create {
        let layout = Layout::new();
        layout.stripe_count(4)?.stripe_size(1024 * 1024)?;
        println!("layout: {:?}", &layout);
        let mut f = rustreapi::OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .layout(layout)
            .open(&args.path)?;

        println!("create f: {:?}", &f);
        let _ = f.write("hello world\n".as_bytes())?;
    }

    let mdtidx = file_get_mdtidx(&args.path)?;
    println!("mdt idx: {mdtidx}");

    let layout = get_layout(&args.path, LayoutGetFlags::NONE)?;
    println!("{:?} layout:\n{}", &*args.path, &LayoutList(layout));

    let l = Layout::with_path(&args.path, LayoutGetFlags::NONE)?;
    println!("{:?} layout:\n{}", &*args.path, l);

    Ok(())
}
