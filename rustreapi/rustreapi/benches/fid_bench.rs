// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use criterion::{Criterion, criterion_group, criterion_main};

use rustreapi::Fid;

fn fid_parse() {
    let str = "[0xCAFE:0x11:0x22]";
    let _fid = Fid::parse(str).expect("Fid should parse.");
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("fid_parse", |b| {
        b.iter(|| {
            fid_parse();
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
