#!/bin/bash
# SPDX-License-Identifier: MIT

# Copyright (c) 2025 DDN. All rights reserved.
# Use of this source code is governed by a MIT-style
# license that can be found in the LICENSE file.

# automate setting env variables and setting params.
export LUSTRE_DIR=/mnt/lustre
export TEST_DIR=/mnt/lustre/test-dir
export POOL=testp
echo "Environment variables set: LUSTRE_DIR=$LUSTRE_DIR, TEST_DIR=$TEST_DIR, POOL=$POOL"
mkdir -p "$TEST_DIR"
pushd "$LUSTRE_DIR" || exit 1
lctl set_param mdt.*.hsm_control=enabled
lctl pool_new lustre.testp
popd || exit 1
cargo test --test hsm_test
cargo test --test layout_test
