#! /bin/bash
# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

insmod loop
dd if=/dev/zero of=/tmp/fs bs=1024 count=10000
losetup /dev/loop0 /tmp/fs
mke2fs -b 4096 /dev/loop0
