#! /bin/bash
# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution
#!/bin/sh

R=/r

insmod /lib/modules/2.4.17/kernel/drivers/block/loop.o
dd if=/dev/zero of=/tmp/fs bs=1024 count=10000
mke2fs -b 4096 -F /tmp/fs
losetup /dev/loop/0 /tmp/fs

insmod $R/usr/src/obd/class/obdclass.o 
insmod $R/usr/src/obd/ext2obd/obdext2.o
mknod /dev/obd c 10 241

$R/usr/src/obd/utils/obdctl <<EOF
device 0
attach obdext2 OBDEXT2DEV
setup /dev/loop/0
quit
EOF

insmod $R/usr/src/obd/obdfs/obdfs.o
mount -t obdfs -o device=0 none /mnt
