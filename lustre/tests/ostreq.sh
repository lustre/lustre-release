#!/bin/sh

R=/r

insmod /lib/modules/2.4.17/kernel/drivers/block/loop.o
insmod $R/usr/src/obd/class/obdclass.o 
insmod $R/usr/src/obd/ext2obd/obdext2.o
insmod $R/usr/src/obd/ost/ost.o
insmod $R/usr/src/obd/osc/osc.o

dd if=/dev/zero of=/tmp/fs bs=1024 count=10000
mke2fs -F /tmp/fs
losetup /dev/loop/0 /tmp/fs

echo 4095 > /proc/sys/obd/debug
echo 4095 > /proc/sys/obd/trace

mknod /dev/obd c 10 241

$R/usr/src/obd/utils/obdctl <<EOF
device 0
attach obdext2
setup /dev/loop/0
device 1
attach ost
setup 0
device 2
attach osc
setup 1
quit
EOF




