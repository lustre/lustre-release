#!/bin/sh

R=/r

insmod /lib/modules/2.4.17/kernel/drivers/block/loop.o
insmod $R/usr/src/portals/linux/oslib/portals.o
insmod $R/usr/src/portals/linux/socknal/ksocknal.o
insmod $R/usr/src/obd/rpc/ptlrpc.o
insmod $R/usr/src/obd/class/obdclass.o 
insmod $R/usr/src/obd/ext2obd/obdext2.o
insmod $R/usr/src/obd/ost/ost.o
insmod $R/usr/src/obd/osc/osc.o
insmod $R/usr/src/obd/mds/mds.o
insmod $R/usr/src/obd/mdc/mdc.o
insmod $R/usr/src/obd/llight/llight.o

dd if=/dev/zero of=/tmp/ost bs=1024 count=10000
mke2fs -b 4096 -F /tmp/ost
losetup /dev/loop/0 /tmp/ost

dd if=/dev/zero of=/tmp/mds bs=1024 count=10000
mke2fs -b 4096 -F /tmp/mds
losetup /dev/loop/1 /tmp/mds

mknod /dev/obd c 10 241

$R/usr/src/obd/utils/obdctl <<EOF
device 0
attach mds
setup /dev/loop/1 ext2
device 1
attach obdext2
setup /dev/loop/0
device 2
attach ost
setup 1
device 3
attach osc
setup 2
quit
EOF

mkdir /mnt/obd
mount -t lustre_light -o device=3 none /mnt/obd



