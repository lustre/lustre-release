#!/bin/sh

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

setup

$R/usr/src/portals/linux/utils/ptlctl <<EOF
mynid localhost
setup tcp
connect localhost 1234
add_uuid self
add_uuid mds
add_uuid ost
quit
EOF

dd if=/dev/zero of=/tmp/ost bs=1024 count=10000
mke2fs -b 4096 -F /tmp/ost
losetup ${LOOP}0 /tmp/ost || exit -1

dd if=/dev/zero of=/tmp/mds bs=1024 count=10000
mke2fs -b 4096 -N 150000 -F /tmp/mds
losetup ${LOOP}1 /tmp/mds || exit -1

mknod /dev/obd c 10 241
echo 8191 > /proc/sys/portals/debug

$R/usr/src/obd/utils/obdctl <<EOF
device 0
attach mds
setup ${LOOP}1 ext2
device 1
attach obdext2
setup ${LOOP}0
device 2
attach ost
setup 1
device 3
attach osc
setup -1
quit
EOF

mkdir /mnt/obd
mount -t lustre_light -o device=3 none /mnt/obd
