#!/bin/sh

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

mknod /dev/portals c 10 240

insmod $R/usr/src/portals/linux/oslib/portals.o || exit -1
insmod $R/usr/src/portals/linux/socknal/ksocknal.o || exit -1

$R/usr/src/portals/linux/utils/acceptor 1234 &

insmod $R/usr/src/obd/class/obdclass.o || exit -1
insmod $R/usr/src/obd/rpc/ptlrpc.o || exit -1
insmod $R/usr/src/obd/ext2obd/obdext2.o || exit -1
insmod $R/usr/src/obd/ost/ost.o || exit -1
insmod $R/usr/src/obd/osc/osc.o || exit -1
insmod $R/usr/src/obd/mds/mds.o || exit -1
insmod $R/usr/src/obd/mdc/mdc.o || exit -1
insmod $R/usr/src/obd/llight/llight.o || exit -1

$R/usr/src/portals/linux/utils/ptlctl <<EOF
mynid
setup tcp
connect localhost 1234
add_uuid self
add_uuid mds
add_uuid ost
quit
EOF

dd if=/dev/zero of=/tmp/ost bs=1024 count=30000
mke2fs -b 4096 -F /tmp/ost
losetup ${LOOP}0 /tmp/ost || exit -1

dd if=/dev/zero of=/tmp/mds bs=1024 count=100000
mke2fs -b 4096 -F /tmp/mds
losetup ${LOOP}1 /tmp/mds || exit -1

mknod /dev/obd c 10 241
echo 8291 > /proc/sys/obd/debug
echo 8291 > /proc/sys/obd/trace

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
setup
quit
EOF

mkdir /mnt/obd
mount -t lustre_light -o device=3 none /mnt/obd
