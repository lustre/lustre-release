#!/bin/sh

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

SERVER=localhost

mknod /dev/portals c 10 240

insmod $R/usr/src/portals/linux/oslib/portals.o || exit -1
insmod $R/usr/src/portals/linux/socknal/ksocknal.o || exit -1

$R/usr/src/portals/linux/utils/acceptor 1234 &

insmod $R/usr/src/obd/class/obdclass.o || exit -1
insmod $R/usr/src/obd/rpc/ptlrpc.o || exit -1
insmod $R/usr/src/obd/ext2obd/obdext2.o || exit -1
insmod $R/usr/src/obd/ost/ost.o || exit -1
insmod $R/usr/src/obd/osc/osc.o || exit -1

$R/usr/src/portals/linux/utils/ptlctl <<EOF
mynid localhost
setup tcp
connect $SERVER 1234
add_uuid self
add_uuid ost
quit
EOF


dd if=/dev/zero of=/tmp/fs bs=1024 count=10000
mke2fs -F /tmp/fs
losetup ${LOOP}0 /tmp/fs || exit -1

echo 4095 > /proc/sys/obd/debug
echo 4095 > /proc/sys/obd/trace

mknod /dev/obd c 10 241

$R/usr/src/portals/linux/utils/debugctl modules > $R/tmp/ogdb

$R/usr/src/obd/utils/obdctl <<EOF
device 0
attach obdext2
setup ${LOOP}0
device 1
attach ost
setup 0
device 2
attach osc
setup -1
quit
EOF
