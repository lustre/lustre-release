#!/bin/sh

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

setup

$PTLCTL <<EOF
mynid localhost
setup tcp
connect localhost 1234
add_uuid self
add_uuid mds
quit
EOF

MDSFS=ext2
new_fs ${MDSFS} /tmp/mds 10000
MDS=$LOOPDEV

echo 0xffffffff > /proc/sys/portals/debug

$OBDCTL <<EOF
device 0
attach mds
setup ${MDS} ${MDSFS}
quit
EOF

mknod /dev/request c 10 244
# $R/usr/src/obd/tests/testreq
