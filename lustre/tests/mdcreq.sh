#!/bin/sh

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

NETWORK=tcp
LOCALHOST=localhost
SERVER=localhost
PORT=1234

setup_portals
setup_lustre

MDSFS=ext2
new_fs ${MDSFS} /tmp/mds 1000
MDS=$LOOPDEV

echo 0xffffffff > /proc/sys/portals/debug

$OBDCTL <<EOF
device 0
attach mds MDSDEV
setup ${MDS} ${MDSFS}
quit
EOF

mknod /dev/request c 10 244

./testreq --getattr
./testreq --setattr
./testreq --readpage
./testreq --open
./testreq --close junk_file_handle
./testreq --create

echo "Done."
