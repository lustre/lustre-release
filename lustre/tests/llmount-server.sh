#!/bin/sh

export PATH=/sbin:/usr/sbin:$PATH

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

NETWORK=elan
LOCALHOST=5
SERVER=5

setup

$PTLCTL <<EOF
setup $NETWORK
mynid $LOCALHOST
connect $LOCALHOST
add_uuid self
add_uuid mds
add_uuid ost
EOF

tmp_fs ext2 /tmp/ost 10000
OST=${LOOPDEV}
MDSFS=ext2
tmp_fs ${MDSFS} /tmp/mds 10000
MDS=${LOOPDEV}

$OBDCTL <<EOF
device 0
attach mds
setup ${MDS} ${MDSFS}
device 1
attach obdext2
setup ${OBD}
device 2
attach ost
setup 1
quit
EOF
