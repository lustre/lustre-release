#!/bin/sh

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

SERVER=localhost

setup

$PTLCTL <<EOF
mynid localhost
setup tcp
connect $SERVER 1234
add_uuid self
add_uuid ost
quit
EOF


tmp_fs ext2 /tmp/fs 10000
OBD=${LOOPDEV}

$OBDCTL <<EOF
device 0
attach obdext2
setup ${OBD}
device 1
attach ost
setup 0
device 2
attach osc
setup -1
quit
EOF
