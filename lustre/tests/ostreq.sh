#!/bin/sh

SRCDIR="`dirname $0`/"
. $SRCDIR/common.sh

SERVER=localhost
PORT=1234

$ACCEPTOR $PORT

$PTLCTL <<EOF
mynid localhost
setup tcp
connect $SERVER $PORT
add_uuid $SERVER
add_uuid self
quit
EOF

setup_lustre

tmp_fs ext2 /tmp/fs 10000
OBD=${LOOPDEV}

$OBDCTL <<EOF
device 0
attach obdext2 OBDEXT2DEV
setup ${OBD}
device 1
attach ost OSTDEV
setup 0
device 2
attach osc OSCDEV
setup -1
quit
EOF
