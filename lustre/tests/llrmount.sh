#!/bin/sh

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

NETWORK=tcp
LOCALHOST=localhost
SERVER=localhost
PORT=1234

setup_portals
setup_lustre

old_fs ext2 /tmp/ost 80000
OST=$LOOPDEV
MDSFS=ext2
old_fs ${MDSFS} /tmp/mds 10000
MDS=$LOOPDEV

echo 0xffffffff > /proc/sys/portals/debug

$OBDCTL <<EOF
device 0
attach mds MDSDEV
setup ${MDS} ${MDSFS}
device 1
attach obdext2 OBDDEV
setup ${OST}
device 2
attach ost OSTDEV
setup \$OBDDEV
device 3
attach ptlrpc RPCDEV
setup
device 4
attach ldlm LDLMDEV
setup
device 5
attach osc OSCDEV
setup -1
quit
EOF

mount -t lustre_lite -o device=5 none /mnt/lustre
