#!/bin/sh

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

NETWORK=tcp
LOCALHOST=localhost
SERVER=localhost
PORT=1234

setup_portals
setup_lustre
echo -n "Hit return to continue..."
read

new_fs ext2 /tmp/ost 10000
OST=$LOOPDEV
MDSFS=ext2
new_fs ${MDSFS} /tmp/mds 10000
MDS=$LOOPDEV

echo 0xffffffff > /proc/sys/portals/debug

$OBDCTL <<EOF
device 0
attach mds MDSDEV
setup ${MDS} ${MDSFS}
device 1
attach obdfilter FILTERDEV
setup ${OST} ext2
device 2
attach ost OSTDEV
setup 1
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

mount -t lustre_lite -o device=`$OBDCTL name2dev OSCDEV` none /mnt/lustre
