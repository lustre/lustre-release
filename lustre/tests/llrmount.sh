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
newdev
attach mds MDSDEV
setup ${MDS} ${MDSFS}
newdev
attach obdext2 OBDDEV
setup ${OST}
newdev
attach ost OSTDEV
setup \$OBDDEV
newdev
attach ldlm LDLMDEV
setup
newdev
attach osc OSCDEV
setup -1
quit
EOF

mount -t lustre_lite -o device=`$OBDCTL name2dev OSCDEV` none /mnt/lustre
