#!/bin/sh

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

NETWORK=tcp
LOCALHOST=localhost
SERVER=localhost
PORT=1234

setup_portals
setup_lustre

new_fs ext2 /tmp/ost 10000
OST=${LOOPDEV}

MDSFS=ext2
new_fs ${MDSFS} /tmp/mds 10000
MDS=${LOOPDEV}

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
setup 1
device 3
attach osc OSCDEV
setup 2
quit
EOF

# mount -t lustre_lite -o device=3 none /mnt/lustre
