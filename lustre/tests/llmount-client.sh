#!/bin/sh
export PATH=/sbin:/usr/sbin:$PATH

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

NETWORK=elan
LOCALHOST=4
SERVER=5

setup
setup_portals

tmp_fs ext2 /tmp/ost 10000
OST=${LOOPDEV}

$OBDCTL <<EOF
device 1
attach obdext2
setup ${OST}
device 2
attach ost
setup 1
device 3
attach osc
setup 2
quit
EOF

mkdir /mnt/obd
# mount -t lustre_light -o device=3 none /mnt/obd
