#!/bin/sh
export PATH=/sbin:/usr/sbin:$PATH

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

NETWORK=tcp
LOCALHOST=dev5
SERVER=dev4
PORT=1234

setup
setup_portals

$OBDCTL <<EOF
device 0
attach osc
setup -1
quit
EOF

mkdir /mnt/obd
mount -t lustre_light -o device=0 none /mnt/obd
