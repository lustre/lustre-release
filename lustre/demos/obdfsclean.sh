#!/bin/sh
# Utility script for cleaning up a simple OBDFS mounted filesystem
OBDDIR="`dirname $0`/.."
. $OBDDIR/demos/config.sh

umount $MNTOBD
rmmod obdfs

$OBDDIR/class/obdcontrol -f << EOF
cleanup
detach
quit
EOF

rmmod obdext2
rmmod obdclass

$OBDDIR/demos/baseclean.sh
