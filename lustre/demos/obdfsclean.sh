#!/bin/sh
# Utility script for cleaning up a simple OBDFS mounted filesystem
OBDDIR="`dirname $0`/.."
. $OBDDIR/demos/config.sh

plog umount $MNTOBD
killall -STOP pupd	# stop the OBDFS flush daemon (both signals required)
plog killall pupd
rmmod obdfs

plog log "CLEANUP/DETACH"
$OBDDIR/class/obdcontrol -f << EOF
cleanup
detach
quit
EOF

rmmod obdext2
rmmod obdclass

$OBDDIR/demos/baseclean.sh
