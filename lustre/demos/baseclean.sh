#!/bin/sh
# Script to remove the loopback device and temp file created in newtest.sh
OBDDIR="`dirname $0`/.."
[ "$OBDDIR" = "" ] && OBDDIR=".."
. $OBDDIR/demos/config.sh

[ "$LOOPDEV" ] && losetup -d $LOOPDEV
[ "$TMPFILE" ] && rm $TMPFILE

