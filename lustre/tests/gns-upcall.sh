#!/bin/sh

MOUNT=`which mount 2>/dev/null`
test "x$MOUNT" = "x" && MOUNT="/bin/mount"

OPTIONS=$1
MNTPATH=$2

test "x$OPTIONS" = "x" || "x$MNTPATH" = "x" && 
    exit 1

$MOUNT $OPTIONS $MNTPATH > /tmp/gns-log 2>&1
exit $?
