#!/bin/sh

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

setup_ldlm

mknod /dev/obd c 10 241
echo 0xffffffff > /proc/sys/portals/debug

$OBDCTL <<EOF
device 0
attach ldlm
setup
test_ldlm
quit
EOF
