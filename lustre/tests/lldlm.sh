#!/bin/sh

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

setup_ldlm

mknod /dev/obd c 10 241
echo 8191 > /proc/sys/portals/debug

$R/usr/src/obd/utils/obdctl <<EOF
device 0
attach ldlm
setup
test_ldlm
quit
EOF
