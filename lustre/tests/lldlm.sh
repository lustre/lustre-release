#!/bin/sh

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

NETWORK=tcp
LOCALHOST=localhost
SERVER=localhost
PORT=1234

setup
setup_portals

$OBDCTL <<EOF
device 0
attach ldlm
setup
test_ldlm
quit
EOF
