#!/bin/sh

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

NETWORK=tcp
LOCALHOST=localhost
SERVER=localhost
PORT=1234

setup_portals
setup_lustre

$OBDCTL <<EOF
device 0
attach ldlm LDLMDEV
setup
test_ldlm
quit
EOF
