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
attach obdecho ECHODEV
setup
device 1
attach ost OSTDEV
setup 0
device 2
attach osc OSCDEV
setup -1
quit
EOF

cat <<EOF
run getattr tests as:
obdctl --device 2 test_getattr 1000000
EOF
