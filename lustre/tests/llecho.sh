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
newdev
attach obdecho OBDDEV
setup
newdev
attach ost OSTDEV
setup \$OBDDEV
newdev
attach osc OSCDEV
setup -1
quit
EOF

cat <<EOF

run getattr tests as:
obdctl --device 2 test_getattr 1000000
EOF
