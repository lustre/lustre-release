#!/bin/sh

SRCDIR="`dirname $0`/"
. $SRCDIR/common.sh

export DEBUG_WAIT=yes
. $SRCDIR/llsetup.sh $SRCDIR/net-local.cfg $SRCDIR/obdecho.cfg $SRCDIR/client-echo.cfg

cat <<EOF

run getattr tests as:
$OBDCTL --device `$OBDCTL name2dev OSCDEV` test_getattr 1000000
EOF
