#!/bin/sh

SRCDIR="`dirname $0`/"
. $SRCDIR/common.sh

export DEBUG_WAIT=yes
. $SRCDIR/llsetup.sh $SRCDIR/net-local.cfg $SRCDIR/ldlm.cfg || exit 2

$OBDCTL <<EOF
name2dev LDLMDEV
test_ldlm
quit
EOF
