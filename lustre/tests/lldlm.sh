#!/bin/sh

SRCDIR="`dirname $0`/"
. $SRCDIR/common.sh

export DEBUG_WAIT=yes
. $SRCDIR/llsetup.sh $SRCDIR/net-local.cfg $SRCDIR/ldlm.cfg $SRCDIR/obdecho.cfg $SRCDIR/client-echo.cfg || exit 2

cat <<EOF
**********************************************
To run tests, use $OBDCTL.
$OBDCTL
device `$OBDCTL name2dev OSCDEV`
probe

To test basic locking functionality:
test_ldlm

The regression stress test will start some
number of threads, each locking and unlocking
extents from a set of resources. To run it:
ldlm_regress_start [numthreads]

And to stop it:
ldlm_regress_stop
**********************************************
EOF
