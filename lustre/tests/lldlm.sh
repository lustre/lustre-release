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
ldlm_regress_start [numthreads [refheld [numres [numext]]]] 
numthreads is the number of threads to start.
       (default 1)
refheld is the total number of resources to hold,
       between all the threads. Once this number
       is reached, every time a lock is granted
       or matched, the oldest reference is
       decremented.
       (default 10)
numres is the number of resources to use
       (default 10)
numext is the number of extents to divide
       each resource into
       (default 10)

To stop the test:
ldlm_regress_stop
**********************************************
EOF
