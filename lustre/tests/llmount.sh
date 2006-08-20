#!/bin/sh

export PATH=`dirname $0`/../utils:$PATH

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/local.sh}

[ -z "$NOFORMAT" ] && formatall
[ -z "$NOSETUP" ] && setupall
