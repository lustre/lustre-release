#!/bin/bash
export PATH=`dirname $0`/../utils:$PATH
NAME=${NAME:-local}

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}

if [ ! -f $LUSTRE/tests/rpc.sh ]; then
    LUSTRE=$(cd $(dirname $(which $0))/..; echo $PWD)
fi

. $LUSTRE/tests/test-framework.sh
RPC_MODE=true init_test_env
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

# Reset the trap on ERR set by the framework.  Noticing this failure is the
# framework's job.
trap - ERR

log "$HOSTNAME: executing $@"
# Execute the command
"$@"
