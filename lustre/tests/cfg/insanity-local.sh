mds_HOST=${mds_HOST:-`hostname`}
mdsfailover_HOST=${mdsfailover_HOST:-""}
ost1_HOST=${ost1_HOST:-"`hostname`"}
ost2_HOST=${ost2_HOST:-"`hostname`"}
client_HOST="'*'"
LIVE_CLIENT=${LIVE_CLIENT:-"`hostname`"}
# This should always be a list, not a regexp
FAIL_CLIENTS=${FAIL_CLIENTS:-""}

NETTYPE=${NETTYPE:-tcp}
TIMEOUT=${TIMEOUT:-30}
PTLDEBUG=${PTLDEBUG:-0}
SUBSYSTEM=${SUBSYSTEM:-0}
MOUNT=${MOUNT:-"/mnt/lustre"}
#CLIENT_UPCALL=${CLIENT_UPCALL:-`pwd`/client-upcall-mdev.sh}
UPCALL=${CLIENT_UPCALL:-`pwd`/replay-single-upcall.sh}

MDSDEV=${MDSDEV:-$ROOT/tmp/mds-`hostname`}
MDSSIZE=${MDSSIZE:-10000} #50000000

OSTDEV=${OSTDEV:-$ROOT/tmp/ost-`hostname`}
OSTSIZE=${OSTSIZE:=10000} #50000000
FSTYPE=${FSTYPE:-ext3}
STRIPE_BYTES=${STRIPE_BYTES:-65536} #1048576
STRIPES_PER_OBJ=${STRIPES_PER_OBJ:-0}

FAILURE_MODE=${FAILURE_MODE:-SOFT} # or HARD
POWER_DOWN=${POWER_DOWN:-"powerman --off"}
POWER_UP=${POWER_UP:-"powerman --on"}

PDSH=no_dsh
