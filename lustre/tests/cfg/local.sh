# oldstyle
MDSNODE=${MDSNODE:-`hostname`}
OSTNODE=${OSTNODE:-`hostname`}
CLIENT=${CLIENT:-client}

mds_HOST=${mds_HOST:-$MDSNODE}
mdsfailover_HOST=${mdsfailover_HOST}
ost_HOST=${ost_HOST:-$OSTNODE}
ost2_HOST=${ost2_HOST:-$ost_HOST}
client_HOST=${client_HOST:-$CLIENT}
NETTYPE=${NETTYPE:-tcp}

MOUNT=${MOUNT:-"/mnt/lustre"}
MOUNT1=${MOUNT1:-$MOUNT}
MOUNT2=${MOUNT2:-"/mnt/lustre2"}
DIR=${DIR:-$MOUNT}
DIR2=${DIR2:-$MOUNT1}
PTLDEBUG=${PTLDEBUG:-0x3f0400}
SUBSYSTEM=${SUBSYSTEM:-0}
PDSH=${PDSH:-no_dsh}

MDSDEV=${MDSDEV:-$ROOT/tmp/mds-`hostname`}
MDSSIZE=${MDSSIZE:-10000}
OSTDEV=${OSTDEV:-$ROOT/tmp/ost-`hostname`}
OSTSIZE=${OSTSIZE:-10000}
FSTYPE=${FSTYPE:-ext3}
TIMEOUT=${TIMEOUT:-10}
UPCALL=${UPCALL:-$PWD/replay-single-upcall.sh}

STRIPE_BYTES=${STRIPE_BYTES:-65536}
STRIPES_PER_OBJ=${STRIPES_PER_OBJ:-0}

FAILURE_MODE=${FAILURE_MODE:-SOFT} # or HARD
POWER_DOWN=${POWER_DOWN:-"powerman --off"}
POWER_UP=${POWER_UP:-"powerman --on"}
