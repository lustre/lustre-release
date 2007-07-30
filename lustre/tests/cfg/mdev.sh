
mds_HOST=${mds_HOST:-mdev4}
mdsfailover_HOST=${mdsfailover_HOST:-mdev5}
ost_HOST=${ost_HOST:-mdev2}
ost2_HOST=${ost2_HOST:-mdev3}
client_HOST=${client_HOST:-client}
NETTYPE=${NETTYPE:-tcp}
SINGLEMDS=${SINGLEMDS:-"mds"}

MOUNT=${MOUNT:-"/mnt/lustre"}
MOUNT1=${MOUNT1:-$MOUNT}
MOUNT2=${MOUNT2:-"/mnt/lustre2"}
DIR=${DIR:-$MOUNT}
DIR2=${DIR2:-$MOUNT1}
PTLDEBUG=${PTLDEBUG:-0x3f0400}
SUBSYSTEM=${SUBSYSTEM:- 0xffb7e3ff}
PDSH=${PDSH:-pdsh -S -w}

MDSDEV=${MDSDEV:-/dev/sda1}
MDSSIZE=${MDSSIZE:-100000}
OSTDEV=${OSTDEV:-/tmp/ost1-`hostname`}
OSTSIZE=${OSTSIZE:-200000}
FSTYPE=${FSTYPE:-ext3}
TIMEOUT=${TIMEOUT:-10}
#UPCALL=${UPCALL:-$PWD/replay-single-upcall.sh}

STRIPE_BYTES=${STRIPE_BYTES:-1048576}
STRIPES_PER_OBJ=${STRIPES_PER_OBJ:-0}

FAILURE_MODE=${FAILURE_MODE:-SOFT} # or HARD
POWER_DOWN=${POWER_DOWN:-"powerman --off"}
POWER_UP=${POWER_UP:-"powerman --on"}
