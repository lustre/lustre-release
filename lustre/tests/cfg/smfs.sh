# oldstyle
MDSNODE=${MDSNODE:-`hostname`}
OSTNODE=${OSTNODE:-`hostname`}
CLIENT=${CLIENT:-client}

MDSCOUNT=1
mds_HOST=${mds_HOST:-$MDSNODE}
mds1_HOST=${mds1_HOST:-$MDSNODE}
mds2_HOST=$mds1_HOST
mdsfailover_HOST=${mdsfailover_HOST}
#cache_mds_HOST=${mds1_HOST:-$MDSNODE}
#master1_mds_HOST=$mds1_HOST
#master2_mds_HOST=$mds1_HOST

mds1failover_HOST=${mds1failover_HOST}
ost_HOST=${ost_HOST:-$OSTNODE}
client_HOST=${client_HOST:-$CLIENT}
NETTYPE=${NETTYPE:-tcp}

MOUNT=${MOUNT:-"/mnt/lustre"}
MOUNT1=${MOUNT1:-$MOUNT}
DIR=${DIR:-$MOUNT}
PTLDEBUG=${PTLDEBUG:-0x3f0400}
SUBSYSTEM=${SUBSYSTEM:- 0xffb7e3ff}
PDSH=${PDSH:-no_dsh}

MDS_CACHE_DEV=${MDS_CACHE_DEV:-$ROOT/tmp/mds1-`hostname`}
MDS_MASTER1_DEV=${MDS_MASTER1_DEV:-$ROOT/tmp/mds2-`hostname`}
MDS_MASTER2_DEV=${MDS_MASTER1_DEV:-$ROOT/tmp/mds3-`hostname`}

MDSSIZE=${MDSSIZE:-10000}
OSTDEV=${OSTDEV:-$ROOT/tmp/ost1-`hostname`}
OSTSIZE=${OSTSIZE:-50000}
FSTYPE=${FSTYPE:-smfs}
MDS_MOUNT_OPS=${MDS_MOUNT_OPS:-"kml"}
TIMEOUT=${TIMEOUT:-20}
UPCALL=${UPCALL:-DEFAULT}

CACHE_MDS=${CACHE_MDS:-"mds1"}
MASTER1_MDS=${MASTER1_MDS:-"mds2"}
MASTER2_MDS=${MASTER2_MDS:-"mds3"}
CMOBD_NAME=${CMOBD_NAME:-"cmobd_mds_svc"}

STRIPE_BYTES=${STRIPE_BYTES:-524288}
STRIPES_PER_OBJ=${STRIPES_PER_OBJ:-0}

LCTL=${LCTL:-"../utils/lctl"}
FAILURE_MODE=${FAILURE_MODE:-SOFT} # or HARD
POWER_DOWN=${POWER_DOWN:-"powerman --off"}
POWER_UP=${POWER_UP:-"powerman --on"}
