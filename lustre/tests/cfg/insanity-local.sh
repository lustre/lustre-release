FSNAME=lustre
mds_HOST=${mds_HOST:-`hostname`}
mgs_HOST=${mgs_HOST:-$mds_HOST}
mdsfailover_HOST=${mdsfailover_HOST:-""}
ost1_HOST=${ost1_HOST:-"`hostname`"}
ost2_HOST=${ost2_HOST:-"`hostname`"}
EXTRA_OSTS=${EXTRA_OSTS:-"`hostname`"}
LIVE_CLIENT=${LIVE_CLIENT:-"`hostname`"}
# This should always be a list, not a regexp
FAIL_CLIENTS=${FAIL_CLIENTS:-""}

MDSDEV=${MDSDEV:-$TMP/${FSNAME}-mdt}
MDSSIZE=${MDSSIZE:-10000} #50000000
OSTDEV=${OSTDEV:-"$TMP/${FSNAME}-ost%d"}
OSTSIZE=${OSTSIZE:=10000} #50000000

NETTYPE=${NETTYPE:-tcp}
MGSNID=`h2$NETTYPE $mgs_HOST`
FSTYPE=${FSTYPE:-ext3}
STRIPE_BYTES=${STRIPE_BYTES:-1048576}
STRIPES_PER_OBJ=${STRIPES_PER_OBJ:-0}
TIMEOUT=${TIMEOUT:-30}
PTLDEBUG=${PTLDEBUG:-0x33f0404}
SUBSYSTEM=${SUBSYSTEM:- 0xffb7e3ff}

MKFSOPT=""
MOUNTOPT=""
[ "x$MDSJOURNALSIZE" != "x" ] &&
    MKFSOPT=$MKFSOPT" -J size=$MDSJOURNALSIZE"
[ "x$MDSISIZE" != "x" ] &&
    MKFSOPT=$MKFSOPT" -i $MDSISIZE"
[ "x$MKFSOPT" != "x" ] &&
    MKFSOPT="--mkfsoptions=\"$MKFSOPT\""
[ "x$mdsfailover_HOST" != "x" ] &&
    MOUNTOPT=$MOUNTOPT" --failnode=`h2$NETTYPE $mdsfailover_HOST`"
[ "x$STRIPE_BYTES" != "x" ] &&
    MOUNTOPT=$MOUNTOPT" --param default_stripe_size=$STRIPE_BYTES"
[ "x$STRIPES_PER_OBJ" != "x" ] &&
    MOUNTOPT=$MOUNTOPT" --param default_stripe_count=$STRIPES_PER_OBJ"
MDS_MKFS_OPTS="--mgs --mdt --device-size=$MDSSIZE $MKFSOPT $MOUNTOPT $MDSOPT"

MKFSOPT=""
MOUNTOPT=""
[ "x$OSTJOURNALSIZE" != "x" ] &&
    MKFSOPT=$MKFSOPT" -J size=$OSTJOURNALSIZE"
[ "x$MKFSOPT" != "x" ] &&
    MKFSOPT="--mkfsoptions=\"$MKFSOPT\""
[ "x$ostfailover_HOST" != "x" ] &&
    MOUNTOPT=$MOUNTOPT" --failnode=`h2$NETTYPE $ostfailover_HOST`"
OST_MKFS_OPTS="--ost --device-size=$OSTSIZE --mgsnode=$MGSNID $MKFSOPT $MOUNTOPT $OSTOPT"

MDS_MOUNT_OPTS="-o loop"
OST_MOUNT_OPTS="-o loop"
MOUNT=${MOUNT:-"/mnt/lustre"}

PDSH=${PDSH:-no_dsh}
FAILURE_MODE=${FAILURE_MODE:-SOFT} # or HARD
POWER_DOWN=${POWER_DOWN:-"powerman --off"}
POWER_UP=${POWER_UP:-"powerman --on"}

PDSH=${PDSH:-no_dsh}
