# oldstyle
MDSNODE=${MDSNODE:-`hostname`}
OSTNODE=${OSTNODE:-`hostname`}
CLIENT=${CLIENT:-client}

FSNAME=lustre
mds_HOST=${mds_HOST:-$MDSNODE}
mdsfailover_HOST=${mdsfailover_HOST}
mgs_HOST=${mgs_HOST:-$mds_HOST}
ost_HOST=${ost_HOST:-$OSTNODE}
ostfailover_HOST=${ostfailover_HOST}
ost2_HOST=${ost2_HOST:-$ost_HOST}

TMP=${TMP:-/tmp}
MDSDEV=${MDSDEV:-$TMP/${FSNAME}-mdt}
MDSSIZE=${MDSSIZE:-100000}
MDSOPT=${MDSOPT:-"--mountfsoptions=acl"}
OSTDEV=${OSTDEV:-$TMP/${FSNAME}-ost0}
OSTSIZE=${OSTSIZE:-200000}
OSTDEV2=${OSTDEV2:-$TMP/${FSNAME}-ost1}

NETTYPE=${NETTYPE:-tcp}
MGSNID=`h2$NETTYPE $mgs_HOST`
FSTYPE=${FSTYPE:-ldiskfs}
STRIPE_BYTES=${STRIPE_BYTES:-1048576}
STRIPES_PER_OBJ=${STRIPES_PER_OBJ:-0}
TIMEOUT=${TIMEOUT:-20}
UPCALL=${UPCALL:-DEFAULT}
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
MDS_MKFS_OPTS="--mgs --mdt --device-size=$MDSSIZE --param obd_timeout=$TIMEOUT $MKFSOPT $MOUNTOPT $MDSOPT"

MKFSOPT=""
MOUNTOPT=""
[ "x$OSTJOURNALSIZE" != "x" ] &&
    MKFSOPT=$MKFSOPT" -J size=$OSTJOURNALSIZE"
[ "x$MKFSOPT" != "x" ] &&
    MKFSOPT="--mkfsoptions=\"$MKFSOPT\""
[ "x$ostfailover_HOST" != "x" ] &&
    MOUNTOPT=$MOUNTOPT" --failnode=`h2$NETTYPE $ostfailover_HOST`"
OST_MKFS_OPTS="--ost --device-size=$OSTSIZE --mgsnode=$MGSNID --param obd_timeout=$TIMEOUT $MKFSOPT $MOUNTOPT $OSTOPT"
OST2_MKFS_OPTS=${OST2_MKFS_OPTS:-${OST_MKFS_OPTS}}

MDS_MOUNT_OPTS="-o loop"
OST_MOUNT_OPTS="-o loop"
OST2_MOUNT_OPTS="-o loop"

MOUNT=${MOUNT:-/mnt/${FSNAME}}
MOUNT1=${MOUNT1:-$MOUNT}
MOUNT2=${MOUNT2:-${MOUNT}2}
DIR=${DIR:-$MOUNT}
DIR1=${DIR:-$MOUNT1}
DIR2=${DIR2:-$MOUNT2}
MOUNTOPT=${MOUNTOPT:-"user_xattr,acl"}

PDSH=${PDSH:-no_dsh}
FAILURE_MODE=${FAILURE_MODE:-SOFT} # or HARD
POWER_DOWN=${POWER_DOWN:-"powerman --off"}
POWER_UP=${POWER_UP:-"powerman --on"}
