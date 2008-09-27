FSNAME=lustre

# facet hosts
mds_HOST=${mds_HOST:-`hostname`}
mdsfailover_HOST=${mdsfailover_HOST}
mgs_HOST=${mgs_HOST:-$mds_HOST}
ost_HOST=${ost_HOST:-`hostname`}
ostfailover_HOST=${ostfailover_HOST}

mds1_HOST=${mds1_HOST:-$mds_HOST}
mds2_HOST=${mds2_HOST:-$mds_HOST}
mds3_HOST=${mds3_HOST:-$mds_HOST}
mds4_HOST=${mds4_HOST:-$mds_HOST}
ost2_HOST=${ost2_HOST:-$ost_HOST}
gks_HOST=${gks_HOST:-$mds_HOST}

NETTYPE=${NETTYPE:-tcp}
MGSNID=${MGSNID:-`h2$NETTYPE $mgs_HOST`}
FSTYPE=${FSTYPE:-ldiskfs}
STRIPE_BYTES=${STRIPE_BYTES:-1048576}
STRIPES_PER_OBJ=${STRIPES_PER_OBJ:-$((OSTCOUNT -1))}
TIMEOUT=${TIMEOUT:-20}
PTLDEBUG=${PTLDEBUG:-0x33f0404}
DEBUG_SIZE=${DEBUG_SIZE:-10}
SUBSYSTEM=${SUBSYSTEM:-0xffb7e3ff}

TMP=${TMP:-/tmp}

MDSDEV=${MDSDEV:-$TMP/${FSNAME}-mdt1}
MDSCOUNT=${MDSCOUNT:-3}
test $MDSCOUNT -gt 4 && MDSCOUNT=4
MDSDEVBASE=${MDSDEVBASE:-$TMP/${FSNAME}-mdt}
MDSSIZE=${MDSSIZE:-100000}

OSTCOUNT=${OSTCOUNT:-2}
OSTDEVBASE=${OSTDEVBASE:-$TMP/${FSNAME}-ost}
OSTSIZE=${OSTSIZE:-200000}

#client
MOUNT=${MOUNT:-/mnt/${FSNAME}}
MOUNT1=${MOUNT1:-$MOUNT}
MOUNT2=${MOUNT2:-${MOUNT}2}
MOUNTOPT=${MOUNTOPT:-"user_xattr,"}
[ "x$RMTCLIENT" != "x" ] &&
	MOUNTOPT=$MOUNTOPT",remote_client"
DIR=${DIR:-$MOUNT}
DIR1=${DIR:-$MOUNT1}
DIR2=${DIR2:-$MOUNT2}

if [ $UID -ne 0 ]; then
        log "running as non-root uid $UID"
        RUNAS_ID="$UID"
        RUNAS=""
else
        RUNAS_ID=${RUNAS_ID:-500}
        RUNAS=${RUNAS:-"runas -u $RUNAS_ID"}
fi

PDSH=${PDSH:-no_dsh}
FAILURE_MODE=${FAILURE_MODE:-SOFT} # or HARD
POWER_DOWN=${POWER_DOWN:-"powerman --off"}
POWER_UP=${POWER_UP:-"powerman --on"}

MKFSOPT=""
MOUNTOPT=""
[ "x$MDSJOURNALSIZE" != "x" ] &&
    MKFSOPT=$MKFSOPT" -J size=$MDSJOURNALSIZE"
[ "x$MDSISIZE" != "x" ] &&
    MKFSOPT=$MKFSOPT" -i $MDSISIZE"
[ "x$MKFSOPT" != "x" ] &&
    MKFSOPT="--mkfsoptions=\"$MKFSOPT\""
[ "x$MDSCAPA" != "x" ] &&
    MKFSOPT="--param mdt.capa=$MDSCAPA"
[ "x$mdsfailover_HOST" != "x" ] &&
    MOUNTOPT=$MOUNTOPT" --failnode=`h2$NETTYPE $mdsfailover_HOST`"
[ "x$STRIPE_BYTES" != "x" ] &&
    MOUNTOPT=$MOUNTOPT" --param lov.stripesize=$STRIPE_BYTES"
[ "x$STRIPES_PER_OBJ" != "x" ] &&
    MOUNTOPT=$MOUNTOPT" --param lov.stripecount=$STRIPES_PER_OBJ"
[ "x$L_GETIDENTITY" != "x" ] &&
    MOUNTOPT=$MOUNTOPT" --param mdt.identity_upcall=$L_GETIDENTITY"
MDS_MKFS_OPTS="--mgs --mdt --fsname=$FSNAME --device-size=$MDSSIZE --param sys.timeout=$TIMEOUT $MKFSOPT $MOUNTOPT $MDSOPT"
MDSn_MKFS_OPTS="--mgsnode=$MGSNID --mdt --fsname=$FSNAME --device-size=$MDSSIZE --param sys.timeout=$TIMEOUT $MKFSOPT $MOUNTOPT $MDSOPT"

MKFSOPT=""
MOUNTOPT=""
[ "x$OSTJOURNALSIZE" != "x" ] &&
    MKFSOPT=$MKFSOPT" -J size=$OSTJOURNALSIZE"
[ "x$MKFSOPT" != "x" ] &&
    MKFSOPT="--mkfsoptions=\"$MKFSOPT\""
[ "x$OSSCAPA" != "x" ] &&
    MKFSOPT="--param ost.capa=$OSSCAPA"
[ "x$ostfailover_HOST" != "x" ] &&
    MOUNTOPT=$MOUNTOPT" --failnode=`h2$NETTYPE $ostfailover_HOST`"
OST_MKFS_OPTS="--ost --fsname=$FSNAME --device-size=$OSTSIZE --mgsnode=$MGSNID --param sys.timeout=$TIMEOUT $MKFSOPT $MOUNTOPT $OSTOPT"

MDS_MOUNT_OPTS=${MDS_MOUNT_OPTS:-"-o loop"}
OST_MOUNT_OPTS=${OST_MOUNT_OPTS:-"-o loop"}

SINGLEMDS=${SINGLEMDS:-"mds1"}
