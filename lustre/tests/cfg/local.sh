FSNAME=${FSNAME:-lustre}

# facet hosts
mds_HOST=${mds_HOST:-`hostname`}
mdsfailover_HOST=${mdsfailover_HOST}
mds1_HOST=${mds1_HOST:-$mds_HOST}
mds1failover_HOST=${mds1failover_HOST:-$mdsfailover_HOST}
mgs_HOST=${mgs_HOST:-$mds1_HOST}
ost_HOST=${ost_HOST:-`hostname`}
ostfailover_HOST=${ostfailover_HOST}
CLIENTS=""

TMP=${TMP:-/tmp}

DAEMONSIZE=${DAEMONSIZE:-500}
MDSCOUNT=${MDSCOUNT:-1}
[ $MDSCOUNT -gt 4 ] && MDSCOUNT=4
[ $MDSCOUNT -gt 1 ] && IAMDIR=yes
for num in $(seq $MDSCOUNT); do
    eval mds${num}_HOST=\$\{mds${num}_HOST:-$mds_HOST\}
    eval mds${num}failover_HOST=\$\{mds${num}failover_HOST:-$mdsfailover_HOST\}
done
MDSDEVBASE=${MDSDEVBASE:-$TMP/${FSNAME}-mdt}
MDSSIZE=${MDSSIZE:-200000}
MDSOPT=${MDSOPT:-"--mountfsoptions=errors=remount-ro,user_xattr,acl"}

MGSDEV=${MGSDEV:-$MDSDEV1}
MGSSIZE=${MGSSIZE:-$MDSSIZE}

OSTCOUNT=${OSTCOUNT:-2}
OSTDEVBASE=${OSTDEVBASE:-$TMP/${FSNAME}-ost}
OSTSIZE=${OSTSIZE:-200000}
OSTOPT=""
# Can specify individual ost devs with
# OSTDEV1="/dev/sda"
# on specific hosts with
# ost1_HOST="uml2"

NETTYPE=${NETTYPE:-tcp}
MGSNID=${MGSNID:-`h2$NETTYPE $mgs_HOST`}
FSTYPE=${FSTYPE:-ldiskfs}
STRIPE_BYTES=${STRIPE_BYTES:-1048576}
STRIPES_PER_OBJ=${STRIPES_PER_OBJ:-0}
SINGLEMDS=${SINGLEMDS:-"mds1"}
TIMEOUT=${TIMEOUT:-20}
PTLDEBUG=${PTLDEBUG:-0x33f0404}

# promise 2MB for every cpu
if [ -f /sys/devices/system/cpu/possible ]; then
    _debug_mb=$((($(cut -d "-" -f 2 /sys/devices/system/cpu/possible)+1)*2))
else
    _debug_mb=$(($(getconf _NPROCESSORS_CONF)*2))
fi

DEBUG_SIZE=${DEBUG_SIZE:-$_debug_mb}

SUBSYSTEM=${SUBSYSTEM:- 0xffb7e3ff}

ENABLE_QUOTA=${ENABLE_QUOTA:-""}
QUOTA_TYPE="ug3"
QUOTA_USERS=${QUOTA_USERS:-"quota_usr quota_2usr sanityusr sanityusr1"}
LQUOTAOPTS=${LQUOTAOPTS:-"hash_lqs_cur_bits=3"}

MKFSOPT=""
[ "x$MDSJOURNALSIZE" != "x" ] &&
    MKFSOPT=$MKFSOPT" -J size=$MDSJOURNALSIZE"
[ "x$MDSISIZE" != "x" ] &&
    MKFSOPT=$MKFSOPT" -i $MDSISIZE"
[ "x$MKFSOPT" != "x" ] &&
    MKFSOPT="--mkfsoptions=\\\"$MKFSOPT\\\""
[ "x$SECLEVEL" != "x" ] &&
    MKFSOPT=$MKFSOPT" --param mdt.sec_level=$SECLEVEL"
[ "x$MDSCAPA" != "x" ] &&
    MKFSOPT=$MKFSOPT" --param mdt.capa=$MDSCAPA"
[ "x$mdsfailover_HOST" != "x" ] &&
    MDSOPT=$MDSOPT" --failnode=`h2$NETTYPE $mdsfailover_HOST`"
[ "x$STRIPE_BYTES" != "x" ] &&
    MDSOPT=$MDSOPT" --param lov.stripesize=$STRIPE_BYTES"
[ "x$STRIPES_PER_OBJ" != "x" ] &&
    MDSOPT=$MDSOPT" --param lov.stripecount=$STRIPES_PER_OBJ"
[ "x$L_GETIDENTITY" != "x" ] &&
    MDSOPT=$MDSOPT" --param mdt.identity_upcall=$L_GETIDENTITY"

MDS_MKFS_OPTS="--mdt --fsname=$FSNAME --device-size=$MDSSIZE --param sys.timeout=$TIMEOUT $MKFSOPT $MDSOPT $MDS_MKFS_OPTS"
if [[ $mds1_HOST == $mgs_HOST ]] && [[ $MDSDEV1 == $MGSDEV ]]; then
    MDS_MKFS_OPTS="--mgs $MDS_MKFS_OPTS"
else
    MDS_MKFS_OPTS="--mgsnode=$MGSNID $MDS_MKFS_OPTS"
    MGS_MKFS_OPTS="--mgs --device-size=$MGSSIZE"
fi

MKFSOPT=""
[ "x$OSTJOURNALSIZE" != "x" ] &&
    MKFSOPT=$MKFSOPT" -J size=$OSTJOURNALSIZE"
[ "x$MKFSOPT" != "x" ] &&
    MKFSOPT="--mkfsoptions=\\\"$MKFSOPT\\\""
[ "x$SECLEVEL" != "x" ] &&
    MKFSOPT=$MKFSOPT" --param ost.sec_level=$SECLEVEL"
[ "x$OSSCAPA" != "x" ] &&
    MKFSOPT=$MKFSOPT" --param ost.capa=$OSSCAPA"
[ "x$ostfailover_HOST" != "x" ] &&
    OSTOPT=$OSTOPT" --failnode=`h2$NETTYPE $ostfailover_HOST`"
OST_MKFS_OPTS="--ost --fsname=$FSNAME --device-size=$OSTSIZE --mgsnode=$MGSNID --param sys.timeout=$TIMEOUT $MKFSOPT $OSTOPT $OST_MKFS_OPTS"

MDS_MOUNT_OPTS=${MDS_MOUNT_OPTS:-"-o loop,user_xattr,acl"}
OST_MOUNT_OPTS=${OST_MOUNT_OPTS:-"-o loop"}
MGS_MOUNT_OPTS=${MGS_MOUNT_OPTS:-$MDS_MOUNT_OPTS}

#client
MOUNT=${MOUNT:-/mnt/${FSNAME}}
MOUNT1=${MOUNT1:-$MOUNT}
MOUNT2=${MOUNT2:-${MOUNT}2}
MOUNTOPT=${MOUNTOPT:-"-o user_xattr,acl,flock"}
DIR=${DIR:-$MOUNT}
DIR1=${DIR:-$MOUNT1}
DIR2=${DIR2:-$MOUNT2}

if [ $UID -ne 0 ]; then
        log "running as non-root uid $UID"
        RUNAS_ID="$UID"
        RUNAS_GID=`id -g $USER`
        RUNAS=""
else
        RUNAS_ID=${RUNAS_ID:-500}
        RUNAS_GID=${RUNAS_GID:-$RUNAS_ID}
        RUNAS=${RUNAS:-"runas -u $RUNAS_ID -g $RUNAS_GID"}
fi

PDSH=${PDSH:-no_dsh}
FAILURE_MODE=${FAILURE_MODE:-SOFT} # or HARD
POWER_DOWN=${POWER_DOWN:-"powerman --off"}
POWER_UP=${POWER_UP:-"powerman --on"}
SLOW=${SLOW:-no}
FAIL_ON_ERROR=${FAIL_ON_ERROR:-true}

MPIRUN=$(which mpirun 2>/dev/null) || true
MPI_USER=${MPI_USER:-mpiuser}
MACHINEFILE_OPTION=${MACHINEFILE_OPTION:-"-machinefile"}

# This is used by a small number of tests to share state between the client
# running the tests, or in some cases between the servers (e.g. lfsck.sh).
# It needs to be a non-lustre filesystem that is available on all the nodes.
SHARED_DIRECTORY=${SHARED_DIRECTORY:-""}	# bug 17839 comment 65
