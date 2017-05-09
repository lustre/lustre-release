FSNAME=${FSNAME:-lustre}

# facet hosts
mds_HOST=${mds_HOST:-$(hostname)}
mdsfailover_HOST=${mdsfailover_HOST}
mgs_HOST=${mgs_HOST:-$mds_HOST}
ost_HOST=${ost_HOST:-$(hostname)}
ostfailover_HOST=${ostfailover_HOST}
CLIENTS=""
# FILESET variable is used by sanity.sh to verify fileset
# feature, tests should pass even under subdirectory namespace.
FILESET=${FILESET:-""}
[[ -z "$FILESET" ]] || [[ "${FILESET:0:1}" = "/" ]] || FILESET="/$FILESET"

TMP=${TMP:-/tmp}

DAEMONSIZE=${DAEMONSIZE:-500}
MDSCOUNT=${MDSCOUNT:-1}
MDSDEVBASE=${MDSDEVBASE:-$TMP/${FSNAME}-mdt}
MDSSIZE=${MDSSIZE:-200000}
#
# Format options of facets can be specified with these variables:
#
#   - <facet_type>OPT
#
# Arguments for "--mkfsoptions" shall be specified with these
# variables:
#
#   - <fstype>_MKFS_OPTS
#   - <facet_type>_FS_MKFS_OPTS
#
# A number of other options have their own specific variables.  See
# mkfs_opts().
#
MDSOPT=${MDSOPT:-}
MDS_FS_MKFS_OPTS=${MDS_FS_MKFS_OPTS:-}
MDS_MOUNT_OPTS=${MDS_MOUNT_OPTS:-}
# <facet_type>_MOUNT_FS_OPTS is the mount options specified when formatting
# the underlying device by argument "--mountfsoptions"
MDS_MOUNT_FS_OPTS=${MDS_MOUNT_FS_OPTS:-}

MGSSIZE=${MGSSIZE:-$MDSSIZE}
MGSOPT=${MGSOPT:-}
MGS_FS_MKFS_OPTS=${MGS_FS_MKFS_OPTS:-}
MGS_MOUNT_OPTS=${MGS_MOUNT_OPTS:-}
MGS_MOUNT_FS_OPTS=${MGS_MOUNT_FS_OPTS:-}

OSTCOUNT=${OSTCOUNT:-2}
OSTDEVBASE=${OSTDEVBASE:-$TMP/${FSNAME}-ost}
OSTSIZE=${OSTSIZE:-400000}
OSTOPT=${OSTOPT:-}
OST_FS_MKFS_OPTS=${OST_FS_MKFS_OPTS:-}
OST_MOUNT_OPTS=${OST_MOUNT_OPTS:-}
OST_MOUNT_FS_OPTS=${OST_MOUNT_FS_OPTS:-}
OST_INDEX_LIST=${OST_INDEX_LIST:-}
# Can specify individual ost devs with
# OSTDEV1="/dev/sda"
# on specific hosts with
# ost1_HOST="uml2"
# ost1_JRN="/dev/sdb1"
#
# For ZFS, ost devices can be specified via either or both of the following:
# OSTZFSDEV1="${FSNAME}-ost1/ost1"
# OSTDEV1="/dev/sdb1"
#
# OST indices can be specified as follows:
# OSTINDEX1="1"
# OSTINDEX2="2"
# OSTINDEX3="4"
# ......
# or
# OST_INDEX_LIST="[1,2,4-6,8]"	# [n-m,l-k,...], where n < m and l < k, etc.
#
# The default index value of an individual OST is its facet number minus 1.
# More specific ones override more general ones. See facet_index().

NETTYPE=${NETTYPE:-tcp}
MGSNID=${MGSNID:-$(h2nettype $mgs_HOST)}

#
# Back end file system type(s) of facets can be specified with these
# variables:
#
#   1. <facet>_FSTYPE
#   2. <facet_type>FSTYPE
#   3. FSTYPE
#
# More specific ones override more general ones.  See facet_fstype().
#
FSTYPE=${FSTYPE:-ldiskfs}

LDISKFS_MKFS_OPTS=${LDISKFS_MKFS_OPTS:-}
ZFS_MKFS_OPTS=${ZFS_MKFS_OPTS:-}

LOAD_MODULES_REMOTE=${LOAD_MODULES_REMOTE:-false}

STRIPE_BYTES=${STRIPE_BYTES:-1048576}
STRIPES_PER_OBJ=${STRIPES_PER_OBJ:-0}
SINGLEMDS=${SINGLEMDS:-"mds1"}
TIMEOUT=${TIMEOUT:-20}
PTLDEBUG=${PTLDEBUG:-"vfstrace rpctrace dlmtrace neterror ha config \
		      ioctl super lfsck"}
SUBSYSTEM=${SUBSYSTEM:-"all"}

# promise 2MB for every cpu
if [ -f /sys/devices/system/cpu/possible ]; then
    _debug_mb=$((($(cut -d "-" -f 2 /sys/devices/system/cpu/possible)+1)*2))
else
    _debug_mb=$(($(getconf _NPROCESSORS_CONF)*2))
fi

DEBUG_SIZE=${DEBUG_SIZE:-$_debug_mb}

ENABLE_QUOTA=${ENABLE_QUOTA:-""}
QUOTA_TYPE="ug3"
QUOTA_USERS=${QUOTA_USERS:-"quota_usr quota_2usr sanityusr sanityusr1"}
# "error: conf_param: No such device" issue in every test suite logs
# sanity-quota test_32 hash_lqs_cur_bits is not set properly
LQUOTAOPTS=${LQUOTAOPTS:-"hash_lqs_cur_bits=3"}

#client
MOUNT=${MOUNT:-/mnt/${FSNAME}}
MOUNT1=${MOUNT1:-$MOUNT}
MOUNT2=${MOUNT2:-${MOUNT}2}
MOUNT3=${MOUNT3:-${MOUNT}3}
# Comma-separated option list used as "mount [...] -o $MOUNT_OPTS [...]"
MOUNT_OPTS=${MOUNT_OPTS:-"user_xattr,flock"}
# Mount flags (e.g. "-n") used as "mount [...] $MOUNT_FLAGS [...]"
MOUNT_FLAGS=${MOUNT_FLAGS:-""}
DIR=${DIR:-$MOUNT}
DIR1=${DIR:-$MOUNT1}
DIR2=${DIR2:-$MOUNT2}
DIR3=${DIR3:-$MOUNT3}

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

MPIRUN=${MPIRUN:-$(which mpirun 2>/dev/null || true)}
MPI_USER=${MPI_USER:-mpiuser}
SHARED_DIR_LOGS=${SHARED_DIR_LOGS:-""}
MACHINEFILE_OPTION=${MACHINEFILE_OPTION:-"-machinefile"}

# This is used by a small number of tests to share state between the client
# running the tests, or in some cases between the servers (e.g. lfsck.sh).
# It needs to be a non-lustre filesystem that is available on all the nodes.
SHARED_DIRECTORY=${SHARED_DIRECTORY:-$TMP}	# bug 17839 comment 65

#
# In order to test multiple remote HSM agents, a new facet type named "AGT" and
# the following associated variables are added:
#
# AGTCOUNT: number of agents
# AGTDEV{N}: target HSM mount point (root path of the backend)
# agt{N}_HOST: hostname of the agent agt{N}
# SINGLEAGT: facet of the single agent
#
# Please refer to init_agt_vars() in sanity-hsm.sh for the default values of
# these variables.
#
