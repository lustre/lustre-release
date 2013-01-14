#!/bin/bash
# vim:expandtab:shiftwidth=4:softtabstop=4:tabstop=4:

trap 'print_summary && touch $TF_FAIL && \
    echo "test-framework exiting on error"' ERR
set -e
#set -x


export REFORMAT=${REFORMAT:-""}
export WRITECONF=${WRITECONF:-""}
export VERBOSE=${VERBOSE:-false}
export GMNALNID=${GMNALNID:-/usr/sbin/gmlndnid}
export CATASTROPHE=${CATASTROPHE:-/proc/sys/lnet/catastrophe}
#export PDSH="pdsh -S -Rssh -w"

# function used by scripts run on remote nodes
LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/functions.sh
. $LUSTRE/tests/yaml.sh

LUSTRE_TESTS_CFG_DIR=${LUSTRE_TESTS_CFG_DIR:-${LUSTRE}/tests/cfg}

EXCEPT_LIST_FILE=${EXCEPT_LIST_FILE:-${LUSTRE_TESTS_CFG_DIR}/tests-to-skip.sh}

if [ -f "$EXCEPT_LIST_FILE" ]; then
    echo "Reading test skip list from $EXCEPT_LIST_FILE"
    cat $EXCEPT_LIST_FILE
    . $EXCEPT_LIST_FILE
fi

# check config files for options in decreasing order of preference
[ -z "$MODPROBECONF" -a -f /etc/modprobe.d/lustre.conf ] &&
    MODPROBECONF=/etc/modprobe.d/lustre.conf
[ -z "$MODPROBECONF" -a -f /etc/modprobe.d/Lustre ] &&
    MODPROBECONF=/etc/modprobe.d/Lustre
[ -z "$MODPROBECONF" -a -f /etc/modprobe.conf ] &&
    MODPROBECONF=/etc/modprobe.conf

assert_DIR () {
    local failed=""
    [[ $DIR/ = $MOUNT/* ]] || \
        { failed=1 && echo "DIR=$DIR not in $MOUNT. Aborting."; }
    [[ $DIR1/ = $MOUNT1/* ]] || \
        { failed=1 && echo "DIR1=$DIR1 not in $MOUNT1. Aborting."; }
    [[ $DIR2/ = $MOUNT2/* ]] || \
        { failed=1 && echo "DIR2=$DIR2 not in $MOUNT2. Aborting"; }

    [ -n "$failed" ] && exit 99 || true
}

usage() {
    echo "usage: $0 [-r] [-f cfgfile]"
    echo "       -r: reformat"

    exit
}

print_summary () {
    trap 0
    [ "$TESTSUITE" == "lfsck" ] && return 0
    [ -n "$ONLY" ] && echo "WARNING: ONLY is set to $(echo $ONLY)"
    local details
    local form="%-13s %-17s %-9s %s %s\n"
    printf "$form" "status" "script" "Total(sec)" "E(xcluded) S(low)"
    echo "------------------------------------------------------------------------------------"
    for O in $DEFAULT_SUITES; do
        [ "${!O}" = "no" ] && continue || true
        O=$(echo $O  | tr "-" "_" | tr "[:lower:]" "[:upper:]")
        local o=$(echo $O | tr "[:upper:]" "[:lower:]")
        o=${o//_/-}
        local log=${TMP}/${o}.log
        if is_sanity_benchmark $o; then
            log=${TMP}/sanity-benchmark.log
        fi
        local slow=
        local skipped=
        local total=
        local status=Unfinished
        if [ -f $log ]; then
            skipped=$(grep excluded $log | awk '{ printf " %s", $3 }' | sed 's/test_//g')
            slow=$(egrep "^PASS|^FAIL" $log | tr -d "("| sed s/s\)$//g | sort -nr -k 3  | head -5 |  awk '{ print $2":"$3"s" }')
            total=$(grep duration $log | awk '{ print $2}')
            if [ "${!O}" = "done" ]; then
                status=Done
            fi
            if $DDETAILS; then
                local durations=$(egrep "^PASS|^FAIL" $log |  tr -d "("| sed s/s\)$//g | awk '{ print $2":"$3"|" }')
                details=$(printf "%s\n%s %s %s\n" "$details" "DDETAILS" "$O" "$(echo $durations)")
            fi
        fi
        printf "$form" $status "$O" "${total}" "E=$skipped"
        printf "$form" "-" "-" "-" "S=$(echo $slow)"
    done

    for O in $DEFAULT_SUITES; do
        O=$(echo $O  | tr "-" "_" | tr "[:lower:]" "[:upper:]")
        if [ "${!O}" = "no" ]; then
            # FIXME.
            # only for those tests suits which are run directly from acc-sm script:
            # bonnie, iozone, etc.
            if [ -f "$TESTSUITELOG" ] && grep FAIL $TESTSUITELOG | grep -q ' '$O  ; then
               printf "$form" "UNFINISHED" "$O" ""
            else
               printf "$form" "Skipped" "$O" ""
            fi
        fi
    done

    for O in $DEFAULT_SUITES; do
        O=$(echo $O  | tr "-" "_" | tr "[:lower:]" "[:upper:]")
        [ "${!O}" = "done" -o "${!O}" = "no" ] || \
            printf "$form" "UNFINISHED" "$O" ""
    done
}

init_test_env() {
    export LUSTRE=`absolute_path $LUSTRE`
    export TESTSUITE=`basename $0 .sh`
    export TEST_FAILED=false
    export FAIL_ON_SKIP_ENV=${FAIL_ON_SKIP_ENV:-false}

    export MKE2FS=${MKE2FS:-mke2fs}
    export DEBUGFS=${DEBUGFS:-debugfs}
    export TUNE2FS=${TUNE2FS:-tune2fs}
    export E2LABEL=${E2LABEL:-e2label}
    export DUMPE2FS=${DUMPE2FS:-dumpe2fs}
    export E2FSCK=${E2FSCK:-e2fsck}
    export LFSCK_BIN=${LFSCK_BIN:-lfsck}

    export LFSCK_ALWAYS=${LFSCK_ALWAYS:-"no"} # check fs after each test suite
    export FSCK_MAX_ERR=4   # File system errors left uncorrected
    declare -a OSTDEVS

    #[ -d /r ] && export ROOT=${ROOT:-/r}
    export TMP=${TMP:-$ROOT/tmp}
    export TESTSUITELOG=${TMP}/${TESTSUITE}.log
    export LOGDIR=${LOGDIR:-${TMP}/test_logs/$(date +%s)}
    export TESTLOG_PREFIX=$LOGDIR/$TESTSUITE

    export HOSTNAME=${HOSTNAME:-`hostname -s`}
    if ! echo $PATH | grep -q $LUSTRE/utils; then
        export PATH=$PATH:$LUSTRE/utils
    fi
    if ! echo ":$PATH:" | grep -q ":$LUSTRE/tests:"; then
        export PATH=$LUSTRE/tests:$PATH
    fi
    if ! echo $PATH | grep -q $LUSTRE/../lustre-iokit/sgpdd-survey; then
        export PATH=$PATH:$LUSTRE/../lustre-iokit/sgpdd-survey
    fi
    export LST=${LST:-"$LUSTRE/../lnet/utils/lst"}
    [ ! -f "$LST" ] && export LST=$(which lst)
    export SGPDDSURVEY=${SGPDDSURVEY:-"$LUSTRE/../lustre-iokit/sgpdd-survey/sgpdd-survey")}
    [ ! -f "$SGPDDSURVEY" ] && export SGPDDSURVEY=$(which sgpdd-survey)
    # Ubuntu, at least, has a truncate command in /usr/bin
    # so fully path our truncate command.
    export TRUNCATE=${TRUNCATE:-$LUSTRE/tests/truncate}
    export MDSRATE=${MDSRATE:-"$LUSTRE/tests/mpi/mdsrate"}
    [ ! -f "$MDSRATE" ] && export MDSRATE=$(which mdsrate 2> /dev/null)
    if ! echo $PATH | grep -q $LUSTRE/tests/racer; then
        export PATH=$LUSTRE/tests/racer:$PATH:
    fi
    if ! echo $PATH | grep -q $LUSTRE/tests/mpi; then
        export PATH=$PATH:$LUSTRE/tests/mpi
    fi
    export RSYNC_RSH=${RSYNC_RSH:-rsh}
    export LCTL=${LCTL:-"$LUSTRE/utils/lctl"}
    [ ! -f "$LCTL" ] && export LCTL=$(which lctl)
    export LFS=${LFS:-"$LUSTRE/utils/lfs"}
    [ ! -f "$LFS" ] && export LFS=$(which lfs)
    export MKFS=${MKFS:-"$LUSTRE/utils/mkfs.lustre"}
    [ ! -f "$MKFS" ] && export MKFS=$(which mkfs.lustre)
    export TUNEFS=${TUNEFS:-"$LUSTRE/utils/tunefs.lustre"}
    [ ! -f "$TUNEFS" ] && export TUNEFS=$(which tunefs.lustre)
    export CHECKSTAT="${CHECKSTAT:-"checkstat -v"} "
    export LUSTRE_RMMOD=${LUSTRE_RMMOD:-$LUSTRE/scripts/lustre_rmmod}
    [ ! -f "$LUSTRE_RMMOD" ] && export LUSTRE_RMMOD=$(which lustre_rmmod 2> /dev/null)
    export FSTYPE=${FSTYPE:-"ldiskfs"}
    export NAME=${NAME:-local}
    export DIR2
    export SAVE_PWD=${SAVE_PWD:-$LUSTRE/tests}

    if [ "$ACCEPTOR_PORT" ]; then
        export PORT_OPT="--port $ACCEPTOR_PORT"
    fi

    export LOAD_MODULES_REMOTE=${LOAD_MODULES_REMOTE:-false}

    # Paths on remote nodes, if different
    export RLUSTRE=${RLUSTRE:-$LUSTRE}
    export RPWD=${RPWD:-$PWD}
    export I_MOUNTED=${I_MOUNTED:-"no"}
    if [ ! -f /lib/modules/$(uname -r)/kernel/fs/lustre/mds.ko -a \
        ! -f /lib/modules/$(uname -r)/updates/kernel/fs/lustre/mds.ko -a \
        ! -f `dirname $0`/../mds/mds.ko ]; then
        export CLIENTMODSONLY=yes
    fi

    export SHUTDOWN_ATTEMPTS=${SHUTDOWN_ATTEMPTS:-3}

    # command line

    while getopts "rvwf:" opt $*; do
        case $opt in
            f) CONFIG=$OPTARG;;
            r) REFORMAT=--reformat;;
            v) VERBOSE=true;;
            w) WRITECONF=writeconf;;
            \?) usage;;
        esac
    done

    shift $((OPTIND - 1))
    ONLY=${ONLY:-$*}

    # print the durations of each test if "true"
    DDETAILS=${DDETAILS:-false}
    [ "$TESTSUITELOG" ] && rm -f $TESTSUITELOG || true
    cntlog=0
    rm -f $TMP/*active
}

case `uname -r` in
    *) EXT=".ko"; USE_QUOTA=yes;;
esac

pool_list () {
   do_facet mgs lctl pool_list $1
}

create_pool() {
    local fsname=${1%%.*}
    local poolname=${1##$fsname.}

    do_facet mgs lctl pool_new $1
    local RC=$?
    # get param should return err unless pool is created
    [[ $RC -ne 0 ]] && return $RC

    wait_update $HOSTNAME "lctl get_param -n lov.$fsname-*.pools.$poolname \
        2>/dev/null || echo foo" "" || RC=1
    if [[ $RC -eq 0 ]]; then
        add_pool_to_list $1
    else
        error "pool_new failed $1"
    fi
    return $RC
}

add_pool_to_list () {
    local fsname=${1%%.*}
    local poolname=${1##$fsname.}

    local listvar=${fsname}_CREATED_POOLS
    eval export ${listvar}=$(expand_list ${!listvar} $poolname)
}

remove_pool_from_list () {
    local fsname=${1%%.*}
    local poolname=${1##$fsname.}

    local listvar=${fsname}_CREATED_POOLS
    eval export ${listvar}=$(exclude_items_from_list ${!listvar} $poolname)
}

module_loaded () {
   /sbin/lsmod | grep -q $1
}

load_module() {
    module=$1
    shift
    BASE=`basename $module $EXT`

    module_loaded ${BASE} && return

    if [ "$BASE" == "lnet_selftest" ] && \
            [ -f ${LUSTRE}/../lnet/selftest/${module}${EXT} ]; then
        insmod ${LUSTRE}/../lnet/selftest/${module}${EXT}

    elif [ -f ${LUSTRE}/${module}${EXT} ]; then
        insmod ${LUSTRE}/${module}${EXT} $@
    else
        # must be testing a "make install" or "rpm" installation
        modprobe $BASE $@
    fi
}

load_module_llite_lloop() {
    local n1=$(uname -r | cut -d. -f1)
    local n2=$(uname -r | cut -d. -f2)
    local n3=$(uname -r | cut -d- -f1 | cut -d. -f3)

    # load the llite_lloop module for < 2.6.32 kernels
    if [[ $n1 -lt 2 ]] || [[ $n1 -eq 2 && $n2 -lt 6 ]] || \
        [[ $n1 -eq 2 && $n2 -eq 6 && $n3 -lt 32 ]]; then
        load_module llite/llite_lloop
    fi
}

load_modules_local() {
    if [ -n "$MODPROBE" ]; then
        # use modprobe
    return 0
    fi
    if [ "$HAVE_MODULES" = true ]; then
    # we already loaded
        return 0
    fi
    HAVE_MODULES=true

    echo Loading modules from $LUSTRE
    load_module ../lnet/libcfs/libcfs
    [ "$PTLDEBUG" ] && lctl set_param debug="$PTLDEBUG"
    [ "$SUBSYSTEM" ] && lctl set_param subsystem_debug="${SUBSYSTEM# }"
    [ -z "$LNETOPTS" -a "$MODPROBECONF" ] && \
        LNETOPTS=$(awk '/^options lnet/ { print $0}' $MODPROBECONF | sed 's/^options lnet //g')
    echo $LNETOPTS | grep -q "accept=all"  || LNETOPTS="$LNETOPTS accept=all";
    # bug 19380
    # disable it for now since it only hides the stack overflow upon test w/
    # local servers
#    if [ "$NETTYPE" = "tcp" -o "$NETTYPE" = "o2ib" -o "$NETTYPE" = "ptl" ]; then
#        echo $LNETOPTS | grep -q "local_nid_dist_zero=0" ||
#        LNETOPTS="$LNETOPTS local_nid_dist_zero=0"
#    fi
    echo "lnet options: '$LNETOPTS'"
    # note that insmod will ignore anything in modprobe.conf
    load_module ../lnet/lnet/lnet $LNETOPTS
    LNETLND=${LNETLND:-"socklnd/ksocklnd"}
    load_module ../lnet/klnds/$LNETLND
    load_module lvfs/lvfs
    load_module obdclass/obdclass
    load_module ptlrpc/ptlrpc
    [ "$USE_QUOTA" = "yes" ] && load_module quota/lquota $LQUOTAOPTS
    load_module mdc/mdc
    load_module osc/osc
    load_module lov/lov
    load_module mgc/mgc
    if ! client_only; then
        load_module mgs/mgs
        load_module mds/mds
        grep -q crc16 /proc/kallsyms || { modprobe crc16 2>/dev/null || true; }
        grep -q -w jbd /proc/kallsyms || { modprobe jbd 2>/dev/null || true; }
        grep -q -w jbd2 /proc/kallsyms || { modprobe jbd2 2>/dev/null || true; }
        [ "$FSTYPE" = "ldiskfs" ] && load_module ../ldiskfs/ldiskfs/ldiskfs
        load_module lvfs/fsfilt_$FSTYPE
        load_module ost/ost
        load_module obdfilter/obdfilter
    fi

    load_module llite/lustre
    load_module_llite_lloop
    rm -f $TMP/ogdb-$HOSTNAME
    OGDB=$TMP
    [ -d /r ] && OGDB="/r/tmp"
    $LCTL modules > $OGDB/ogdb-$HOSTNAME
    # 'mount' doesn't look in $PATH, just sbin
    [ -f $LUSTRE/utils/mount.lustre ] && cp $LUSTRE/utils/mount.lustre /sbin/. || true
}

load_modules () {
    load_modules_local
    # bug 19124
    # load modules on remote nodes optionally
    # lustre-tests have to be installed on these nodes
    if $LOAD_MODULES_REMOTE ; then
        local list=$(comma_list $(remote_nodes_list))
        echo loading modules on $list
        do_rpc_nodes $list load_modules
    fi
}

check_mem_leak () {
    LEAK_LUSTRE=$(dmesg | tail -n 30 | grep "obd_memory.*leaked" || true)
    LEAK_PORTALS=$(dmesg | tail -n 20 | grep "Portals memory leaked" || true)
    if [ "$LEAK_LUSTRE" -o "$LEAK_PORTALS" ]; then
        echo "$LEAK_LUSTRE" 1>&2
        echo "$LEAK_PORTALS" 1>&2
        mv $TMP/debug $TMP/debug-leak.`date +%s` || true
        echo "Memory leaks detected"
        [ -n "$IGNORE_LEAK" ] && { echo "ignoring leaks" && return 0; } || true
        return 1
    fi
}

unload_modules() {
    wait_exit_ST client # bug 12845

    if $LOAD_MODULES_REMOTE ; then
        local list=$(comma_list $(remote_nodes_list))
        if [ ! -z $list ]; then
            echo unloading modules on $list
            do_rpc_nodes $list $LUSTRE_RMMOD $FSTYPE
            do_rpc_nodes $list check_mem_leak
        fi
    fi

    $LUSTRE_RMMOD $FSTYPE || return 2

    HAVE_MODULES=false

    check_mem_leak || return 254

    echo "modules unloaded."
    return 0
}

#
# This and set_obdfilter_param() shall be used to access OBDFilter parameters
# moved to OSD in 2.3, 2.4, or later server versions.
#
#   mntdev
#   stats
#   read_cache_enable
#   writethrough_cache_enable
#
get_obdfilter_param() {
    local nodes=$1
    local device=${2:-$FSNAME-OST*}
    local name=$3

    do_nodes $nodes "$LCTL get_param -n obdfilter.$device.$name \
        osd-*.$device.$name 2>&1" | grep -v 'Found no match'
}

set_obdfilter_param() {
    local nodes=$1
    local device=${2:-$FSNAME-OST*}
    local name=$3
    local value=$4

    do_nodes $nodes "$LCTL set_param -n obdfilter.$device.$name=$value \
        osd-*.$device.$name=$value 2>&1" | grep -v 'Found no match'
}

set_debug_size () {
    local dz=${1:-$DEBUG_SIZE}

    if [ -f /sys/devices/system/cpu/possible ]; then
        local cpus=$(($(cut -d "-" -f 2 /sys/devices/system/cpu/possible)+1))
    else
        local cpus=$(getconf _NPROCESSORS_CONF)
    fi

    # bug 19944, adjust size to be -gt num_possible_cpus()
    # promise 2MB for every cpu at least
    if [ -n "$cpus" ] && [ $((cpus * 2)) -gt $dz ]; then
        dz=$((cpus * 2))
    fi
    lctl set_param debug_mb=$dz
}

set_default_debug () {
    local debug=${1:-"$PTLDEBUG"}
    local subsystem_debug=${2:-"$SUBSYSTEM"}
    local debug_size=${3:-$DEBUG_SIZE}

    lctl set_param debug="$debug"
    lctl set_param subsystem_debug="${subsystem_debug# }"

    set_debug_size $debug_size
    sync
}

set_default_debug_nodes () {
    local nodes=$1

    if [[ ,$nodes, = *,$HOSTNAME,* ]]; then
        nodes=$(exclude_items_from_list "$nodes" "$HOSTNAME")
            set_default_debug
    fi

    [[ -n $nodes ]] && do_rpc_nodes $nodes set_default_debug \
            \\\"$PTLDEBUG\\\" \\\"$SUBSYSTEM\\\" $DEBUG_SIZE || true
}

set_default_debug_facet () {
    local facet=$1
    local node=$(facet_active_host $facet)
    [ -z "$node" ] && echo "No host defined for facet $facet" && exit 1

    set_default_debug_nodes $node
}

# Facet functions
mount_facets () {
    local facets=${1:-$(get_facets)}
    local facet

    for facet in ${facets//,/ }; do
        mount_facet $facet || error "Restart of $facet failed!"
    done
}

mount_facet() {
    local facet=$1
    shift
    local dev=$(facet_active $facet)_dev
    local opt=${facet}_opt
    local mntpt=$(facet_mntpt $facet)

    echo "Starting ${facet}: ${!opt} $@ ${!dev} $mntpt"
    do_facet ${facet} "mkdir -p $mntpt; mount -t lustre ${!opt} $@ ${!dev} $mntpt"
    RC=${PIPESTATUS[0]}
    if [ $RC -ne 0 ]; then
        echo "mount -t lustre $@ ${!dev} $mntpt"
        echo "Start of ${!dev} on ${facet} failed ${RC}"
    else
        set_default_debug_facet $facet

        label=$(do_facet ${facet} "$E2LABEL ${!dev}")
        [ -z "$label" ] && echo no label for ${!dev} && exit 1
        eval export ${facet}_svc=${label}
        echo Started ${label}
    fi
    return $RC
}

# start facet device options
start() {
    local facet=$1
    shift
    local device=$1
    shift
    eval export ${facet}_dev=${device}
    eval export ${facet}_opt=\"$@\"

    local varname=${facet}failover_dev
    if [ -n "${!varname}" ] ; then
        eval export ${facet}failover_dev=${!varname}
    else
        eval export ${facet}failover_dev=$device
    fi

    local mntpt=$(facet_mntpt $facet)
    do_facet ${facet} mkdir -p $mntpt
    eval export ${facet}_MOUNT=$mntpt
    mount_facet ${facet}
    RC=$?
    return $RC
}

stop() {
    local running
    local facet=$1
    shift
    local HOST=`facet_active_host $facet`
    [ -z $HOST ] && echo stop: no host for $facet && return 0

    local mntpt=$(facet_mntpt $facet)
    running=$(do_facet ${facet} "grep -c $mntpt' ' /proc/mounts") || true
    if [ ${running} -ne 0 ]; then
        echo "Stopping $mntpt (opts:$@)"
        do_facet ${facet} umount -d $@ $mntpt
    fi

    # umount should block, but we should wait for unrelated obd's
    # like the MGS or MGC to also stop.

    wait_exit_ST ${facet}
}

# set quota version (both administrative and operational quotas)
#
# XXX This function is kept for interoperability with old server (< 2.3.50),
#     it should be removed whenever we drop the interoperability for such
#     server.
quota_set_version() {
    do_facet mds "lctl set_param lquota.${FSNAME}-MDT*.quota_type=$1"
    local varsvc
    local osts=$(get_facets OST)
    for ost in ${osts//,/ }; do
        varsvc=${ost}_svc
        do_facet $ost "lctl set_param lquota.${!varsvc}.quota_type=$1"
    done
}

# save quota version (both administrative and operational quotas)
# the function will also switch to the new version and the new type
#
# XXX This function is kept for interoperability with old server (< 2.3.50),
#     it should be removed whenever we drop the interoperability for such
#     server.
quota_save_version() {
    local spec=$1
    local ver=$(tr -c -d "123" <<< $spec)
    local type=$(tr -c -d "ug" <<< $spec)

    local lustre_version=$(get_lustre_version mds)
    if [[ $lustre_version = 1.8* ]] ; then
        $LFS quotaoff -ug $MOUNT # just in case
        [ -n "$ver" ] && quota_set_version $ver
    else
        echo mds running $lustre_version
        [ -n "$ver" -a "$ver" != "3" ] && error "wrong quota version specifier"
    fi

    [ -n "$type" ] &&
        { $LFS quotacheck -$type $MOUNT || error "quotacheck has failed"; }

    do_facet mgs "lctl conf_param $FSNAME-MDT*.$(get_md_name).quota_type=$spec"
    local varsvc
    local osts=$(get_facets OST)
    for ost in ${osts//,/ }; do
        varsvc=${ost}_svc
        do_facet mgs "lctl conf_param ${!varsvc}.ost.quota_type=$spec"
    done
}

# client could mount several lustre
#
# XXX This function is kept for interoperability with old server (< 2.3.50),
#     it should be removed whenever we drop the interoperability for such
#     server.
quota_type() {
    local fsname=${1:-$FSNAME}
    local rc=0
    do_facet mds lctl get_param md*.${fsname}-MDT*.quota_type ||
        rc=$?
    do_nodes $(comma_list $(osts_nodes)) \
        lctl get_param obdfilter.${fsname}-OST*.quota_type || rc=$?
    return $rc
}

# XXX This function is kept for interoperability with old server (< 2.3.50),
#     it should be removed whenever we drop the interoperability for such
#     server.
restore_quota_old() {
    local mntpt=${1:-$MOUNT}
    local quota_type=$(quota_type $FSNAME | grep MDT | cut -d "=" -f2)
    if [ ! "$old_QUOTA_TYPE" ] || [ "$quota_type" = "$old_QUOTA_TYPE" ]; then
        return
    fi
    quota_save_version $old_QUOTA_TYPE
}

# Handle the case when there is a space in the lfs df
# "filesystem summary" line the same as when there is no space.
# This will allow fixing the "lfs df" summary line in the future.
lfs_df() {
    $LFS df $* | sed -e 's/filesystem /filesystem_/'
}

# XXX This function is kept for interoperability with old server (< 2.3.50),
#     it should be removed whenever we drop the interoperability for such
#     server.
setup_quota_old() {
    local mntpt=$1

    # We need:
    # 1. run quotacheck only if quota is off
    # 2. save the original quota_type params, restore them after testing

    # Suppose that quota type the same on mds and ost
    local quota_type=$(quota_type | grep MDT | cut -d "=" -f2)
    [ ${PIPESTATUS[0]} -eq 0 ] || error "quota_type failed!"
    echo "[HOST:$HOSTNAME] [old_quota_type:$quota_type] [new_quota_type:$QUOTA_TYPE]"
    if [ "$quota_type" != "$QUOTA_TYPE" ]; then
        export old_QUOTA_TYPE=$quota_type
        quota_save_version $QUOTA_TYPE
    fi

    local quota_usrs=$QUOTA_USERS

    # get_filesystem_size
    local disksz=$(lfs_df $mntpt | grep "summary" | awk '{print $2}')
    local blk_soft=$((disksz + 1024))
    local blk_hard=$((blk_soft + blk_soft / 20)) # Go 5% over

    local Inodes=$(lfs_df -i $mntpt | grep "summary" | awk '{print $2}')
    local i_soft=$Inodes
    local i_hard=$((i_soft + i_soft / 20))

    echo "Total disk size: $disksz  block-softlimit: $blk_soft block-hardlimit:
        $blk_hard inode-softlimit: $i_soft inode-hardlimit: $i_hard"

    local cmd
    for usr in $quota_usrs; do
        echo "Setting up quota on $HOSTNAME:$mntpt for $usr..."
        for type in u g; do
            cmd="$LFS setquota -$type $usr -b $blk_soft -B $blk_hard -i $i_soft -I $i_hard $mntpt"
            echo "+ $cmd"
            eval $cmd || error "$cmd FAILED!"
        done
        # display the quota status
        echo "Quota settings for $usr : "
        $LFS quota -v -u $usr $mntpt || true
    done
}

# get mdt quota type
mdt_quota_type() {
    local varsvc=mds_svc
    do_facet mds $LCTL get_param -n \
        osd-$FSTYPE.${!varsvc}.quota_slave.enabled
}

# get ost quota type
ost_quota_type() {
    # All OSTs should have same quota type
    local varsvc=ost1_svc
    do_facet ost1 $LCTL get_param -n \
        osd-$FSTYPE.${!varsvc}.quota_slave.enabled
}

# restore old quota type settings
restore_quota() {
    if [ $(lustre_version_code mds) -lt $(version_code 2.3.50) ]; then
        restore_quota_old
        return
    fi

    if [ "$old_MDT_QUOTA_TYPE" ]; then
        do_facet mgs $LCTL conf_param \
            $FSNAME.quota.mdt=$old_MDT_QUOTA_TYPE
    fi

    if [ "$old_OST_QUOTA_TYPE" ]; then
        do_facet mgs $LCTL conf_param \
            $FSNAME.quota.ost=$old_OST_QUOTA_TYPE
    fi
}

setup_quota() {
	if [ $(lustre_version_code mds) -lt $(version_code 2.3.50) ]; then
		setup_quota_old $1
		return
	fi

	local mntpt=$1

	# save old quota type & set new quota type
	local mdt_qtype=$(mdt_quota_type)
	local ost_qtype=$(ost_quota_type)

	echo "[HOST:$HOSTNAME] [old_mdt_qtype:$mdt_qtype]" \
		"[old_ost_qtype:$ost_qtype] [new_qtype:$QUOTA_TYPE]"

	export old_MDT_QUOTA_TYPE=$mdt_qtype
	export old_OST_QUOTA_TYPE=$ost_qtype

	do_facet mgs $LCTL conf_param $FSNAME.quota.mdt=$QUOTA_TYPE ||
		error "set mdt quota type failed"
	do_facet mgs $LCTL conf_param $FSNAME.quota.ost=$QUOTA_TYPE ||
		error "set ost quota type failed"

	local quota_usrs=$QUOTA_USERS

	# get_filesystem_size
	local disksz=$(lfs_df $mntpt | grep "summary" |
		     awk '{print $3}')
	local blk_soft=$((disksz + 1024))
	local blk_hard=$((blk_soft + blk_soft / 20)) # Go 5% over

	local inodes=$(lfs_df -i $mntpt | grep "summary" |
		     awk '{print $3}')
	local i_soft=$inodes
	local i_hard=$((i_soft + i_soft / 20))

	echo "Total disk size: $disksz  block-softlimit: $blk_soft" \
		"block-hardlimit: $blk_hard inode-softlimit: $i_soft" \
		"inode-hardlimit: $i_hard"

	local cmd
	for usr in $quota_usrs; do
		echo "Setting up quota on $HOSTNAME:$mntpt for $usr..."
		for type in u g; do
			cmd="$LFS setquota -$type $usr -b $blk_soft"
			cmd="$cmd -B $blk_hard -i $i_soft -I $i_hard $mntpt"
			echo "+ $cmd"
			eval $cmd || error "$cmd FAILED!"
		done
		# display the quota status
		echo "Quota settings for $usr : "
		$LFS quota -v -u $usr $mntpt || true
	done
}

zconf_mount() {
    local client=$1
    local mnt=$2
    local OPTIONS=${3:-$MOUNTOPT}

    local device=$MGSNID:/$FSNAME
    if [ -z "$mnt" -o -z "$FSNAME" ]; then
        echo Bad zconf mount command: opt=$OPTIONS dev=$device mnt=$mnt
        exit 1
    fi

    echo "Starting client: $client: $OPTIONS $device $mnt"
    do_node $client mkdir -p $mnt
    do_node $client mount -t lustre $OPTIONS $device $mnt || return 1
    set_default_debug_nodes $client

    return 0
}

zconf_umount() {
    local client=$1
    local mnt=$2
    local force
    local busy
    local need_kill

    [ "$3" ] && force=-f
    local running=$(do_node $client "grep -c $mnt' ' /proc/mounts") || true
    if [ $running -ne 0 ]; then
        echo "Stopping client $client $mnt (opts:$force)"
        do_node $client lsof -t $mnt || need_kill=no
        if [ "x$force" != "x" -a "x$need_kill" != "xno" ]; then
            pids=$(do_node $client lsof -t $mnt | sort -u);
            if [ -n $pids ]; then
                do_node $client kill -9 $pids || true
            fi
        fi

        busy=$(do_node $client "umount $force $mnt 2>&1" | grep -c "busy") || true
        if [ $busy -ne 0 ] ; then
            echo "$mnt is still busy, wait one second" && sleep 1
            do_node $client umount $force $mnt
        fi
    fi
}

# nodes is comma list
sanity_mount_check_nodes () {
    local nodes=$1
    shift
    local mnts="$@"
    local mnt

    # FIXME: assume that all cluster nodes run the same os
    [ "$(uname)" = Linux ] || return 0

    local rc=0
    for mnt in $mnts ; do
        do_nodes $nodes "running=\\\$(grep -c $mnt' ' /proc/mounts);
mpts=\\\$(mount | grep -c $mnt' ');
if [ \\\$running -ne \\\$mpts ]; then
    echo \\\$(hostname) env are INSANE!;
    exit 1;
fi"
    [ $? -eq 0 ] || rc=1
    done
    return $rc
}

sanity_mount_check_servers () {
    [ "$CLIENTONLY" ] &&
        { echo "CLIENTONLY mode, skip mount_check_servers"; return 0; } || true
    echo Checking servers environments

    # FIXME: modify get_facets to display all facets wo params
    local facets="$(get_facets OST),$(get_facets MDS),mgs"
    local node
    local mntpt
    local facet
    for facet in ${facets//,/ }; do
        node=$(facet_host ${facet})
        mntpt=$(facet_mntpt $facet)
        sanity_mount_check_nodes $node $mntpt ||
            { error "server $node environments are insane!"; return 1; }
    done
}

sanity_mount_check_clients () {
    local clients=${1:-$CLIENTS}
    local mntpt=${2:-$MOUNT}
    local mntpt2=${3:-$MOUNT2}

    [ -z $clients ] && clients=$(hostname)
    echo Checking clients $clients environments

    sanity_mount_check_nodes $clients $mntpt $mntpt2 ||
       error "clients environments are insane!"
}

sanity_mount_check () {
    sanity_mount_check_servers || return 1
    sanity_mount_check_clients || return 2
}

# mount clients if not mouted
zconf_mount_clients() {
    local clients=$1
    local mnt=$2
    local OPTIONS=${3:-$MOUNTOPT}

    local device=$MGSNID:/$FSNAME
    if [ -z "$mnt" -o -z "$FSNAME" ]; then
        echo Bad zconf mount command: opt=$OPTIONS dev=$device mnt=$mnt
        exit 1
    fi

    echo "Starting client $clients: $OPTIONS $device $mnt"

    do_nodes $clients "
running=\\\$(mount | grep -c $mnt' ');
rc=0;
if [ \\\$running -eq 0 ] ; then
    mkdir -p $mnt;
    mount -t lustre $OPTIONS $device $mnt;
    rc=$?;
fi;
exit $rc"

    echo "Started clients $clients: "
    do_nodes $clients "mount | grep $mnt' '"

    set_default_debug_nodes $clients

    return 0
}

zconf_umount_clients() {
    local clients=$1
    local mnt=$2
    local force

    [ "$3" ] && force=-f

    echo "Stopping clients: $clients $mnt (opts:$force)"
    do_nodes $clients "running=\\\$(grep -c $mnt' ' /proc/mounts);
if [ \\\$running -ne 0 ] ; then
echo Stopping client \\\$(hostname) $mnt opts:$force;
lsof -t $mnt || need_kill=no;
if [ "x$force" != "x" -a "x\\\$need_kill" != "xno" ]; then
    pids=\\\$(lsof -t $mnt | sort -u);
    if [ -n \\\"\\\$pids\\\" ]; then
             kill -9 \\\$pids;
    fi
fi;
busy=\\\$(umount $force $mnt 2>&1 | grep -c "busy");
if [ \\\$busy -ne 0 ] ; then
    echo "$mnt is still busy, wait one second" && sleep 1;
    umount $force $mnt;
fi
fi"
}

shutdown_node () {
    local node=$1
    echo + $POWER_DOWN $node
    $POWER_DOWN $node
}

shutdown_node_hard () {
    local host=$1
    local attempts=$SHUTDOWN_ATTEMPTS

    for i in $(seq $attempts) ; do
        shutdown_node $host
        sleep 1
        wait_for_function --quiet "! ping -w 3 -c 1 $host" 5 1 && return 0
        echo "waiting for $host to fail attempts=$attempts"
        [ $i -lt $attempts ] || \
            { echo "$host still pingable after power down! attempts=$attempts" && return 1; }
    done
}

shutdown_client() {
    local client=$1
    local mnt=${2:-$MOUNT}
    local attempts=3

    if [ "$FAILURE_MODE" = HARD ]; then
        shutdown_node_hard $client
    else
       zconf_umount_clients $client $mnt -f
    fi
}

facets_on_host () {
    local host=$1
    local facets="$(get_facets OST),$(get_facets MDS)"
    local affected

    combined_mgs_mds || facets="$facets,mgs"

    for facet in ${facets//,/ }; do
        if [ $(facet_active_host $facet) == $host ]; then
           affected="$affected $facet"
        fi
    done

    echo $(comma_list $affected)
}

facet_up() {
    local facet=$1
    local host=${2:-$(facet_host $facet)}

    local label=$(convert_facet2label $facet)
    do_node $host $LCTL dl | awk '{print $4}' | grep -q -x $label
}

facets_up_on_host () {
    local host=$1
    local facets=$(facets_on_host $host)
    local affected_up

    for facet in ${facets//,/ }; do
        if $(facet_up $facet $host); then
            affected_up="$affected_up $facet"
        fi
    done

    echo $(comma_list $affected_up)
}

shutdown_facet() {
    local facet=$1

    if [ "$FAILURE_MODE" = HARD ]; then
        shutdown_node_hard $(facet_active_host $facet)
    else
        stop $facet
    fi
}

reboot_node() {
    local node=$1
    echo + $POWER_UP $node
    $POWER_UP $node
}

remount_facet() {
    local facet=$1

    stop $facet
    mount_facet $facet
}

reboot_facet() {
    local facet=$1
    if [ "$FAILURE_MODE" = HARD ]; then
        reboot_node $(facet_active_host $facet)
    else
        sleep 10
    fi
}

boot_node() {
    local node=$1
    if [ "$FAILURE_MODE" = HARD ]; then
       reboot_node $node
       wait_for_host $node
    fi
}

facets_hosts () {
    local facets=$1
    local hosts

    for facet in ${facets//,/ }; do
        hosts=$(expand_list $hosts $(facet_host $facet) )
    done

    echo $hosts
}

_check_progs_installed () {
    local progs=$@
    local rc=0

    for prog in $progs; do
        if ! [ "$(which $prog)"  -o  "${!prog}" ]; then
           echo $prog missing on $(hostname)
           rc=1
        fi
    done
    return $rc
}

check_progs_installed () {
    local nodes=$1
    shift

    do_rpc_nodes $nodes _check_progs_installed $@
}

node_var_name() {
    local node=${1//./_}
    echo __${node//-/_}
}

start_client_load() {
    local client=$1
    local load=$2
    local var=$(node_var_name $client)_load
    eval export ${var}=$load

    do_node $client "PATH=$PATH MOUNT=$MOUNT ERRORS_OK=$ERRORS_OK \
BREAK_ON_ERROR=$BREAK_ON_ERROR \
END_RUN_FILE=$END_RUN_FILE \
LOAD_PID_FILE=$LOAD_PID_FILE \
TESTLOG_PREFIX=$TESTLOG_PREFIX \
TESTNAME=$TESTNAME \
DBENCH_LIB=$DBENCH_LIB \
DBENCH_SRC=$DBENCH_SRC \
run_${load}.sh" &
    local ppid=$!
    log "Started client load: ${load} on $client"

    # get the children process IDs
    local pids=$(ps --ppid $ppid -o pid= | xargs)
    CLIENT_LOAD_PIDS="$CLIENT_LOAD_PIDS $ppid $pids"
    return 0
}

start_client_loads () {
    local -a clients=(${1//,/ })
    local numloads=${#CLIENT_LOADS[@]}
    local testnum

    for ((nodenum=0; nodenum < ${#clients[@]}; nodenum++ )); do
        testnum=$((nodenum % numloads))
        start_client_load ${clients[nodenum]} ${CLIENT_LOADS[testnum]}
    done
    # bug 22169: wait the background threads to start
    sleep 2
}

# only for remote client
check_client_load () {
    local client=$1
    local var=$(node_var_name $client)_load
    local TESTLOAD=run_${!var}.sh

    ps auxww | grep -v grep | grep $client | grep -q "$TESTLOAD" || return 1

    # bug 18914: try to connect several times not only when
    # check ps, but  while check_catastrophe also
    local tries=3
    local RC=254
    while [ $RC = 254 -a $tries -gt 0 ]; do
        let tries=$tries-1
        # assume success
        RC=0
        if ! check_catastrophe $client; then
            RC=${PIPESTATUS[0]}
            if [ $RC -eq 254 ]; then
                # FIXME: not sure how long we shuold sleep here
                sleep 10
                continue
            fi
            echo "check catastrophe failed: RC=$RC "
            return $RC
        fi
    done

    # We can continue try to connect if RC=254
    # Just print the warning about this
    if [ $RC = 254 ]; then
        echo "got a return status of $RC from do_node while checking catastrophe on $client"
    fi

    # see if the load is still on the client
    tries=3
    RC=254
    while [ $RC = 254 -a $tries -gt 0 ]; do
        let tries=$tries-1
        # assume success
        RC=0
        if ! do_node $client "ps auxwww | grep -v grep | grep -q $TESTLOAD"; then
            RC=${PIPESTATUS[0]}
            sleep 30
        fi
    done
    if [ $RC = 254 ]; then
        echo "got a return status of $RC from do_node while checking (catastrophe and 'ps') the client load on $client"
        # see if we can diagnose a bit why this is
    fi

    return $RC
}
check_client_loads () {
   local clients=${1//,/ }
   local client=
   local rc=0

   for client in $clients; do
      check_client_load $client
      rc=${PIPESTATUS[0]}
      if [ "$rc" != 0 ]; then
        log "Client load failed on node $client, rc=$rc"
        return $rc
      fi
   done
}

restart_client_loads () {
    local clients=${1//,/ }
    local expectedfail=${2:-""}
    local client=
    local rc=0

    for client in $clients; do
        check_client_load $client
        rc=${PIPESTATUS[0]}
        if [ "$rc" != 0 -a "$expectedfail" ]; then
            local var=$(node_var_name $client)_load
            start_client_load $client ${!var}
            echo "Restarted client load ${!var}: on $client. Checking ..."
            check_client_load $client
            rc=${PIPESTATUS[0]}
            if [ "$rc" != 0 ]; then
                log "Client load failed to restart on node $client, rc=$rc"
                # failure one client load means test fail
                # we do not need to check other
                return $rc
            fi
        else
            return $rc
        fi
    done
}

# Start vmstat and save its process ID in a file.
start_vmstat() {
    local nodes=$1
    local pid_file=$2

    [ -z "$nodes" -o -z "$pid_file" ] && return 0

    do_nodes $nodes \
        "vmstat 1 > $TESTLOG_PREFIX.$TESTNAME.vmstat.\\\$(hostname -s).log \
        2>/dev/null </dev/null & echo \\\$! > $pid_file"
}

# Display the nodes on which client loads failed.
print_end_run_file() {
    local file=$1
    local node

    [ -s $file ] || return 0

    echo "Found the END_RUN_FILE file: $file"
    cat $file

    # A client load will stop if it finds the END_RUN_FILE file.
    # That does not mean the client load actually failed though.
    # The first node in END_RUN_FILE is the one we are interested in.
    read node < $file

    if [ -n "$node" ]; then
        local var=$(node_var_name $node)_load

        local prefix=$TESTLOG_PREFIX
        [ -n "$TESTNAME" ] && prefix=$prefix.$TESTNAME
        local stdout_log=$prefix.run_${!var}_stdout.$node.log
        local debug_log=$(echo $stdout_log | sed 's/\(.*\)stdout/\1debug/')

        echo "Client load ${!var} failed on node $node:"
        echo "$stdout_log"
        echo "$debug_log"
    fi
}

# Stop the process which had its PID saved in a file.
stop_process() {
    local nodes=$1
    local pid_file=$2

    [ -z "$nodes" -o -z "$pid_file" ] && return 0

    do_nodes $nodes "test -f $pid_file &&
        { kill -s TERM \\\$(cat $pid_file); rm -f $pid_file; }" || true
}

# Stop all client loads.
stop_client_loads() {
    local nodes=${1:-$CLIENTS}
    local pid_file=$2

    # stop the client loads
    stop_process $nodes $pid_file

    # clean up the processes that started them
    [ -n "$CLIENT_LOAD_PIDS" ] && kill -9 $CLIENT_LOAD_PIDS 2>/dev/null || true
}

# verify that lustre actually cleaned up properly
cleanup_check() {
    [ -f $CATASTROPHE ] && [ `cat $CATASTROPHE` -ne 0 ] && \
        error "LBUG/LASSERT detected"
    BUSY=`dmesg | grep -i destruct || true`
    if [ "$BUSY" ]; then
        echo "$BUSY" 1>&2
        [ -e $TMP/debug ] && mv $TMP/debug $TMP/debug-busy.`date +%s`
        exit 205
    fi

    check_mem_leak || exit 204

    [ "`lctl dl 2> /dev/null | wc -l`" -gt 0 ] && lctl dl && \
        echo "$0: lustre didn't clean up..." 1>&2 && return 202 || true

    if module_loaded lnet || module_loaded libcfs; then
        echo "$0: modules still loaded..." 1>&2
        /sbin/lsmod 1>&2
        return 203
    fi
    return 0
}

wait_update () {
    local node=$1
    local TEST=$2
    local FINAL=$3
    local MAX=${4:-90}

        local RESULT
        local WAIT=0
        local sleep=5
        while [ true ]; do
            RESULT=$(do_node $node "$TEST")
            if [ "$RESULT" == "$FINAL" ]; then
                [ -z "$RESULT" -o $WAIT -le $sleep ] ||
                    echo "Updated after ${WAIT}s: wanted '$FINAL' got '$RESULT'"
                return 0
            fi
            [ $WAIT -ge $MAX ] && break
            echo "Waiting $((MAX - WAIT)) secs for update"
            WAIT=$((WAIT + sleep))
            sleep $sleep
        done
        echo "Update not seen after ${MAX}s: wanted '$FINAL' got '$RESULT'"
        return 3
}

wait_update_facet () {
    local facet=$1
    shift
    wait_update  $(facet_active_host $facet) "$@"
}

sync_all_data() {
    if [ $(lustre_version_code mds) -ge $(version_code 2.2.58) ]; then
        do_nodes $(comma_list $(osts_nodes)) \
            "lctl set_param -n osd*.*OS*.force_sync 1 2>&1" |
            grep -v 'Found no match' || true
    fi
}

wait_delete_completed_mds() {
	[[ $(lustre_version_code mds) -lt $(version_code 2.2.58) ]] &&
		return 0

	local MAX_WAIT=${1:-20}
	local mds2sync=""
	local stime=`date +%s`
	local etime
	local node
	local changes

	# find MDS with pending deletions
	for node in $(mdts_nodes); do
		changes=$(do_node $node "lctl get_param -n osc.*MDT*.sync_*" \
			2>/dev/null | calc_sum)
		if [ -z "$changes" ] || [ $changes -eq 0 ]; then
			continue
		fi
		mds2sync="$mds2sync $node"
	done
	if [ "$mds2sync" == "" ]; then
		return
	fi
	mds2sync=$(comma_list $mds2sync)

	# sync MDS transactions
	do_nodes $mds2sync "lctl set_param -n osd*.*MD*.force_sync 1"

	# wait till all changes are sent and commmitted by OSTs
	# for ldiskfs space is released upon execution, but DMU
	# do this upon commit

	local WAIT=0
	while [ "$WAIT" -ne "$MAX_WAIT" ]; do
		changes=$(do_nodes $mds2sync "lctl get_param -n osc.*MDT*.sync_*" \
			| calc_sum)
		#echo "$node: $changes changes on all"
		if [ "$changes" -eq "0" ]; then
			etime=`date +%s`
			#echo "delete took $((etime - stime)) seconds"
			return
		fi
		sleep 1
		WAIT=$(( WAIT + 1))
	done

	etime=`date +%s`
	echo "Delete is not completed in $((etime - stime)) seconds"
	do_nodes $mds2sync "lctl get_param osc.*MDT*.sync_*"
}

wait_for_host() {
    local hostlist=$1

    # we can use "for" here because we are waiting the slowest
    for host in ${hostlist//,/ }; do
        check_network "$host" 900
    done
    while ! do_nodes $hostlist hostname  > /dev/null; do sleep 5; done
}

wait_for_facet() {
    local facetlist=$1
    local hostlist

    for facet in ${facetlist//,/ }; do
        hostlist=$(expand_list $hostlist $(facet_active_host $facet))
    done
    wait_for_host $hostlist
}

_wait_recovery_complete () {
    local param=$1

    # Use default policy if $2 is not passed by caller.
    local MAX=${2:-$(max_recovery_time)}

    local WAIT=0
    local STATUS=

    while [ $WAIT -lt $MAX ]; do
        STATUS=$(lctl get_param -n $param | grep status)
        echo $param $STATUS
        [[ $STATUS = "status: COMPLETE" || $STATUS = "status: INACTIVE" ]] && return 0
        sleep 5
        WAIT=$((WAIT + 5))
        echo "Waiting $((MAX - WAIT)) secs for $param recovery done. $STATUS"
    done
    echo "$param recovery not done in $MAX sec. $STATUS"
    return 1
}

wait_recovery_complete () {
    local facet=$1

    # with an assumption that at_max is the same on all nodes
    local MAX=${2:-$(max_recovery_time)}

    local facets=$facet
    if [ "$FAILURE_MODE" = HARD ]; then
        facets=$(facets_on_host $(facet_active_host $facet))
    fi
    echo affected facets: $facets

    # we can use "for" here because we are waiting the slowest
    for facet in ${facets//,/ }; do
        local var_svc=${facet}_svc
        local param="*.${!var_svc}.recovery_status"

        local host=$(facet_active_host $facet)
        do_rpc_nodes $host _wait_recovery_complete $param $MAX
    done
}

wait_mds_ost_sync () {
    # just because recovery is done doesn't mean we've finished
    # orphan cleanup. Wait for llogs to get synchronized.
    echo "Waiting for orphan cleanup..."
    # MAX value includes time needed for MDS-OST reconnection
    local MAX=$(( TIMEOUT * 2 ))
    local WAIT=0
    while [ $WAIT -lt $MAX ]; do
        local -a sync=($(do_nodes $(comma_list $(osts_nodes)) \
            "$LCTL get_param -n obdfilter.*.mds_sync"))
        local con=1
        for ((i=0; i<${#sync[@]}; i++)); do
            [ ${sync[$i]} -eq 0 ] && continue
            # there is a not finished MDS-OST synchronization
            con=0
            break;
        done
        sleep 2 # increase waiting time and cover statfs cache
        [ ${con} -eq 1 ] && return 0
        echo "Waiting $WAIT secs for $facet mds-ost sync done."
        WAIT=$((WAIT + 2))
    done
    echo "$facet recovery not done in $MAX sec. $STATUS"
    return 1
}

wait_destroy_complete () {
	echo "Waiting for local destroys to complete"
	# MAX value shouldn't be big as this mean server responsiveness
	# never increase this just to make test pass but investigate
	# why it takes so long time
	local MAX=5
	local WAIT=0
	while [ $WAIT -lt $MAX ]; do
		local -a RPCs=($($LCTL get_param -n osc.*.destroys_in_flight))
		local con=1
		local i

		for ((i=0; i<${#RPCs[@]}; i++)); do
			[ ${RPCs[$i]} -eq 0 ] && continue
			# there are still some destroy RPCs in flight
			con=0
			break;
		done
		sleep 1
		[ ${con} -eq 1 ] && return 0 # done waiting
		echo "Waiting ${WAIT}s for local destroys to complete"
		WAIT=$((WAIT + 1))
	done
	echo "Local destroys weren't done in $MAX sec."
	return 1
}

wait_delete_completed() {
	wait_delete_completed_mds $1 || return $?
	wait_destroy_complete
}

wait_exit_ST () {
    local facet=$1

    local WAIT=0
    local INTERVAL=1
    local running
    # conf-sanity 31 takes a long time cleanup
    while [ $WAIT -lt 300 ]; do
        running=$(do_facet ${facet} "lsmod | grep lnet > /dev/null && lctl dl | grep ' ST '") || true
        [ -z "${running}" ] && return 0
        echo "waited $WAIT for${running}"
        [ $INTERVAL -lt 64 ] && INTERVAL=$((INTERVAL + INTERVAL))
        sleep $INTERVAL
        WAIT=$((WAIT + INTERVAL))
    done
    echo "service didn't stop after $WAIT seconds.  Still running:"
    echo ${running}
    return 1
}

wait_remote_prog () {
   local prog=$1
   local WAIT=0
   local INTERVAL=5
   local rc=0

   [ "$PDSH" = "no_dsh" ] && return 0

   while [ $WAIT -lt $2 ]; do
        running=$(ps uax | grep "$PDSH.*$prog.*$MOUNT" | grep -v grep) || true
        [ -z "${running}" ] && return 0 || true
        echo "waited $WAIT for: "
        echo "$running"
        [ $INTERVAL -lt 60 ] && INTERVAL=$((INTERVAL + INTERVAL))
        sleep $INTERVAL
        WAIT=$((WAIT + INTERVAL))
    done
    local pids=$(ps  uax | grep "$PDSH.*$prog.*$MOUNT" | grep -v grep | awk '{print $2}')
    [ -z "$pids" ] && return 0
    echo "$PDSH processes still exists after $WAIT seconds.  Still running: $pids"
    # FIXME: not portable
    for pid in $pids; do
        cat /proc/${pid}/status || true
        cat /proc/${pid}/wchan || true
        echo "Killing $pid"
        kill -9 $pid || true
        sleep 1
        ps -P $pid && rc=1
    done

    return $rc
}

clients_up() {
    # not every config has many clients
    sleep 1
    if [ -n "$CLIENTS" ]; then
        $PDSH $CLIENTS "stat -f $MOUNT" > /dev/null
    else
        stat -f $MOUNT > /dev/null
    fi
}

client_up() {
    local client=$1
    # usually checked on particular client or locally
    sleep 1
    if [ ! -z "$client" ]; then
        $PDSH $client "stat -f $MOUNT" > /dev/null
    else
        stat -f $MOUNT > /dev/null
    fi
}

client_evicted() {
    ! client_up $1
}

client_reconnect() {
    uname -n >> $MOUNT/recon
    if [ -z "$CLIENTS" ]; then
        df $MOUNT; uname -n >> $MOUNT/recon
    else
        do_nodes $CLIENTS "df $MOUNT; uname -n >> $MOUNT/recon" > /dev/null
    fi
    echo Connected clients:
    cat $MOUNT/recon
    ls -l $MOUNT/recon > /dev/null
    rm $MOUNT/recon
}

affected_facets () {
    local facet=$1

    local host=$(facet_active_host $facet)
    local affected=$facet

    if [ "$FAILURE_MODE" = HARD ]; then
        affected=$(facets_up_on_host $host)
    fi
    echo $affected
}

facet_failover() {
    local facet=$1
    local sleep_time=$2
    local host=$(facet_active_host $facet)

    echo "Failing $facet on node $host"

    local affected=$(affected_facets $facet)

    shutdown_facet $facet

    echo affected facets: $affected

    [ -n "$sleep_time" ] && sleep $sleep_time

    reboot_facet $facet
    clients_up &
    local dfpid=$!
    RECOVERY_START_TIME=`date +%s`
    echo "df pid is $dfpid"

    change_active $affected

    wait_for_facet $affected
    # start mgs first if it is affected
    if ! combined_mgs_mds && list_member $affected mgs; then
        mount_facet mgs || error "Restart of mgs failed"
    fi
    # FIXME; has to be changed to mount all facets concurrently
    affected=$(exclude_items_from_list $affected mgs)
    mount_facets $affected
}

obd_name() {
    local facet=$1
}

replay_barrier() {
    local facet=$1
    do_facet $facet sync
    df $MOUNT
    local svc=${facet}_svc
    do_facet $facet $LCTL --device %${!svc} notransno
    do_facet $facet $LCTL --device %${!svc} readonly
    do_facet $facet $LCTL mark "$facet REPLAY BARRIER on ${!svc}"
    $LCTL mark "local REPLAY BARRIER on ${!svc}"
}

replay_barrier_nodf() {
    local facet=$1    echo running=${running}
    do_facet $facet sync
    local svc=${facet}_svc
    echo Replay barrier on ${!svc}
    do_facet $facet $LCTL --device %${!svc} notransno
    do_facet $facet $LCTL --device %${!svc} readonly
    do_facet $facet $LCTL mark "$facet REPLAY BARRIER on ${!svc}"
    $LCTL mark "local REPLAY BARRIER on ${!svc}"
}

mds_evict_client() {
    UUID=`lctl get_param -n mdc.${mds_svc}-mdc-*.uuid`
    local mdtdevice=$(get_mds_mdt_device_proc_path)
    do_facet mds "lctl set_param -n ${mdtdevice}.${mds_svc}.evict_client $UUID"
}

ost_evict_client() {
    UUID=`lctl get_param -n osc.${ost1_svc}-osc-*.uuid`
    do_facet ost1 "lctl set_param -n obdfilter.${ost1_svc}.evict_client $UUID"
}

fail() {
    facet_failover $* || error "failover: $?"
    clients_up || error "post-failover df: $?"
}

fail_nodf() {
    local facet=$1
    facet_failover $facet
}

fail_abort() {
    local facet=$1
    stop $facet
    change_active $facet
    wait_for_facet $facet
    mount_facet $facet -o abort_recovery
    clients_up || echo "first df failed: $?"
    clients_up || error "post-failover df: $?"
}

do_lmc() {
    echo There is no lmc.  This is mountconf, baby.
    exit 1
}

h2gm () {
    if [ "$1" = "client" -o "$1" = "'*'" ]; then echo \'*\'; else
        ID=`$PDSH $1 $GMNALNID -l | cut -d\  -f2`
        echo $ID"@gm"
    fi
}

h2name_or_ip() {
    if [ "$1" = "client" -o "$1" = "'*'" ]; then echo \'*\'; else
        echo $1"@$2"
    fi
}

h2ptl() {
   if [ "$1" = "client" -o "$1" = "'*'" ]; then echo \'*\'; else
       ID=`xtprocadmin -n $1 2>/dev/null | egrep -v 'NID' | awk '{print $1}'`
       if [ -z "$ID" ]; then
           echo "Could not get a ptl id for $1..."
           exit 1
       fi
       echo $ID"@ptl"
   fi
}
declare -fx h2ptl

h2tcp() {
    if [ "$1" = "client" -o "$1" = "'*'" ]; then echo \'*\'; else
        echo $1"@tcp"
    fi
}
declare -fx h2tcp

h2elan() {
    if [ "$1" = "client" -o "$1" = "'*'" ]; then echo \'*\'; else
        if type __h2elan >/dev/null 2>&1; then
            ID=$(__h2elan $1)
        else
            ID=`echo $1 | sed 's/[^0-9]*//g'`
        fi
        echo $ID"@elan"
    fi
}
declare -fx h2elan

h2openib() {
    if [ "$1" = "client" -o "$1" = "'*'" ]; then echo \'*\'; else
        ID=`echo $1 | sed 's/[^0-9]*//g'`
        echo $ID"@openib"
    fi
}
declare -fx h2openib

h2o2ib() {
    h2name_or_ip "$1" "o2ib"
}
declare -fx h2o2ib

facet_host() {
    local facet=$1

    [ "$facet" == client ] && echo -n $HOSTNAME && return
    varname=${facet}_HOST
    if [ -z "${!varname}" ]; then
        if [ "${facet:0:3}" == "ost" ]; then
            eval ${facet}_HOST=${ost_HOST}
        fi
    fi
    echo -n ${!varname}
}

facet_active() {
    local facet=$1
    local activevar=${facet}active

    if [ -f $TMP/${facet}active ] ; then
        source $TMP/${facet}active
    fi

    active=${!activevar}
    if [ -z "$active" ] ; then
        echo -n ${facet}
    else
        echo -n ${active}
    fi
}

facet_active_host() {
    local facet=$1
    local active=`facet_active $facet`
    if [ "$facet" == client ]; then
        echo $HOSTNAME
    else
        echo `facet_host $active`
    fi
}

change_active() {
    local facetlist=$1
    local facet

    facetlist=$(exclude_items_from_list $facetlist mgs)

    for facet in ${facetlist//,/ }; do
    local failover=${facet}failover
    local host=`facet_host $failover`
    [ -z "$host" ] && return

    local curactive=`facet_active $facet`
    if [ -z "${curactive}" -o "$curactive" == "$failover" ] ; then
        eval export ${facet}active=$facet
    else
        eval export ${facet}active=$failover
    fi
    # save the active host for this facet
    local activevar=${facet}active
    echo "$activevar=${!activevar}" > $TMP/$activevar
    [[ $facet = mds ]] && combined_mgs_mds && \
        echo "mgsactive=${!activevar}" > $TMP/mgsactive
    local TO=`facet_active_host $facet`
    echo "Failover $facet to $TO"
    done
}

do_node() {
    local verbose=false
    # do not stripe off hostname if verbose, bug 19215
    if [ x$1 = x--verbose ]; then
        shift
        verbose=true
    fi

    local HOST=$1
    shift
    local myPDSH=$PDSH
    if [ "$HOST" = "$HOSTNAME" ]; then
        myPDSH="no_dsh"
    elif [ -z "$myPDSH" -o "$myPDSH" = "no_dsh" ]; then
        echo "cannot run remote command on $HOST with $myPDSH"
        return 128
    fi
    if $VERBOSE; then
        echo "CMD: $HOST $@" >&2
        $myPDSH $HOST "$LCTL mark \"$@\"" > /dev/null 2>&1 || :
    fi

    if [ "$myPDSH" = "rsh" ]; then
# we need this because rsh does not return exit code of an executed command
        local command_status="$TMP/cs"
        rsh $HOST ":> $command_status"
        rsh $HOST "(PATH=\$PATH:$RLUSTRE/utils:$RLUSTRE/tests:/sbin:/usr/sbin;
                    cd $RPWD; sh -c \"$@\") ||
                    echo command failed >$command_status"
        [ -n "$($myPDSH $HOST cat $command_status)" ] && return 1 || true
        return 0
    fi

    if $verbose ; then
        # print HOSTNAME for myPDSH="no_dsh"
        if [[ $myPDSH = no_dsh ]]; then
            $myPDSH $HOST "(PATH=\$PATH:$RLUSTRE/utils:$RLUSTRE/tests:/sbin:/usr/sbin; cd $RPWD; sh -c \"$@\")" | sed -e "s/^/${HOSTNAME}: /"
        else
            $myPDSH $HOST "(PATH=\$PATH:$RLUSTRE/utils:$RLUSTRE/tests:/sbin:/usr/sbin; cd $RPWD; sh -c \"$@\")"
        fi
    else
        $myPDSH $HOST "(PATH=\$PATH:$RLUSTRE/utils:$RLUSTRE/tests:/sbin:/usr/sbin; cd $RPWD; sh -c \"$@\")" | sed "s/^${HOST}: //"
    fi
    return ${PIPESTATUS[0]}
}

do_nodev() {
    do_node --verbose "$@"
}

single_local_node () {
   [ "$1" = "$HOSTNAME" ]
}

do_nodes() {
    local verbose=false
    # do not stripe off hostname if verbose, bug 19215
    if [ x$1 = x--verbose ]; then
        shift
        verbose=true
    fi

    local rnodes=$1
    shift

    if single_local_node $rnodes; then
        if $verbose; then
           do_nodev $rnodes "$@"
        else
           do_node $rnodes "$@"
        fi
        return $?
    fi

    # This is part from do_node
    local myPDSH=$PDSH

    [ -z "$myPDSH" -o "$myPDSH" = "no_dsh" -o "$myPDSH" = "rsh" ] && \
        echo "cannot run remote command on $rnodes with $myPDSH" && return 128

    export FANOUT=$(get_node_count "${rnodes//,/ }")
    if $VERBOSE; then
        echo "CMD: $rnodes $@" >&2
        $myPDSH $rnodes "$LCTL mark \"$@\"" > /dev/null 2>&1 || :
    fi

    # do not replace anything from pdsh output if -N is used
    # -N     Disable hostname: prefix on lines of output.
    if $verbose || [[ $myPDSH = *-N* ]]; then
        $myPDSH $rnodes "(PATH=\$PATH:$RLUSTRE/utils:$RLUSTRE/tests:/sbin:/usr/sbin; cd $RPWD; sh -c \"$@\")"
    else
        $myPDSH $rnodes "(PATH=\$PATH:$RLUSTRE/utils:$RLUSTRE/tests:/sbin:/usr/sbin; cd $RPWD; sh -c \"$@\")" | sed -re "s/^[^:]*: //g"
    fi
    return ${PIPESTATUS[0]}
}

do_facet() {
    local facet=$1
    shift
    local HOST=`facet_active_host $facet`
    [ -z $HOST ] && echo No host defined for facet ${facet} && exit 1
    do_node $HOST "$@"
}

do_nodesv() {
    do_nodes --verbose "$@"
}

add() {
    local facet=$1
    shift
    # make sure its not already running
    stop ${facet} -f
    rm -f $TMP/${facet}active
    [[ $facet = mds ]] && combined_mgs_mds && rm -f $TMP/mgsactive
    do_facet ${facet} $MKFS $*
}

ostdevname() {
    num=$1
    DEVNAME=OSTDEV$num
    #if $OSTDEVn isn't defined, default is $OSTDEVBASE + num
    eval DEVPTR=${!DEVNAME:=${OSTDEVBASE}${num}}
    echo -n $DEVPTR
}

facet_mntpt() {
    local facet=$1
    if combined_mgs_mds && [[ $facet = "mgs" ]]  ; then
        facet="mds"
    fi
    local var=${facet}_MOUNT
    eval mntpt=${!var:-${MOUNT%/*}/$facet}

    echo -n $mntpt
}

########
## MountConf setup

stopall() {
    # make sure we are using the primary server, so test-framework will
    # be able to clean up properly.
    activemds=`facet_active mds`
    if [ $activemds != "mds" ]; then
        fail mds
    fi

    local clients=$CLIENTS
    [ -z $clients ] && clients=$(hostname)

    zconf_umount_clients $clients $MOUNT "$*" || true
    [ -n "$MOUNT2" ] && zconf_umount_clients $clients $MOUNT2 "$*" || true

    [ "$CLIENTONLY" ] && return
    # The add fn does rm ${facet}active file, this would be enough
    # if we use do_facet <facet> only after the facet added, but
    # currently we use do_facet mds in local.sh
    stop mds -f
    rm -f ${TMP}/mdsactive
    combined_mgs_mds && rm -f $TMP/mgsactive
    for num in `seq $OSTCOUNT`; do
        stop ost$num -f
        rm -f $TMP/ost${num}active
    done
    if ! combined_mgs_mds ; then
        stop mgs
    fi

    return 0
}

cleanup_echo_devs () {
    local devs=$($LCTL dl | grep echo | awk '{print $4}')

    for dev in $devs; do
        $LCTL --device $dev cleanup
        $LCTL --device $dev detach
    done
}

cleanupall() {
    nfs_client_mode && return

    stopall $*
    cleanup_echo_devs

    unload_modules
}

combined_mgs_mds () {
    [[ $MDSDEV = $MGSDEV ]] && [[ $mds_HOST = $mgs_HOST ]]
}

facet_number() {
    local facet=$1

    local number=$(echo -n $facet | sed -e 's/^fs[0-9]\+//' |
                   sed -e 's/^[a-z]\+//')

    [[ -z $number ]] && number=1

    echo -n $number
}

mkfs_opts() {
    local facet=$1

    local index=$(($(facet_number $facet) - 1))
    local tgt=$(echo $facet | tr -d [:digit:] | tr "[:lower:]" "[:upper:]")
    local optvar=${tgt}_MKFS_OPTS
    local opt=${!optvar}

    # FIXME: ! combo  mgs/mds + mgsfailover is not supported yet
    [[ $facet = mgs ]] && echo $opt && return

    # --index option
    [[ $opt != *--index* ]] && opt+=" --index=$index"

    # 1.
    # --failnode options
    local var=${facet}failover_HOST
    if [ x"${!var}" != x ] && [ x"${!var}" != x$(facet_host $facet) ] ; then
        local failnode=$(h2$NETTYPE ${!var})
        failnode="--failnode=$failnode"
        # options does not contain
        # or contains wrong --failnode=
        if [[ $opt != *${failnode}* ]]; then
            opt=$(echo $opt | sed 's/--failnode=.* / /')
            opt="$opt $failnode"
        fi
    fi

    # 2.
    # --mgsnode options
    # no additional mkfs mds "--mgsnode" option for this configuration
    if [[ $facet = mds ]] && combined_mgs_mds; then
        echo $opt
        return
    fi

    # additional mkfs "--mgsnode"
    local mgsnode="--mgsnode=$MGSNID"
    opt=${opt//$mgsnode }
    for nid in ${MGSNID//:/ }; do
        local mgsnode="--mgsnode=$nid"
        # options does not contain
        # --mgsnode=$nid
        if [[ $opt != *${mgsnode}" "* ]]; then
            opt="$opt --mgsnode=$nid"
        fi
    done

    echo $opt
}

formatall() {
    [ "$FSTYPE" ] && FSTYPE_OPT="--backfstype $FSTYPE"

    stopall
    # We need ldiskfs here, may as well load them all
    load_modules
    [ "$CLIENTONLY" ] && return
    echo Formatting mgs, mds, osts
    if ! combined_mgs_mds ; then
        add mgs $(mkfs_opts mgs) $FSTYPE_OPT --reformat $MGSDEV || exit 10
    fi

    if $VERBOSE; then
        add mds $(mkfs_opts mds) $FSTYPE_OPT --reformat $MDSDEV || exit 10
    else
        add mds $(mkfs_opts mds) $FSTYPE_OPT --reformat $MDSDEV > /dev/null || exit 10
    fi

    # the ost-s could have different OST_MKFS_OPTS
    # because of different failnode-s
    for num in `seq $OSTCOUNT`; do
        if $VERBOSE; then
            add ost$num $(mkfs_opts ost${num}) $FSTYPE_OPT --reformat `ostdevname $num` || exit 10
        else
            add ost$num $(mkfs_opts ost${num}) $FSTYPE_OPT --reformat `ostdevname $num` > /dev/null || exit 10
        fi
    done
}

mount_client() {
    grep " $1 " /proc/mounts || zconf_mount $HOSTNAME $*
}

remount_client()
{
        zconf_umount `hostname` $1 || error "umount failed"
        zconf_mount `hostname` $1 || error "mount failed"
}

writeconf_facet () {
    local facet=$1
    local dev=$2

    do_facet $facet "$TUNEFS --writeconf $dev"
}

writeconf_all () {
    writeconf_facet mds $MDSDEV

    for num in `seq $OSTCOUNT`; do
        DEVNAME=`ostdevname $num`
        writeconf_facet ost$num $DEVNAME
    done
}

setupall() {
    nfs_client_mode && return

    sanity_mount_check ||
        error "environments are insane!"

    load_modules
    if [ -z "$CLIENTONLY" ]; then
        echo Setup mgs, mdt, osts

        echo $WRITECONF | grep -q "writeconf" && \
            writeconf_all

        if ! combined_mgs_mds ; then
            start mgs $MGSDEV $MGS_MOUNT_OPTS
        fi

        start mds $MDSDEV $MDS_MOUNT_OPTS
        # We started mds, now we should set failover variable properly.
        # Set mdsfailover_HOST if it is not set (the default failnode).
        if [ -z "$mdsfailover_HOST" ]; then
           mdsfailover_HOST=$(facet_host mds)
        fi

        for num in `seq $OSTCOUNT`; do
            DEVNAME=`ostdevname $num`
            start ost$num $DEVNAME $OST_MOUNT_OPTS

            # We started ost$num, now we should set ost${num}failover variable properly.
            # Set ost${num}failover_HOST if it is not set (the default failnode).
            varname=ost${num}failover_HOST
            if [ -z "${!varname}" ]; then
                eval ost${num}failover_HOST=$(facet_host ost${num})
            fi

        done
    fi
    [ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE
    mount_client $MOUNT
    [ -n "$CLIENTS" ] && zconf_mount_clients $CLIENTS $MOUNT
    clients_up

    if [ "$MOUNT_2" ]; then
        mount_client $MOUNT2
        [ -n "$CLIENTS" ] && zconf_mount_clients $CLIENTS $MOUNT2
    fi
    sleep 5
    init_param_vars
}

mounted_lustre_filesystems() {
        awk '($3 ~ "lustre" && $1 ~ ":") { print $2 }' /proc/mounts
}

init_facet_vars () {
    [ "$CLIENTONLY" ] && return 0
    local facet=$1
    shift
    local device=$1

    shift

    eval export ${facet}_dev=${device}
    eval export ${facet}_opt=\"$@\"

    local dev=${facet}_dev
    local label=$(do_facet ${facet} "$E2LABEL ${!dev}")
    [ -z "$label" ] && echo no label for ${!dev} && exit 1

    eval export ${facet}_svc=${label}

    local varname=${facet}failover_HOST
    if [ -z "${!varname}" ]; then
       eval $varname=$(facet_host $facet)
    fi

    # ${facet}failover_dev is set in cfg file
    varname=${facet}failover_dev
    if [ -n "${!varname}" ] ; then
        eval export ${facet}failover_dev=${!varname}
    else
        eval export ${facet}failover_dev=$device
    fi

    # get mount point of already mounted device
    # is facet_dev is already mounted then use the real
    #  mount point of this facet; otherwise use $(facet_mntpt $facet)
    # i.e. ${facet}_MOUNT if specified by user or default
    local mntpt=$(do_facet ${facet} cat /proc/mounts | \
            awk '"'${!dev}'" == $1 && $3 == "lustre" { print $2 }')
    if [ -z $mntpt ]; then
        mntpt=$(facet_mntpt $facet)
    fi
    eval export ${facet}_MOUNT=$mntpt
}

init_facets_vars () {
    remote_mds_nodsh ||
        init_facet_vars mds $MDSDEV $MDS_MOUNT_OPTS

    combined_mgs_mds || init_facet_vars mgs $MGSDEV $MGS_MOUNT_OPTS

    remote_ost_nodsh && return

    for num in `seq $OSTCOUNT`; do
        DEVNAME=`ostdevname $num`
        init_facet_vars ost$num $DEVNAME $OST_MOUNT_OPTS
    done
}

init_param_vars () {
    remote_mds_nodsh ||
        TIMEOUT=$(do_facet mds "lctl get_param -n timeout")

    log "Using TIMEOUT=$TIMEOUT"

    if [ "$ENABLE_QUOTA" ]; then
        setup_quota $MOUNT  || return 2
    fi
}

nfs_client_mode () {
    if [ "$NFSCLIENT" ]; then
        echo "NFSCLIENT mode: setup, cleanup, check config skipped"
        local clients=$CLIENTS
        [ -z $clients ] && clients=$(hostname)

        do_nodesv $clients "grep ' '$MOUNT' ' /proc/mounts"
        declare -a nfsexport=(`grep ' '$MOUNT' ' /proc/mounts | awk '{print $1}' | awk -F: '{print $1 " "  $2}'`)
        if [[ ${#nfsexport[@]} -eq 0 ]]; then
                error_exit NFSCLIENT=$NFSCLIENT mode, but no NFS export found!
        fi
        do_nodesv ${nfsexport[0]} "df -T  ${nfsexport[1]}"
        return
    fi
    return 1
}

check_config_client () {
    local mntpt=$1

    local mounted=$(mount | grep " $mntpt ")
    if [ "$CLIENTONLY" ]; then
        # bug 18021
        # CLIENTONLY should not depend on *_HOST settings
        local mgc=$($LCTL device_list | awk '/MGC/ {print $4}')
        # in theory someone could create a new,
        # client-only config file that assumed lustre was already
        # configured and didn't set the MGSNID. If MGSNID is not set,
        # then we should use the mgs nid currently being used
        # as the default value. bug 18021
        [[ x$MGSNID = x ]] &&
            MGSNID=${mgc//MGC/}

        if [[ x$mgc != xMGC$MGSNID ]]; then
            if [ "$mgs_HOST" ]; then
                local mgc_ip=$(ping -q -c1 -w1 $mgs_HOST | grep PING | awk '{print $3}' | sed -e "s/(//g" -e "s/)//g")
                [[ x$mgc = xMGC$mgc_ip@$NETTYPE ]] ||
                    error_exit "MGSNID=$MGSNID, mounted: $mounted, MGC : $mgc"
            fi
        fi
        return 0
    fi

    local myMGS_host=$mgs_HOST
    if [ "$NETTYPE" = "ptl" ]; then
        myMGS_host=$(h2ptl $mgs_HOST | sed -e s/@ptl//)
    fi

    echo Checking config lustre mounted on $mntpt
    local mgshost=$(mount | grep " $mntpt " | awk -F@ '{print $1}')
    mgshost=$(echo $mgshost | awk -F: '{print $1}')

#    if [ "$mgshost" != "$myMGS_host" ]; then
#            error_exit "Bad config file: lustre is mounted with mgs $mgshost, but mgs_HOST=$mgs_HOST, NETTYPE=$NETTYPE
#                   Please use correct config or set mds_HOST correctly!"
#    fi

}

check_config_clients () {
    local clients=${CLIENTS:-$HOSTNAME}
    local mntpt=$1

    nfs_client_mode && return

    do_rpc_nodes $clients check_config_client $mntpt

    sanity_mount_check ||
        error "environments are insane!"
}

check_timeout () {
    local mdstimeout=$(do_facet mds "lctl get_param -n timeout")
    local cltimeout=$(lctl get_param -n timeout)
    if [ $mdstimeout -ne $TIMEOUT ] || [ $mdstimeout -ne $cltimeout ]; then
        error "timeouts are wrong! mds: $mdstimeout, client: $cltimeout, TIMEOUT=$TIMEOUT"
        return 1
    fi
}

is_mounted () {
    local mntpt=$1
    local mounted=$(mounted_lustre_filesystems)

    echo $mounted' ' | grep -w -q $mntpt' '
}

is_empty_dir() {
    [ $(find $1 -maxdepth 1 -print | wc -l) = 1 ] && return 0
    return 1
}

# empty lustre filesystem may have empty directories lost+found and .lustre
is_empty_fs() {
    [ $(find $1 -maxdepth 1 -name lost+found -o -name .lustre -prune -o \
       -print | wc -l) = 1 ] || return 1
    [ ! -d $1/lost+found ] || is_empty_dir $1/lost+found && return 0
    [ ! -d $1/.lustre ] || is_empty_dir $1/.lustre && return 0
    return 1
}

check_and_setup_lustre() {
    nfs_client_mode && return

    local MOUNTED=$(mounted_lustre_filesystems)

    local do_check=true
    # 1.
    # both MOUNT and MOUNT2 are not mounted
    if ! is_mounted $MOUNT && ! is_mounted $MOUNT2; then
        [ "$REFORMAT" ] && formatall
        # setupall mounts both MOUNT and MOUNT2 (if MOUNT_2 is set)
        setupall
        is_mounted $MOUNT || error "NAME=$NAME not mounted"
        export I_MOUNTED=yes
        do_check=false
    # 2.
    # MOUNT2 is mounted
    elif is_mounted $MOUNT2; then
            # 3.
            # MOUNT2 is mounted, while MOUNT_2 is not set
            if ! [ "$MOUNT_2" ]; then
                cleanup_mount $MOUNT2
                export I_UMOUNTED2=yes

            # 4.
            # MOUNT2 is mounted, MOUNT_2 is set
            else
                # FIXME: what to do if check_config failed?
                # i.e. if:
                # 1) remote client has mounted other Lustre fs ?
                # 2) it has insane env ?
                # let's try umount MOUNT2 on all clients and mount it again:
                if ! check_config_clients $MOUNT2; then
                    cleanup_mount $MOUNT2
                    restore_mount $MOUNT2
                    export I_MOUNTED2=yes
                fi
            fi

    # 5.
    # MOUNT is mounted MOUNT2 is not mounted
    elif [ "$MOUNT_2" ]; then
        restore_mount $MOUNT2
        export I_MOUNTED2=yes
    fi

    if $do_check; then
        # FIXME: what to do if check_config failed?
        # i.e. if:
        # 1) remote client has mounted other Lustre fs?
        # 2) lustre is mounted on remote_clients atall ?
        check_config_clients $MOUNT
        init_facets_vars
        init_param_vars

        set_default_debug_nodes $(comma_list $(nodes_list))
    fi
    if [ "$ONLY" == "setup" ]; then
        exit 0
    fi
}

restore_mount () {
   local clients=${CLIENTS:-$HOSTNAME}
   local mntpt=$1

   zconf_mount_clients $clients $mntpt
}

cleanup_mount () {
    local clients=${CLIENTS:-$HOSTNAME}
    local mntpt=$1

    zconf_umount_clients $clients $mntpt
}

cleanup_and_setup_lustre() {
    if [ "$ONLY" == "cleanup" -o "`mount | grep $MOUNT`" ]; then
        lctl set_param debug=0 || true
        cleanupall
        if [ "$ONLY" == "cleanup" ]; then
            exit 0
        fi
    fi
    check_and_setup_lustre
}

# Get all of the server target devices from a given server node and type.
get_mnt_devs() {
    local node=$1
    local type=$2
    local devs
    local dev

    if [ "$type" == ost ]; then
        devs=$(get_obdfilter_param $node "" mntdev)
    else
        devs=$(do_node $node \
            "lctl get_param -n osd-*.$FSNAME-M*.mntdev")
    fi
    for dev in $devs; do
        case $dev in
        *loop*) do_node $node "losetup $dev" | \
                sed -e "s/.*(//" -e "s/).*//" ;;
        *) echo $dev ;;
        esac
    done
}

# Get all of the server target devices.
get_svr_devs() {
    local i

    # OST devices
    i=0
    for node in $(osts_nodes); do
        OSTDEVS[i]=$(get_mnt_devs $node ost)
        i=$((i + 1))
    done
}

# Run e2fsck on MDT or OST device.
run_e2fsck() {
    local node=$1
    local target_dev=$2
    local extra_opts=$3

    df > /dev/null    # update statfs data on disk
    local cmd="$E2FSCK -d -v -t -t -f -n $extra_opts $target_dev"
    echo $cmd
    local rc=0
    do_node $node $cmd || rc=$?
    [ $rc -le $FSCK_MAX_ERR ] || \
        error_exit "$cmd returned $rc, should be <= $FSCK_MAX_ERR"
    return 0
}

# verify a directory is shared among nodes.
check_shared_dir() {
    local dir=$1

    [ -z "$dir" ] && return 1
    do_rpc_nodes $(comma_list $(nodes_list)) check_logdir $dir
    check_write_access $dir || return 1
    return 0
}

# Run e2fsck on MDT and OST(s) to generate databases used for lfsck.
generate_db() {
    local i
    local ostidx
    local dev

    check_shared_dir $SHARED_DIRECTORY ||
        error "$SHARED_DIRECTORY isn't a shared directory"

    export MDSDB=$SHARED_DIRECTORY/mdsdb
    export OSTDB=$SHARED_DIRECTORY/ostdb

    run_e2fsck $(facet_host mds) $MDSDEV "--mdsdb $MDSDB"

    i=0
    ostidx=0
    OSTDB_LIST=""
    for node in $(osts_nodes); do
        for dev in ${OSTDEVS[i]}; do
            run_e2fsck $node $dev "--mdsdb $MDSDB --ostdb $OSTDB-$ostidx"
            OSTDB_LIST="$OSTDB_LIST $OSTDB-$ostidx"
            ostidx=$((ostidx + 1))
        done
        i=$((i + 1))
    done
}

run_lfsck() {
    local cmd="$LFSCK_BIN -c -l --mdsdb $MDSDB --ostdb $OSTDB_LIST $MOUNT"
    echo $cmd
    local rc=0
    eval $cmd || rc=$?
    [ $rc -le $FSCK_MAX_ERR ] || \
        error_exit "$cmd returned $rc, should be <= $FSCK_MAX_ERR"
    echo "lfsck finished with rc=$rc"

    rm -rvf $MDSDB* $OSTDB* || true
    return 0
}

check_and_cleanup_lustre() {
    if [ "$LFSCK_ALWAYS" = "yes" -a "$TESTSUITE" != "lfsck" ]; then
        get_svr_devs
        generate_db
        run_lfsck
    fi

    if is_mounted $MOUNT; then
        [ -n "$DIR" ] && rm -rf $DIR/[Rdfs][0-9]* ||
            error "remove sub-test dirs failed"
        [ "$ENABLE_QUOTA" ] && restore_quota || true
    fi

    if [ "$I_UMOUNTED2" = "yes" ]; then
        restore_mount $MOUNT2 || error "restore $MOUNT2 failed"
    fi

    if [ "$I_MOUNTED2" = "yes" ]; then
        cleanup_mount $MOUNT2
    fi

    if [ "$I_MOUNTED" = "yes" ]; then
        cleanupall -f || error "cleanup failed"
        unset I_MOUNTED
    fi
}

#######
# General functions

wait_for_function () {
    local quiet=""

    # suppress fn both stderr and stdout
    if [ "$1" = "--quiet" ]; then
        shift
        quiet=" > /dev/null 2>&1"
    fi

    local fn=$1
    local max=${2:-900}
    local sleep=${3:-5}

    local wait=0

    while true; do

        eval $fn $quiet && return 0

        wait=$((wait + sleep))
        [ $wait -lt $max ] || return 1
        echo waiting $fn, $((max - wait)) secs left ...
        sleep $sleep
    done
}

check_network() {
    local host=$1
    local max=$2
    local sleep=${3:-5}

    echo `date +"%H:%M:%S (%s)"` waiting for $host network $max secs ...
    if ! wait_for_function --quiet "ping -c 1 -w 3 $host" $max $sleep ; then
        echo "Network not available!"
        exit 1
    fi

    echo `date +"%H:%M:%S (%s)"` network interface is UP
}

no_dsh() {
    shift
    eval $@
}

comma_list() {
    # the sed converts spaces to commas, but leaves the last space
    # alone, so the line doesn't end with a comma.
    echo "$*" | tr -s " " "\n" | sort -b -u | tr "\n" " " | sed 's/ \([^$]\)/,\1/g'
}

list_member () {
    local list=$1
    local item=$2
    echo $list | grep -qw $item
}

# list, excluded are the comma separated lists
exclude_items_from_list () {
    local list=$1
    local excluded=$2
    local item

    list=${list//,/ }
    for item in ${excluded//,/ }; do
        list=$(echo " $list " | sed -re "s/\s+$item\s+/ /g")
    done
    echo $(comma_list $list)
}

# list, expand  are the comma separated lists
expand_list () {
    local list=${1//,/ }
    local expand=${2//,/ }
    local expanded=

    expanded=$(for i in $list $expand; do echo $i; done | sort -u)
    echo $(comma_list $expanded)
}

testslist_filter () {
    local script=$LUSTRE/tests/${TESTSUITE}.sh

    [ -f $script ] || return 0

    local start_at=$START_AT
    local stop_at=$STOP_AT

    local var=${TESTSUITE//-/_}_START_AT
    [ x"${!var}" != x ] && start_at=${!var}
    var=${TESTSUITE//-/_}_STOP_AT
    [ x"${!var}" != x ] && stop_at=${!var}

    sed -n 's/^test_\([^ (]*\).*/\1/p' $script | \
        awk ' BEGIN { if ("'${start_at:-0}'" != 0) flag = 1 }
            /^'${start_at}'$/ {flag = 0}
            {if (flag == 1) print $0}
            /^'${stop_at}'$/ { flag = 1 }'
}

absolute_path() {
    (cd `dirname $1`; echo $PWD/`basename $1`)
}

get_facets () {
    local types=${1:-"OST MDS MGS"}

    local list=""
    for entry in $types; do
        local name=$(echo $entry | tr "[:upper:]" "[:lower:]")
        local type=$(echo $entry | tr "[:lower:]" "[:upper:]")

        case $type in
            MDS|MGS ) list="$list $name";;
                OST ) for ((i=1; i<=$OSTCOUNT; i++)) do
                          list="$list ${name}$i"
                      done;;
                  * ) error "Invalid facet type"
                 exit 1;;
        esac
    done
    echo $(comma_list $list)
}

##################################
# Adaptive Timeouts funcs

at_is_enabled() {
    # only check mds, we assume at_max is the same on all nodes
    local at_max=$(do_facet mds "lctl get_param -n at_max")
    if [ $at_max -eq 0 ]; then
        return 1
    else
        return 0
    fi
}

at_get() {
    local facet=$1
    local at=$2

    # suppose that all ost-s have the same $at value set
    [ $facet != "ost" ] || facet=ost1

    do_facet $facet "lctl get_param -n $at"
}

at_max_get() {
    at_get $1 at_max
}

at_max_set() {
    local at_max=$1
    shift

    local facet
    local hosts
    for facet in $@; do
        if [ $facet == "ost" ]; then
            facet=$(get_facets OST)
        fi
        hosts=$(expand_list $hosts $(facets_hosts $facet))
    done

    do_nodes $hosts lctl set_param at_max=$at_max
}

##################################
# OBD_FAIL funcs

drop_request() {
# OBD_FAIL_MDS_ALL_REQUEST_NET
    RC=0
    do_facet mds lctl set_param fail_loc=0x123
    do_facet client "$1" || RC=$?
    do_facet mds lctl set_param fail_loc=0
    return $RC
}

drop_reply() {
# OBD_FAIL_MDS_ALL_REPLY_NET
    RC=0
    do_facet mds lctl set_param fail_loc=0x122
    do_facet client "$@" || RC=$?
    do_facet mds lctl set_param fail_loc=0
    return $RC
}

drop_reint_reply() {
# OBD_FAIL_MDS_REINT_NET_REP
    RC=0
    do_facet mds lctl set_param fail_loc=0x119
    do_facet client "$@" || RC=$?
    do_facet mds lctl set_param fail_loc=0
    return $RC
}

pause_bulk() {
#define OBD_FAIL_OST_BRW_PAUSE_BULK      0x214
    RC=0
    do_facet ost1 lctl set_param fail_loc=0x214
    do_facet client "$1" || RC=$?
    do_facet client "sync"
    do_facet ost1 lctl set_param fail_loc=0
    return $RC
}

drop_ldlm_cancel() {
#define OBD_FAIL_LDLM_CANCEL             0x304
    RC=0
    do_facet client lctl set_param fail_loc=0x304
    do_facet client "$@" || RC=$?
    do_facet client lctl set_param fail_loc=0
    return $RC
}

drop_bl_callback() {
#define OBD_FAIL_LDLM_BL_CALLBACK        0x305
    RC=0
    do_facet client lctl set_param fail_loc=0x305
    do_facet client "$@" || RC=$?
    do_facet client lctl set_param fail_loc=0
    return $RC
}

drop_ldlm_reply() {
#define OBD_FAIL_LDLM_REPLY              0x30c
    RC=0
    do_facet mds lctl set_param fail_loc=0x30c
    do_facet client "$@" || RC=$?
    do_facet mds lctl set_param fail_loc=0
    return $RC
}

clear_failloc() {
    facet=$1
    pause=$2
    sleep $pause
    echo "clearing fail_loc on $facet"
    do_facet $facet "lctl set_param fail_loc=0 2>/dev/null || true"
}

set_nodes_failloc () {
    do_nodes $(comma_list $1)  lctl set_param fail_loc=$2
}

cancel_lru_locks() {
    $LCTL mark "cancel_lru_locks $1 start"
    for d in `lctl get_param -N ldlm.namespaces.*.lru_size | egrep -i $1`; do
        $LCTL set_param -n $d=clear
    done
    $LCTL get_param ldlm.namespaces.*.lock_unused_count | egrep -i $1 | grep -v '=0'
    $LCTL mark "cancel_lru_locks $1 stop"
}

default_lru_size()
{
        NR_CPU=$(grep -c "processor" /proc/cpuinfo)
        DEFAULT_LRU_SIZE=$((100 * NR_CPU))
        echo "$DEFAULT_LRU_SIZE"
}

lru_resize_enable()
{
    lctl set_param ldlm.namespaces.*$1*.lru_size=0
}

lru_resize_disable()
{
    lctl set_param ldlm.namespaces.*$1*.lru_size $(default_lru_size)
}

pgcache_empty() {
    local FILE
    for FILE in `lctl get_param -N "llite.*.dump_page_cache"`; do
        if [ `lctl get_param -n $FILE | wc -l` -gt 1 ]; then
            echo there is still data in page cache $FILE ?
            lctl get_param -n $FILE
            return 1
        fi
    done
    return 0
}

create_fake_exports () {
    local facet=$1
    local num=$2
#obd_fail_val = num;
#define OBD_FAIL_TGT_FAKE_EXP 0x708
    do_facet $facet "lctl set_param fail_val=$num"
    do_facet $facet "lctl set_param fail_loc=0x80000708"
    fail $facet
}

debugsave() {
    DEBUGSAVE="$(lctl get_param -n debug)"
}

debugrestore() {
    [ -n "$DEBUGSAVE" ] && lctl set_param debug="${DEBUGSAVE}"
    DEBUGSAVE=""
}

##################################
# Test interface
##################################

error_noexit() {
    local TYPE=${TYPE:-"FAIL"}

    local dump=true
    # do not dump logs if $1=false
    if [ "x$1" = "xfalse" ]; then
        shift
        dump=false
    fi

    log " ${TESTSUITE} ${TESTNAME}: @@@@@@ ${TYPE}: $@ "

    mkdir -p $LOGDIR
    # We need to dump the logs on all nodes
    if $dump; then
        gather_logs $(comma_list $(nodes_list))
    fi

    debugrestore
    [ "$TESTSUITELOG" ] && echo "$0: ${TYPE}: $TESTNAME $@" >> $TESTSUITELOG
    echo "$@" > $LOGDIR/err
}

exit_status () {
    local status=0
    local log=$TESTSUITELOG

    [ -f "$log" ] && egrep -q .FAIL: $log && status=1
    exit $status
}

error() {
    error_noexit "$@"
    if $FAIL_ON_ERROR;  then
        reset_fail_loc
        exit 1
    fi
}

error_exit() {
    error_noexit "$@"
    exit 1
}

# use only if we are ignoring failures for this test, bugno required.
# (like ALWAYS_EXCEPT, but run the test and ignore the results.)
# e.g. error_ignore 5494 "your message"
error_ignore() {
    local TYPE="IGNORE (bz$1)"
    shift
    error_noexit "$@"
}

skip_env () {
    $FAIL_ON_SKIP_ENV && error false $@ || skip $@
}

skip() {
    echo
    log " SKIP: $TESTSUITE $TESTNAME $@"

    if [[ -n "$ALWAYS_SKIPPED" ]]; then
        skip_logged $TESTNAME "$@"
    else
        mkdir -p $LOGDIR
        echo "$@" > $LOGDIR/skip
    fi

    [[ -n "$TESTSUITELOG" ]] &&
        echo "$TESTSUITE: SKIP: $TESTNAME $@" >> $TESTSUITELOG || true
}

build_test_filter() {
    EXCEPT="$EXCEPT $(testslist_filter)"

    [ "$ONLY" ] && log "only running test `echo $ONLY`"
    for O in $ONLY; do
        eval ONLY_${O}=true
    done
    [ "$EXCEPT$ALWAYS_EXCEPT" ] && \
        log "excepting tests: `echo $EXCEPT $ALWAYS_EXCEPT`"
    [ "$EXCEPT_SLOW" ] && \
        log "skipping tests SLOW=no: `echo $EXCEPT_SLOW`"
    for E in $EXCEPT; do
        eval EXCEPT_${E}=true
    done
    for E in $ALWAYS_EXCEPT; do
        eval EXCEPT_ALWAYS_${E}=true
    done
    for E in $EXCEPT_SLOW; do
        eval EXCEPT_SLOW_${E}=true
    done
    for G in $GRANT_CHECK_LIST; do
        eval GCHECK_ONLY_${G}=true
    done
}

basetest() {
    if [[ $1 = [a-z]* ]]; then
        echo $1
    else
        echo ${1%%[a-z]*}
    fi
}

# print a newline if the last test was skipped
export LAST_SKIPPED=
export ALWAYS_SKIPPED=

run_test() {
    assert_DIR

    export base=`basetest $1`
    if [ ! -z "$ONLY" ]; then
        testname=ONLY_$1
        if [ ${!testname}x != x ]; then
            [ "$LAST_SKIPPED" ] && echo "" && LAST_SKIPPED=
            run_one_logged $1 "$2"
            return $?
        fi
        testname=ONLY_$base
        if [ ${!testname}x != x ]; then
            [ "$LAST_SKIPPED" ] && echo "" && LAST_SKIPPED=
            run_one_logged $1 "$2"
            return $?
        fi
        LAST_SKIPPED="y"
        echo -n "."
        return 0
    fi

    LAST_SKIPPED="y"
    ALWAYS_SKIPPED="y"
    testname=EXCEPT_$1
    if [ ${!testname}x != x ]; then
        TESTNAME=test_$1 skip "skipping excluded test $1"
        return 0
    fi
    testname=EXCEPT_$base
    if [ ${!testname}x != x ]; then
        TESTNAME=test_$1 skip "skipping excluded test $1 (base $base)"
        return 0
    fi
    testname=EXCEPT_ALWAYS_$1
    if [ ${!testname}x != x ]; then
        TESTNAME=test_$1 skip "skipping ALWAYS excluded test $1"
        return 0
    fi
    testname=EXCEPT_ALWAYS_$base
    if [ ${!testname}x != x ]; then
        TESTNAME=test_$1 skip "skipping ALWAYS excluded test $1 (base $base)"
        return 0
    fi
    testname=EXCEPT_SLOW_$1
    if [ ${!testname}x != x ]; then
        TESTNAME=test_$1 skip "skipping SLOW test $1"
        return 0
    fi
    testname=EXCEPT_SLOW_$base
    if [ ${!testname}x != x ]; then
        TESTNAME=test_$1 skip "skipping SLOW test $1 (base $base)"
        return 0
    fi

    LAST_SKIPPED=
    ALWAYS_SKIPPED=
    run_one_logged $1 "$2"

    return $?
}

EQUALS="======================================================================"
equals_msg() {
    msg="$@"

    local suffixlen=$((${#EQUALS} - ${#msg}))
    [ $suffixlen -lt 5 ] && suffixlen=5
    log `echo $(printf '===== %s %.*s\n' "$msg" $suffixlen $EQUALS)`
}

log() {
    echo "$*"
    module_loaded lnet || load_modules

    local MSG="$*"
    # Get rid of '
    MSG=${MSG//\'/\\\'}
    MSG=${MSG//\(/\\\(}
    MSG=${MSG//\)/\\\)}
    MSG=${MSG//\;/\\\;}
    MSG=${MSG//\|/\\\|}
    MSG=${MSG//\>/\\\>}
    MSG=${MSG//\</\\\<}
    MSG=${MSG//\//\\\/}
    do_nodes $(comma_list $(nodes_list)) $LCTL mark "$MSG" 2> /dev/null || true
}

trace() {
	log "STARTING: $*"
	strace -o $TMP/$1.strace -ttt $*
	RC=$?
	log "FINISHED: $*: rc $RC"
	return 1
}

complete () {
    equals_msg $1 test complete, duration $2 sec
    [ -f "$TESTSUITELOG" ] && grep ".IGNORE\|.FAIL" $TESTSUITELOG || true
    echo duration $2 >>$TESTSUITELOG
}

pass() {
    # Set TEST_STATUS here. It will be used for logging the result.
    TEST_STATUS="PASS"

    if [[ -f $LOGDIR/err ]]; then
        TEST_STATUS="FAIL"
    elif [[ -f $LOGDIR/skip ]]; then
        TEST_STATUS="SKIP"
    fi
    echo "$TEST_STATUS $@" 2>&1 | tee -a $TESTSUITELOG
}

check_mds() {
    FFREE=`lctl get_param -n mds.*.filesfree`
    FTOTAL=`lctl get_param -n mds.*.filestotal`
    [ $FFREE -ge $FTOTAL ] && error "files free $FFREE > total $FTOTAL" || true
}

reset_fail_loc () {
    echo -n "Resetting fail_loc on all nodes..."
    do_nodes $(comma_list $(nodes_list)) "lctl set_param -n fail_loc=0 2>/dev/null || true"
    echo done.
}

run_one() {
    testnum=$1
    message=$2
    tfile=f${testnum}
    export tdir=d0.${TESTSUITE}/d${base}
    export TESTNAME=test_$testnum
    local SAVE_UMASK=`umask`
    umask 0022

    echo
    log "== test $testnum: $message == `date +%H:%M:%S`"
    test_${testnum} || error "test_$testnum failed with $?"
    cd $SAVE_PWD
    reset_fail_loc
    check_grant ${testnum} || error "check_grant $testnum failed with $?"
    check_catastrophe || error "LBUG/LASSERT detected"
    ps auxww | grep -v grep | grep -q multiop && error "multiop still running"
    unset TESTNAME
    unset tdir
    umask $SAVE_UMASK
    return 0
}

run_one_logged() {
    local BEFORE=`date +%s`
    local TEST_ERROR
    local name=${TESTSUITE}.test_${1}.test_log.$(hostname -s).log
    local test_log=$LOGDIR/$name
    rm -rf $LOGDIR/err
    rm -rf $LOGDIR/skip
    local SAVE_UMASK=`umask`
    umask 0022

    echo
    log_sub_test_begin test_${1}
    (run_one $1 "$2") 2>&1 | tee $test_log
    local RC=${PIPESTATUS[0]}

    [ $RC -ne 0 ] && [ ! -f $LOGDIR/err ] && \
        echo "test_$1 returned $RC" | tee $LOGDIR/err

    duration=$((`date +%s` - $BEFORE))
    pass "$1" "(${duration}s)"

    if [[ -f $LOGDIR/err ]]; then
        TEST_ERROR=$(cat $LOGDIR/err)
    elif [[ -f $LOGDIR/skip ]]; then
        TEST_ERROR=$(cat $LOGDIR/skip)
    fi
    log_sub_test_end $TEST_STATUS $duration "$RC" "$TEST_ERROR"

    if [ -f $LOGDIR/err ]; then
        $FAIL_ON_ERROR && exit $RC
    fi

    umask $SAVE_UMASK

    return 0
}

#
# Print information of skipped tests to result.yml
#
skip_logged() {
    log_sub_test_begin $1
    shift
    log_sub_test_end "SKIP" "0" "0" "$@"
}


canonical_path() {
    (cd `dirname $1`; echo $PWD/`basename $1`)
}

check_grant() {
    export base=`basetest $1`
    [ "$CHECK_GRANT" == "no" ] && return 0

	testname=GCHECK_ONLY_${base}
    [ ${!testname}x == x ] && return 0

    echo -n "checking grant......"

    local clients=$CLIENTS
    [ -z $clients ] && clients=$(hostname)

    # sync all the data and make sure no pending data on server
    do_nodes $clients sync

    # get client grant
    client_grant=`do_nodes $clients \
                    "$LCTL get_param -n osc.${FSNAME}-*.cur_*grant_bytes" | \
                    awk '{total += $1} END{print total}'`

    # get server grant
    server_grant=`do_nodes $(comma_list $(osts_nodes)) \
                    "$LCTL get_param -n obdfilter.${FSNAME}-OST*.tot_granted" | \
                    awk '{total += $1} END{print total}'`

    # check whether client grant == server grant
    if [ $client_grant -ne $server_grant ]; then
        echo "failed: client:${client_grant} server: ${server_grant}."
        do_nodes $(comma_list $(osts_nodes)) \
                   "$LCTL get_param obdfilter.${FSNAME}-OST*.tot*"
        do_nodes $clients "$LCTL get_param osc.${FSNAME}-*.cur_*_bytes"
        return 1
    else
        echo "pass: client:${client_grant} server: ${server_grant}"
    fi
}

########################
# helper functions

osc_to_ost()
{
    osc=$1
    ost=`echo $1 | awk -F_ '{print $3}'`
    if [ -z $ost ]; then
        ost=`echo $1 | sed 's/-osc.*//'`
    fi
    echo $ost
}

ostuuid_from_index()
{
    $LFS osts $2 | sed -ne "/^$1: /s/.* \(.*\) .*$/\1/p"
}

ostname_from_index() {
    local uuid=$(ostuuid_from_index $1)
    echo ${uuid/_UUID/}
}

index_from_ostuuid()
{
    $LFS osts $2 | sed -ne "/${1}/s/\(.*\): .* .*$/\1/p"
}

remote_node () {
    local node=$1
    [[ $node != $HOSTNAME ]]
}

remote_mds ()
{
    remote_node $mds_HOST
}

remote_mds_nodsh()
{
    [ "$CLIENTONLY" ] && return 0 || true
    remote_mds && [ "$PDSH" = "no_dsh" -o -z "$PDSH" -o -z "$mds_HOST" ]
}

require_dsh_mds()
{
        remote_mds_nodsh && echo "SKIP: $TESTSUITE: remote MDS with nodsh" && \
            MSKIPPED=1 && return 1
        return 0
}

remote_ost ()
{
    local node
    for node in $(osts_nodes) ; do
        remote_node $node && return 0
    done
    return 1
}

remote_ost_nodsh()
{
    [ "$CLIENTONLY" ] && return 0 || true
    remote_ost && [ "$PDSH" = "no_dsh" -o -z "$PDSH" -o -z "$ost_HOST" ]
}

require_dsh_ost()
{
        remote_ost_nodsh && echo "SKIP: $TESTSUITE: remote OST with nodsh" && \
            OSKIPPED=1 && return 1
        return 0
}

remote_mgs_nodsh()
{
    local MGS
    MGS=$(facet_host mgs)
    remote_node $MGS && [ "$PDSH" = "no_dsh" -o -z "$PDSH" -o -z "$ost_HOST" ]
}

remote_servers () {
    remote_ost && remote_mds
}

local_mode ()
{
    remote_mds_nodsh || remote_ost_nodsh || \
        $(single_local_node $(comma_list $(nodes_list)))
}

facets_nodes () {
    local facets=$1
    local nodes
    local NODES_sort

    for facet in ${facets//,/ }; do
        if [ "$FAILURE_MODE" = HARD ]; then
            nodes="$nodes $(facet_active_host $facet)"
        else
            nodes="$nodes $(facet_host $facet)"
        fi
    done
    NODES_sort=$(for i in $nodes; do echo $i; done | sort -u)

    echo $NODES_sort
}

osts_nodes () {
    local facets=$(get_facets OST)
    local nodes=$(facets_nodes $facets)

    echo $nodes
}

nodes_list () {
    # FIXME. We need a list of clients
    local myNODES=$HOSTNAME
    local myNODES_sort

    # CLIENTS (if specified) contains the local client
    [ -n "$CLIENTS" ] && myNODES=${CLIENTS//,/ }

    if [ "$PDSH" -a "$PDSH" != "no_dsh" ]; then
        myNODES="$myNODES $(facets_nodes $(get_facets))"
    fi

    myNODES_sort=$(for i in $myNODES; do echo $i; done | sort -u)

    echo $myNODES_sort
}

remote_nodes_list () {
    local rnodes=$(nodes_list)
    rnodes=$(echo " $rnodes " | sed -re "s/\s+$HOSTNAME\s+/ /g")
    echo $rnodes
}

init_clients_lists () {
    # Sanity check: exclude the local client from RCLIENTS
    local rclients=$(echo " $RCLIENTS " | sed -re "s/\s+$HOSTNAME\s+/ /g")

    # Sanity check: exclude the dup entries
    rclients=$(for i in $rclients; do echo $i; done | sort -u)

    local clients="$SINGLECLIENT $HOSTNAME $rclients"

    # Sanity check: exclude the dup entries from CLIENTS
    # for those configs which has SINGLCLIENT set to local client
    clients=$(for i in $clients; do echo $i; done | sort -u)

    CLIENTS=`comma_list $clients`
    local -a remoteclients=($rclients)
    for ((i=0; $i<${#remoteclients[@]}; i++)); do
            varname=CLIENT$((i + 2))
            eval $varname=${remoteclients[i]}
    done

    CLIENTCOUNT=$((${#remoteclients[@]} + 1))
}

get_random_entry () {
    local rnodes=$1

    rnodes=${rnodes//,/ }

    local -a nodes=($rnodes)
    local num=${#nodes[@]}
    local i=$((RANDOM * num * 2 / 65536))

    echo ${nodes[i]}
}

client_only () {
    [ "$CLIENTONLY" ] || [ "$CLIENTMODSONLY" = yes ]
}

is_patchless ()
{
    lctl get_param version | grep -q patchless
}

check_versions() {
    [ "$(lustre_version_code client)" = "$(lustre_version_code mds)" -a \
      "$(lustre_version_code client)" = "$(lustre_version_code ost1)" ]
}

get_node_count() {
    local nodes="$@"
    echo $nodes | wc -w || true
}

mixed_ost_devs () {
    local nodes=$(osts_nodes)
    local osscount=$(get_node_count "$nodes")
    [ ! "$OSTCOUNT" = "$osscount" ]
}

generate_machine_file() {
    local nodes=${1//,/ }
    local machinefile=$2
    rm -f $machinefile
    for node in $nodes; do
        echo $node >>$machinefile || \
            { echo "can not generate machinefile $machinefile" && return 1; }
    done
}

get_stripe () {
    local file=$1/stripe
    touch $file
    $LFS getstripe -v $file || error
    rm -f $file
}

nfs_server () {
    local dir=$1

    local nfsserver=$(awk '"'$dir'" ~ $2 && $3 ~ "nfs" && $2 != "/" \
            { print $1 }' /proc/mounts | cut -f 1 -d : | head -1)
    echo $nfsserver
}

setstripe_nfsserver () {
    local dir=$1
    local nfsserver=$(nfs_server $dir)

    [ -z $nfsserver ] && echo "$dir is not nfs mounted" && return 1

    do_nodev $nfsserver lfs setstripe "$@"
}

# Check and add a test group.
add_group() {
	local group_id=$1
	local group_name=$2
	local rc=0

	local gid=$(getent group $group_name | cut -d: -f3)
	if [[ -n "$gid" ]]; then
		[[ "$gid" -eq "$group_id" ]] || {
			error_noexit "inconsistent group ID:" \
				     "new: $group_id, old: $gid"
			rc=1
		}
	else
		groupadd -g $group_id $group_name
		rc=${PIPESTATUS[0]}
	fi

	return $rc
}

# Check and add a test user.
add_user() {
	local user_id=$1
	shift
	local user_name=$1
	shift
	local group_name=$1
	shift
	local home=$1
	shift
	local opts="$@"
	local rc=0

	local uid=$(getent passwd $user_name | cut -d: -f3)
	if [[ -n "$uid" ]]; then
		if [[ "$uid" -eq "$user_id" ]]; then
			local dir=$(getent passwd $user_name | cut -d: -f6)
			if [[ "$dir" != "$home" ]]; then
				mkdir -p $home
				usermod -d $home $user_name
				rc=${PIPESTATUS[0]}
			fi
		else
			error_noexit "inconsistent user ID:" \
				     "new: $user_id, old: $uid"
			rc=1
		fi
	else
		mkdir -p $home
		useradd -M -u $user_id -d $home -g $group_name $opts $user_name
		rc=${PIPESTATUS[0]}
	fi

	return $rc
}

check_runas_id_ret() {
    local myRC=0
    local myRUNAS_UID=$1
    local myRUNAS_GID=$2
    shift 2
    local myRUNAS=$@
    if [ -z "$myRUNAS" ]; then
        error_exit "myRUNAS command must be specified for check_runas_id"
    fi
    mkdir $DIR/d0_runas_test
    chmod 0755 $DIR
    chown $myRUNAS_UID:$myRUNAS_GID $DIR/d0_runas_test
    if ! $myRUNAS touch $DIR/d0_runas_test/f$$ ; then
        do_nodesv $(comma_list $(nodes_list)) grep -w $myRUNAS_UID /etc/passwd
        myRC=1
    fi
    rm -rf $DIR/d0_runas_test
    return $myRC
}

check_runas_id() {
    local myRUNAS_UID=$1
    local myRUNAS_GID=$2
    shift 2
    local myRUNAS=$@
    check_runas_id_ret $myRUNAS_UID $myRUNAS_GID $myRUNAS || \
        error "unable to write to $DIR/d0_runas_test as UID $myRUNAS_UID.
        Please set RUNAS_ID to some UID which exists on MDS and client or
        add user $myRUNAS_UID:$myRUNAS_GID on these nodes."
}

# Run multiop in the background, but wait for it to print
# "PAUSING" to its stdout before returning from this function.
multiop_bg_pause() {
    MULTIOP_PROG=${MULTIOP_PROG:-multiop}
    FILE=$1
    ARGS=$2

    TMPPIPE=/tmp/multiop_open_wait_pipe.$$
    mkfifo $TMPPIPE

    echo "$MULTIOP_PROG $FILE v$ARGS"
    $MULTIOP_PROG $FILE v$ARGS > $TMPPIPE &

    echo "TMPPIPE=${TMPPIPE}"
    local multiop_output

    read -t 60 multiop_output < $TMPPIPE
    if [ $? -ne 0 ]; then
        rm -f $TMPPIPE
        return 1
    fi
    rm -f $TMPPIPE
    if [ "$multiop_output" != "PAUSING" ]; then
        echo "Incorrect multiop output: $multiop_output"
        kill -9 $PID
        return 1
    fi

    return 0
}

rmultiop_start() {
    local uniq=$$
    if [ x$1 = x--uniq ]; then
        shift
        uniq=${uniq}_$1
        shift
    fi

    local client=$1
    local file=$2
    local cmds=$3

    # We need to run do_node in bg, because pdsh does not exit
    # if child process of run script exists.
    # I.e. pdsh does not exit when runmultiop_bg_pause exited,
    # because of multiop_bg_pause -> $MULTIOP_PROG &
    # By the same reason we need sleep a bit after do_nodes starts
    # to let runmultiop_bg_pause start muliop and
    # update /tmp/multiop_bg.pid ;
    # The rm /tmp/multiop_bg.pid guarantees here that
    # we have the updated by runmultiop_bg_pause
    # /tmp/multiop_bg.pid file

    local pid_file=$TMP/multiop_bg.pid.$uniq
    do_node $client "rm -f $pid_file && MULTIOP_PID_FILE=$pid_file LUSTRE= runmultiop_bg_pause $file $cmds" &
    local pid=$!
    sleep 3
    local multiop_pid
    multiop_pid=$(do_node $client cat $pid_file)
    [ -n "$multiop_pid" ] || error "$client : Can not get multiop_pid from $pid_file "
    eval export $(node_var_name $client)_multiop_pid$uniq=$multiop_pid
    eval export $(node_var_name $client)_do_node_pid$uniq=$pid
    local var=$(node_var_name $client)_multiop_pid$uniq
    echo node $client multiop_bg started multiop_pid=${!var}
    return $?
}

rmultiop_stop() {
    local uniq=$$
    if [ x$1 = x--uniq ]; then
        shift
        uniq=${uniq}_$1
        shift
    fi

    local client=$1
    local multiop_pid=$(node_var_name $client)_multiop_pid$uniq
    local do_node_pid=$(node_var_name $client)_do_node_pid$uniq

    echo "Stopping multiop_pid=${!multiop_pid} (kill ${!multiop_pid} on $client)"
    do_node $client kill -USR1 ${!multiop_pid}

    wait ${!do_node_pid}
}

do_and_time () {
    local cmd=$1
    local rc

    SECONDS=0
    eval '$cmd'

    [ ${PIPESTATUS[0]} -eq 0 ] || rc=1

    echo $SECONDS
    return $rc
}

inodes_available () {
    local IFree=$($LFS df -i $MOUNT | grep ^$FSNAME | awk '{print $4}' | sort -un | head -1) || return 1
    echo $IFree
}

mdsrate_inodes_available () {
    local min_inodes=$(inodes_available)
    echo $((min_inodes * 99 / 100))
}

# reset llite stat counters
clear_llite_stats(){
        lctl set_param -n llite.*.stats 0
}

# sum llite stat items
calc_llite_stats() {
        local res=$(lctl get_param -n llite.*.stats |
                    awk 'BEGIN {s = 0} END {print s} /^'"$1"'/ {s += $2}')
        echo $res
}

calc_sum () {
        awk 'BEGIN {s = 0}; {s += $1}; END {print s}'
}

calc_osc_kbytes () {
        df $MOUNT > /dev/null
        $LCTL get_param -n osc.*[oO][sS][cC][-_]*.$1 | calc_sum
}

# save_lustre_params(node, parameter_mask)
# generate a stream of formatted strings (<node> <param name>=<param value>)
save_lustre_params() {
        local s
        do_nodesv $1 "lctl get_param $2 | while read s; do echo \\\$s; done"
}

# restore lustre parameters from input stream, produces by save_lustre_params
restore_lustre_params() {
        local node
        local name
        local val
        while IFS=" =" read node name val; do
                do_node ${node//:/} "lctl set_param -n $name $val"
        done
}

check_catastrophe() {
    local rnodes=${1:-$(comma_list $(remote_nodes_list))}
    local C=$CATASTROPHE
    [ -f $C ] && [ $(cat $C) -ne 0 ] && return 1

    if [ $rnodes ]; then
        do_nodes $rnodes "rc=\\\$([ -f $C ] && echo \\\$(< $C) || echo 0);
if [ \\\$rc -ne 0 ]; then echo \\\$(hostname): \\\$rc; fi
exit \\\$rc;"
    fi
}

# $1 node
# $2 file
# $3 $RUNAS
get_stripe_info() {
        local tmp_file

        stripe_size=0
        stripe_count=0
        stripe_index=0
        tmp_file=$(mktemp)

        do_facet $1 $3 lfs getstripe -v $2 > $tmp_file

        stripe_size=`awk '$1 ~ /size/ {print $2}' $tmp_file`
        stripe_count=`awk '$1 ~ /count/ {print $2}' $tmp_file`
        stripe_index=`awk '$1 ~ /stripe_offset/ {print $2}' $tmp_file`
        rm -f $tmp_file
}

mdsrate_cleanup () {
    mpi_run -np $1 ${MACHINEFILE_OPTION} $2 ${MDSRATE} --unlink --nfiles $3 \
            --dir $4 --filefmt $5 $6
}

delayed_recovery_enabled () {
    do_facet mds "lctl get_param -n mds.${mds_svc}.stale_export_age" > /dev/null 2>&1
}

################################################################################
# The following functions are used to enable interop testing between
# 1.8 and 2.0. The lprocfs layout changed from 1.8 to 2.0 as the followings:
# mds -> mdt
# {blocksize filesfree filestotal fstype kbytesavail kbytesfree kbytestotal mntdev} moved from mds to osd
# mdt lov: fsname-mdtlov -> fsname-MDTXXXX-mdtlov
# mdt osc: fsname-OSTXXXX-osc -> fsname-OSTXXXX-osc-MDTXXXX
################################################################################

version_code() {
    # split arguments like "1.8.6-wc3" into "1", "8", "6", "wc3"
    eval set -- $(tr "[:punct:]" " " <<< $*)

    echo -n $((($1 << 16) | ($2 << 8) | $3))
}

get_lustre_version() {
    local facet=${1:-"mds"}
    do_facet $facet $LCTL get_param -n version | awk '/^lustre:/ {print $2}'
}

lustre_version_code() {
    local facet=${1:-"mds"}
    version_code $(get_lustre_version $1)
}

get_mds_version_major () {
    local version=$(get_lustre_version mds)
    echo $version | awk -F. '{print $1}'
}

get_mds_version_minor () {
    local version=$(get_lustre_version mds)
    echo $version | awk -F. '{print $2}'
}

get_mds_version_patch () {
    local version=$(get_lustre_version mds)
    echo $version | awk -F. '{print $3}'
}

get_mds_version_fix () {
    local version=$(get_lustre_version mds)
    echo $version | awk -F. '{print $4}'
}

get_kernel_version () {
    local facet=${1:-"mds"}
    do_facet $facet uname -r | awk -F "-" '{print $1}'
}

get_mds_kernel_major () {
    local version=$(get_kernel_version mds)
    echo $version | awk -F. '{print $1"."$2}'
}

get_mds_kernel_minor () {
    local version=$(get_kernel_version mds)
    echo $version | awk -F. '{print $3}'
}

get_mds_fsstat_proc_path() {
    local major=$(get_mds_version_major)
    local minor=$(get_mds_version_minor)
    if [ $major -le 1 -a $minor -le 8 ] ; then
        echo "mds"
    else
        echo "osd*"
    fi
}

get_mds_mntdev_proc_path() {
    local fsstat_dev=$(get_mds_fsstat_proc_path)
    echo "$fsstat_dev.*.mntdev"
}

get_mdtlov_proc_path() {
    local fsname=$1
    local major=$(get_mds_version_major)
    local minor=$(get_mds_version_minor)
    if [ $major -le 1 -a $minor -le 8 ] ; then
        echo "${fsname}-mdtlov"
    else
        echo "${fsname}-MDT0000-mdtlov"
    fi
}

get_mdtosc_proc_path() {
    local ost=$1
    local major=$(get_mds_version_major)
    local minor=$(get_mds_version_minor)
    if [ $major -le 1 -a $minor -le 8 ] ; then
        echo "${ost}-osc"
    else
        echo "${ost}-osc-MDT0000"
    fi
}

get_mds_mdt_device_proc_path() {
    local major=$(get_mds_version_major)
    local minor=$(get_mds_version_minor)
    if [ $major -le 1 -a $minor -le 8 ] ; then
        echo "mds"
    else
        echo "mdt"
    fi
}

get_md_name () {
    local major=$(get_mds_version_major)
    local minor=$(get_mds_version_minor)
    if [ $major -le 1 -a $minor -le 8 ] ; then
        echo "mdt"
    else
        echo "mdd"
    fi
}

########################

convert_facet2label() {
    local facet=$1

    if [ x$facet = xost ]; then
       facet=ost1
    fi

    local varsvc=${facet}_svc

    if [ -n ${!varsvc} ]; then
        echo ${!varsvc}
    else
        error "No lablel for $facet!"
    fi
}

get_clientosc_proc_path() {
    local ost=$1

    echo "${1}-osc-*"
}

get_osc_import_name() {
    local facet=$1
    local ost=$2
    local label=$(convert_facet2label $ost)

    if [ "$facet" == "mds" ]; then
        get_mdtosc_proc_path $label
        return 0
    fi

    get_clientosc_proc_path $label
    return 0
}

_wait_import_state () {
    local expected=$1
    local CONN_PROC=$2
    local maxtime=${3:-$(max_recovery_time)}
    local CONN_STATE
    local i=0

    CONN_STATE=$($LCTL get_param -n $CONN_PROC 2>/dev/null | cut -f2)
    while [ "${CONN_STATE}" != "${expected}" ]; do
        if [ "${expected}" == "DISCONN" ]; then
            # for disconn we can check after proc entry is removed
            [ "x${CONN_STATE}" == "x" ] && return 0
            #  with AT enabled, we can have connect request timeout near of
            # reconnect timeout and test can't see real disconnect
            [ "${CONN_STATE}" == "CONNECTING" ] && return 0
        fi
        [ $i -ge $maxtime ] && \
            error "can't put import for $CONN_PROC into ${expected} state after $i sec, have ${CONN_STATE}" && \
            return 1
        sleep 1
        CONN_STATE=$($LCTL get_param -n $CONN_PROC 2>/dev/null | cut -f2)
        i=$(($i + 1))
    done

    log "$CONN_PROC in ${CONN_STATE} state after $i sec"
    return 0
}

wait_import_state() {
    local state=$1
    local params=$2
    local maxtime=${3:-$(max_recovery_time)}
    local param

    for param in ${params//,/ }; do
        _wait_import_state $state $param $maxtime || return
    done
}

# One client request could be timeouted because server was not ready
# when request was sent by client.
# The request timeout calculation details :
# ptl_send_rpc ()
#      /* We give the server rq_timeout secs to process the req, and
#      add the network latency for our local timeout. */
#      request->rq_deadline = request->rq_sent + request->rq_timeout +
#           ptlrpc_at_get_net_latency(request) ;
#
# ptlrpc_connect_import ()
#      request->rq_timeout = INITIAL_CONNECT_TIMEOUT
#
# init_imp_at () ->
#   -> at_init(&at->iat_net_latency, 0, 0) -> iat_net_latency=0
# ptlrpc_at_get_net_latency(request) ->
#       at_get (max (iat_net_latency=0, at_min)) = at_min
#
# i.e.:
# request->rq_timeout + ptlrpc_at_get_net_latency(request) =
# INITIAL_CONNECT_TIMEOUT + at_min
#
# We will use obd_timeout instead of INITIAL_CONNECT_TIMEOUT
# because we can not get this value in runtime,
# the value depends on configure options, and it is not stored in /proc.
# obd_support.h:
# #define CONNECTION_SWITCH_MIN 5U
# #ifndef CRAY_XT3
# #define INITIAL_CONNECT_TIMEOUT max(CONNECTION_SWITCH_MIN,obd_timeout/20)
# #else
# #define INITIAL_CONNECT_TIMEOUT max(CONNECTION_SWITCH_MIN,obd_timeout/2)

request_timeout () {
    local facet=$1

    # request->rq_timeout = INITIAL_CONNECT_TIMEOUT
    local init_connect_timeout=$TIMEOUT
    [[ $init_connect_timeout -ge 5 ]] || init_connect_timeout=5

    local at_min=$(at_get $facet at_min)

    echo $(( init_connect_timeout + at_min ))
}

wait_osc_import_state() {
    local facet=$1
    local ost_facet=$2
    local expected=$3
    local ost=$(get_osc_import_name $facet $ost_facet)

    local param="osc.${ost}.ost_server_uuid"

    # 1. wait the deadline of client 1st request (it could be skipped)
    # 2. wait the deadline of client 2nd request
    local maxtime=$(( 2 * $(request_timeout $facet)))

    if ! do_rpc_nodes $(facet_host $facet) \
_wait_import_state $expected $param $maxtime; then
        error "import is not in ${expected} state"
        return 1
    fi

    return 0
}

get_clientmdc_proc_path() {
    echo "${1}-mdc-*"
}

do_rpc_nodes () {
    local list=$1
    shift

    # Add paths to lustre tests for 32 and 64 bit systems.
    local RPATH="PATH=$RLUSTRE/tests:/usr/lib/lustre/tests:/usr/lib64/lustre/tests:$PATH"
    do_nodesv $list "${RPATH} NAME=${NAME} sh rpc.sh $@ "
}

wait_clients_import_state () {
    local list=$1
    local facet=$2
    local expected=$3

    local facets=$facet

    if [ "$FAILURE_MODE" = HARD ]; then
        facets=$(facets_on_host $(facet_active_host $facet))
    fi

    for facet in ${facets//,/ }; do
    local label=$(convert_facet2label $facet)
    local proc_path
    case $facet in
        ost* ) proc_path="osc.$(get_clientosc_proc_path $label).ost_server_uuid" ;;
        mds* ) proc_path="mdc.$(get_clientmdc_proc_path $label).mds_server_uuid" ;;
        *) error "unknown facet!" ;;
    esac
    local params=$(expand_list $params $proc_path)
    done

    if ! do_rpc_nodes $list wait_import_state $expected $params; then
        error "import is not in ${expected} state"
        return 1
    fi
}

destroy_pool_int() {
    local ost
    local OSTS=$(do_facet mds lctl pool_list $1 | awk '$1 !~ /^Pool:/ {print $1}')
    for ost in $OSTS; do
        do_facet mgs lctl pool_remove $1 $ost
    done
    do_facet mgs lctl pool_destroy $1
}

# <fsname>.<poolname> or <poolname>
destroy_pool() {
    local fsname=${1%%.*}
    local poolname=${1##$fsname.}

    [[ x$fsname = x$poolname ]] && fsname=$FSNAME

    local RC

    pool_list $fsname.$poolname || return $?

    destroy_pool_int $fsname.$poolname
    RC=$?
    [[ $RC -ne 0 ]] && return $RC

    wait_update $HOSTNAME "lctl get_param -n lov.$fsname-*.pools.$poolname \
      2>/dev/null || echo foo" "foo" || RC=1

    if [[ $RC -eq 0 ]]; then
        remove_pool_from_list $fsname.$poolname
    else
        error "destroy pool failed $1"
    fi
    return $RC
}

destroy_pools () {
    local fsname=${1:-$FSNAME}
    local poolname
    local listvar=${fsname}_CREATED_POOLS

    pool_list $fsname

    [ x${!listvar} = x ] && return 0

    echo destroy the created pools: ${!listvar}
    for poolname in ${!listvar//,/ }; do
        destroy_pool $fsname.$poolname
    done
}

cleanup_pools () {
    local fsname=${1:-$FSNAME}
    trap 0
    destroy_pools $fsname
}

gather_logs () {
    local list=$1

    local ts=$(date +%s)
    local docp=true

    if [[ ! -f "$YAML_LOG" ]]; then
        # init_logging is not performed before gather_logs,
        # so the $LOGDIR needs to be checked here
        check_shared_dir $LOGDIR && touch $LOGDIR/shared
    fi

    # bug 20237, comment 11
    # It would also be useful to provide the option
    # of writing the file to an NFS directory so it doesn't need to be copied.
    [ -f $LOGDIR/shared ] && docp=false

    # dump lustre logs, dmesg

    prefix="$LOGDIR/${TESTSUITE}.${TESTNAME}"
    suffix="$ts.log"
    echo "Dumping lctl log to ${prefix}.*.${suffix}"

    if [ "$CLIENTONLY" -o "$PDSH" == "no_dsh" ]; then
        echo "Dumping logs only on local client."
        $LCTL dk > ${prefix}.debug_log.$(hostname -s).${suffix}
        dmesg > ${prefix}.dmesg.$(hostname -s).${suffix}
        return
    fi

    do_nodes --verbose $list \
        "$LCTL dk > ${prefix}.debug_log.\\\$(hostname -s).${suffix};
         dmesg > ${prefix}.dmesg.\\\$(hostname -s).${suffix}"
    if $docp; then
        do_nodes $list rsync -az "${prefix}.*.${suffix}" $HOSTNAME:$LOGDIR
    fi
}

do_ls () {
    local mntpt_root=$1
    local num_mntpts=$2
    local dir=$3
    local i
    local cmd
    local pids
    local rc=0

    for i in $(seq 0 $num_mntpts); do
        cmd="ls -laf ${mntpt_root}$i/$dir"
        echo + $cmd;
        $cmd > /dev/null &
        pids="$pids $!"
    done
    echo pids=$pids
    for pid in $pids; do
        wait $pid || rc=$?
    done

    return $rc
}

# target_start_and_reset_recovery_timer()
#        service_time = at_est2timeout(service_time);
#        service_time += 2 * (CONNECTION_SWITCH_MAX + CONNECTION_SWITCH_INC +
#                             INITIAL_CONNECT_TIMEOUT);
# CONNECTION_SWITCH_MAX : min(25U, max(CONNECTION_SWITCH_MIN,obd_timeout))
#define CONNECTION_SWITCH_INC 1
#define INITIAL_CONNECT_TIMEOUT max(CONNECTION_SWITCH_MIN,obd_timeout/20)
#define CONNECTION_SWITCH_MIN 5U

max_recovery_time () {
    local init_connect_timeout=$(( TIMEOUT / 20 ))
    [[ $init_connect_timeout -ge 5 ]] || init_connect_timeout=5

    local service_time=$(( $(at_max_get client) + $(( 2 * $(( 25 + 1  + init_connect_timeout)) )) ))

    echo $service_time
}

remove_mdt_files() {
    local facet=$1
    local mdtdev=$2
    shift 2
    local files="$@"
    local mntpt=${MOUNT%/*}/$facet

    echo "removing files from $mdtdev on $facet: $files"
    mount -t $FSTYPE $MDS_MOUNT_OPTS $mdtdev $mntpt || return $?
    rc=0;
    for f in $files; do
	rm $mntpt/ROOT/$f || { rc=$?; break; }
    done
    umount -f $mntpt || return $?
    return $rc
}

duplicate_mdt_files() {
    local facet=$1
    local mdtdev=$2
    shift 2
    local files="$@"
    local mntpt=${MOUNT%/*}/$facet

    echo "duplicating files on $mdtdev on $facet: $files"
    mkdir -p $mntpt || return $?
    mount -t $FSTYPE $MDS_MOUNT_OPTS $mdtdev $mntpt || return $?

    do_umount() {
	trap 0
	popd > /dev/null
	rm $tmp
	umount -f $mntpt
    }
    trap do_umount EXIT

    tmp=$(mktemp $TMP/setfattr.XXXXXXXXXX)
    pushd $mntpt/ROOT > /dev/null || return $?
    rc=0
    for f in $files; do
	touch $f.bad || return $?
	getfattr -n trusted.lov $f | sed "s#$f#&.bad#" > $tmp
	rc=${PIPESTATUS[0]}
	[ $rc -eq 0 ] || return $rc
	setfattr --restore $tmp || return $?
    done
    do_umount
}

run_sgpdd () {
    local devs=${1//,/ }
    shift
    local params=$@
    local rslt=$TMP/sgpdd_survey

    # sgpdd-survey cleanups ${rslt}.* files

    local cmd="rslt=$rslt $params scsidevs=\"$devs\" $SGPDDSURVEY"
    echo + $cmd
    eval $cmd
    cat ${rslt}.detail
}

# returns the canonical name for an ldiskfs device
ldiskfs_canon() {
        local dev="$1"
        local facet="$2"

        do_facet $facet "dv=\\\$(lctl get_param -n $dev);
if foo=\\\$(lvdisplay -c \\\$dv 2>/dev/null); then
    echo dm-\\\${foo##*:};
else
    echo \\\$(basename \\\$dv);
fi;"
}

is_sanity_benchmark() {
    local benchmarks="dbench bonnie iozone fsx"
    local suite=$1
    for b in $benchmarks; do
        if [ "$b" == "$suite" ]; then
            return 0
        fi
    done
    return 1
}

min_ost_size () {
    $LCTL get_param -n osc.*.kbytesavail | sort -n | head -n1
}

check_logdir() {
    local dir=$1
    # Checking for shared logdir
    if [ ! -d $dir ]; then
        # Not found. Create local logdir
        mkdir -p $dir
    else
        touch $dir/check_file.$(hostname -s)
    fi
    return 0
}

check_write_access() {
    local dir=$1
    local node
    local file

    for node in $(nodes_list); do
        file=$dir/check_file.$(short_hostname $node)
        if [[ ! -f $file ]]; then
            # Logdir not accessible/writable from this node.
            return 1
        fi
        rm -f $file || return 1
    done
    return 0
}

init_logging() {
    if [[ -n $YAML_LOG ]]; then
        return
    fi
    local SAVE_UMASK=`umask`
    umask 0000

    export YAML_LOG=${LOGDIR}/results.yml
    mkdir -p $LOGDIR
    init_clients_lists

    # If the yaml log already exists then we will just append to it.
    [[ -f $YAML_LOG ]] && return 0

    if check_shared_dir $LOGDIR; then
        touch $LOGDIR/shared
        echo "Logging to shared log directory: $LOGDIR"
    else
        echo "Logging to local directory: $LOGDIR"
    fi

    yml_nodes_file $LOGDIR >> $YAML_LOG
    yml_results_file >> $YAML_LOG

    umask $SAVE_UMASK
}

log_test() {
    yml_log_test $1 >> $YAML_LOG
}

log_sub_test() {
    yml_log_sub_test $@ >> $YAML_LOG
}

log_test_status() {
     yml_log_test_status $@ >> $YAML_LOG
}

log_sub_test_begin() {
    yml_log_sub_test_begin $@ >> $YAML_LOG
}

log_sub_test_end() {
    yml_log_sub_test_end $@ >> $YAML_LOG
}
