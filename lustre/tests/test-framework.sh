#!/bin/bash
# vim:expandtab:shiftwidth=4:softtabstop=4:tabstop=4:

trap 'print_summary && echo "test-framework exiting on error"' ERR
set -e
#set -x


export REFORMAT=${REFORMAT:-""}
export WRITECONF=${WRITECONF:-""}
export VERBOSE=false
export GMNALNID=${GMNALNID:-/usr/sbin/gmlndnid}
export CATASTROPHE=${CATASTROPHE:-/proc/sys/lnet/catastrophe}
#export PDSH="pdsh -S -Rssh -w"

# function used by scripts run on remote nodes
LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/functions.sh

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
    [ "$TESTSUITE" == "lfscktest" ] && return 0
    [ -n "$ONLY" ] && echo "WARNING: ONLY is set to ${ONLY}."
    local form="%-13s %-17s %s\n"
    printf "$form" "status" "script" "skipped tests E(xcluded) S(low)"
    echo "------------------------------------------------------------------------------------"
    for O in $TESTSUITE_LIST; do
        local skipped=""
        local slow=""
        local o=$(echo $O | tr "[:upper:]" "[:lower:]")
        o=${o//_/-}
        o=${o//tyn/tyN}
        local log=${TMP}/${o}.log
        [ -f $log ] && skipped=$(grep excluded $log | awk '{ printf " %s", $3 }' | sed 's/test_//g')
        [ -f $log ] && slow=$(grep SLOW $log | awk '{ printf " %s", $3 }' | sed 's/test_//g')
        [ "${!O}" = "done" ] && \
            printf "$form" "Done" "$O" "E=$skipped" && \
            [ -n "$slow" ] && printf "$form" "-" "-" "S=$slow"

    done

    for O in $TESTSUITE_LIST; do
        [ "${!O}" = "no" ] && \
            printf "$form" "Skipped" "$O" ""
    done

    for O in $TESTSUITE_LIST; do
        [ "${!O}" = "done" -o "${!O}" = "no" ] || \
            printf "$form" "UNFINISHED" "$O" ""
    done
}

init_test_env() {
    export LUSTRE=`absolute_path $LUSTRE`
    export TESTSUITE=`basename $0 .sh`
    export TEST_FAILED=false

    export MKE2FS=${MKE2FS:-mke2fs}
    export DEBUGFS=${DEBUGFS:-debugfs}
    export TUNE2FS=${TUNE2FS:-tune2fs}
    export E2LABEL=${E2LABEL:-e2label}
    export DUMPE2FS=${DUMPE2FS:-dumpe2fs}
    export E2FSCK=${E2FSCK:-e2fsck}

    #[ -d /r ] && export ROOT=${ROOT:-/r}
    export TMP=${TMP:-$ROOT/tmp}
    export TESTSUITELOG=${TMP}/${TESTSUITE}.log
    export HOSTNAME=${HOSTNAME:-`hostname`}
    if ! echo $PATH | grep -q $LUSTRE/utils; then
	export PATH=$PATH:$LUSTRE/utils
    fi
    if ! echo $PATH | grep -q $LUSTRE/test; then
	export PATH=$PATH:$LUSTRE/tests
    fi
    export MDSRATE=${MDSRATE:-"$LUSTRE/tests/mpi/mdsrate"}
    [ ! -f "$MDSRATE" ] && export MDSRATE=$(which mdsrate 2> /dev/null)
    if ! echo $PATH | grep -q $LUSTRE/tests/racer; then
        export PATH=$PATH:$LUSTRE/tests/racer
    fi
    if ! echo $PATH | grep -q $LUSTRE/tests/mpi; then
        export PATH=$PATH:$LUSTRE/tests/mpi
    fi
    export LCTL=${LCTL:-"$LUSTRE/utils/lctl"}
    export LFS=${LFS:-"$LUSTRE/utils/lfs"}
    [ ! -f "$LCTL" ] && export LCTL=$(which lctl)
    export LFS=${LFS:-"$LUSTRE/utils/lfs"}
    [ ! -f "$LFS" ] && export LFS=$(which lfs)
    export MKFS=${MKFS:-"$LUSTRE/utils/mkfs.lustre"}
    [ ! -f "$MKFS" ] && export MKFS=$(which mkfs.lustre)
    export TUNEFS=${TUNEFS:-"$LUSTRE/utils/tunefs.lustre"}
    [ ! -f "$TUNEFS" ] && export TUNEFS=$(which tunefs.lustre)
    export CHECKSTAT="${CHECKSTAT:-"checkstat -v"} "
    export FSTYPE=${FSTYPE:-"ldiskfs"}
    export NAME=${NAME:-local}
    export DIR2
    export SAVE_PWD=${SAVE_PWD:-$LUSTRE/tests}

    if [ "$ACCEPTOR_PORT" ]; then
        export PORT_OPT="--port $ACCEPTOR_PORT"
    fi

    # Paths on remote nodes, if different
    export RLUSTRE=${RLUSTRE:-$LUSTRE}
    export RPWD=${RPWD:-$PWD}
    export I_MOUNTED=${I_MOUNTED:-"no"}

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

    [ "$TESTSUITELOG" ] && rm -f $TESTSUITELOG || true
    rm -f $TMP/*active

}

case `uname -r` in
    *) EXT=".ko"; USE_QUOTA=yes;;
esac

load_module() {
    module=$1
    shift
    BASE=`basename $module $EXT`
    lsmod | grep -q ${BASE} || \
      if [ -f ${LUSTRE}/${module}${EXT} ]; then
        insmod ${LUSTRE}/${module}${EXT} $@
    else
        # must be testing a "make install" or "rpm" installation
        modprobe $BASE $@
    fi
}

load_modules() {
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
    local MODPROBECONF=
    [ -f /etc/modprobe.conf ] && MODPROBECONF=/etc/modprobe.conf
    [ ! "$MODPROBECONF" -a -d /etc/modprobe.d ] && MODPROBECONF=/etc/modprobe.d/Lustre
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
    [ "$USE_QUOTA" = "yes" ] && load_module quota/lquota
    load_module mdc/mdc
    load_module osc/osc
    load_module lov/lov
    load_module mgc/mgc
    if [ -z "$CLIENTONLY" ] && [ -z "$CLIENTMODSONLY" ]; then
        load_module mgs/mgs
        load_module mds/mds
        grep -q crc16 /proc/kallsyms || { modprobe crc16 2>/dev/null || true; }
        grep -q jbd /proc/kallsyms || { modprobe jbd 2>/dev/null || true; }
        [ "$FSTYPE" = "ldiskfs" ] && load_module ../ldiskfs/ldiskfs/ldiskfs
        load_module lvfs/fsfilt_$FSTYPE
        load_module ost/ost
        load_module obdfilter/obdfilter
    fi

    load_module llite/lustre
    load_module llite/llite_lloop
    rm -f $TMP/ogdb-$HOSTNAME
    OGDB=$TMP
    [ -d /r ] && OGDB="/r/tmp"
    $LCTL modules > $OGDB/ogdb-$HOSTNAME
    # 'mount' doesn't look in $PATH, just sbin
    [ -f $LUSTRE/utils/mount.lustre ] && cp $LUSTRE/utils/mount.lustre /sbin/. || true
}

RMMOD=rmmod
if [ `uname -r | cut -c 3` -eq 4 ]; then
    RMMOD="modprobe -r"
fi

wait_for_lnet() {
    local UNLOADED=0
    local WAIT=0
    local MAX=60
    MODULES=$($LCTL modules | awk '{ print $2 }')
    while [ -n "$MODULES" ]; do
    sleep 5
    $RMMOD $MODULES >/dev/null 2>&1 || true
    MODULES=$($LCTL modules | awk '{ print $2 }')
        if [ -z "$MODULES" ]; then
        return 0
        else
            WAIT=$((WAIT + 5))
            echo "waiting, $((MAX - WAIT)) secs left"
        fi
        if [ $WAIT -eq $MAX ]; then
            echo "LNET modules $MODULES will not unload"
        lsmod
            return 3
        fi
    done
}

unload_dep_module() {
    #lsmod output
    #libcfs                107852  17 llite_lloop,lustre,obdfilter,ost,...
    local MODULE=$1
    local DEPS=$(lsmod | awk '($1 == "'$MODULE'") { print $4 }' | tr ',' ' ')
    for SUBMOD in $DEPS; do
        unload_dep_module $SUBMOD
    done
    [ "$MODULE" = "libcfs" ] && $LCTL dk $TMP/debug || true
    $RMMOD $MODULE || true
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

    lsmod | grep libcfs > /dev/null && $LCTL dl
    [ -z "$CLIENTONLY" ] && unload_dep_module $FSTYPE
    unload_dep_module libcfs

    local MODULES=$($LCTL modules | awk '{ print $2 }')
    if [ -n "$MODULES" ]; then
        echo "Modules still loaded: "
        echo $MODULES
        if [ "$(lctl dl)" ]; then
            echo "Lustre still loaded"
            lctl dl || true
            lsmod
            return 2
        else
            echo "Lustre stopped but LNET is still loaded, waiting..."
            wait_for_lnet || return 3
        fi
    fi
    HAVE_MODULES=false

    check_mem_leak || return 254

    echo "modules unloaded."
    return 0
}

# Facet functions
mount_facet() {
    local facet=$1
    shift
    local dev=$(facet_active $facet)_dev
    local opt=${facet}_opt
    echo "Starting ${facet}: ${!opt} $@ ${!dev} ${MOUNT%/*}/${facet}"
    do_facet ${facet} mount -t lustre ${!opt} $@ ${!dev} ${MOUNT%/*}/${facet}
    RC=${PIPESTATUS[0]}
    if [ $RC -ne 0 ]; then
        echo "mount -t lustre $@ ${!dev} ${MOUNT%/*}/${facet}"
        echo "Start of ${!dev} on ${facet} failed ${RC}"
    else
        do_facet ${facet} "lctl set_param debug=\\\"$PTLDEBUG\\\"; \
            lctl set_param subsystem_debug=\\\"${SUBSYSTEM# }\\\"; \
            lctl set_param debug_mb=${DEBUG_SIZE}; \
            sync"

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

    do_facet ${facet} mkdir -p ${MOUNT%/*}/${facet}
    mount_facet ${facet}
    RC=$?
    return $RC
}

stop() {
    local running
    facet=$1
    shift
    HOST=`facet_active_host $facet`
    [ -z $HOST ] && echo stop: no host for $facet && return 0

    running=$(do_facet ${facet} "grep -c ${MOUNT%/*}/${facet}' ' /proc/mounts") || true
    if [ ${running} -ne 0 ]; then
        echo "Stopping ${MOUNT%/*}/${facet} (opts:$@)"
        do_facet ${facet} umount -d $@ ${MOUNT%/*}/${facet}
    fi

    # umount should block, but we should wait for unrelated obd's
    # like the MGS or MGC to also stop.

    wait_exit_ST ${facet}
}

# set quota version (both administrative and operational quotas)
quota_set_version() {
        do_facet mds "lctl set_param lquota.${FSNAME}-MDT*.quota_type=$1"
        for j in `seq $OSTCOUNT`; do
                do_facet ost$j "lctl set_param lquota.${FSNAME}-OST*.quota_type=$1"
        done
}

# save quota version (both administrative and operational quotas)
# the function will also switch to the new version and the new type
quota_save_version() {
    local spec=$1
    local ver=$(tr -c -d "123" <<< $spec)
    local type=$(tr -c -d "ug" <<< $spec)

    $LFS quotaoff -ug $MOUNT # just in case
    [ -n "$ver" ] && quota_set_version $ver
    [ -n "$type" ] && { $LFS quotacheck -$type $MOUNT || error "quotacheck has failed"; }

    do_facet mgs "lctl conf_param ${FSNAME}-MDT*.mdt.quota_type=$spec"
    local varsvc
    local osts=$(get_facets OST)
    for ost in ${osts//,/ }; do
        varsvc=${ost}_svc
        do_facet mgs "lctl conf_param ${!varsvc}.ost.quota_type=$spec"
    done
}

# client could mount several lustre
quota_type () {
    local fsname=${1:-$FSNAME}
    local rc=0
    do_facet mgs lctl get_param mds.${fsname}-MDT*.quota_type || rc=$?
    do_nodes $(comma_list $(osts_nodes)) \
        lctl get_param obdfilter.${fsname}-OST*.quota_type || rc=$?
    return $rc
}

restore_quota_type () {
   local mntpt=${1:-$MOUNT}
   local quota_type=$(quota_type $FSNAME | grep MDT | cut -d "=" -f2)
   if [ ! "$old_QUOTA_TYPE" ] || [ "$quota_type" = "$old_QUOTA_TYPE" ]; then
        return
   fi
   quota_save_version $old_QUOTA_TYPE
}

setup_quota(){
    local mntpt=$1

    # We need:
    # 1. run quotacheck only if quota is off
    # 2. save the original quota_type params, restore them after testing

    # Suppose that quota type the same on mds and ost
    local quota_type=$(quota_type | grep MDT | cut -d "=" -f2)
    [ ${PIPESTATUS[0]} -eq 0 ] || error "quota_type failed!"
    if [ "$quota_type" != "$QUOTA_TYPE" ]; then
        export old_QUOTA_TYPE=$quota_type
        quota_save_version $QUOTA_TYPE
    fi

    local quota_usrs=$QUOTA_USERS

    # get_filesystem_size
    local disksz=$(lfs df $mntpt | grep "filesystem summary:"  | awk '{print $3}')
    local blk_soft=$((disksz + 1024))
    local blk_hard=$((blk_soft + blk_soft / 20)) # Go 5% over

    local Inodes=$(lfs df -i $mntpt | grep "filesystem summary:"  | awk '{print $3}')
    local i_soft=$Inodes
    local i_hard=$((i_soft + i_soft / 20))

    echo "Total disk size: $disksz  block-softlimit: $blk_soft block-hardlimit:
        $blk_hard inode-softlimit: $i_soft inode-hardlimit: $i_hard"

    local cmd
    for usr in $quota_usrs; do
        echo "Setting up quota on $client:$mntpt for $usr..."
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

zconf_mount() {
    local OPTIONS
    local client=$1
    local mnt=$2
    # Only supply -o to mount if we have options
    if [ -n "$MOUNTOPT" ]; then
        OPTIONS="-o $MOUNTOPT"
    fi
    local device=$MGSNID:/$FSNAME
    if [ -z "$mnt" -o -z "$FSNAME" ]; then
        echo Bad zconf mount command: opt=$OPTIONS dev=$device mnt=$mnt
        exit 1
    fi

    echo "Starting client: $client: $OPTIONS $device $mnt"
    do_node $client mkdir -p $mnt
    do_node $client mount -t lustre $OPTIONS $device $mnt || return 1
    do_node $client "lctl set_param debug=\\\"$PTLDEBUG\\\";
        lctl set_param subsystem_debug=\\\"${SUBSYSTEM# }\\\";
        lctl set_param debug_mb=${DEBUG_SIZE}"

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
        do_nodes $nodes "set -x; running=\\\$(grep -c $mnt' ' /proc/mounts);
mpts=\\\$(mount | grep -w -c $mnt);
if [ \\\$running -ne \\\$mpts ]; then
    echo \\\$(hostname) env are INSANE!;
    exit 1;
fi"
    [ $? -eq 0 ] || rc=1
    done
    return $rc
}

sanity_mount_check_servers () {
    echo Checking servers environments

    # FIXME: modify get_facets to display all facets wo params
    local facets="$(get_facets OST),$(get_facets MDS)"
    local node
    local mnt
    local facet
    for facet in ${facets//,/ }; do
        node=$(facet_host ${facet})
        mnt=${MOUNT%/*}/${facet}
        sanity_mount_check_nodes $node $mnt ||
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
    local OPTIONS
    local clients=$1
    local mnt=$2

    # Only supply -o to mount if we have options
    if [ -n "$MOUNTOPT" ]; then
        OPTIONS="-o $MOUNTOPT"
    fi
    local device=$MGSNID:/$FSNAME
    if [ -z "$mnt" -o -z "$FSNAME" ]; then
        echo Bad zconf mount command: opt=$OPTIONS dev=$device mnt=$mnt
        exit 1
    fi

    echo "Starting client $clients: $OPTIONS $device $mnt"

    do_nodes $clients "set -x;
running=\\\$(mount | grep -c $mnt' ');
rc=0;
if [ \\\$running -eq 0 ] ; then
    mkdir -p $mnt;
    mount -t lustre $OPTIONS $device $mnt;
    rc=$?;
fi;
exit $rc"

    echo "Started clients $clients: "
    do_nodes $clients "mount | grep -w $mnt"

    do_nodes $clients "sysctl -w lnet.debug=\\\"$PTLDEBUG\\\";
        sysctl -w lnet.subsystem_debug=\\\"${SUBSYSTEM# }\\\";
        sysctl -w lnet.debug_mb=${DEBUG_SIZE};"

    return 0
}

zconf_umount_clients() {
    local clients=$1
    local mnt=$2
    local force

    [ "$3" ] && force=-f

    echo "Stopping clients: $clients $mnt (opts:$force)"
    do_nodes $clients "set -x; running=\\\$(grep -c $mnt' ' /proc/mounts);
if [ \\\$running -ne 0 ] ; then
echo Stopping client \\\$(hostname) client $mnt opts:$force;
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

shudown_node_hard () {
    local host=$1
    local attempts=3

    for i in $(seq $attempts) ; do
        $POWER_DOWN $host
        sleep 1
        ping -w 3 -c 1 $host > /dev/null 2>&1 || return 0
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
        shudown_node_hard $client
    else
       zconf_umount_clients $client $mnt -f
    fi
}

shutdown_facet() {
    local facet=$1
    if [ "$FAILURE_MODE" = HARD ]; then
        shudown_node_hard $(facet_active_host $facet)
    elif [ "$FAILURE_MODE" = SOFT ]; then
        stop $facet
    fi
}

reboot_facet() {
    facet=$1
    if [ "$FAILURE_MODE" = HARD ]; then
        $POWER_UP `facet_active_host $facet`
    else
        sleep 10
    fi
}

boot_node() {
    local node=$1
    if [ "$FAILURE_MODE" = HARD ]; then
       $POWER_UP $node
       wait_for_host $node
    fi
}

# recovery-scale functions
check_progs_installed () {
    local clients=$1
    shift
    local progs=$@

    do_nodes $clients "set -x ; PATH=:$PATH; status=true;
for prog in $progs; do
    if ! [ \\\"\\\$(which \\\$prog)\\\"  -o  \\\"\\\${!prog}\\\" ]; then
       echo \\\$prog missing on \\\$(hostname);
       status=false;
    fi
done;
eval \\\$status"
}

client_var_name() {
    echo __$(echo $1 | tr '-' 'X')
}

start_client_load() {
    local client=$1
    local load=$2
    local var=$(client_var_name $client)_load
    eval export ${var}=$load

    do_node $client "PATH=$PATH MOUNT=$MOUNT ERRORS_OK=$ERRORS_OK \
                              BREAK_ON_ERROR=$BREAK_ON_ERROR \
                              END_RUN_FILE=$END_RUN_FILE \
                              LOAD_PID_FILE=$LOAD_PID_FILE \
                              TESTSUITELOG=$TESTSUITELOG \
                              run_${load}.sh" &
    CLIENT_LOAD_PIDS="$CLIENT_LOAD_PIDS $!"
    log "Started client load: ${load} on $client"

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
}

# only for remote client
check_client_load () {
    local client=$1
    local var=$(client_var_name $client)_load
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
            local var=$(client_var_name $client)_load
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
# End recovery-scale functions

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

    if [ "`/sbin/lsmod 2>&1 | egrep 'lnet|libcfs'`" ]; then
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
                echo "Updated after $WAIT sec: wanted '$FINAL' got '$RESULT'"
                return 0
            fi
            [ $WAIT -ge $MAX ] && break
            echo "Waiting $((MAX - WAIT)) secs for update"
            WAIT=$((WAIT + sleep))
            sleep $sleep
        done
        echo "Update not seen after $MAX sec: wanted '$FINAL' got '$RESULT'"
        return 3
}

wait_update_facet () {
    local facet=$1
    shift
    wait_update  $(facet_active_host $facet) "$@"
}

wait_delete_completed () {
    local TOTALPREV=`lctl get_param -n osc.*.kbytesavail | \
                     awk 'BEGIN{total=0}; {total+=$1}; END{print total}'`

    local WAIT=0
    local MAX_WAIT=20
    while [ "$WAIT" -ne "$MAX_WAIT" ]; do
        sleep 1
        TOTAL=`lctl get_param -n osc.*.kbytesavail | \
               awk 'BEGIN{total=0}; {total+=$1}; END{print total}'`
        [ "$TOTAL" -eq "$TOTALPREV" ] && break
        echo "Waiting delete completed ... prev: $TOTALPREV current: $TOTAL "
        TOTALPREV=$TOTAL
        WAIT=$(( WAIT + 1))
    done
    echo "Delete completed."
}

wait_for_host() {
    local host=$1
    check_network "$host" 900
    while ! do_node $host "ls -d $LUSTRE " > /dev/null; do sleep 5; done
}

wait_for() {
    local facet=$1
    local host=`facet_active_host $facet`
    wait_for_host $host
}

wait_recovery_complete () {
    local facet=$1

    # Use default policy if $2 is not passed by caller.
    #define OBD_RECOVERY_TIMEOUT (obd_timeout * 5 / 2)
    # as we are in process of changing obd_timeout in different ways
    # let's set MAX longer than that
    local MAX=${2:-$(( TIMEOUT * 4 ))}

    local var_svc=${facet}_svc
    local procfile="*.${!var_svc}.recovery_status"
    local WAIT=0
    local STATUS=

    while [ $WAIT -lt $MAX ]; do
        STATUS=$(do_facet $facet lctl get_param -n $procfile | grep status)
        [[ $STATUS = "status: COMPLETE" ]] && return 0
        sleep 5
        WAIT=$((WAIT + 5))
        echo "Waiting $((MAX - WAIT)) secs for $facet recovery done. $STATUS"
    done
    echo "$facet recovery not done in $MAX sec. $STATUS"
    return 1
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

client_df() {
    # not every config has many clients
    if [ -n "$CLIENTS" ]; then
        $PDSH $CLIENTS "df $MOUNT" > /dev/null
    else
	df $MOUNT > /dev/null
    fi
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

facet_failover() {
    local facet=$1
    local sleep_time=$2
    echo "Failing $facet on node `facet_active_host $facet`"
    shutdown_facet $facet
    [ -n "$sleep_time" ] && sleep $sleep_time
    reboot_facet $facet
    client_df &
    DFPID=$!
    RECOVERY_START_TIME=`date +%s`
    echo "df pid is $DFPID"
    change_active $facet
    local TO=`facet_active_host $facet`
    echo "Failover $facet to $TO"
    wait_for $facet
    mount_facet $facet || error "Restart of $facet failed"
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
    df $MOUNT || error "post-failover df: $?"
}

fail_nodf() {
    local facet=$1
    facet_failover $facet
}

fail_abort() {
    local facet=$1
    stop $facet
    change_active $facet
    mount_facet $facet -o abort_recovery
    df $MOUNT || echo "first df failed: $?"
    sleep 1
    df $MOUNT || error "post-failover df: $?"
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
    local facet=$1
    local failover=${facet}failover
    host=`facet_host $failover`
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
}

do_node() {
    HOST=$1
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
        $myPDSH $HOST $LCTL mark "$@" > /dev/null 2>&1 || :
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
    $myPDSH $HOST "(PATH=\$PATH:$RLUSTRE/utils:$RLUSTRE/tests:/sbin:/usr/sbin; cd $RPWD; sh -c \"$@\")" | sed "s/^${HOST}: //"
    return ${PIPESTATUS[0]}
}

single_local_node () {
   [ "$1" = "$HOSTNAME" ]
}

do_nodes() {
    local rnodes=$1
    shift

    if $(single_local_node $rnodes); then
        do_node $rnodes $@
        return $?
    fi

    # This is part from do_node
    local myPDSH=$PDSH

    [ -z "$myPDSH" -o "$myPDSH" = "no_dsh" -o "$myPDSH" = "rsh" ] && \
        echo "cannot run remote command on $rnodes with $myPDSH" && return 128

    if $VERBOSE; then
        echo "CMD: $rnodes $@" >&2
        $myPDSH $rnodes $LCTL mark "$@" > /dev/null 2>&1 || :
    fi

    $myPDSH $rnodes "(PATH=\$PATH:$RLUSTRE/utils:$RLUSTRE/tests:/sbin:/usr/sbin; cd $RPWD; sh -c \"$@\")" | sed -re "s/\w+:\s//g"
    return ${PIPESTATUS[0]}
}

do_facet() {
    local facet=$1
    shift
    local HOST=`facet_active_host $facet`
    [ -z $HOST ] && echo No host defined for facet ${facet} && exit 1
    do_node $HOST "$@"
}

add() {
    local facet=$1
    shift
    # make sure its not already running
    stop ${facet} -f
    rm -f $TMP/${facet}active
    do_facet ${facet} $MKFS $*
}

ostdevname() {
    num=$1
    DEVNAME=OSTDEV$num
    #if $OSTDEVn isn't defined, default is $OSTDEVBASE + num
    eval DEVPTR=${!DEVNAME:=${OSTDEVBASE}${num}}
    echo -n $DEVPTR
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
    for num in `seq $OSTCOUNT`; do
        stop ost$num -f
        rm -f $TMP/ost${num}active
    done
    return 0
}

cleanupall() {
    stopall $*
    unload_modules
}

formatall() {
    [ "$FSTYPE" ] && FSTYPE_OPT="--backfstype $FSTYPE"

    stopall
    # We need ldiskfs here, may as well load them all
    load_modules
    [ "$CLIENTONLY" ] && return
    echo Formatting mds, osts
    if $VERBOSE; then
        add mds $MDS_MKFS_OPTS $FSTYPE_OPT --reformat $MDSDEV || exit 10
    else
        add mds $MDS_MKFS_OPTS $FSTYPE_OPT --reformat $MDSDEV > /dev/null || exit 10
    fi

    for num in `seq $OSTCOUNT`; do
        if $VERBOSE; then
            add ost$num $OST_MKFS_OPTS $FSTYPE_OPT --reformat `ostdevname $num` || exit 10
        else
            add ost$num $OST_MKFS_OPTS $FSTYPE_OPT --reformat `ostdevname $num` > /dev/null || exit 10
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
    sanity_mount_check ||
        error "environments are insane!"

    load_modules
    if [ -z "$CLIENTONLY" ]; then
        echo Setup mdt, osts

        echo $WRITECONF | grep -q "writeconf" && \
            writeconf_all

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
}

init_facets_vars () {
    remote_mds_nodsh ||
        init_facet_vars mds $MDSDEV $MDS_MOUNT_OPTS

    remote_ost_nodsh && return

    for num in `seq $OSTCOUNT`; do
        DEVNAME=`ostdevname $num`
        init_facet_vars ost$num $DEVNAME $OST_MOUNT_OPTS
    done
}

init_param_vars () {
    if ! remote_ost_nodsh && ! remote_mds_nodsh; then
        export MDSVER=$(do_facet mds "lctl get_param version" | cut -d. -f1,2)
        export OSTVER=$(do_facet ost1 "lctl get_param version" | cut -d. -f1,2)
        export CLIVER=$(lctl get_param version | cut -d. -f 1,2)
    fi

    remote_mds_nodsh ||
        TIMEOUT=$(do_facet mds "lctl get_param -n timeout")

    log "Using TIMEOUT=$TIMEOUT"

    if [ "$ENABLE_QUOTA" ]; then
        setup_quota $MOUNT  || return 2
    fi
}

check_config () {
    local mntpt=$1
    local myMGS_host=$mgs_HOST
    if [ "$NETTYPE" = "ptl" ]; then
        myMGS_host=$(h2ptl $mgs_HOST | sed -e s/@ptl//)
    fi

    echo Checking config lustre mounted on $mntpt
    local mgshost=$(mount | grep " $mntpt " | awk -F@ '{print $1}')
    mgshost=$(echo $mgshost | awk -F: '{print $1}')

    if [ "$mgshost" != "$myMGS_host" ]; then
            log "Bad config file: lustre is mounted with mgs $mgshost, but mgs_HOST=$mgs_HOST, NETTYPE=$NETTYPE
                   Please use correct config or set mds_HOST correctly!"
    fi

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

check_and_setup_lustre() {
    local MOUNTED=$(mounted_lustre_filesystems)
    if [ -z "$MOUNTED" ] || ! $(echo $MOUNTED | grep -w -q $MOUNT); then
        [ "$REFORMAT" ] && formatall
        setupall
        MOUNTED=$(mounted_lustre_filesystems | head -1)
        [ -z "$MOUNTED" ] && error "NAME=$NAME not mounted"
        export I_MOUNTED=yes
    else
        check_config $MOUNT
        init_facets_vars
        init_param_vars

        do_nodes $(comma_list $(nodes_list)) "lctl set_param debug=\\\"$PTLDEBUG\\\";
            lctl set_param subsystem_debug=\\\"${SUBSYSTEM# }\\\";
            lctl set_param debug_mb=${DEBUG_SIZE};
            sync"
    fi
    if [ "$ONLY" == "setup" ]; then
        exit 0
    fi
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

check_and_cleanup_lustre() {
    if [ "`mount | grep $MOUNT`" ]; then
        [ -n "$DIR" ] && rm -rf $DIR/[Rdfs][0-9]*
        [ "$ENABLE_QUOTA" ] && restore_quota_type || true
    fi
    if [ "$I_MOUNTED" = "yes" ]; then
        cleanupall -f || error "cleanup failed"
    fi
    unset I_MOUNTED
}

#######
# General functions

check_network() {
    local NETWORK=0
    local WAIT=0
    local MAX=$2
    while [ $NETWORK -eq 0 ]; do
        if ping -c 1 -w 3 $1 > /dev/null; then
            NETWORK=1
        else
            WAIT=$((WAIT + 5))
            echo "waiting for $1, $((MAX - WAIT)) secs left"
            sleep 5
        fi
        if [ $WAIT -gt $MAX ]; then
            echo "Network not available"
            exit 1
        fi
    done
}
check_port() {
    while( !($DSH2 $1 "netstat -tna | grep -q $2") ) ; do
        sleep 9
    done
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

absolute_path() {
    (cd `dirname $1`; echo $PWD/`basename $1`)
}

get_facets () {
    local name=$(echo $1 | tr "[:upper:]" "[:lower:]")
    local type=$(echo $1 | tr "[:lower:]" "[:upper:]")

    local list=""

    case $type in
        MDS )    list=mds;;
        OST )    for ((i=1; i<=$OSTCOUNT; i++)) do
                    list="$list ${name}$i"
                 done;;
          * )    error "Invalid facet type"
                 exit 1;;
    esac
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

at_max_get() {
    local facet=$1

    # suppose that all ost-s has the same at_max set
    if [ $facet == "ost" ]; then
        do_facet ost1 "lctl get_param -n at_max"
    else
        do_facet $facet "lctl get_param -n at_max"
    fi
}

at_max_set() {
    local at_max=$1
    shift

    local facet
    for facet in $@; do
        if [ $facet == "ost" ]; then
            for i in `seq $OSTCOUNT`; do
                do_facet ost$i "lctl set_param at_max=$at_max"
            done
        else
            do_facet $facet "lctl set_param at_max=$at_max"
        fi
    done
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
    local nodes=$1
    local node

    for node in $nodes ; do
        do_node $node lctl set_param fail_loc=$2
    done
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
    local ERRLOG
    lctl set_param fail_loc=0 2>/dev/null || true
    log " ${TESTSUITE} ${TESTNAME}: @@@@@@ ${TYPE}: $@ "
    ERRLOG=$TMP/lustre_${TESTSUITE}_${TESTNAME}.$(date +%s)
    echo "Dumping lctl log to $ERRLOG"
    # We need to dump the logs on all nodes
    local NODES=$(nodes_list)
    for NODE in $NODES; do
        do_node $NODE $LCTL dk $ERRLOG
    done
    debugrestore
    [ "$TESTSUITELOG" ] && echo "$0: ${TYPE}: $TESTNAME $@" >> $TESTSUITELOG
    TEST_FAILED=true
}

error() {
    error_noexit "$@"
    $FAIL_ON_ERROR && exit 1 || true
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

skip () {
	log " SKIP: ${TESTSUITE} ${TESTNAME} $@"
	[ "$TESTSUITELOG" ] && \
		echo "${TESTSUITE}: SKIP: $TESTNAME $@" >> $TESTSUITELOG || true
}

build_test_filter() {
    [ "$ONLY" ] && log "only running test `echo $ONLY`"
    for O in $ONLY; do
        eval ONLY_${O}=true
    done
    [ "$EXCEPT$ALWAYS_EXCEPT" ] && \
        log "excepting tests: `echo $EXCEPT $ALWAYS_EXCEPT`"
    [ "$EXCEPT_SLOW" ] && \
        log "skipping tests SLOW=no: `echo $EXCEPT_SLOW`"
    for E in $EXCEPT $ALWAYS_EXCEPT; do
        eval EXCEPT_${E}=true
    done
    for E in $EXCEPT_SLOW; do
        eval EXCEPT_SLOW_${E}=true
    done
    for G in $GRANT_CHECK_LIST; do
        eval GCHECK_ONLY_${G}=true
   	done
}

_basetest() {
    echo $*
}

basetest() {
    IFS=abcdefghijklmnopqrstuvwxyz _basetest $1
}

# print a newline if the last test was skipped
export LAST_SKIPPED=
run_test() {
    assert_DIR

    export base=`basetest $1`
    if [ ! -z "$ONLY" ]; then
        testname=ONLY_$1
        if [ ${!testname}x != x ]; then
            [ "$LAST_SKIPPED" ] && echo "" && LAST_SKIPPED=
            run_one $1 "$2"
            return $?
        fi
        testname=ONLY_$base
        if [ ${!testname}x != x ]; then
            [ "$LAST_SKIPPED" ] && echo "" && LAST_SKIPPED=
            run_one $1 "$2"
            return $?
        fi
        LAST_SKIPPED="y"
        echo -n "."
        return 0
    fi
    testname=EXCEPT_$1
    if [ ${!testname}x != x ]; then
        LAST_SKIPPED="y"
        TESTNAME=test_$1 skip "skipping excluded test $1"
        return 0
    fi
    testname=EXCEPT_$base
    if [ ${!testname}x != x ]; then
        LAST_SKIPPED="y"
        TESTNAME=test_$1 skip "skipping excluded test $1 (base $base)"
        return 0
    fi
    testname=EXCEPT_SLOW_$1
    if [ ${!testname}x != x ]; then
        LAST_SKIPPED="y"
        TESTNAME=test_$1 skip "skipping SLOW test $1"
        return 0
    fi
    testname=EXCEPT_SLOW_$base
    if [ ${!testname}x != x ]; then
        LAST_SKIPPED="y"
        TESTNAME=test_$1 skip "skipping SLOW test $1 (base $base)"
        return 0
    fi

    LAST_SKIPPED=
    run_one $1 "$2"

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
    lsmod | grep lnet > /dev/null || load_modules

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
    local NODES=$(nodes_list)
    for NODE in $NODES; do
        do_node $NODE $LCTL mark "$MSG" 2> /dev/null || true
    done
}

trace() {
	log "STARTING: $*"
	strace -o $TMP/$1.strace -ttt $*
	RC=$?
	log "FINISHED: $*: rc $RC"
	return 1
}

pass() {
    $TEST_FAILED && echo -n "FAIL " || echo -n "PASS "
    echo $@
}

check_mds() {
    FFREE=`lctl get_param -n mds.*.filesfree`
    FTOTAL=`lctl get_param -n mds.*.filestotal`
    [ $FFREE -ge $FTOTAL ] && error "files free $FFREE > total $FTOTAL" || true
}

reset_fail_loc () {
    local myNODES=$(nodes_list)
    local NODE

    echo -n "Resetting fail_loc on all nodes..."
    for NODE in $myNODES; do
        do_node $NODE "lctl set_param -n fail_loc=0 2>/dev/null || true"
    done
    echo done.
}

run_one() {
    testnum=$1
    message=$2
    tfile=f${testnum}
    export tdir=d0.${TESTSUITE}/d${base}

    local SAVE_UMASK=`umask`
    umask 0022

    local BEFORE=`date +%s`
    echo
    log "== test $testnum: $message == `date +%H:%M:%S` ($BEFORE)"
    #check_mds
    export TESTNAME=test_$testnum
    TEST_FAILED=false
    test_${testnum} || error "test_$testnum failed with $?"
    #check_mds
    cd $SAVE_PWD
    reset_fail_loc
    check_grant ${testnum} || error "check_grant $testnum failed with $?"
    check_catastrophe || error "LBUG/LASSERT detected"
    ps auxww | grep -v grep | grep -q multiop && error "multiop still running"
    pass "($((`date +%s` - $BEFORE))s)"
    TEST_FAILED=false
    unset TESTNAME
    unset tdir
    umask $SAVE_UMASK
}

canonical_path() {
    (cd `dirname $1`; echo $PWD/`basename $1`)
}

sync_clients() {
    [ -d $DIR1 ] && cd $DIR1 && sync; sleep 1; sync
    [ -d $DIR2 ] && cd $DIR2 && sync; sleep 1; sync
	cd $SAVE_PWD
}

check_grant() {
    export base=`basetest $1`
    [ "$CHECK_GRANT" == "no" ] && return 0

	testname=GCHECK_ONLY_${base}
    [ ${!testname}x == x ] && return 0

    echo -n "checking grant......"
	cd $SAVE_PWD
	# write some data to sync client lost_grant
	rm -f $DIR1/${tfile}_check_grant_* 2>&1
	for i in `seq $OSTCOUNT`; do
		$LFS setstripe $DIR1/${tfile}_check_grant_$i -i $(($i -1)) -c 1
		dd if=/dev/zero of=$DIR1/${tfile}_check_grant_$i bs=4k \
					      count=1 > /dev/null 2>&1
	done
    # sync all the data and make sure no pending data on server
    sync_clients

    #get client grant and server grant
    client_grant=0
    for d in `lctl get_param -n osc.*.cur_grant_bytes`; do
        client_grant=$((client_grant + $d))
    done
    server_grant=0
    for d in `lctl get_param -n obdfilter.*.tot_granted`; do
        server_grant=$((server_grant + $d))
    done

	# cleanup the check_grant file
	for i in `seq $OSTCOUNT`; do
	        rm $DIR1/${tfile}_check_grant_$i
	done

	#check whether client grant == server grant
	if [ $client_grant != $server_grant ]; then
		echo "failed: client:${client_grant} server: ${server_grant}"
		return 1
	else
		echo "pass"
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

remote_node () {
    local node=$1
    [ "$node" != "$(hostname)" ]
}

remote_mds ()
{
    remote_node $mds_HOST
}

remote_mds_nodsh()
{
    remote_mds && [ "$PDSH" = "no_dsh" -o -z "$PDSH" -o -z "$mds_HOST" ]
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
    remote_ost && [ "$PDSH" = "no_dsh" -o -z "$PDSH" -o -z "$ost_HOST" ]
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

osts_nodes () {
    local OSTNODES=$(facet_host ost1)
    local NODES_sort

    for num in `seq $OSTCOUNT`; do
        local myOST=$(facet_host ost$num)
        OSTNODES="$OSTNODES $myOST"
    done
    NODES_sort=$(for i in $OSTNODES; do echo $i; done | sort -u)

    echo $NODES_sort
}

nodes_list () {
    # FIXME. We need a list of clients
    local myNODES=$HOSTNAME
    local myNODES_sort

    # CLIENTS (if specified) contains the local client
    [ -n "$CLIENTS" ] && myNODES=${CLIENTS//,/ }

    if [ "$PDSH" -a "$PDSH" != "no_dsh" ]; then
        myNODES="$myNODES $(osts_nodes) $mds_HOST"
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

is_patchless ()
{
    lctl get_param version | grep -q patchless
}

check_versions () {
    [ "$MDSVER" = "$CLIVER" -a "$OSTVER" = "$CLIVER" ]
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
    rm -f $machinefile || error "can't rm $machinefile"
    for node in $nodes; do
        echo $node >>$machinefile
    done
}

get_stripe () {
    local file=$1/stripe
    touch $file
    $LFS getstripe -v $file || error
    rm -f $file
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
    $myRUNAS touch $DIR/d0_runas_test/f$$ || myRC=1
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
        do_node $1 "lctl get_param $2" | while read s; do echo "$1 $s"; done
}

# restore lustre parameters from input stream, produces by save_lustre_params
restore_lustre_params() {
        local node
        local name
        local val
        while IFS=" =" read node name val; do
                do_node $node "lctl set_param -n $name $val"
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
	stripe_index=`awk '/obdidx/ {start = 1; getline; print $1; exit}' $tmp_file`
	rm -f $tmp_file
}

mdsrate_cleanup () {
    mpi_run -np $1 -machinefile $2 ${MDSRATE} --unlink --nfiles $3 --dir $4 --filefmt $5 $6
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

get_lustre_version () {
    local node=${1:-"mds"}
    do_facet $node $LCTL get_param -n version |  awk '/^lustre:/ {print $2}'
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

get_mds_fsstat_proc_path() {
    local major=$(get_mds_version_major)
    local minor=$(get_mds_version_minor)
    if [ $major -le 1 -a $minor -le 8 ] ; then
        echo "mds"
    else
        echo "osd"
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

########################
convert_facet2name() {
    case "$1" in
        "ost" ) echo "OST0000" ;;
        "ost1") echo "OST0000" ;;
        "ost2") echo "OST0001" ;;
        "ost3") echo "OST0002" ;;
        "ost4") echo "OST0003" ;;
        "ost5") echo "OST0004" ;;
        *) error "unknown facet!" ;;
    esac
}

get_clientosc_proc_path() {
    local ost=$1

    echo "{$1}-osc-*"
}

get_osc_import_name() {
    local node=$1
    local ost=$2
    local name=$(convert_facet2name $ost)

    if [ "$node" == "mds" ]; then
        get_mdtosc_proc_path $name
        return 0
    fi

    get_clientosc_proc_path $name
    return 0
}

wait_osc_import_state() {
    local node=$1
    local ost_facet=$2
    local expected=$3
    local ost=$(get_osc_import_name $node $ost_facet)
    local CONN_PROC
    local CONN_STATE
    local i=0

    CONN_PROC="osc.${FSNAME}-${ost}.ost_server_uuid"
    CONN_STATE=$(do_facet $node lctl get_param -n $CONN_PROC | cut -f2)
    while [ "${CONN_STATE}" != "${expected}" ]; do
        if [ "${expected}" == "DISCONN" ]; then 
            # for disconn we can check after proc entry is removed
            [ "x${CONN_STATE}" == "x" ] && return 0
            #  with AT enabled, we can have connect request timeout near of 
            # reconnect timeout and test can't see real disconnect
            [ "${CONN_STATE}" == "CONNECTING" ] && return 0
        fi
        # disconnect rpc should be wait not more obd_timeout
        [ $i -ge $(($TIMEOUT * 3 / 2)) ] && \
            error "can't put import for ${ost}(${ost_facet}) into ${expected} state" && return 1
        sleep 1
        CONN_STATE=$(do_facet $node lctl get_param -n $CONN_PROC | cut -f2)
        i=$(($i + 1))
    done

    log "${ost_facet} now in ${CONN_STATE} state"
    return 0
}
