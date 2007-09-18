#!/bin/bash
# vim:expandtab:shiftwidth=4:softtabstop=4:tabstop=4:

trap 'echo "test-framework exiting on error"' ERR
set -e
#set -x


export REFORMAT=${REFORMAT:-""}
export VERBOSE=false
export GMNALNID=${GMNALNID:-/usr/sbin/gmlndnid}
export CATASTROPHE=${CATASTROPHE:-/proc/sys/lnet/catastrophe}
#export PDSH="pdsh -S -Rssh -w"

# eg, assert_env LUSTRE MDSNODES OSTNODES CLIENTS
assert_env() {
    local failed=""
    for name in $@; do
        if [ -z "${!name}" ]; then
            echo "$0: $name must be set"
            failed=1
        fi
    done
    [ $failed ] && exit 1 || true
}

usage() {
    echo "usage: $0 [-r] [-f cfgfile]"
    echo "       -r: reformat"

    exit
}

init_test_env() {
    export LUSTRE=`absolute_path $LUSTRE`
    export TESTSUITE=`basename $0 .sh`
    export LTESTDIR=${LTESTDIR:-$LUSTRE/../ltest}

    [ -d /r ] && export ROOT=${ROOT:-/r}
    export TMP=${TMP:-$ROOT/tmp}
    export TESTSUITELOG=${TMP}/${TESTSUITE}.log

    export PATH=:$PATH:$LUSTRE/utils:$LUSTRE/tests
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
    export FSYTPE=${FSTYPE:-"ldiskfs"}
    export NAME=${NAME:-local}
    export LPROC=/proc/fs/lustre
    export DIR2

    if [ "$ACCEPTOR_PORT" ]; then
        export PORT_OPT="--port $ACCEPTOR_PORT"
    fi

    # Paths on remote nodes, if different 
    export RLUSTRE=${RLUSTRE:-$LUSTRE}
    export RPWD=${RPWD:-$PWD}
    export I_MOUNTED=${I_MOUNTED:-"no"}

    # command line
    
    while getopts "rvf:" opt $*; do 
        case $opt in
            f) CONFIG=$OPTARG;;
            r) REFORMAT=--reformat;;
            v) VERBOSE=true;;
            \?) usage;;
        esac
    done

    shift $((OPTIND - 1))
    ONLY=${ONLY:-$*}

    [ "$TESTSUITELOG" ] && rm -f $TESTSUITELOG || true

}

case `uname -r` in
2.4.*) EXT=".o"; USE_QUOTA=no; [ ! "$CLIENTONLY" ] && FSTYPE=ext3;;
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
    [ -f /etc/modprobe.conf ] && MODPROBECONF=/etc/modprobe.conf
    [ -f /etc/modprobe.d/Lustre ] && MODPROBECONF=/etc/modprobe.d/Lustre
    [ -z "$LNETOPTS" -a -n "$MODPROBECONF" ] && \
        LNETOPTS=$(awk '/^options lnet/ { print $0}' $MODPROBECONF | sed 's/^options lnet //g')
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
    if [ -z "$CLIENTONLY" ]; then
        load_module mgs/mgs
        load_module mds/mds
        [ "$FSTYPE" = "ldiskfs" ] && load_module ../ldiskfs/ldiskfs/ldiskfs
        load_module lvfs/fsfilt_$FSTYPE
        load_module ost/ost
        load_module obdfilter/obdfilter
    fi

    load_module llite/lustre
    rm -f $TMP/ogdb-`hostname`
    OGDB=$TMP
    [ -d /r ] && OGDB="/r/tmp"
    $LCTL modules > $OGDB/ogdb-`hostname`
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

unload_modules() {
    lsmod | grep lnet > /dev/null && $LCTL dl && $LCTL dk $TMP/debug
    local MODULES=$($LCTL modules | awk '{ print $2 }')
    $RMMOD $MODULES > /dev/null 2>&1 || true
     # do it again, in case we tried to unload ksocklnd too early
    MODULES=$($LCTL modules | awk '{ print $2 }')
    [ -n "$MODULES" ] && $RMMOD $MODULES > /dev/null 2>&1 || true
    MODULES=$($LCTL modules | awk '{ print $2 }')
    if [ -n "$MODULES" ]; then
    echo "Modules still loaded: "
    echo $MODULES 
    if [ -e $LPROC ]; then
        echo "Lustre still loaded"
        cat $LPROC/devices || true
        lsmod
        return 2
    else
        echo "Lustre stopped but LNET is still loaded, waiting..."
        wait_for_lnet || return 3
    fi
    fi
    HAVE_MODULES=false

    LEAK_LUSTRE=$(dmesg | tail -n 30 | grep "obd mem.*leaked" || true)
    LEAK_PORTALS=$(dmesg | tail -n 20 | grep "Portals memory leaked" || true)
    if [ "$LEAK_LUSTRE" -o "$LEAK_PORTALS" ]; then
        echo "$LEAK_LUSTRE" 1>&2
        echo "$LEAK_PORTALS" 1>&2
        mv $TMP/debug $TMP/debug-leak.`date +%s` || true
        echo "Memory leaks detected"
	[ -n "$IGNORE_LEAK" ] && echo "ignoring leaks" && return 0
        return 254
    fi
    echo "modules unloaded."
    return 0
}

# Facet functions
# start facet device options 
start() {
    facet=$1
    shift
    device=$1
    shift
    echo "Starting ${facet}: $@ ${device} ${MOUNT%/*}/${facet}"
    do_facet ${facet} mkdir -p ${MOUNT%/*}/${facet}
    do_facet ${facet} mount -t lustre $@ ${device} ${MOUNT%/*}/${facet} 
    RC=${PIPESTATUS[0]}
    if [ $RC -ne 0 ]; then
        echo "mount -t lustre $@ ${device} ${MOUNT%/*}/${facet}" 
        echo "Start of ${device} on ${facet} failed ${RC}"
    else 
        do_facet ${facet} sync
        label=$(do_facet ${facet} "e2label ${device}")
        [ -z "$label" ] && echo no label for ${device} && exit 1
        eval export ${facet}_svc=${label}
        eval export ${facet}_dev=${device}
        eval export ${facet}_opt=\"$@\"
        echo Started ${label}
    fi
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
    local WAIT=0
    local INTERVAL=1
    # conf-sanity 31 takes a long time cleanup
    while [ $WAIT -lt 300 ]; do
	running=$(do_facet ${facet} "[ -e $LPROC ] && grep ST' ' $LPROC/devices") || true
	if [ -z "${running}" ]; then
	    return 0
	fi
	echo "waited $WAIT for${running}"
	if [ $INTERVAL -lt 64 ]; then 
	    INTERVAL=$((INTERVAL + INTERVAL))
	fi
	sleep $INTERVAL
	WAIT=$((WAIT + INTERVAL))
    done
    echo "service didn't stop after $WAIT seconds.  Still running:"
    echo ${running}
    exit 1
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

    echo "Starting client: $OPTIONS $device $mnt" 
    do_node $client mkdir -p $mnt
    do_node $client mount -t lustre $OPTIONS $device $mnt || return 1

    do_node $client "sysctl -w lnet.debug=$PTLDEBUG; sysctl -w lnet.subsystem_debug=${SUBSYSTEM# }"
    [ -d /r ] && $LCTL modules > /r/tmp/ogdb-`hostname`
    return 0
}

zconf_umount() {
    client=$1
    mnt=$2
    [ "$3" ] && force=-f
    local running=$(do_node $client "grep -c $mnt' ' /proc/mounts") || true
    if [ $running -ne 0 ]; then
        echo "Stopping client $mnt (opts:$force)"
        do_node $client umount $force $mnt
    fi
}

shutdown_facet() {
    facet=$1
    if [ "$FAILURE_MODE" = HARD ]; then
        $POWER_DOWN `facet_active_host $facet`
        sleep 2 
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
    LEAK_LUSTRE=`dmesg | tail -n 30 | grep "obd mem.*leaked" || true`
    LEAK_PORTALS=`dmesg | tail -n 20 | grep "Portals memory leaked" || true`
    if [ "$LEAK_LUSTRE" -o "$LEAK_PORTALS" ]; then
        echo "$0: $LEAK_LUSTRE" 1>&2
        echo "$0: $LEAK_PORTALS" 1>&2
        echo "$0: Memory leak(s) detected..." 1>&2
        mv $TMP/debug $TMP/debug-leak.`date +%s`
        exit 204
    fi

    [ "`lctl dl 2> /dev/null | wc -l`" -gt 0 ] && lctl dl && \
        echo "$0: lustre didn't clean up..." 1>&2 && return 202 || true

    if [ "`/sbin/lsmod 2>&1 | egrep 'lnet|libcfs'`" ]; then
        echo "$0: modules still loaded..." 1>&2
        /sbin/lsmod 1>&2
        return 203
    fi
    return 0
}

wait_for_host() {
    HOST=$1
    check_network "$HOST" 900
    while ! do_node $HOST "ls -d $LUSTRE " > /dev/null; do sleep 5; done
}

wait_for() {
    facet=$1
    HOST=`facet_active_host $facet`
    wait_for_host $HOST
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
    if [ ! -z "$CLIENTS" ]; then
        $PDSH $CLIENTS "df $MOUNT; uname -n >> $MOUNT/recon" > /dev/null
    fi
    echo Connected clients:
    cat $MOUNT/recon
    ls -l $MOUNT/recon > /dev/null
    rm $MOUNT/recon
}

facet_failover() {
    facet=$1
    echo "Failing $facet on node `facet_active_host $facet`"
    shutdown_facet $facet
    reboot_facet $facet
    client_df &
    DFPID=$!
    echo "df pid is $DFPID"
    change_active $facet
    TO=`facet_active_host $facet`
    echo "Failover $facet to $TO"
    wait_for $facet
    local dev=${facet}_dev
    local opt=${facet}_opt
    start $facet ${!dev} ${!opt} || error "Restart of $facet failed"
}

obd_name() {
    local facet=$1
}

replay_barrier() {
    local facet=$1
    do_facet $facet sync
    df $MOUNT
    local svc=${facet}_svc
    do_facet $facet $LCTL --device %${!svc} readonly
    do_facet $facet $LCTL --device %${!svc} notransno
    do_facet $facet $LCTL mark "$facet REPLAY BARRIER on ${!svc}"
    $LCTL mark "local REPLAY BARRIER on ${!svc}"
}

replay_barrier_nodf() {
    local facet=$1    echo running=${running}
    do_facet $facet sync
    local svc=${facet}_svc
    echo Replay barrier on ${!svc}
    do_facet $facet $LCTL --device %${!svc} readonly
    do_facet $facet $LCTL --device %${!svc} notransno
    do_facet $facet $LCTL mark "$facet REPLAY BARRIER on ${!svc}"
    $LCTL mark "local REPLAY BARRIER on ${!svc}"
}

mds_evict_client() {
    UUID=`cat /proc/fs/lustre/mdc/${mds_svc}-mdc-*/uuid`
    do_facet mds "echo $UUID > /proc/fs/lustre/mds/${mds_svc}/evict_client"
}

ost_evict_client() {
    UUID=`cat /proc/fs/lustre/osc/${ost1_svc}-osc-*/uuid`
    do_facet ost1 "echo $UUID > /proc/fs/lustre/obdfilter/${ost1_svc}/evict_client"
}

fail() {
    facet_failover $* || error "failover: $?"
    df $MOUNT || error "post-failover df: $?"
}

fail_abort() {
    local facet=$1
    stop $facet
    change_active $facet
    local svc=${facet}_svc
    local dev=${facet}_dev
    local opt=${facet}_opt
    start $facet ${!dev} ${!opt}
    do_facet $facet lctl --device %${!svc} abort_recovery
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

facet_host() {
    local facet=$1
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

    if [ -f ./${facet}active ] ; then
        source ./${facet}active
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
        hostname
    else
        echo `facet_host $active`
    fi
}

change_active() {
    local facet=$1
    failover=${facet}failover 
    host=`facet_host $failover`
    [ -z "$host" ] && return
    curactive=`facet_active $facet`
    if [ -z "${curactive}" -o "$curactive" == "$failover" ] ; then
        eval export ${facet}active=$facet
    else
        eval export ${facet}active=$failover
    fi
    # save the active host for this facet
    activevar=${facet}active
    echo "$activevar=${!activevar}" > ./$activevar
}

do_node() {
    HOST=$1
    shift
    local myPDSH=$PDSH
    if [ "$HOST" = "$(hostname)" ]; then
        myPDSH="no_dsh"
    fi
    if $VERBOSE; then
        echo "CMD: $HOST $@" >&2
        $myPDSH $HOST $LCTL mark "$@" > /dev/null 2>&1 || :
    fi
    $myPDSH $HOST "(PATH=\$PATH:$RLUSTRE/utils:$RLUSTRE/tests:/sbin:/usr/sbin; cd $RPWD; sh -c \"$@\")" | sed "s/^${HOST}: //"
    return ${PIPESTATUS[0]}
}

do_facet() {
    facet=$1
    shift
    HOST=`facet_active_host $facet`
    [ -z $HOST ] && echo No host defined for facet ${facet} && exit 1
    do_node $HOST "$@"
}

add() {
    local facet=$1
    shift
    # make sure its not already running
    stop ${facet} -f
    rm -f ${facet}active
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
    
    # assume client mount is local 
    grep " $MOUNT " /proc/mounts && zconf_umount `hostname` $MOUNT $*
    grep " $MOUNT2 " /proc/mounts && zconf_umount `hostname` $MOUNT2 $*
    [ "$CLIENTONLY" ] && return
    stop mds -f
    for num in `seq $OSTCOUNT`; do
        stop ost$num -f
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
    grep " $1 " /proc/mounts || zconf_mount `hostname` $*
}

setupall() {
    load_modules
    if [ -z "$CLIENTONLY" ]; then
        echo Setup mdt, osts
        echo $REFORMAT | grep -q "reformat" \
	    || do_facet mds "$TUNEFS --writeconf $MDSDEV"
        start mds $MDSDEV $MDS_MOUNT_OPTS
        for num in `seq $OSTCOUNT`; do
            DEVNAME=`ostdevname $num`
            start ost$num $DEVNAME $OST_MOUNT_OPTS
        done
    fi
    [ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE
    mount_client $MOUNT
    if [ "$MOUNT_2" ]; then
        mount_client $MOUNT2
    fi
    sleep 5
}

mounted_lustre_filesystems() {
	awk '($3 ~ "lustre" && $1 ~ ":") { print $2 }' /proc/mounts
}

check_and_setup_lustre() {
    MOUNTED="`mounted_lustre_filesystems`"
    if [ -z "$MOUNTED" ]; then
        [ "$REFORMAT" ] && formatall
        setupall
        MOUNTED="`mounted_lustre_filesystems`"
        [ -z "$MOUNTED" ] && error "NAME=$NAME not mounted"
        export I_MOUNTED=yes
    fi
    if [ "$ONLY" == "setup" ]; then
        exit 0
    fi
}

cleanup_and_setup_lustre() {
    if [ "$ONLY" == "cleanup" -o "`mount | grep $MOUNT`" ]; then
        sysctl -w lnet.debug=0 || true
        cleanupall
        if [ "$ONLY" == "cleanup" ]; then 
    	    exit 0
        fi
    fi
    check_and_setup_lustre
}

check_and_cleanup_lustre() {
    if [ "`mount | grep $MOUNT`" ]; then
        rm -rf $DIR/[Rdfs][1-9]*
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
        ping -c 1 -w 3 $1 > /dev/null
        if [ $? -eq 0 ]; then
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

absolute_path() {
    (cd `dirname $1`; echo $PWD/`basename $1`)
}

##################################
# OBD_FAIL funcs

drop_request() {
# OBD_FAIL_MDS_ALL_REQUEST_NET
    RC=0
    do_facet mds sysctl -w lustre.fail_loc=0x123
    do_facet client "$1" || RC=$?
    do_facet mds sysctl -w lustre.fail_loc=0
    return $RC
}

drop_reply() {
# OBD_FAIL_MDS_ALL_REPLY_NET
    RC=0
    do_facet mds sysctl -w lustre.fail_loc=0x122
    do_facet client "$@" || RC=$?
    do_facet mds sysctl -w lustre.fail_loc=0
    return $RC
}

drop_reint_reply() {
# OBD_FAIL_MDS_REINT_NET_REP
    RC=0
    do_facet mds sysctl -w lustre.fail_loc=0x119
    do_facet client "$@" || RC=$?
    do_facet mds sysctl -w lustre.fail_loc=0
    return $RC
}

pause_bulk() {
#define OBD_FAIL_OST_BRW_PAUSE_BULK      0x214
    RC=0
    do_facet ost1 sysctl -w lustre.fail_loc=0x214
    do_facet client "$1" || RC=$?
    do_facet client "sync"
    do_facet ost1 sysctl -w lustre.fail_loc=0
    return $RC
}

drop_ldlm_cancel() {
#define OBD_FAIL_LDLM_CANCEL             0x304
    RC=0
    do_facet client sysctl -w lustre.fail_loc=0x304
    do_facet client "$@" || RC=$?
    do_facet client sysctl -w lustre.fail_loc=0
    return $RC
}

drop_bl_callback() {
#define OBD_FAIL_LDLM_BL_CALLBACK        0x305
    RC=0
    do_facet client sysctl -w lustre.fail_loc=0x305
    do_facet client "$@" || RC=$?
    do_facet client sysctl -w lustre.fail_loc=0
    return $RC
}

drop_ldlm_reply() {
#define OBD_FAIL_LDLM_REPLY              0x30c
    RC=0
    do_facet mds sysctl -w lustre.fail_loc=0x30c
    do_facet client "$@" || RC=$?
    do_facet mds sysctl -w lustre.fail_loc=0
    return $RC
}

clear_failloc() {
    facet=$1
    pause=$2
    sleep $pause
    echo "clearing fail_loc on $facet"
    do_facet $facet "sysctl -w lustre.fail_loc=0"
}

cancel_lru_locks() {
    $LCTL mark "cancel_lru_locks $1 start"
    for d in `find $LPROC/ldlm/namespaces | egrep -i $1`; do
        [ -f $d/lru_size ] && echo clear > $d/lru_size
        [ -f $d/lock_unused_count ] && grep [1-9] $d/lock_unused_count /dev/null
    done
    $LCTL mark "cancel_lru_locks $1 stop"
}


pgcache_empty() {
    for a in /proc/fs/lustre/llite/*/dump_page_cache; do
        if [ `wc -l $a | awk '{print $1}'` -gt 1 ]; then
            echo there is still data in page cache $a ?
            cat $a;
            return 1;
        fi
    done
    return 0
}

debugsave() {
    DEBUGSAVE="$(sysctl -n lnet.debug)"
}

debugrestore() {
    [ -n "$DEBUGSAVE" ] && sysctl -w lnet.debug="${DEBUGSAVE}"
    DEBUGSAVE=""
}

FAIL_ON_ERROR=true
##################################
# Test interface 
error() {
    local ERRLOG
    sysctl -w lustre.fail_loc=0 2> /dev/null || true
    log "${TESTSUITE} ${TESTNAME}: **** FAIL:" $@
    ERRLOG=$TMP/lustre_${TESTSUITE}_${TESTNAME}.$(date +%s)
    echo "Dumping lctl log to $ERRLOG"
    # We need to dump the logs on all nodes
    $LCTL dk $ERRLOG
    [ ! "$mds_HOST" = "$(hostname)" ] && do_node $mds_HOST $LCTL dk $ERRLOG
    [ ! "$ost_HOST" = "$(hostname)" -a ! "$ost_HOST" = "$mds_HOST" ] && do_node $ost_HOST $LCTL dk $ERRLOG
    debugrestore
    [ "$TESTSUITELOG" ] && echo "$0: FAIL: $TESTNAME $@" >> $TESTSUITELOG
    if $FAIL_ON_ERROR; then
	exit 1
    fi
}

skip () {
	log " SKIP: ${TESTSUITE} ${TESTNAME} $@"
	[ "$TESTSUITELOG" ] && echo "${TESTSUITE}: SKIP: $TESTNAME $@" >> $TESTSUITELOG
}

build_test_filter() {
    [ "$ONLY" ] && log "only running test `echo $ONLY`"
    for O in $ONLY; do
        eval ONLY_${O}=true
    done
    [ "$EXCEPT$ALWAYS_EXCEPT" ] && \
        log "skipping tests: `echo $EXCEPT $ALWAYS_EXCEPT`"
    for E in $EXCEPT $ALWAYS_EXCEPT; do
        eval EXCEPT_${E}=true
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

run_test() {
    export base=`basetest $1`
    if [ ! -z "$ONLY" ]; then
        testname=ONLY_$1
        if [ ${!testname}x != x ]; then
            run_one $1 "$2"
            return $?
        fi
        testname=ONLY_$base
        if [ ${!testname}x != x ]; then
            run_one $1 "$2"
            return $?
        fi
        echo -n "."
        return 0
    fi
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
    run_one $1 "$2"
    
    return $?
}

EQUALS="======================================================================"
equals_msg() {
    msg="$@"

    local suffixlen=$((${#EQUALS} - ${#msg}))
    [ $suffixlen -lt 5 ] && suffixlen=5
    printf '===== %s %.*s\n' "$msg" $suffixlen $EQUALS
}

log() {
    echo "$*"
    lsmod | grep lnet > /dev/null || load_modules
    $LCTL mark "$*" 2> /dev/null || true
}

trace() {
	log "STARTING: $*"
	strace -o $TMP/$1.strace -ttt $*
	RC=$?
	log "FINISHED: $*: rc $RC"
	return 1
}

pass() {
    echo PASS $@
}

check_mds() {
    FFREE=`cat /proc/fs/lustre/mds/*/filesfree`
    FTOTAL=`cat /proc/fs/lustre/mds/*/filestotal`
    [ $FFREE -ge $FTOTAL ] && error "files free $FFREE > total $FTOTAL" || true
}

run_one() {
    testnum=$1
    message=$2
    tfile=f${testnum}
    export tdir=d${base}

    BEFORE=`date +%s`
    log "== test $testnum: $message ============ `date +%H:%M:%S` ($BEFORE)"
    #check_mds
    export TESTNAME=test_$testnum
    test_${testnum} || error "test_$testnum failed with $?"
    #check_mds
    check_grant ${testnum} || error "check_grant $testnum failed with $?"
    [ -f $CATASTROPHE ] && [ `cat $CATASTROPHE` -ne 0 ] && \
        error "LBUG/LASSERT detected"
    pass "($((`date +%s` - $BEFORE))s)"
    unset TESTNAME
    unset tdir
    cd $SAVE_PWD
    $CLEANUP
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
		$LFS setstripe $DIR1/${tfile}_check_grant_$i 0 $(($i -1)) 1
		dd if=/dev/zero of=$DIR1/${tfile}_check_grant_$i bs=4k \
					      count=1 > /dev/null 2>&1 
	done
	# sync all the data and make sure no pending data on server
	sync_clients
	
	#get client grant and server grant 
	client_grant=0
    for d in ${LPROC}/osc/*/cur_grant_bytes; do 
		client_grant=$((client_grant + `cat $d`))
	done
	server_grant=0
	for d in ${LPROC}/obdfilter/*/tot_granted; do
		server_grant=$((server_grant + `cat $d`))
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

remote_mds ()
{
    [ ! -e /proc/fs/lustre/mds/*MDT* ]
}

remote_ost ()
{
    [ $(grep -c obdfilter $LPROC/devices) -eq 0 ]
}

is_patchless ()
{
    grep -q patchless $LPROC/version
}
