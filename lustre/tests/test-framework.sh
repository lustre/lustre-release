#!/bin/sh

set -e

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
    export XMLCONFIG="${TESTSUITE}.xml"
    export LTESTDIR=${LTESTDIR:-$LUSTRE/../ltest}

    [ -d /r ] && export ROOT=/r

    export PATH=:$PATH:$LUSTRE/utils:$LUSTRE/tests
    export LCONF=${LCONF:-"lconf"}
    export LMC=${LMC:-"lmc"}
    export LCTL=${LCTL:-"lctl"}
    export CHECKSTAT="${CHECKSTAT:-checkstat} -v"

    # Paths on remote nodes, if different 
    export RLUSTRE=${RLUSTRE:-$LUSTRE}
    export RPWD=${RPWD:-$PWD}

    # command line
    
    while getopts "rf:" opt $*; do 
	case $opt in
	    f) CONFIG=$OPTARG;;
	    r) REFORMAT=--reformat;;
	    \?) usage;;
	esac
    done
    
    # save the name of the config file for the upcall
    echo "XMLCONFIG=$LUSTRE/tests/$XMLCONFIG"  > $LUSTRE/tests/XMLCONFIG
}

# Facet functions
start() {
    facet=$1
    shift
    active=`facet_active $facet`
    do_facet $facet $LCONF --select ${facet}_svc=${active}_facet --node ${active}_facet $@ $XMLCONFIG
}

stop() {
    facet=$1
    active=`facet_active $facet`
    shift
    do_facet $facet $LCONF --select ${facet}_svc=${active}_facet --node ${active}_facet $@ --cleanup $XMLCONFIG
}

zconf_mount() {
    mnt=$1

    [ -d $mnt ] || mkdir $mnt
    
    if [ -x /sbin/mount.lustre ] ; then
	mount -t lustre -o nettype=$NETTYPE \
	    `facet_host mds`:/mds_svc/client_facet $mnt
    else
       insmod $LUSTRE/llite/llite.o || :
       $LUSTRE/utils/llmount `facet_host mds`:/mds_svc/client_facet $mnt \
            -o nettype=$NETTYPE 
    fi

    [ -d /r ] && $LCTL modules > /r/tmp/ogdb-`hostname`
    return 0
}

zconf_umount() {
    mnt=$1
    umount  $mnt || :
    rmmod llite || :
}

shutdown_facet() {
    facet=$1
    if [ "$FAILURE_MODE" = HARD ]; then
       $POWER_DOWN `facet_active_host $facet`
    else
       stop $facet --force --failover --nomod
    fi
}

reboot_facet() {
    facet=$1
    if [ "$FAILURE_MODE" = HARD ]; then
       $POWER_UP `facet_active_host $facet`
    fi
}

replay_barrier() {
    local facet=$1
    do_facet $facet sync
    df $MOUNT
    do_facet $facet $LCTL --device %${facet}_svc readonly
    do_facet $facet $LCTL --device %${facet}_svc notransno
    do_facet $facet $LCTL mark "REPLAY BARRIER"
    $LCTL mark "REPLAY BARRIER"
}

mds_evict_client() {
    UUID=`cat /proc/fs/lustre/mdc/*_MNT_*/uuid`
    do_facet mds "echo $UUID > /proc/fs/lustre/mds/mds_svc/evict_client"
}

fail() {
    local facet=$1
    stop $facet --force --failover --nomod
    change_active $facet
    start $facet
    df $MOUNT || error "post-failover df: $?"
}

fail_abort() {
    local facet=$1
    stop $facet --force --failover --nomod
    change_active $facet
    start $facet
    do_facet $facet lctl --device %${facet}_svc abort_recovery
    df $MOUNT || echo "first df failed: $?"
    df $MOUNT || error "post-failover df: $?"
}

do_lmc() {
    $LMC -m ${XMLCONFIG} $@
}

h2tcp() {
   if [ "$1" = "client" ]; then echo \'*\'; else
   echo $1 
   fi
}
declare -fx h2tcp

h2elan() {
   if [ "$1" = "client" ]; then echo \'*\'; else
   echo $1 | sed 's/[^0-9]*//g'
   fi
}
declare -fx h2elan

facet_host() {
   local facet=$1
   varname=${facet}_HOST
   echo -n ${!varname}
}

facet_nid() {
   facet=$1
   HOST=`facet_host $facet`
   if [ -z "$HOST" ]; then
	echo "The env variable ${facet}_HOST must be set."
	exit 1
   fi
   echo `h2$NETTYPE $HOST`
}

facet_active() {
    local facet=$1
    local activevar=${facet}active
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
    echo `facet_host $active`
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
    $PDSH $HOST "(PATH=\$PATH:$RLUSTRE/utils:$RLUSTRE/tests; cd $RPWD; sh -c \"$@\")"
}
do_facet() {
    facet=$1
    shift
    HOST=`facet_active_host $facet`
    do_node $HOST $@
}

add_facet() {
    local facet=$1
    shift
    echo "add facet $facet: `facet_host $facet`"
    do_lmc --add node --node ${facet}_facet $@ --timeout $TIMEOUT
    do_lmc --add net --node ${facet}_facet --nid `facet_nid $facet` \
	--nettype $NETTYPE
}

add_mds() {
    facet=$1
    shift
    add_facet $facet 
    do_lmc --add mds --node ${facet}_facet --mds ${facet}_svc $*
}

add_mdsfailover() {
    facet=$1
    shift
    add_facet ${facet}failover
    do_lmc --add mds  --node ${facet}failover_facet --mds ${facet}_svc $*
}

add_ost() {
    facet=$1
    shift
    add_facet $facet
    do_lmc --add ost --node ${facet}_facet --ost ${facet}_svc $*
}

add_ostfailover() {
    facet=$1
    shift
    add_facet ${facet}failover
    do_lmc --add ost --failover --node ${facet}failover_facet --ost ${facet}_svc $*
}

add_lov() {
    lov=$1
    mds_facet=$2
    shift; shift
    do_lmc --add lov --mds ${mds_facet}_svc --lov $lov $*
    
}

add_client() {
    facet=$1
    mds=$2
    shift; shift
    add_facet $facet --lustre_upcall $UPCALL
    do_lmc --add mtpt --node ${facet}_facet --mds ${mds}_svc $*

}


####### 
# General functions

check_network() {
   local NETWORK=0
   local WAIT=0
   while [ $NETWORK -eq 0 ]; do
      ping -c 1 -w 3 $1
      if [ $? -eq 0 ]; then
         NETWORK=1
      else
         sleep 5
         WAIT=`expr $WAIT + 5`
      fi
      if [ $WAIT -gt $2 ]; then
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
# Test interface 
error() {
    echo "${TESTSUITE}: **** FAIL:" $@
    exit 1
}

build_test_filter() {
        for O in $ONLY; do
            eval ONLY_${O}=true
        done
        for E in $EXCEPT $ALWAYS_EXCEPT; do
            eval EXCEPT_${E}=true
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
                 echo "skipping excluded test $1"
                 return 0
        fi
        testname=EXCEPT_$base
        if [ ${!testname}x != x ]; then
                 echo "skipping excluded test $1 (base $base)"
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

run_one() {
    testnum=$1
    message=$2
    tfile=f$base
    tdir=d$base

    # Pretty tests run faster.
    equals_msg $testnum: $message

    test_${testnum} || error "test_$testnum failed with $?"
}
