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

init_test_env() {
    export TESTSUITE=`basename $0 .sh`
    export XMLCONFIG="${TESTSUITE}.xml"
    export LTESTDIR=${LTESTDIR:-$LUSTRE/../ltest}

    [ -d /r ] && export ROOT=/r
    export RLUSTRE=${RLUSTRE:-$LUSTRE}
    export RPWD=${RPWD:-$PWD}
    export PATH=$PATH:$RLUSTRE/utils:$RLUSTRE/tests
    export PATH=$RLUSTRE/utils:$RLUSTRE/tests:$PATH
    
    export CHECKSTAT="${CHECKSTAT:-checkstat} -v"
}

start() {
    facet=$1
    shift
    active=`facet_active $facet`
    do_facet $facet $LCONF --select ${facet}1=${active}_facet --node ${active}_facet $@ $XMLCONFIG
}

stop() {
    facet=$1
    active=`facet_active $facet`
    shift
    do_facet $facet $LCONF --select ${facet}1=${active}_facet --node ${active}_facet $@ --cleanup $XMLCONFIG
}

replay_barrier() {
    local facet=$1
    do_facet $facet sync
    df $MOUNT
    do_facet $facet $LCTL --device %${facet}1 readonly
    do_facet $facet $LCTL --device %${facet}1 notransno
    do_facet $facet $LCTL mark "REPLAY BARRIER"
    $LCTL mark "REPLAY BARRIER"
}

mds_evict_client() {
    UUID= `cat /proc/fs/lustre/mdc/*_MNT_*/uuid`
    do_facet mds "echo $UUID > /proc/fs/lustre/mds/mds1/evict_client"
}

fail() {
    local facet=$1
    stop $facet --force --failover --nomod
    change_active $facet
    start $facet
    df $MOUNT || error "post-failover df: $?"
}

do_lmc() {
    $LMC -m ${XMLCONFIG} $@
}

h2tcp() {
    echo $1
}
declare -fx h2tcp

h2elan() {
    echo $1 | sed "s/[^0-9]*//"
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

no_dsh() {
   shift
   eval $@
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

do_facet() {
    facet=$1
    shift
    active=`facet_active $facet`
    HOST=`facet_host $active`
    $PDSH $HOST "(PATH=\$PATH:$LUSTRE/utils:$LUSTRE/tests; cd $PWD; sh -c \"$@\")"
}

add_facet() {
    local facet=$1
    shift
    echo "add facet $facet: `facet_host $facet`"
    do_lmc --add node --node ${facet}_facet $@ --timeout $TIMEOUT
    do_lmc --add net --node ${facet}_facet --nid `facet_nid $facet` \
	--nettype $NETTYPE
}

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
