#!/bin/sh

set -e

init_test_env() {
    export TESTSUITE=`basename $0 .sh`
    export XMLCONFIG="${TESTSUITE}.xml"
    export LTESTDIR=${LTESTDIR:-$LUSTRE/../ltest}
    export PATH=$LUSTRE/utils:$LUSTRE/tests:$PATH

    export RLUSTRE=${RLUSTRE:-$LUSTRE}
    export RPWD=${RPWD:-$PWD}
    export CHECKSTAT="${CHECKSTAT:-checkstat} -v"
}

start() {
    facet=$1
    shift
    lconf --node ${facet}_facet $@ $XMLCONFIG
}

stop() {
    facet=$1
    shift
    lconf --node ${facet}_facet $@ --cleanup $XMLCONFIG
}

replay_barrier() {
    local dev=$1
    sync
    df $MOUNT
    lctl --device %${dev}1 readonly
    lctl --device %${dev}1 notransno
    lctl mark "REPLAY BARRIER"
}

mds_evict_client() {
    cat /proc/fs/lustre/mdc/*_MNT_*/uuid > /proc/fs/lustre/mds/mds1/evict_client
}

fail() {
    local facet=$1
    stop $facet --force --failover --nomod
    start $facet --nomod
    df $MOUNT || error "post-failover df: $?"
}

do_lmc() {
    lmc -m ${XMLCONFIG} $@
}

add_facet() {
    local facet=$1
    shift
    do_lmc --add node --node ${facet}_facet $@ --timeout $TIMEOUT
    do_lmc --add net --node ${facet}_facet --nid localhost --nettype tcp
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

   local suffixlen=$((65 - ${#msg}))
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
