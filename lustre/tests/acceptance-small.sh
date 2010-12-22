#!/bin/bash
# script which _must_ complete successfully (at minimum) before checkins to
# the CVS HEAD are allowed.
#set -vx
set -e

export TESTSUITE_LIST="RUNTESTS SANITY DBENCH BONNIE IOZONE FSX SANITYN LFSCK LIBLUSTRE RACER REPLAY_SINGLE CONF_SANITY RECOVERY_SMALL REPLAY_OST_SINGLE REPLAY_DUAL REPLAY_VBR INSANITY SANITY_QUOTA PERFORMANCE_SANITY LARGE_SCALE RECOVERY_MDS_SCALE RECOVERY_DOUBLE_SCALE RECOVERY_RANDOM_SCALE PARALLEL_SCALE METADATA_UPDATES OST_POOLS SANITY_BENCHMARK LNET_SELFTEST MMP OBDFILTER_SURVEY SGPDD_SURVEY"

if [ "$ACC_SM_ONLY" ]; then
    for O in $TESTSUITE_LIST; do
	export ${O}="no"
    done
    for O in $ACC_SM_ONLY; do
	O=`echo ${O%.sh} | tr "-" "_"`
	O=`echo $O | tr "[:lower:]" "[:upper:]"`
	export ${O}="yes"
    done
fi

LIBLUSTRETESTS=${LIBLUSTRETESTS:-../liblustre/tests}

RANTEST=""

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@

SETUP=${SETUP:-setupall}
FORMAT=${FORMAT:-formatall}
CLEANUP=${CLEANUP:-stopall}

setup_if_needed() {
    nfs_client_mode && return

    local MOUNTED=$(mounted_lustre_filesystems)
    if $(echo $MOUNTED | grep -w -q $MOUNT); then
        check_config_clients $MOUNT
        init_facets_vars
        init_param_vars
        return
    fi

    echo "Lustre is not mounted, trying to do setup SETUP=$SETUP ... "
    [ "$REFORMAT" ] && $FORMAT
    $SETUP

    MOUNTED=$(mounted_lustre_filesystems)
    if ! $(echo $MOUNTED | grep -w -q $MOUNT); then
        echo "Lustre is not mounted after setup! SETUP=$SETUP"
        exit 1
    fi
}

find_in_path() {
    target=$1
    for dir in $(tr : " " <<< $PATH); do
      if [ -e $dir/$target ]; then
          echo "$dir/$target found in PATH"
          return 0
      fi
    done
    return 1
}

title() {
    # update titlebar if stdin is attached to an xterm
    if ${UPDATE_TITLEBAR:-false}; then
	if tty -s; then
	    case $TERM in 
		xterm*)
		    echo -ne "\033]2; acceptance-small: $* \007" >&0
		    ;;
	    esac
	fi
    fi 
    log "-----============= acceptance-small: "$*" ============----- `date`"
    RANTEST=${RANTEST}$*", "
}

skip_remost() {
	remote_ost_nodsh && log "SKIP: $1: remote OST with nodsh" && return 0
	return 1
}

skip_remmds() {
	remote_mds_nodsh && log "SKIP: $1: remote MDS with nodsh" && return 0
	return 1
}

# cleanup the logs of all suites
cleanup_log () {
    local suite
    local o=$(echo $O | tr "[:upper:]" "[:lower:]")
    o=${o//_/-}
    
    rm -f ${TMP}/${o}.log
}

cleanup_logs () {
    local suite
    for suite in ${ACC_SM_ONLY:-$TESTSUITE_LIST}; do
        cleanup_log $suite
    done
}

export NAME MOUNT START CLEAN
. $LUSTRE/tests/cfg/$NAME.sh

assert_env mds_HOST MDS_MKFS_OPTS MDSDEV
assert_env ost_HOST OST_MKFS_OPTS OSTCOUNT
assert_env FSNAME MOUNT MOUNT2

setup_if_needed

for s in ${ACC_SM_ONLY:-$TESTSUITE_LIST}; do
    suite_name=$(echo ${s%.sh} | tr "[:upper:]_" "[:lower:]-" )
    suite=$(echo ${suite_name} | tr "[:lower:]-" "[:upper:]_")
    suite_only=ONLY # Change to ${suite}_ONLY after fixing YALA

    if is_sanity_benchmark ${suite_name}; then
        suite_only=suite_name
        suite_script=$LUSTRE/tests/sanity-benchmark.sh
    elif [ -e $LUSTRE/tests/${suite_name}.sh ]; then
        suite_script=$LUSTRE/tests/${suite_name}.sh
    elif [ -e $LUSTRE/tests/$suite_name ]; then
        suite_script=$LUSTRE/tests/$suite_name
    elif find_in_path $suite_name; then
        suite_script=${suite_name}
    elif find_in_path ${suite_name}.sh; then
        suite_script=${suite_name}.sh
    else
        echo "Can't find test script for $suite_name"
        exit 1
    fi

    echo "$suite_script located."

    if [[ ${!suite} = no ]]; then
        echo "Skipping $suite_name"
        continue
    fi

    start_ts=$(date +%s)
    title $suite_name
    bash $suite_script ${!suite_only}
    rc=$?
    duration=$(($(date +%s) - $start_ts))
    if [ $rc -ne 0 ]; then
        RC=$rc
        status="FAIL"
    else
        status="PASS"
    fi
    echo "Script: $status"


    $CLEANUP
    [ x$suite = xSGPDD_SURVEY ] || $SETUP
    eval ${suite}="done"
done

RC=$?
title FINISHED
echo "Finished at `date` in ${SECONDS}s"
echo "Tests ran: $RANTEST"
print_summary
[ "$MSKIPPED" = 1 ] && log "FAIL: remote MDS tests skipped" && RC=1
[ "$OSKIPPED" = 1 ] && log "FAIL: remote OST tests skipped" && RC=1
echo "$0: completed with rc $RC" && exit $RC
