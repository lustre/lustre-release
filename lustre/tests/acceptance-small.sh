#!/bin/bash
# script which _must_ complete successfully (at minimum) before checkins to
# the CVS HEAD are allowed.
#set -vx
set -e

export MSKIPPED=0
export OSKIPPED=0

# This is the default set of tests to run.
DEFAULT_SUITES="runtests sanity sanity-benchmark sanityn lfsck
                racer replay-single conf-sanity recovery-small
                replay-ost-single replay-dual replay-vbr insanity sanity-quota
                sanity-sec sanity-gss performance-sanity large-scale
                recovery-mds-scale recovery-double-scale recovery-random-scale
                parallel-scale lustre_rsync-test metadata-updates ost-pools
                lnet-selftest mmp obdfilter-survey sgpdd-survey"

if [[ -n $@ ]]; then
    ACC_SM_ONLY="${ACC_SM_ONLY} $@"
fi

[ "$SIZE" ] || SIZE=$((RAMKB * 2))
[ "$RSIZE" ] || RSIZE=512
[ "$UID" ] || UID=1000
[ "$MOUNT" ] || MOUNT=/mnt/lustre
[ "$MOUNT2" ] || MOUNT2=${MOUNT}2
[ "$TMP" ] || TMP=/tmp
[ "$COUNT" ] || COUNT=1000
[ "$DEBUG_LVL" ] || DEBUG_LVL=0
[ "$DEBUG_OFF" ] || DEBUG_OFF="eval lctl set_param debug=\"$DEBUG_LVL\""
[ "$DEBUG_ON" ] || DEBUG_ON="eval lctl set_param debug=0x33f0484"

export TF_FAIL=$TMP/tf.fail

if [ "$ACC_SM_ONLY" ]; then
    for O in $DEFAULT_SUITES; do
        O=$(echo $O | tr "-" "_" | tr "[:lower:]" "[:upper:]")
        export ${O}="no"
    done
    for O in $ACC_SM_ONLY; do
        O=`echo ${O%.sh} | tr "-" "_"`
        O=`echo $O | tr "[:lower:]" "[:upper:]"`
        export ${O}="yes"
    done
fi

STARTTIME=`date +%s`

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env

if $GSS; then
    # liblustre doesn't support GSS
    export LIBLUSTRE=no
else
    export SANITY_GSS="no"
fi

SETUP=${SETUP:-setupall}
FORMAT=${FORMAT:-formatall}
CLEANUP=${CLEANUP:-stopall}

setup_if_needed() {
    nfs_client_mode && return

    local MOUNTED=$(mounted_lustre_filesystems)
    if $(echo $MOUNTED' ' | grep -w -q $MOUNT' '); then
        check_config_clients $MOUNT
        init_facets_vars
        init_param_vars
        return
    fi

    echo "Lustre is not mounted, trying to do setup SETUP=$SETUP ... "
    [ "$REFORMAT" ] && $FORMAT
    $SETUP

    MOUNTED=$(mounted_lustre_filesystems)
    if ! $(echo $MOUNTED' ' | grep -w -q $MOUNT' '); then
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
    # update titlebar if stdin is attaached to an xterm
    if ${UPDATE_TITLEBAR:-false}; then
        if tty -s; then
            case $TERM in 
                xterm*)
                    echo -ne "\033]2; acceptance-small: $* \007" >&0
                    ;;
            esac
        fi
    fi 
    log "-----============= acceptance-small: "$*" ============----- $(date)"
}

run_suite() {
    local suite_name=$(echo ${1%.sh} | tr "[:upper:]_" "[:lower:]-" )
    local suite=$(echo ${suite_name} | tr "[:lower:]-" "[:upper:]_")
    local suite_only=ONLY # Change to ${suite}_ONLY after fixing YALA

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
        return 1
    fi

    echo "$suite_script located."
    if [[ ${!suite} != no ]]; then
        local rc
        local status
        local duration
        local start_ts=$(date +%s)
        rm -rf $TF_FAIL
        title $suite_name
        log_test $suite_name
        bash $suite_script ${!suite_only}
        rc=$?
        duration=$(($(date +%s) - $start_ts))
        if [ -f $TF_FAIL -o $rc -ne 0 ]; then
            status="FAIL"
        else
            status="PASS"
        fi
        echo "Script: $status"
        log_test_status $duration $status

        $CLEANUP
        [ x$suite = xSGPDD_SURVEY ] || $SETUP

        eval ${suite}="done"
    else
        echo "Skipping $suite_name"
    fi
}

run_suites() {
    for suite in $*; do
        run_suite $suite
    done
}

export NAME MOUNT START CLEAN
. $LUSTRE/tests/cfg/$NAME.sh

assert_env mds_HOST MDS_MKFS_OPTS 
assert_env ost_HOST OST_MKFS_OPTS OSTCOUNT
assert_env FSNAME MOUNT MOUNT2

setup_if_needed
init_logging

run_suites ${ACC_SM_ONLY:-$DEFAULT_SUITES}

RC=$?
title FINISHED
echo "Finished at `date` in $((`date +%s` - $STARTTIME))s"
print_summary
[ "$MSKIPPED" = 1 ] && log "FAIL: remote MDS tests skipped" && RC=1
[ "$OSKIPPED" = 1 ] && log "FAIL: remote OST tests skipped" && RC=1
echo "$0: completed with rc $RC" && exit $RC
