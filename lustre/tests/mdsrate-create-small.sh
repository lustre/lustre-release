#!/bin/bash
#
# This test was used in a set of CMD3 tests (cmd3-3 test). 

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

assert_env CLIENTS MDSRATE SINGLECLIENT MPIRUN

MACHINEFILE=${MACHINEFILE:-$(basename $0 .sh).machines}
TESTDIR=$MOUNT

# Requirements
# The default number of stripes per file is set to 1 in test3/run_test.sh.
TIME_PERIOD=${TIME_PERIOD:-600}                        # seconds
SINGLE_TARGET_RATE=1400                # ops/sec
AGGREGATE_TARGET_RATE=10000            # ops/sec

# Local test variables
TESTDIR_SINGLE="${TESTDIR}/single"
TESTDIR_MULTI="${TESTDIR}/multi"

LOG=${TESTSUITELOG:-$TMP/$(basename $0 .sh).log}
CLIENT=$SINGLECLIENT
NODES_TO_USE=${NODES_TO_USE:-$CLIENTS}
NUM_CLIENTS=$(get_node_count ${NODES_TO_USE//,/ })
# XXX - this needs to be determined given the number of MDTs and the number
#       of clients.
THREADS_PER_CLIENT=3                   # threads/client for multi client test
if [ $NUM_CLIENTS -gt 50 ]; then
    THREADS_PER_CLIENT=1
fi

[ ! -x ${MDSRATE} ] && error "${MDSRATE} not built."

# Make sure we start with a clean slate
rm -f ${LOG} PI*

log "===== $0 ====== " 

check_and_setup_lustre

generate_machine_file $NODES_TO_USE $MACHINEFILE

$LFS setstripe $TESTDIR -i 0 -c 1
get_stripe $TESTDIR

if [ -n "$NOSINGLE" ]; then
    echo "NO Tests on single client."
else
    if [ -n "$NOCREATE" ]; then
        echo "NO Test for creates for a single client."
    else
        do_node ${CLIENT} "rm -rf $TESTDIR_SINGLE"

        log "===== $0 ### 1 NODE CREATE ###"
        echo "Running creates on 1 node(s)."

        COMMAND="${MDSRATE} ${MDSRATE_DEBUG} --create --time ${TIME_PERIOD}
                            --dir ${TESTDIR_SINGLE} --filefmt 'f%%d'"
        echo "+ ${COMMAND}"
        $MPIRUN -np 1 -machinefile ${MACHINEFILE} \
            ${MPIRUN_OPTIONS} ${COMMAND} | tee ${LOG}

        if [ ${PIPESTATUS[0]} != 0 ]; then
        [ -f $LOG ] && cat $LOG
            error "mpirun ... mdsrate ... failed, aborting"
        fi
        check_rate create ${SINGLE_TARGET_RATE} 1 ${LOG} || true
    fi

    if [ -n "$NOUNLINK" ]; then
        echo "NO Test for unlinks for a single client."
    else
        log "===== $0 ### 1 NODE UNLINK ###"
        echo "Running unlinks on 1 node(s)."

        let NUM_FILES=${SINGLE_TARGET_RATE}\*${TIME_PERIOD}
        COMMAND="${MDSRATE} ${MDSRATE_DEBUG} --unlink --time ${TIME_PERIOD}
                     --nfiles ${NUM_FILES} --dir ${TESTDIR_SINGLE} --filefmt 'f%%d'"
        echo "+ ${COMMAND}"
        $MPIRUN -np 1 -machinefile ${MACHINEFILE} \
            ${MPIRUN_OPTIONS} ${COMMAND} | tee ${LOG}

        if [ ${PIPESTATUS[0]} != 0 ]; then
        [ -f $LOG ] && cat $LOG
            error "mpirun ... mdsrate ... failed, aborting"
        fi
        check_rate unlink ${SINGLE_TARGET_RATE} 1 ${LOG} || true
    fi
fi

if [ -n "$NOMULTI" ]; then
    echo "NO tests on multiple nodes."
else
    if [ -n "$NOCREATE" ]; then
        echo "NO test for create on multiple nodes."
    else
        do_node $CLIENT rm -rf $TESTDIR_MULTI

        log "===== $0 ### $NUM_CLIENTS NODES CREATE ###"
        echo "Running creates on ${NUM_CLIENTS} node(s) with $THREADS_PER_CLIENT threads per client."

        COMMAND="${MDSRATE} ${MDSRATE_DEBUG} --create --time ${TIME_PERIOD}
                            --dir ${TESTDIR_MULTI} --filefmt 'f%%d'"
        echo "+ ${COMMAND}"
        $MPIRUN -np $((${NUM_CLIENTS}*THREADS_PER_CLIENT)) -machinefile ${MACHINEFILE} \
            ${MPIRUN_OPTIONS} ${COMMAND} | tee ${LOG}
        if [ ${PIPESTATUS[0]} != 0 ]; then
            [ -f $LOG ] && cat $LOG
            error "mpirun ... mdsrate ... failed, aborting"
        fi
        check_rate create ${AGGREGATE_TARGET_RATE} ${NUM_CLIENTS} ${LOG} || true
    fi

    if [ -n "$NOUNLINK" ]; then
        echo "NO Test for unlinks multiple nodes."
    else
        log "===== $0 ### $NUM_CLIENTS NODES UNLINK ###"
        echo "Running unlinks on ${NUM_CLIENTS} node(s) with $THREADS_PER_CLIENT threads per client."

        let NUM_FILES=${AGGREGATE_TARGET_RATE}\*${TIME_PERIOD}
        COMMAND="${MDSRATE} ${MDSRATE_DEBUG} --unlink --time ${TIME_PERIOD}
                      --nfiles ${NUM_FILES} --dir ${TESTDIR_MULTI} --filefmt 'f%%d'"
        echo "+ ${COMMAND}"
        $MPIRUN -np $((${NUM_CLIENTS}*THREADS_PER_CLIENT)) -machinefile ${MACHINEFILE} \
            ${MPIRUN_OPTIONS} ${COMMAND} | tee ${LOG}
        if [ ${PIPESTATUS[0]} != 0 ]; then
            [ -f $LOG ] && cat $LOG
            error "mpirun ... mdsrate ... failed, aborting"
        fi
        check_rate unlink ${AGGREGATE_TARGET_RATE} ${NUM_CLIENTS} ${LOG} || true
    fi
fi

equals_msg `basename $0`: test complete, cleaning up
zconf_umount_clients $NODES_TO_USE $MOUNT
check_and_cleanup_lustre
#rm -f $LOG

exit 0
