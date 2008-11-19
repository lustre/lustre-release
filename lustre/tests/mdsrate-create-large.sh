#!/bin/bash
#
# This test was used in a set of CMD3 tests (cmd3-4 test).

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

assert_env CLIENTS MDSRATE SINGLECLIENT MPIRUN

MACHINEFILE=${MACHINEFILE:-$TMP/$(basename $0 .sh).machines}
TESTDIR=$MOUNT

# Requirements
TIME_PERIOD=${TIME_PERIOD:-600}                        # seconds
SINGLE_TARGET_RATE=$((1300 / OSTCOUNT))     # ops/sec
AGGREGATE_TARGET_RATE=$((7000 / OSTCOUNT))  # ops/sec

# Local test variables
TESTDIR_SINGLE="${TESTDIR}/single"
TESTDIR_MULTI="${TESTDIR}/multi"

LOG=${TESTSUITELOG:-$TMP/$(basename $0 .sh).log}
CLIENT=$SINGLECLIENT
NODES_TO_USE=${NODES_TO_USE:-$CLIENTS}
NUM_CLIENTS=$(get_node_count ${NODES_TO_USE//,/ })

[ ! -x ${MDSRATE} ] && error "${MDSRATE} not built."

log "===== $0 ====== " 

check_and_setup_lustre

generate_machine_file $NODES_TO_USE $MACHINEFILE || error "can not generate machinefile"

$LFS setstripe $TESTDIR -c -1
get_stripe $TESTDIR

# Make sure we start with a clean slate
rm -f ${LOG} PI*

if [ -n "$NOSINGLE" ]; then
    echo "NO Test for creates for a single client."
else
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

if [ -n "$NOMULTI" ]; then
    echo "NO test for create on multiple nodes."
else

    log "===== $0 ### $NUM_CLIENTS NODES CREATE ###"
    echo "Running creates on ${NUM_CLIENTS} node(s)."

    COMMAND="${MDSRATE} ${MDSRATE_DEBUG} --create --time ${TIME_PERIOD}
                        --dir ${TESTDIR_MULTI} --filefmt 'f%%d'"
    echo "+ ${COMMAND}"
   $MPIRUN -np ${NUM_CLIENTS} -machinefile ${MACHINEFILE} \
        ${MPIRUN_OPTIONS} ${COMMAND} | tee ${LOG}

    if [ ${PIPESTATUS[0]} != 0 ]; then
	[ -f $LOG ] && cat $LOG
	error "mpirun ... mdsrate ... failed, aborting"
    fi

    check_rate create ${AGGREGATE_TARGET_RATE} ${NUM_CLIENTS} ${LOG} || true

    echo "Running unlinks on ${NUM_CLIENTS} node(s)."

    let NUM_FILES=${AGGREGATE_TARGET_RATE}\*${TIME_PERIOD}
    COMMAND="${MDSRATE} ${MDSRATE_DEBUG} --unlink --time ${TIME_PERIOD}
                  --nfiles ${NUM_FILES} --dir ${TESTDIR_MULTI} --filefmt 'f%%d'"
    echo "+ ${COMMAND}"
    $MPIRUN -np ${NUM_CLIENTS} -machinefile ${MACHINEFILE} \
        ${MPIRUN_OPTIONS} ${COMMAND} | tee ${LOG}

    if [ ${PIPESTATUS[0]} != 0 ]; then
	[ -f $LOG ] && cat $LOG
	error "mpirun ... mdsrate ... failed, aborting"
    fi

    check_rate unlink ${AGGREGATE_TARGET_RATE} ${NUM_CLIENTS} ${LOG} || true
fi

equals_msg `basename $0`: test complete, cleaning up
rm -f $MACHINEFILE
zconf_umount_clients $NODES_TO_USE $MOUNT
check_and_cleanup_lustre
#rm -f $LOG

exit 0
