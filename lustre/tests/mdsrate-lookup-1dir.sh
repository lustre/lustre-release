#!/bin/bash
#
# This test was used in a set of CMD3 tests (cmd3-5 test).

# Directory lookup retrieval rate single directory 10 million files
# 5900 random lookups/sec per client node 62,000 random lookups/sec aggregate
# 
# In a dir containing 10 million non-striped files the mdsrate Test Program will
# perform lookups for 10 minutes. This test can be run from a single node for
# #1 and from all nodes for #2 aggregate test to measure lookup performance.

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
assert_env CLIENTS MDSRATE SINGLECLIENT MPIRUN

MACHINEFILE=${MACHINEFILE:-$(basename $0 .sh).machines}
TESTDIR=$MOUNT

# Requirements
NUM_FILES=${NUM_FILES:-1000000}
TIME_PERIOD=${TIME_PERIOD:-600}                        # seconds
SINGLE_TARGET_RATE=5900                  # ops/sec
AGGREGATE_TARGET_RATE=62000              # ops/sec

LOG=${TESTSUITELOG:-$TMP/$(basename $0 .sh).log}
CLIENT=$SINGLECLIENT
NODES_TO_USE=${NODES_TO_USE:-$CLIENTS}
NUM_CLIENTS=$(get_node_count ${NODES_TO_USE//,/ })

rm -f $LOG

[ ! -x ${MDSRATE} ] && error "${MDSRATE} not built."

log "===== $0 ====== " 

check_and_setup_lustre

generate_machine_file $NODES_TO_USE $MACHINEFILE

$LFS setstripe $TESTDIR -c 1
get_stripe $TESTDIR

if [ -n "$NOCREATE" ]; then
    echo "NOCREATE=$NOCREATE  => no file creation."
else
    log "===== $0 Test preparation: creating ${NUM_FILES} files."
    echo "Test preparation: creating ${NUM_FILES} files."

    NUM_CLIENTS=$(get_node_count ${NODES_TO_USE//,/ })
    NUM_THREADS=$((NUM_CLIENTS * MDSCOUNT))
    if [ $NUM_CLIENTS -gt 50 ]; then
        NUM_THREADS=$NUM_CLIENTS
    fi
    COMMAND="${MDSRATE} ${MDSRATE_DEBUG} --mknod --dir ${TESTDIR}
                        --nfiles ${NUM_FILES} --filefmt 'f%%d'"
    echo "+" ${COMMAND}
    $MPIRUN -np ${NUM_THREADS} -machinefile ${MACHINEFILE} \
	   ${MPIRUN_OPTIONS} ${COMMAND} 2>&1 

    # No lockup if error occurs on file creation, abort.
    [ ${PIPESTATUS[0]} != 0 ] && error "mpirun ... mdsrate ... file creation failed, aborting"
fi

COMMAND="${MDSRATE} ${MDSRATE_DEBUG} --lookup --time ${TIME_PERIOD} ${SEED_OPTION}
        --dir ${TESTDIR} --nfiles ${NUM_FILES} --filefmt 'f%%d'"

# 1
if [ -n "$NOSINGLE" ]; then
    echo "NO Test for lookups on a single client."
else
    log "===== $0 ### 1 NODE LOOKUPS ###"
    echo "Running lookups on 1 node(s)."
    echo "+" ${COMMAND}
    $MPIRUN -np 1 -machinefile ${MACHINEFILE} \
        ${MPIRUN_OPTIONS} ${COMMAND} | tee ${LOG}

    if [ ${PIPESTATUS[0]} != 0 ]; then
        [ -f $LOG ] && cat $LOG
        error "mpirun ... mdsrate ... failed, aborting"
    fi
    check_rate lookup ${SINGLE_TARGET_RATE} 1 ${LOG} || true
fi

# 2
if [ -n "$NOMULTI" ]; then
    echo "NO test for lookups on multiple nodes."
else
    log "===== $0 ### ${NUM_CLIENTS} NODES LOOKUPS ###"
    echo "Running lookups on ${NUM_CLIENTS} node(s)."
    echo "+" ${COMMAND}
    $MPIRUN -np ${NUM_CLIENTS} -machinefile ${MACHINEFILE} \
        ${MPIRUN_OPTIONS} ${COMMAND} | tee ${LOG}

    if [ ${PIPESTATUS[0]} != 0 ]; then
        [ -f $LOG ] && cat $LOG
        error "mpirun ... mdsrate ... failed, aborting"
    fi
    check_rate lookup ${AGGREGATE_TARGET_RATE} ${NUM_CLIENTS} ${LOG} || true
fi

equals_msg `basename $0`: test complete, cleaning up
zconf_umount_clients $NODES_TO_USE $MOUNT
check_and_cleanup_lustre
#rm -f $LOG

exit 0
