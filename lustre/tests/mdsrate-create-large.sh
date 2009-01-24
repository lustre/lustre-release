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
# set NUM_FILES=0 to force TIME_PERIOD work  
NUM_FILES=${NUM_FILES:-1000000}
TIME_PERIOD=${TIME_PERIOD:-600}                        # seconds

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

IFree=$(inodes_available)
if [ $IFree -lt $NUM_FILES ]; then
    NUM_FILES=$IFree
fi

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
                --nfiles ${NUM_FILES} --dir ${TESTDIR_SINGLE} --filefmt 'f%%d'"
    echo "+ ${COMMAND}"
    mpi_run -np 1 -machinefile ${MACHINEFILE} ${COMMAND} | tee ${LOG}

    if [ ${PIPESTATUS[0]} != 0 ]; then
	[ -f $LOG ] && cat $LOG
	error "mpirun ... mdsrate ... failed, aborting"
    fi
    
    log "===== $0 ### 1 NODE UNLINK ###"
    echo "Running unlinks on 1 node(s)."

    COMMAND="${MDSRATE} ${MDSRATE_DEBUG} --unlink --time ${TIME_PERIOD}
                --nfiles ${NUM_FILES} --dir ${TESTDIR_SINGLE} --filefmt 'f%%d'"
    echo "+ ${COMMAND}"
    mpi_run -np 1 -machinefile ${MACHINEFILE} ${COMMAND} | tee ${LOG}
 
    if [ ${PIPESTATUS[0]} != 0 ]; then
	[ -f $LOG ] && cat $LOG
	error "mpirun ... mdsrate ... failed, aborting"
    fi
fi

IFree=$(inodes_available)
if [ $IFree -lt $NUM_FILES ]; then
    NUM_FILES=$IFree
fi

if [ -n "$NOMULTI" ]; then
    echo "NO test for create on multiple nodes."
else

    log "===== $0 ### $NUM_CLIENTS NODES CREATE ###"
    echo "Running creates on ${NUM_CLIENTS} node(s)."

    COMMAND="${MDSRATE} ${MDSRATE_DEBUG} --create --time ${TIME_PERIOD}
                --nfiles $NUM_FILES --dir ${TESTDIR_MULTI} --filefmt 'f%%d'"
    echo "+ ${COMMAND}"
    mpi_run -np ${NUM_CLIENTS} -machinefile ${MACHINEFILE} ${COMMAND} | tee ${LOG}

    if [ ${PIPESTATUS[0]} != 0 ]; then
	[ -f $LOG ] && cat $LOG
	error "mpirun ... mdsrate ... failed, aborting"
    fi

    echo "Running unlinks on ${NUM_CLIENTS} node(s)."

    COMMAND="${MDSRATE} ${MDSRATE_DEBUG} --unlink --time ${TIME_PERIOD}
                --nfiles ${NUM_FILES} --dir ${TESTDIR_MULTI} --filefmt 'f%%d'"
    echo "+ ${COMMAND}"
    mpi_run -np ${NUM_CLIENTS} -machinefile ${MACHINEFILE} ${COMMAND} | tee ${LOG}

    if [ ${PIPESTATUS[0]} != 0 ]; then
	[ -f $LOG ] && cat $LOG
	error "mpirun ... mdsrate ... failed, aborting"
    fi

fi

equals_msg `basename $0`: test complete, cleaning up
rm -f $MACHINEFILE
check_and_cleanup_lustre
#rm -f $LOG

exit 0
