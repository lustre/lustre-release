#!/bin/bash
#
# This test was used in a set of CMD3 tests (cmd3-4 test).

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

assert_env CLIENTS MDSRATE SINGLECLIENT MPIRUN

MACHINEFILE=${MACHINEFILE:-$TMP/$(basename $0 .sh).machines}
BASEDIR=$MOUNT/mdsrate

# Requirements
# set NUM_FILES=0 to force TIME_PERIOD work
NUM_FILES=${NUM_FILES:-1000000}
TIME_PERIOD=${TIME_PERIOD:-600}                        # seconds

# Local test variables
TESTDIR_SINGLE="${BASEDIR}/single"
TESTDIR_MULTI="${BASEDIR}/multi"

LOG=${TESTSUITELOG:-$TMP/$(basename $0 .sh).log}
CLIENT=$SINGLECLIENT
NODES_TO_USE=${NODES_TO_USE:-$CLIENTS}
NUM_CLIENTS=$(get_node_count ${NODES_TO_USE//,/ })

[ ! -x ${MDSRATE} ] && error "${MDSRATE} not built."

log "===== $0 ====== "

check_and_setup_lustre

mkdir -p $BASEDIR
chmod 0777 $BASEDIR
$LFS setstripe $BASEDIR -c -1
get_stripe $BASEDIR

IFree=$(mdsrate_inodes_available)
if [ $IFree -lt $NUM_FILES ]; then
    NUM_FILES=$IFree
fi

generate_machine_file $NODES_TO_USE $MACHINEFILE || error "can not generate machinefile"

# Make sure we start with a clean slate
rm -f ${LOG}

if [ -n "$NOSINGLE" ]; then
    echo "NO Test for creates for a single client."
else
    # We can use np = $NUM_CLIENTS to speed up the cleanup
    mdsrate_cleanup $NUM_CLIENTS $MACHINEFILE $NUM_FILES $TESTDIR_SINGLE 'f%%d' --ignore

    log "===== $0 ### 1 NODE CREATE ###"

	COMMAND="${MDSRATE} ${MDSRATE_DEBUG} --create --time ${TIME_PERIOD}
		--nfiles ${NUM_FILES} --dir ${TESTDIR_SINGLE} --filefmt 'f%%d'"
	echo "+ ${COMMAND}"
	mpi_run ${MACHINEFILE_OPTION} ${MACHINEFILE} -np 1 ${COMMAND} |
		tee ${LOG}

	if [ ${PIPESTATUS[0]} != 0 ]; then
		[ -f $LOG ] && sed -e "s/^/log: /" $LOG
		error_noexit "mdsrate create on single client failed, aborting"
		mdsrate_cleanup $NUM_CLIENTS $MACHINEFILE $NUM_FILES \
				$TESTDIR_SINGLE 'f%%d' --ignore
		exit 1
	fi

    log "===== $0 ### 1 NODE UNLINK ###"

    COMMAND="${MDSRATE} ${MDSRATE_DEBUG} --unlink
                --nfiles ${NUM_FILES} --dir ${TESTDIR_SINGLE} --filefmt 'f%%d'"
    echo "+ ${COMMAND}"
    mpi_run ${MACHINEFILE_OPTION} ${MACHINEFILE} -np 1 ${COMMAND} | tee ${LOG}

    if [ ${PIPESTATUS[0]} != 0 ]; then
	[ -f $LOG ] && sed -e "s/^/log: /" $LOG
	error "mdsrate unlink on a single client failed, aborting"
    fi

    rmdir $TESTDIR_SINGLE
fi

IFree=$(mdsrate_inodes_available)
if [ $IFree -lt $NUM_FILES ]; then
    NUM_FILES=$IFree
fi

[ $NUM_CLIENTS -eq 1 ] && NOMULTI=yes
if [ -n "$NOMULTI" ]; then
    echo "NO test for create on multiple nodes."
else
    mdsrate_cleanup $NUM_CLIENTS $MACHINEFILE $NUM_FILES $TESTDIR_MULTI 'f%%d' --ignore

    log "===== $0 ### $NUM_CLIENTS NODES CREATE ###"

	COMMAND="${MDSRATE} ${MDSRATE_DEBUG} --create --time ${TIME_PERIOD}
		--nfiles $NUM_FILES --dir ${TESTDIR_MULTI} --filefmt 'f%%d'"
	echo "+ ${COMMAND}"
	mpi_run ${MACHINEFILE_OPTION} ${MACHINEFILE} -np ${NUM_CLIENTS} \
		${COMMAND} | tee ${LOG}

	if [ ${PIPESTATUS[0]} != 0 ]; then
		[ -f $LOG ] && sed -e "s/^/log: /" $LOG
		error_noexit "mdsrate create on multiple nodes failed, aborting"
		mdsrate_cleanup $NUM_CLIENTS $MACHINEFILE $NUM_FILES \
				$TESTDIR_MULTI 'f%%d' --ignore
		exit 1
	fi

    log "===== $0 ### $NUM_CLIENTS NODES UNLINK ###"

	COMMAND="${MDSRATE} ${MDSRATE_DEBUG} --unlink
		--nfiles ${NUM_FILES} --dir ${TESTDIR_MULTI} --filefmt 'f%%d'"
	echo "+ ${COMMAND}"
	mpi_run ${MACHINEFILE_OPTION} ${MACHINEFILE} -np ${NUM_CLIENTS} \
		${COMMAND} | tee ${LOG}

    if [ ${PIPESTATUS[0]} != 0 ]; then
	[ -f $LOG ] && sed -e "s/^/log: /" $LOG
	error "mdsrate unlink on multiple nodes failed, aborting"
    fi

    rmdir $TESTDIR_MULTI
fi

rmdir $BASEDIR || true
rm -f $MACHINEFILE
check_and_cleanup_lustre
#rm -f $LOG

exit 0
