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

MACHINEFILE=${MACHINEFILE:-$TMP/$(basename $0 .sh).machines}
# Do not use name [df][0-9]* to avoid cleanup by rm, bug 18045
BASEDIR=$MOUNT/mdsrate
TESTDIR=$BASEDIR/lookup

# Requirements
NUM_FILES=${NUM_FILES:-1000000}
TIME_PERIOD=${TIME_PERIOD:-600}                        # seconds

LOG=${TESTSUITELOG:-$TMP/$(basename $0 .sh).log}
CLIENT=$SINGLECLIENT
NODES_TO_USE=${NODES_TO_USE:-$CLIENTS}
NUM_CLIENTS=$(get_node_count ${NODES_TO_USE//,/ })

rm -f $LOG

[ ! -x ${MDSRATE} ] && error "${MDSRATE} not built."

log "===== $0 ====== "

check_and_setup_lustre

mkdir -p $BASEDIR
chmod 0777 $BASEDIR
$LFS setstripe $BASEDIR -c 1
get_stripe $BASEDIR

IFree=$(mdsrate_inodes_available)
if [ $IFree -lt $NUM_FILES ]; then
    NUM_FILES=$IFree
fi

generate_machine_file $NODES_TO_USE $MACHINEFILE || error "can not generate machinefile"

if [ -n "$NOCREATE" ]; then
    echo "NOCREATE=$NOCREATE  => no file creation."
else
    mdsrate_cleanup $NUM_CLIENTS $MACHINEFILE $NUM_FILES $TESTDIR 'f%%d' --ignore

    log "===== $0 Test preparation: creating ${NUM_FILES} files."

    NUM_CLIENTS=$(get_node_count ${NODES_TO_USE//,/ })
    NUM_THREADS=$((NUM_CLIENTS * MDSCOUNT))
    if [ $NUM_CLIENTS -gt 50 ]; then
        NUM_THREADS=$NUM_CLIENTS
    fi
    COMMAND="${MDSRATE} ${MDSRATE_DEBUG} --mknod --dir ${TESTDIR}
                        --nfiles ${NUM_FILES} --filefmt 'f%%d'"
	echo "+" ${COMMAND}
	mpi_run ${MACHINEFILE_OPTION} ${MACHINEFILE} -np ${NUM_THREADS} \
		${COMMAND} 2>&1

	# No lockup if error occurs on file creation, abort.
	if [ ${PIPESTATUS[0]} != 0 ]; then
		error_noexit "mdsrate file creation failed, aborting"
		mdsrate_cleanup $NUM_THREADS $MACHINEFILE $NUM_FILES \
				$TESTDIR 'f%%d' --ignore
		exit 1
	fi
fi

COMMAND="${MDSRATE} ${MDSRATE_DEBUG} --lookup --time ${TIME_PERIOD} ${SEED_OPTION}
        --dir ${TESTDIR} --nfiles ${NUM_FILES} --filefmt 'f%%d'"

# 1
if [ -n "$NOSINGLE" ]; then
    echo "NO Test for lookups on a single client."
else
	log "===== $0 ### 1 NODE LOOKUPS ###"
	echo "+" ${COMMAND}
	mpi_run ${MACHINEFILE_OPTION} ${MACHINEFILE} -np 1 ${COMMAND} |
		tee ${LOG}

	if [ ${PIPESTATUS[0]} != 0 ]; then
		[ -f $LOG ] && sed -e "s/^/log: /" $LOG
		error_noexit "mdsrate lookup on single client failed, aborting"
		mdsrate_cleanup $NUM_CLIENTS $MACHINEFILE $NUM_FILES \
				$TESTDIR 'f%%d' --ignore
		exit 1
	fi
fi

# 2
[ $NUM_CLIENTS -eq 1 ] && NOMULTI=yes
if [ -n "$NOMULTI" ]; then
    echo "NO test for lookups on multiple nodes."
else
	log "===== $0 ### ${NUM_CLIENTS} NODES LOOKUPS ###"
	echo "+" ${COMMAND}
	mpi_run ${MACHINEFILE_OPTION} ${MACHINEFILE} -np ${NUM_CLIENTS} \
		${COMMAND} | tee ${LOG}

	if [ ${PIPESTATUS[0]} != 0 ]; then
		[ -f $LOG ] && sed -e "s/^/log: /" $LOG
		error_noexit "mdsrate lookup on multiple nodes failed, aborting"
		mdsrate_cleanup $NUM_CLIENTS $MACHINEFILE $NUM_FILES \
				$TESTDIR 'f%%d' --ignore
		exit 1
	fi
fi

complete $SECONDS
mdsrate_cleanup $NUM_CLIENTS $MACHINEFILE $NUM_FILES $TESTDIR 'f%%d'
rmdir $BASEDIR || true
rm -f $MACHINEFILE
check_and_cleanup_lustre
#rm -f $LOG

exit 0
