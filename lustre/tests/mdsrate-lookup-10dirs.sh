#!/bin/bash
#
# This test was used in a set of CMD3 tests (cmd3-5 test).

# Directory lookup retrieval rate 10 directories 1 million files each
# 6000 random lookups/sec per client node 62,000 random lookups/sec aggregate
#
# In 10 dirs containing 1 million files each the mdsrate Test Program will
# perform lookups for 10 minutes. This test is run from a single node for
# #1 and from all nodes for #2 aggregate test to measure lookup performance.
# TEst performs lookups across all 10 directories.

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
assert_env CLIENTS MDSRATE SINGLECLIENT MPIRUN

MACHINEFILE=${MACHINEFILE:-$TMP/$(basename $0 .sh).machines}
# Do not use name [df][0-9]* to avoid cleanup by rm, bug 18045
BASEDIR=$MOUNT/mdsrate

# Requirements
NUM_DIRS=${NUM_DIRS:-10}
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

IFree=$(($(mdsrate_inodes_available) - NUM_DIRS))
if [ $IFree -lt $((NUM_FILES * NUM_DIRS)) ]; then
    NUM_FILES=$((IFree / NUM_DIRS))
fi

generate_machine_file $NODES_TO_USE $MACHINEFILE || error "can not generate machinefile"

DIRfmt="${BASEDIR}/lookup-%d"

#
# Unlink the files created in the directories under $BASEDIR.
# FIXME: does it make sense to add the possibility to unlink dirfmt to mdsrate?
#
mdsrate_cleanup_all() {
	local i
	for i in $(seq 0 $NUM_DIRS); do
		mdsrate_cleanup $NUM_CLIENTS $MACHINEFILE $NUM_FILES \
				$BASEDIR/lookup-$i 'f%%d' --ignore
	done
}

if [ -n "$NOCREATE" ]; then
    echo "NOCREATE=$NOCREATE  => no file creation."
else
	mdsrate_cleanup_all

    log "===== $0 Test preparation: creating ${NUM_DIRS} dirs with ${NUM_FILES} files."

    COMMAND="${MDSRATE} ${MDSRATE_DEBUG} --mknod
                        --ndirs ${NUM_DIRS} --dirfmt '${DIRfmt}'
                        --nfiles ${NUM_FILES} --filefmt 'f%%d'"

	echo "+" ${COMMAND}
	# For files creation we can use -np equal to NUM_DIRS
	# This is just a test preparation, does not matter how many threads we
	# use for files creation; we just should be aware that NUM_DIRS is less
	# than or equal to the number of threads np
	mpi_run ${MACHINEFILE_OPTION} ${MACHINEFILE} -np ${NUM_DIRS} \
		${COMMAND} 2>&1

	# No lookup if error occurs on file creation, abort.
	if [ ${PIPESTATUS[0]} != 0 ]; then
		error_noexit "mdsrate file creation failed, aborting"
		mdsrate_cleanup_all
		exit 1
	fi
fi

COMMAND="${MDSRATE} ${MDSRATE_DEBUG} --lookup --time ${TIME_PERIOD} ${SEED_OPTION}
        --ndirs ${NUM_DIRS} --dirfmt '${DIRfmt}'
        --nfiles ${NUM_FILES} --filefmt 'f%%d'"

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
		mdsrate_cleanup_all
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
		mdsrate_cleanup_all
		exit 1
	fi
fi

complete $SECONDS
mdsrate_cleanup_all
rmdir $BASEDIR || true
rm -f $MACHINEFILE
check_and_cleanup_lustre
#rm -f $LOG

exit 0
