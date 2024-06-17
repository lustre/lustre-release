#!/bin/bash
#
# Was Test 11 in cmd3.
# For duration of 24 hours repeatedly failover a random MDS at
# 10 minute intervals and verify that no application errors occur.

# Test runs one of CLIENT_LOAD progs on remote clients.
set -e

ONLY=${ONLY:-"$*"}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env "$@"
init_logging
. $LUSTRE/tests/recovery-scale-lib.sh

# bug number for skipped test:
ALWAYS_EXCEPT="$RECOVERY_MDS_SCALE_EXCEPT "
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

build_test_filter

remote_mds_nodsh && skip_env "remote MDS with nodsh"

if (( CLIENTCOUNT < 3 )); then
	skip_env "need three or more clients"
fi

# SHARED_DIRECTORY should be specified with a shared directory which is
# accessable on all of the nodes
if [[ -z "$SHARED_DIRECTORY" ]] || ! check_shared_dir "$SHARED_DIRECTORY"; then
	skip_env "SHARED_DIRECTORY not set"
fi

ERRORS_OK=""    # No application failures should occur during this test.

check_and_setup_lustre
rm -rf $DIR/[Rdfs][0-9]*

insulate_clients
check_progs_installed $NODES_TO_USE "${CLIENT_LOADS[@]}"

MAX_RECOV_TIME=$(max_recovery_time)
MDTS=$(get_facets MDS)
OSTS=$(get_facets OST)

# Print informaiton about settings
run_info $SERVER_FAILOVER_PERIOD $DURATION $MINSLEEP $SLOW $REQFAIL \
	$SHARED_DIRECTORY $END_RUN_FILE $LOAD_PID_FILE $VMSTAT_PID_FILE \
	$CLIENTCOUNT $MDTS $OSTS

test_failover_mds() {
	# failover a random MDS
	failover_target MDS
}
run_test failover_mds "failover MDS"

zconf_mount $HOSTNAME $MOUNT || error "mount $MOUNT on $HOSTNAME failed"
client_up || error "start client on $HOSTNAME failed"

complete_test $SECONDS
check_and_cleanup_lustre
exit_status
