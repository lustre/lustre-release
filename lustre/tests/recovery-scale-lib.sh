#!/bin/bash

# global variables and functions used by:
# recovery-mds-scale, recovery-oss-scale and recovery-random-scale

if [[ "$SLOW" == "no" ]]; then
	DURATION=${DURATION:-$((60 * 30))}
else
	DURATION=${DURATION:-$((60 * 60 * 24))}
fi

SERVER_FAILOVER_PERIOD=${SERVER_FAILOVER_PERIOD:-$((60 * 10))} # 10 minutes
MINSLEEP=${MINSLEEP:-120}
REQFAIL_PERCENT=${REQFAIL_PERCENT:-3}    # bug17839 comment 62
# round up the result of integer division: C=(A + (B - 1)) / B
REQFAIL=${REQFAIL:-$(((DURATION * REQFAIL_PERCENT + (SERVER_FAILOVER_PERIOD *
	100 - 1 )) / SERVER_FAILOVER_PERIOD / 100))}

END_RUN_FILE=${END_RUN_FILE:-$SHARED_DIRECTORY/end_run_file}
LOAD_PID_FILE=${LOAD_PID_FILE:-$TMP/client-load.pid}
VMSTAT_PID_FILE=${VMSTAT_PID_FILE:-$TMP/vmstat.pid}

NODES_TO_USE=${NODES_TO_USE:-$CLIENTS}

# The test node needs to be insulated from a Lustre failure as much as
# possible. Not even loading the lustre modules is ideal.
# -- umount lustre
# -- remove hostname from clients list
insulate_clients() {
	zconf_umount $HOSTNAME $MOUNT
	NODES_TO_USE=$(exclude_items_from_list $NODES_TO_USE $HOSTNAME)
}

run_info() {
	local oput=echo

	$oput "******* Run Information *******"
	$oput "SERVER_FAILOVER_PERIOD:$1"
	$oput "DURATION:$2"
	$oput "MINSLEEP:$3"
	$oput "SLOW:$4"
	$oput "REQFAIL:$5"
	$oput "SHARED_DIRECTORY:$6"
	$oput "END_RUN_FILE:$7"
	$oput "LOAD_PID_FILE:$8"
	$oput "VMSTAT_PID_FILE:$9"
	$oput "CLIENTCOUNT:${10}"
	$oput "MDTS:${11}"
	$oput "OSTS:${12}"
	$oput "*******************************"
}

server_numfailovers () {
	local facet="$1"
	local var="${facet}_numfailovers"
	local val=0

	if [[ -n "${!var}" ]]; then
		val="${!var}"
	fi

	echo "$val"
}

servers_numfailovers () {
	local facet
	local var

	for facet in ${MDTS//,/ } ${OSTS//,/ }; do
		echo "$facet: $(server_numfailovers $facet) times"
	done
}

summary_and_cleanup () {
	local rc=$?
	local result=PASS

	# Having not empty END_RUN_FILE means the failed loads only
	if [[ -s "$END_RUN_FILE" ]]; then
		print_end_run_file "$END_RUN_FILE"
		rc=1
	fi

	echo $(date +'%F %H:%M:%S') Terminating clients loads ...
	echo "$0" >> "$END_RUN_FILE"

	if (( rc != 0 )); then
		result=FAIL
	fi

	log "Duration:               $DURATION seconds"
	log "Server failover period: $SERVER_FAILOVER_PERIOD seconds"
	log "Exited after:           $ELAPSED seconds"
	log "Number of failovers before exit: $(servers_numfailovers)"
	log "Status: $result"
	log "Return code: $rc"

	# stop vmstat on OSS nodes
	if [[ -n "$VMSTAT" ]]; then
		stop_process $(comma_list $(osts_nodes)) "$VMSTAT_PID_FILE"
	fi

	# stop the client loads
	stop_client_loads $NODES_TO_USE $LOAD_PID_FILE

	if (( rc != 0 )); then
		# we are interested in only on failed clients and servers
		local failedclients=$(cat $END_RUN_FILE | grep -v $0)

		gather_logs $(comma_list $(all_server_nodes) $failedclients)
	fi

	exit $rc
}

failover_target() {
	local servers
	local serverfacet
	local var
	local flavor=${1:-"MDS"}

	if [[ "$flavor" == "MDS" ]]; then
		servers=$MDTS
	else
		servers=$OSTS
	fi

	stack_trap summary_and_cleanup EXIT INT

	# start vmstat on OSS nodes
	if [[ -n "$VMSTAT" ]]; then
		start_vmstat $(comma_list $(osts_nodes)) "$VMSTAT_PID_FILE"
	fi

	# start client loads
	rm -f "$END_RUN_FILE"
	start_client_loads $NODES_TO_USE

	echo client loads pids:
	do_nodesv $NODES_TO_USE "cat $LOAD_PID_FILE" || exit 3

	ELAPSED=0
	local sleep=0
	local reqfail=0
	local it_time_start=0
	local start_ts=$(date +%s)
	local current_ts=$start_ts

	while (( ELAPSED < DURATION )) && [[ ! -e "$END_RUN_FILE" ]]; do
		# In order to perform the
		# expected number of failovers, we need to account the
		# following:
		# 1) the time that has elapsed during the client load checking
		# 2) time takes for failover
		it_time_start=$(date +%s)

		serverfacet=$(get_random_entry $servers)
		var=${serverfacet}_numfailovers

		# Check that our client loads are still running. If any have
		# died, that means they have died outside of recovery, which
		# is unacceptable.
		log "==== Check clients loads BEFORE failover: failure NOT OK \
		     ELAPSED=$ELAPSED DURATION=$DURATION \
		     PERIOD=$SERVER_FAILOVER_PERIOD"
		check_client_loads $NODES_TO_USE || exit 4

		log "Wait $serverfacet recovery complete before next failover"
		if ! wait_recovery_complete $serverfacet; then
		    echo "$serverfacet recovery is not completed!"
		    exit 7
		fi

		log "Checking clients are in FULL or IDLE state before next \
		     failover"
		wait_clients_import_ready $NODES_TO_USE $serverfacet ||
			echo "Client import is not ready, please consider" \
			     "to increase SERVER_FAILOVER_PERIOD =" \
			     "$SERVER_FAILOVER_PERIOD!"

		log "Starting failover on $serverfacet"
		facet_failover "$serverfacet" || exit 1

		# Check that our client loads are still running during failover.
		# No application failures should occur.
		log "==== Check clients loads AFTER failover: failure NOT OK"
		if ! check_client_loads $NODES_TO_USE; then
			log "Client load failed during failover. Exiting..."
			exit 5
		fi

		# Increment the number of failovers.
		val=$((${!var} + 1))
		eval $var=$val

		current_ts=$(date +%s)
		ELAPSED=$((current_ts - start_ts))

		sleep=$((SERVER_FAILOVER_PERIOD - (current_ts - it_time_start)))

		# Keep counting the number of iterations when
		# time spent to failover and two client loads check exceeded
		# the value ( SERVER_FAILOVER_PERIOD - MINSLEEP ).
		if (( sleep < MINSLEEP )); then
			reqfail=$((reqfail + 1))

			cat <<- END_WARN
			WARNING: failover and two check_client_loads time
			exceeded: SERVER_FAILOVER_PERIOD - MINSLEEP!

			Failed loading I/O for a min period of $MINSLEEP
			$reqfail times (REQFAIL=$REQFAIL).

			This iteration, load only applied for sleep $sleep
			seconds.

			Estimated max recovery time: $MAX_RECOV_TIME
			Probably hardware is taking excessively long time
			to boot.

			Try increasing SERVER_FAILOVER_PERIOD
			(current is $SERVER_FAILOVER_PERIOD), bug 20918.
			END_WARN

			if (( reqfail > REQFAIL )); then
				exit 6
			fi
		fi

		log "$serverfacet failed over ${!var} times, and counting..."

		if (( (ELAPSED + sleep) >= DURATION )); then
			break
		fi

		if (( sleep > 0 )); then
			echo "sleeping $sleep seconds... "
			sleep $sleep
		fi
	done

	exit 0
}
