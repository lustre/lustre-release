#!/bin/bash
set -e

ONLY=${ONLY:-"$*"}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
init_logging

build_test_filter

racer=$LUSTRE/tests/racer/racer.sh
echo racer: $racer with $MDSCOUNT MDTs

if [ "$SLOW" = "no" ]; then
	DURATION=${DURATION:-300}
else
	DURATION=${DURATION:-900}
fi
MOUNT_2=${MOUNT_2:-"yes"}

check_and_setup_lustre

CLIENTS=${CLIENTS:-$HOSTNAME}
RACERDIRS=${RACERDIRS:-"$DIR $DIR2"}
echo RACERDIRS=$RACERDIRS

RACER_FAILOVER=${RACER_FAILOVER:-false}
FAIL_TARGETS=${FAIL_TARGETS:-"MDS OST"}
RACER_FAILOVER_PERIOD=${RACER_FAILOVER_PERIOD:-60}

if $RACER_FAILOVER; then
	declare -a  victims
	for target in $FAIL_TARGETS; do
		victims=(${victims[@]} $(get_facets $target))
	done
	echo Victim facets ${victims[@]}
fi

#LU-4684
RACER_ENABLE_MIGRATION=false

if ((MDSCOUNT > 1 && "$MDS1_VERSION" >= $(version_code 2.8.0))); then
	RACER_ENABLE_REMOTE_DIRS=${RACER_ENABLE_REMOTE_DIRS:-true}
	RACER_ENABLE_STRIPED_DIRS=${RACER_ENABLE_STRIPED_DIRS:-true}
	RACER_ENABLE_MIGRATION=${RACER_ENABLE_MIGRATION:-true}
elif ((MDSCOUNT > 1 && "$MDS1_VERSION" >= $(version_code 2.5.0))); then
	RACER_ENABLE_REMOTE_DIRS=${RACER_ENABLE_REMOTE_DIRS:-true}
fi

[[ "$MDS1_VERSION" -lt $(version_code 2.9.54) ||
   $(facet_fstype mgs) != zfs ]] && RACER_ENABLE_SNAPSHOT=false

[[ "$MDS1_VERSION" -le $(version_code 2.9.55) ]] &&
	RACER_ENABLE_PFL=false

[[ "$MDS1_VERSION" -le $(version_code 2.10.53) ]] &&
	RACER_ENABLE_DOM=false

[[ "$MDS1_VERSION" -lt $(version_code 2.10.55) ]] &&
	RACER_ENABLE_FLR=false

[[ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.12.0) ]] &&
	RACER_ENABLE_SEL=false

RACER_ENABLE_REMOTE_DIRS=${RACER_ENABLE_REMOTE_DIRS:-false}
RACER_ENABLE_STRIPED_DIRS=${RACER_ENABLE_STRIPED_DIRS:-false}
RACER_ENABLE_MIGRATION=${RACER_ENABLE_MIGRATION:-false}
RACER_ENABLE_SNAPSHOT=${RACER_ENABLE_SNAPSHOT:-true}
RACER_ENABLE_PFL=${RACER_ENABLE_PFL:-true}
RACER_ENABLE_DOM=${RACER_ENABLE_DOM:-true}
RACER_ENABLE_FLR=${RACER_ENABLE_FLR:-true}
RACER_ENABLE_SEL=${RACER_ENABLE_SEL:-true}

fail_random_facet () {
	local facets=${victims[@]}
	facets=${facets// /,}

	sleep $RACER_FAILOVER_PERIOD
	while [ ! -f $racer_done ]; do
		local facet=$(get_random_entry $facets)
		facet_failover $facet
		sleep $RACER_FAILOVER_PERIOD
	done
}

# run racer
test_1() {
	local rrc=0
	local rc=0
	local clients=$CLIENTS
	local RDIRS
	local i
	local racer_done=$TMP/racer_done

	rm -f $racer_done

	for d in ${RACERDIRS}; do
		is_mounted $d || continue

		RDIRS="$RDIRS $d/racer"
		mkdir -p $d/racer
	#	lfs setstripe $d/racer -c -1
		if [ $MDSCOUNT -ge 2 ]; then
			for i in $(seq $((MDSCOUNT - 1))); do
				RDIRS="$RDIRS $d/racer$i"
				if [ ! -e $d/racer$i ]; then
					$LFS mkdir -i $i $d/racer$i ||
						error "lfs mkdir $i failed"
				fi
			done
		fi
	done

	local rpids=""
	for rdir in $RDIRS; do
		do_nodes $clients "DURATION=$DURATION \
			MDSCOUNT=$MDSCOUNT OSTCOUNT=$OSTCOUNT\
			RACER_ENABLE_REMOTE_DIRS=$RACER_ENABLE_REMOTE_DIRS \
			RACER_ENABLE_STRIPED_DIRS=$RACER_ENABLE_STRIPED_DIRS \
			RACER_ENABLE_MIGRATION=$RACER_ENABLE_MIGRATION \
			RACER_ENABLE_PFL=$RACER_ENABLE_PFL \
			RACER_ENABLE_DOM=$RACER_ENABLE_DOM \
			RACER_ENABLE_FLR=$RACER_ENABLE_FLR \
			RACER_MAX_CLEANUP_WAIT=$RACER_MAX_CLEANUP_WAIT \
			RACER_ENABLE_SEL=$RACER_ENABLE_SEL \
			RACER_EXTRA=$RACER_EXTRA \
			LFS=$LFS \
			LCTL=$LCTL \
			$racer $rdir $NUM_RACER_THREADS" &
		pid=$!
		rpids="$rpids $pid"
	done

	local failpid=""
	if $RACER_FAILOVER; then
		fail_random_facet &
		failpid=$!
		echo racers failpid: $failpid
	fi

	local lss_pids=""
	if $RACER_ENABLE_SNAPSHOT; then
		lss_gen_conf

		$LUSTRE/tests/racer/lss_create.sh &
		pid=$!
		lss_pids="$lss_pids $pid"

		$LUSTRE/tests/racer/lss_destroy.sh &
		pid=$!
		lss_pids="$lss_pids $pid"
	fi

	echo racers pids: $rpids
	for pid in $rpids; do
		wait $pid
		rc=$?
		echo "pid=$pid rc=$rc"
		if [ $rc != 0 ]; then
		    rrc=$((rrc + 1))
		fi
	done

	if $RACER_FAILOVER; then
		touch $racer_done
		wait $failpid
		rrc=$((rrc + $?))
	fi

	if $RACER_ENABLE_SNAPSHOT; then
		killall -q lss_create.sh
		killall -q lss_destroy.sh

		for pid in $lss_pids; do
			wait $pid
		done

		lss_cleanup
	fi

	return $rrc
}
run_test 1 "racer on clients: ${CLIENTS:-$(hostname)} DURATION=$DURATION"

complete $SECONDS
check_and_cleanup_lustre
exit_status
