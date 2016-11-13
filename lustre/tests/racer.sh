#!/bin/bash
#set -vx
set -e

ONLY=${ONLY:-"$*"}
LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

racer=$LUSTRE/tests/racer/racer.sh
echo racer: $racer with $MDSCOUNT MDTs

if [ "$SLOW" = "no" ]; then
    DURATION=${DURATION:-300}
else
    DURATION=${DURATION:-900}
fi
MOUNT_2=${MOUNT_2:-"yes"}

build_test_filter
check_and_setup_lustre

CLIENTS=${CLIENTS:-$HOSTNAME}
RACERDIRS=${RACERDIRS:-"$DIR $DIR2"}
echo RACERDIRS=$RACERDIRS

if ((MDSCOUNT > 1 &&
     $(lustre_version_code $SINGLEMDS) >= $(version_code 2.8.0))); then
	RACER_ENABLE_REMOTE_DIRS=${RACER_ENABLE_REMOTE_DIRS:-true}
	RACER_ENABLE_STRIPED_DIRS=${RACER_ENABLE_STRIPED_DIRS:-true}
	RACER_ENABLE_MIGRATION=${RACER_ENABLE_MIGRATION:-true}
elif ((MDSCOUNT > 1 &&
       $(lustre_version_code $SINGLEMDS) >= $(version_code 2.5.0))); then
	RACER_ENABLE_REMOTE_DIRS=${RACER_ENABLE_REMOTE_DIRS:-true}
fi

[[ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.9.54) ||
   $(facet_fstype mgs) != zfs ]] && RACER_ENABLE_SNAPSHOT=false

RACER_ENABLE_REMOTE_DIRS=${RACER_ENABLE_REMOTE_DIRS:-false}
RACER_ENABLE_STRIPED_DIRS=${RACER_ENABLE_STRIPED_DIRS:-false}
RACER_ENABLE_MIGRATION=${RACER_ENABLE_MIGRATION:-false}
RACER_ENABLE_SNAPSHOT=${RACER_ENABLE_SNAPSHOT:-true}

check_progs_installed $CLIENTS $racer ||
	{ skip_env "$racer not found" && exit 0; }

# run racer
test_1() {
	local rrc=0
	local rc=0
	local clients=$CLIENTS
	local RDIRS
	local i

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
			MDSCOUNT=$MDSCOUNT \
			RACER_ENABLE_REMOTE_DIRS=$RACER_ENABLE_REMOTE_DIRS \
			RACER_ENABLE_STRIPED_DIRS=$RACER_ENABLE_STRIPED_DIRS \
			RACER_ENABLE_MIGRATION=$RACER_ENABLE_MIGRATION \
			LFS=$LFS \
			$racer $rdir $NUM_RACER_THREADS" &
		pid=$!
		rpids="$rpids $pid"
	done

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
