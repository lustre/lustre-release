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
		do_nodes $clients "DURATION=$DURATION MDSCOUNT=$MDSCOUNT \
				   LFS=$LFS $racer $rdir $NUM_RACER_THREADS" &
		pid=$!
		rpids="$rpids $pid"
	done

	echo racers pids: $rpids
	for pid in $rpids; do
		wait $pid
		rc=$?
		echo "pid=$pid rc=$rc"
		if [ $rc != 0 ]; then
		    rrc=$((rrc + 1))
		fi
	done

	return $rrc
}
run_test 1 "racer on clients: ${CLIENTS:-$(hostname)} DURATION=$DURATION"

complete $SECONDS
check_and_cleanup_lustre
exit_status
