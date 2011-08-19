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
echo racer: $racer

DURATION=${DURATION:-900}
[ "$SLOW" = "no" ] && DURATION=300
MOUNT_2=${MOUNT_2:-"yes"}

build_test_filter
check_and_setup_lustre

CLIENTS=${CLIENTS:-$HOSTNAME}
RACERDIRS=${RACERDIRS:-"$DIR $DIR2"}
echo RACERDIRS=$RACERDIRS
for d in ${RACERDIRS}; do
        is_mounted $d || continue

	RDIRS="$RDIRS $d/racer"
	mkdir -p $d/racer
#	lfs setstripe $d/racer -c -1
done

# run racer
test_1() {
    local rrc=0
    local rc=0
    local clients=${CLIENTS:-$(hostname)}

    check_progs_installed $clients $racer || \
        { skip_env "$racer not found" && return 0; }

    local rpids=""
    for rdir in $RDIRS; do
        do_nodes $clients "DURATION=$DURATION $racer $rdir $NUM_RACER_THREADS" &
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

complete $(basename $0) $SECONDS
check_and_cleanup_lustre
exit_status
