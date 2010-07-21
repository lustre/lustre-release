#!/bin/bash
#set -x
set -e

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@

nobjhi=${nobjhi:-1}
thrhi=${thrhi:-16}
size=${size:-1024}

# the summary file a bit smaller than OSTSIZE
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

[ "$SLOW" = no ] && { nobjhi=1; thrhi=4; }

# Skip these tests
ALWAYS_EXCEPT="$OBDFILTER_SURVEY_EXCEPT"

OBDSURVEY=${OBDSURVEY:-$(which obdfilter-survey)}

build_test_filter
check_and_setup_lustre

min_ost_size () {
    $LCTL get_param -n osc.*.kbytesavail | sort -n | head -n1
}

# FIXME: the summary file a bit smaller than OSTSIZE, add estimation
minsize=$(min_ost_size)
if [ $(( size * 1024 )) -ge $minsize  ]; then
    size=$((minsize * 10 / 1024 / 12 ))
    echo min kbytesavail: $minsize using size=${size} MBytes per obd instance
fi

get_targets () {
        local targets
        local devs
        local oss

        for oss in $(osts_nodes); do
                devs=$(do_node $oss "lctl dl |grep obdfilter |sort" | awk '{print $4}')
                for d in $devs; do
                        # if oss is local -- obdfilter-survey needs dev wo/ host
                        target=$d
                        [[ $oss = `hostname` ]] || target=$oss:$target
                        targets="$targets $target"
                done
        done

	echo $targets
}

test_1 () {
	rm -f ${TMP}/obdfilter_survey*

	local targets=$(get_targets)
	local cmd="nobjhi=$nobjhi thrhi=$thrhi size=$size case=disk rslt_loc=${TMP} targets=\"$targets\" sh $OBDSURVEY"
	echo + $cmd
	eval $cmd

	cat ${TMP}/obdfilter_survey*
}
run_test 1 "Object Storage Targets survey"

test_2 () {
	rm -f ${TMP}/obdfilter_survey*

	local targets=$(get_targets)
	local cmd="nobjhi=$nobjhi thrhi=$thrhi size=$size rslt_loc=${TMP} case=netdisk targets=\"$targets\" sh $OBDSURVEY"
	echo + $cmd
	eval $cmd

	cat ${TMP}/obdfilter_survey*
}
run_test 2 "Stripe F/S over the Network"

# README.obdfilter-survey: In network test only automated run is supported.
test_3 () {
	remote_servers || { skip "Local servers" && return 0; }


	rm -f ${TMP}/obdfilter_survey*
	# The Network survey test needs:
	# Start lctl and check for the device list. The device list must be empty.
	cleanupall

	local cmd="nobjhi=2 thrhi=4 size=$size targets="$(osts_nodes)" case=network sh $OBDSURVEY"
	echo + $cmd
	eval $cmd

	cat ${TMP}/obdfilter_survey*
	setupall
}
run_test 3 "Network survey"

equals_msg `basename $0`: test complete, cleaning up
cleanup_echo_devs
check_and_cleanup_lustre
[ -f "$TESTSUITELOG" ] && cat $TESTSUITELOG || true
