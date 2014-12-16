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
init_logging

[ "$SLOW" = no ] && { nobjhi=1; thrhi=4; }
thrlo=${thrlo:-$(( thrhi / 2))}

# Skip these tests
# bug number   23791 23791
ALWAYS_EXCEPT="1b    2b    $OBDFILTER_SURVEY_EXCEPT"

OBDSURVEY=${OBDSURVEY:-$(which obdfilter-survey)}

build_test_filter
check_and_setup_lustre

# FIXME: the summary file a bit smaller than OSTSIZE, add estimation
minsize=$(min_ost_size)
if [ $(( size * 1024 )) -ge $minsize  ]; then
    size=$((minsize * 10 / 1024 / 12 ))
    echo min kbytesavail: $minsize using size=${size} MBytes per obd instance
fi

get_devs() {
        echo $(do_nodes $1 'lctl dl | grep obdfilter' | \
             awk '{print $4}' | sort -u)
}

get_targets () {
        local targets
        local devs
        local nid
        local oss

        for oss in $(osts_nodes); do
                devs=$(get_devs $oss)
                nid=$(host_nids_address $oss $NETTYPE)
                for d in $devs; do
                        # if oss is local -- obdfilter-survey needs dev wo/ host
                        target=$d
                        [[ $oss = `hostname` && "$1" == "disk" ]] || target=$nid:$target
                        targets="$targets $target"
                done
        done

	echo $targets
}

obdflter_survey_targets () {
	local case=$1
	local targets

	case $case in
		disk)    targets=$(get_targets $case);;
		netdisk) targets=$(get_targets $case);;
		network) targets=$(host_nids_address $(comma_list $(osts_nodes)) $NETTYPE);;
		*) error "unknown obdflter-survey case!" ;;
	esac
	echo $targets
}

obdflter_survey_run () {
	local case=$1

	rm -f ${TMP}/obdfilter_survey*

	local targets=$(obdflter_survey_targets $case)
	local cmd="NETTYPE=$NETTYPE thrlo=$thrlo nobjhi=$nobjhi thrhi=$thrhi size=$size case=$case rslt_loc=${TMP} targets=\"$targets\" $OBDSURVEY"
	echo + $cmd
	eval $cmd

	cat ${TMP}/obdfilter_survey*
}
test_1a () {
	obdflter_survey_run disk
}
run_test 1a "Object Storage Targets survey"

print_jbd () {
	local file=$1
	local facet=$2
	local varsvc=${facet}_svc
	local dev=$(ldiskfs_canon "*.${!varsvc}.mntdev" $facet)

	# ext4: /proc/fs/jbd2/sda1:8/history
	# ext3: /proc/fs/jbd/sdb1/history

	do_facet $facet cat /proc/fs/jbd*/${dev}*/$file
}

check_jbd_values () {
	local facet=$1
	local thrhi=$2
	local rtime=$3

	# last two lines from history
	# $4: run >= 5000
	# $8: hndls >= thrhi * 2
	# display history of rtime/4 before, in case obd cleanup consumes time
	local tlines=$((rtime / 5 / 4 + 1))
	local hist=("$(print_jbd history $facet | tail -$tlines | head -n1)")
	echo "$hist"
	local run=($(echo "${hist[*]}" | awk '{print $4}'))
	local hndls=($(echo "${hist[*]}" | awk '{print $8}'))

	local rc=0
	for (( i=0; i<1; i++)); do
		[[ ${run[i]} -lt 5000 ]] && \
			error "$facet: run expected 5000, have ${run[i]}" && rc=1
		[[ ${hndls[i]} -lt $((thrhi * 2)) ]] && \
			error "$facet: hndls expected > $((thrhi * 2)), have ${hndls[i]}" && rc=2
	done
	return $rc
}

check_jbd_values_facets () {
	local facets=$1
	local thrhi=$2
	local rtime=$3
	local facet
	local rc=0
	for facet in  ${facets//,/ }; do
		check_jbd_values $facet $thrhi $rtime || rc=$((rc+$?))
	done
	return $rc
}

test_1b () {
	local param_file=$TMP/$tfile-params

	do_nodesv $(comma_list $(osts_nodes)) \
		$LCTL get_param obdfilter.${FSNAME}-*.sync_journal
	save_lustre_params $(get_facets OST) \
		"obdfilter.${FSNAME}-*.sync_journal" > $param_file
	do_nodesv $(comma_list $(osts_nodes)) \
		$LCTL set_param obdfilter.${FSNAME}-*.sync_journal=0

	local stime=$(date +%s)
	thrlo=4 nobjhi=1 thrhi=4 obdflter_survey_run disk
	local etime=$(date +%s)
	# run time of obd survey
	local rtime=$((etime - stime))

	echo "obd survey finished in $rtime seconds"
	check_jbd_values_facets $(get_facets OST) 4 $rtime || rc=$((rc+$?))

	restore_lustre_params < $param_file

	rm -f $param_file
	return $rc
}
run_test 1b "Object Storage Targets survey, async journal"

test_1c () {
	nobjlo=1 nobjhi=1 thrlo=32 thrhi=32 rszlo=1024 rszhi=1024 size=8192\
	obdflter_survey_run disk
}
run_test 1c "Object Storage Targets survey, big batch"

test_2a () {
	obdflter_survey_run netdisk
}
run_test 2a "Stripe F/S over the Network"

test_2b () {
	local param_file=$TMP/$tfile-params

	do_nodesv $(comma_list $(osts_nodes)) \
		$LCTL get_param obdfilter.${FSNAME}-*.sync_journal
	save_lustre_params $(get_facets OST) \
		"obdfilter.${FSNAME}-*.sync_journal" > $param_file
	do_nodesv $(comma_list $(osts_nodes)) \
		$LCTL set_param obdfilter.${FSNAME}-*.sync_journal=0

	local stime=$(date +%s)
	thrlo=4 nobjhi=1 thrhi=4 obdflter_survey_run netdisk
	local etime=$(date +%s)
	local rtime=$((etime - stime))

	echo "obd survey finished in $rtime seconds"
	check_jbd_values_facets $(get_facets OST) 4 $rtime || rc=$((rc+$?))

	restore_lustre_params < $param_file

	rm -f $param_file
	return $rc
}
run_test 2b "Stripe F/S over the Network, async journal"


# README.obdfilter-survey: In network test only automated run is supported.
test_3a () {
	remote_servers || { skip "Local servers" && return 0; }

	# The Network survey test needs:
	# Start lctl and check for the device list. The device list must be empty.
	cleanupall

	obdflter_survey_run network

	setupall
}
run_test 3a "Network survey"

complete $SECONDS
cleanup_echo_devs
check_and_cleanup_lustre
exit_status
