#!/bin/bash
#set -x
set -e

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

file_count=${file_count:-150000}
dir_count=${dir_count:-4}
thrhi=${thrhi:-8}
thrlo=${thrlo:-1}

[ "$SLOW" = no ] && { file_count=50000; dir_count=2; thrhi=4; }

# Skip these tests
ALWAYS_EXCEPT="$MDS_SURVEY_EXCEPT"

MDSSURVEY=${MDSSURVEY:-$(which mds-survey 2>/dev/null || true)}
if [ -z ${MDSSURVEY} ]; then
    skip_env "mds-survey not found" && exit
fi

if [ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.3.51) ]; then
	skip_env "Need MDS version at least 2.3.51" && exit
fi

build_test_filter
check_and_setup_lustre

adjust_inode() {
    local require_inode=0
    local avail_mdt_inode=0
    local avail_ost_inode=0

    require_inode=$((file_count * thrhi))
    # get available inode for mdt
    avail_mdt_inode=$(mdt_free_inodes 0)
    avail_mdt_inode=$((avail_mdt_inode * 9 / 10))

    # get available inode for ost
    for i in $($LFS df -i | grep ${FSNAME}-OST | awk '{print $4}'); do
        avail_ost_inode=$((avail_ost_inode + i))
    done
    avail_ost_inode=$((avail_ost_inode * 9 / 10))

    ((require_inode > avail_mdt_inode)) && require_inode=$avail_mdt_inode
    ((require_inode > avail_ost_inode)) && require_inode=$avail_ost_inode

    if ((require_inode == 0)); then
        error "Fail to get the inode count"
    fi
    # convert it back to per thread inode
    require_inode=$((require_inode / thrhi))

    echo $require_inode
}


file_count=$(adjust_inode)
ost_count=$($LCTL dl | grep -c osc)

# first unmount all the lustre clients
cleanup_mount $MOUNT
cleanup_mount $MOUNT2

get_target() {
	local node=$1
	local mdt
	local mdts
	local target

	mdts=$(do_node $node "$LCTL dl" |
	       awk "{if (\$2 == \"UP\" && \$3 == \"mdt\") {print \$4}}")

	for mdt in $mdts; do
		target+="${target:+ }$node:$mdt"
	done

	echo -n $target
}

get_targets() {
	local targets
	local node

	for node in $(mdts_nodes); do
		targets+="${targets:+ }$(get_target $node)"
	done

	echo -n $targets
}

mds_survey_run() {
	local layer=${1:-mdd}
	local stripe_count=${2:-0}
	local rc=0

	rm -f ${TMP}/mds_survey*

	local cmd="file_count=$file_count thrlo=$thrlo thrhi=$thrhi"
	cmd+=" dir_count=$dir_count layer=$layer stripe_count=$stripe_count"
	cmd+=" rslt_loc=${TMP} targets=\"$(get_targets)\" $MDSSURVEY"

	trap cleanup_echo_devs EXIT ERR

	echo + $cmd
	eval $cmd || rc=$?
	cat ${TMP}/mds_survey*
	rm -f ${TMP}/mds_survey*
	((rc == 0)) || error "mds-survey failed"
}

test_1() {
    mds_survey_run "mdd" "0"
}
run_test 1 "Metadata survey with zero-stripe"

test_2() {
    if [ $ost_count -eq 0 ]; then
        skip_env "Need to mount OST to test" && return
    fi
    mds_survey_run "mdd" "1"
}
run_test 2 "Metadata survey with stripe_count = 1"

# remount the clients
restore_mount $MOUNT

complete $SECONDS
cleanup_echo_devs
check_and_cleanup_lustre
exit_status
