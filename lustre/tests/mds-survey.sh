#!/bin/bash
#set -x
set -e

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

build_test_filter
check_and_setup_lustre

file_count=${file_count:-100000}
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

# check for available inode, reduce to fit
inode_per_thr=$((dir_count * file_count))
require_inode=$((inode_per_thr * thrhi * 11/10))
avail_inode=$($LFS df -i $MOUNT | grep "filesystem summary:"  | \
    awk '{print $5}')

while [ $require_inode -ge $avail_inode  ]; do
    echo "Require $require_inode inode to run, only have $avail_inode"
    # reduce 20%
    file_count=$((file_count * 8 / 10))
    inode_per_thr=$((dir_count * file_count))
    require_inode=$((inode_per_thr * thrhi * 11 / 10))
done

if [ $require_inode -eq 0 ]; then
    skip_env "Not enough inode to run" && exit
fi

ost_count=$($LCTL dl | grep -c osc)

# first unmount all the lustre clients
cleanup_mount $MOUNT
cleanup_mount $MOUNT2

get_target() {
    local mds=$(facet_host $SINGLEMDS)
    echo $(do_nodes $mds 'lctl dl' | \
        awk "{if (\$2 == \"UP\" && \$3 == \"mdt\") {print \$4}}")
}

mds_survey_run() {
    local layer=${1:-mdd}
    local stripe_count=${2:-0}
    local mds=$(facet_host $SINGLEMDS)

    rm -f ${TMP}/mds_survey*

    local target=$(get_target)
    local cmd1="file_count=$file_count thrlo=$thrlo thrhi=$thrhi"
    local cmd2="dir_count=$dir_count layer=$layer stripe_count=$stripe_count"
    local cmd3="rslt_loc=${TMP} targets=\"$mds:$target\" $MDSSURVEY"
    local cmd="$cmd1 $cmd2 $cmd3"

    echo + $cmd
    eval $cmd || error "mds-survey failed"
    cat ${TMP}/mds_survey*
    rm -f ${TMP}/mds_survey*
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

complete $(basename $0) $SECONDS
cleanup_echo_devs
check_and_cleanup_lustre
exit_status
