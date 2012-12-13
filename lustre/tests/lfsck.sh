#!/bin/bash
#
# test e2fsck and lfsck to detect and fix filesystem corruption
#
#set -vx
set -e

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

NUMFILES=${NUMFILES:-10}
NUMDIRS=${NUMDIRS:-4}
OSTIDX=${OSTIDX:-0} # the OST index in LOV
OBJGRP=${OBJGRP:-0} # the OST object group

[ -d "$SHARED_DIRECTORY" ] || \
    { skip "SHARED_DIRECTORY should be specified with a shared directory \
which can be accessable on all of the nodes" && exit 0; }

which getfattr &>/dev/null || { skip_env "could not find getfattr" && exit 0; }
which setfattr &>/dev/null || { skip_env "could not find setfattr" && exit 0; }

if [ ! -x `which $LFSCK_BIN` ]; then
    log "$($E2FSCK -V)"
    error "e2fsprogs does not support lfsck"
fi

MOUNT_2=""
check_and_setup_lustre

assert_DIR

SAMPLE_FILE=$TMP/$(basename $0 .sh).junk
dd if=/dev/urandom of=$SAMPLE_FILE bs=1M count=1

# Create some dirs and files on the filesystem.
create_files_sub() {
    local test_dir=$1
    local num_dirs=$2
    local file_name=$3
    local first_num=$4
    local last_num=$5
    local d e f

    for d in $(seq -f d%g $first_num $last_num); do
        echo "creating files in $test_dir/$d"
        for e in $(seq -f d%g $num_dirs); do
            mkdir -p $test_dir/$d/$e || error "mkdir $test_dir/$d/$e failed"
            for f in $(seq -f test%g $num_dirs); do
                cp $file_name $test_dir/$d/$e/$f || \
                    error "cp $file_name $test_dir/$d/$e/$f failed"
            done
        done
    done
}

create_files() {
    local test_dir=$1
    local num_dirs=$2
    local num_files=$3
    local f

    # create some files on the filesystem
    local first_num=1
    local last_num=$num_dirs
    create_files_sub $test_dir $num_dirs /etc/fstab $first_num $last_num

    # create files to be modified
    for f in $(seq -f $test_dir/testfile.%g $((num_files * 3))); do
        echo "creating $f"
        cp $SAMPLE_FILE $f || error "cp $SAMPLE_FILE $f failed"
    done

    # create some more files
    first_num=$((num_dirs * 2 + 1))
    last_num=$((num_dirs * 2 + 3))
    create_files_sub $test_dir $num_dirs /etc/hosts $first_num $last_num

    # these should NOT be taken as duplicates
    for f in $(seq -f $test_dir/d$last_num/linkfile.%g $num_files); do
        echo "linking files in $test_dir/d$last_num"
        cp /etc/hosts $f || error "cp /etc/hosts $f failed"
        ln $f $f.link || error "ln $f $f.link failed"
    done
}

# Get the objids for files on the OST (given the OST index and object group).
get_objects() {
    local obdidx=$1
    shift
    local group=$1
    shift
    local ost_files="$@"
    local ost_objids
    ost_objids=$($LFS getstripe $ost_files | \
                awk '{if ($1 == '$obdidx' && $4 == '$group') print $2 }')
    echo $ost_objids
}

# Get the OST nodet name (given the OST index).
get_ost_node() {
    local obdidx=$1
    local ost_uuid
    local ost_node
    local node

    ost_uuid=$($LFS osts | grep "^$obdidx: " | cut -d' ' -f2 | head -n1)

    for node in $(osts_nodes); do
        do_node $node "lctl get_param -n obdfilter.*.uuid" | grep -q $ost_uuid
        [ ${PIPESTATUS[1]} -eq 0 ] && ost_node=$node && break
    done
    [ -z "$ost_node" ] && \
        echo "failed to find the OST with index $obdidx" && return 1
    echo $ost_node
}

# Get the OST target device (given the OST facet name and OST index).
get_ost_dev() {
	local node=$1
	local obdidx=$2
	local ost_name
	local ost_dev

	ost_name=$($LFS osts | grep "^$obdidx: " | cut -d' ' -f2 |
		   head -n1 | sed -e 's/_UUID$//')
	ost_dev=$(get_obdfilter_param $node $ost_name mntdev)
	if [ $? -ne 0 ]; then
		printf "unable to find OST%04x on $facet\n" $obdidx
		return 1
	fi

	if [[ $ost_dev = *loop* ]]; then
		ost_dev=$(do_node $node "losetup $ost_dev" |
		          sed -e "s/.*(//" -e "s/).*//")
	fi

	echo $ost_dev
}

# Get the file names to be duplicated or removed on the MDS.
get_files() {
    local flavor=$1
    local test_dir=$2
    local num_files=$3
    local first last
    local test_file

    case $flavor in
    dup)
        first=$((num_files + 1))
        last=$((num_files * 2))
        ;;
    remove)
        first=$((num_files * 2 + 1))
        last=$((num_files * 3))
        ;;
    *) echo "get_files(): invalid flavor" && return 1 ;;
    esac

    local files=""
    local f 
    for f in $(seq -f testfile.%g $first $last); do
        test_file=$test_dir/$f
        files="$files $test_file"
    done
    files=$(echo $files | sed "s#$DIR/##g")
    echo $files
}

# Remove objects associated with files.
remove_objects() {
    local node=$1
    shift
    local ostdev=$1
    shift
    local group=$1
    shift
    local objids="$@"
    local tmp
    local i
    local rc

    echo "removing objects from $ostdev on $facet: $objids"
    tmp=$(mktemp $SHARED_DIRECTORY/debugfs.XXXXXXXXXX)
    for i in $objids; do
        echo "rm O/$group/d$((i % 32))/$i" >> $tmp
    done

    do_node $node "$DEBUGFS -w -f $tmp $ostdev"
    rc=${PIPESTATUS[0]}
    rm -f $tmp

    return $rc
}

# Remove files from MDS.
remove_files() {
    do_rpc_nodes $(facet_host $1) remove_mdt_files $@
}

# Create EAs on files so objects are referenced from different files.
duplicate_files() {
    do_rpc_nodes $(facet_host $1) duplicate_mdt_files $@
}

#********************************* Main Flow **********************************#

init_logging

# get the server target devices
get_svr_devs

if is_empty_fs $MOUNT; then
    # create test directory
    TESTDIR=$DIR/d0.$TESTSUITE
    mkdir -p $TESTDIR || error "mkdir $TESTDIR failed"

    # create some dirs and files on the filesystem
    create_files $TESTDIR $NUMDIRS $NUMFILES

    # get the objids for files in group $OBJGRP on the OST with index $OSTIDX
    OST_REMOVE=$(get_objects $OSTIDX $OBJGRP \
                $(seq -f $TESTDIR/testfile.%g $NUMFILES))

    # get the node name and target device for the OST with index $OSTIDX
    OSTNODE=$(get_ost_node $OSTIDX) || error "get_ost_node by index $OSTIDX failed"
    OSTDEV=$(get_ost_dev $OSTNODE $OSTIDX) || \
	error "get_ost_dev $OSTNODE $OSTIDX failed"

    # get the file names to be duplicated on the MDS
    MDS_DUPE=$(get_files dup $TESTDIR $NUMFILES) || error "$MDS_DUPE"
    # get the file names to be removed from the MDS
    MDS_REMOVE=$(get_files remove $TESTDIR $NUMFILES) || error "$MDS_REMOVE"

    stopall -f || error "cleanupall failed"

    # remove objects associated with files in group $OBJGRP
    # on the OST with index $OSTIDX
    remove_objects $OSTNODE $OSTDEV $OBJGRP $OST_REMOVE || \
        error "removing objects failed"

    # remove files from MDS
    remove_files $SINGLEMDS $MDTDEV $MDS_REMOVE || error "removing files failed"

    # create EAs on files so objects are referenced from different files
    duplicate_files $SINGLEMDS $MDTDEV $MDS_DUPE || \
        error "duplicating files failed"
    FSCK_MAX_ERR=1   # file system errors corrected
else # is_empty_fs $MOUNT
    FSCK_MAX_ERR=4   # file system errors left uncorrected
fi

# Test 1a - check and repair the filesystem
# lfsck will return 1 if the filesystem had errors fixed
# run e2fsck to generate databases used for lfsck
generate_db

# remount filesystem
REFORMAT=""
check_and_setup_lustre

# run lfsck
rc=0
run_lfsck || rc=$?
if [ $rc -eq 0 ]; then
    echo "clean after the first check"
else
    # run e2fsck again to generate databases used for lfsck
    generate_db

    # run lfsck again
    rc=0
    run_lfsck || rc=$?
    if [ $rc -eq 0 ]; then
        echo "clean after the second check"
    else
        error "lfsck test 2 - finished with rc=$rc"
    fi
fi

complete $(basename $0) $SECONDS
check_and_cleanup_lustre
exit_status
