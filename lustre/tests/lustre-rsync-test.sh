#!/bin/bash
# -*- mode: Bash; tab-width: 4; indent-tabs-mode: t; -*-
# vim:shiftwidth=4:softtabstop=4:tabstop=4:
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# Run test by setting NOSETUP=true when ltest has setup env for us
set -e

SRCDIR=`dirname $0`
export PATH=$PWD/$SRCDIR:$SRCDIR:$PWD/$SRCDIR/../utils:$PATH:/sbin

ONLY=${ONLY:-"$*"}
ALWAYS_EXCEPT="$LRSYNC_EXCEPT"
# bug number for skipped test:
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

[ "$SLOW" = "no" ] && EXCEPT_SLOW=""

[ "$ALWAYS_EXCEPT$EXCEPT" ] &&
	echo "Skipping tests: `echo $ALWAYS_EXCEPT $EXCEPT`"

KILL=/bin/kill

TMP=${TMP:-/tmp}
LREPL_LOG=$TMP/lustre_rsync.log
ORIG_PWD=${PWD}

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

check_and_setup_lustre

DIR=${DIR:-$MOUNT}
assert_DIR


build_test_filter

export LRSYNC=${LRSYNC:-"$LUSTRE/utils/lustre_rsync"}
[ ! -f "$LRSYNC" ] && export LRSYNC=$(which lustre_rsync)
export LRSYNC="$LRSYNC -v -c no -d 2"

# control the time of tests
DBENCH_TIME=${DBENCH_TIME:-60}  # No of seconds to run dbench
TGT=$TMP/target
TGT2=$TMP/target2
MDT0=$($LCTL get_param -n mdc.*.mds_server_uuid |
	awk '{ gsub(/_UUID/,""); print $1 }' | head -n1)

init_changelog() {
    CL_USER=$(do_facet $SINGLEMDS lctl --device $MDT0 changelog_register -n)
    echo $MDT0: Registered changelog user $CL_USER
    CL_USERS=$(( $(do_facet $SINGLEMDS lctl get_param -n \
	mdd.$MDT0.changelog_users | wc -l) - 2 ))
    [ $CL_USERS -ne 1 ] && \
	echo "Other changelog users present ($CL_USERS)"
}

init_src() {
    rm -rf $TGT/$tdir $TGT/d*.lustre_rsync-test 2> /dev/null
    rm -rf $TGT2/$tdir $TGT2/d*.lustre_rsync-test 2> /dev/null
    rm -rf ${DIR}/$tdir $DIR/d*.lustre_rsync-test ${DIR}/tgt 2> /dev/null
    rm -f $LREPL_LOG
    mkdir -p ${DIR}/$tdir
    mkdir -p ${TGT}/$tdir
    mkdir -p ${TGT2}/$tdir
    if [ $? -ne 0 ]; then
        error "Failed to create target: " $TGT
    fi
}

cleanup_src_tgt() {
    rm -rf $TGT/$tdir
    rm -rf $DIR/$tdir
    rm -rf $DIR/tgt
}

fini_changelog() {
    $LFS changelog_clear $MDT0 $CL_USER 0
    do_facet $SINGLEMDS lctl --device $MDT0 changelog_deregister $CL_USER
}

# Check whether the filesystem supports xattr or not.
# Return value:
# "large" - large xattr is supported
# "small" - large xattr is unsupported but small xattr is supported
# "no"    - xattr is unsupported
check_xattr() {
    local tgt=$1
    local xattr="no"

    touch $tgt

    local val="$(generate_string $(max_xattr_size))"
    if large_xattr_enabled &&
       setfattr -n user.foo -v $val $tgt 2>/dev/null; then
            xattr="large"
    else
        setfattr -n user.foo -v bar $tgt 2>/dev/null && xattr="small"
    fi

    rm -f $tgt
    echo $xattr
}

check_diff() {
	local changelog_file=$(generate_logname "changelog")

	if [ -e $1 -o -e $2 ]; then
		diff -rq -x "dev1" $1 $2
		local RC=$?
		if [ $RC -ne 0 ]; then
			$LFS changelog $MDT0 > $changelog_file
			error "Failure in replication; differences found."
		fi
	fi
}

# Test 1 - test basic operations
test_1() {
    init_src
    init_changelog
    local xattr=$(check_xattr $TGT/foo)

    # Directory create
    mkdir $DIR/$tdir/d1
    mkdir $DIR/$tdir/d2

    # File create
    touch $DIR/$tdir/file1
    cp /etc/hosts  $DIR/$tdir/d1/
    touch  $DIR/$tdir/d1/"space in filename"
    touch  $DIR/$tdir/d1/file2

    # File rename
    mv $DIR/$tdir/d1/file2 $DIR/$tdir/d2/file3

    # File and directory delete
    touch $DIR/$tdir/d1/file4
    mkdir $DIR/$tdir/d1/del
    touch  $DIR/$tdir/d1/del/del1
    touch  $DIR/$tdir/d1/del/del2
    rm -rf $DIR/$tdir/d1/del
    rm $DIR/$tdir/d1/file4

    #hard and soft links
    cat /etc/hosts > $DIR/$tdir/d1/link1
    ln  $DIR/$tdir/d1/link1  $DIR/$tdir/d1/link2
    ln -s $DIR/$tdir/d1/link1  $DIR/$tdir/d1/link3

    # Device files
    #mknod $DIR/$tdir/dev1 b 8 1

	# Replicate
	local LRSYNC_LOG=$(generate_logname "lrsync_log")
	echo "Replication #1"
	$LRSYNC -s $DIR -t $TGT -t $TGT2 -m $MDT0 -u $CL_USER -l $LREPL_LOG \
		-D $LRSYNC_LOG

    # Set attributes
    chmod 000 $DIR/$tdir/d2/file3
    chown nobody:nobody $DIR/$tdir/d2/file3

    # Set xattrs
    if [[ "$xattr" != "no" ]]; then
        local value
        touch $DIR/$tdir/file5
        [[ "$xattr" = "large" ]] &&
            value="$(generate_string $(max_xattr_size))" || value="bar"
        setfattr -n user.foo -v $value $DIR/$tdir/file5
    fi

	echo "Replication #2"
	$LRSYNC -l $LREPL_LOG -D $LRSYNC_LOG

    if [[ "$xattr" != "no" ]]; then
        local xval1=$(get_xattr_value user.foo $TGT/$tdir/file5)
        local xval2=$(get_xattr_value user.foo $TGT2/$tdir/file5)
    fi

    RC=0

    # fid2path and path2fid aren't implemented for block devices
    #if [[ ! -b $TGT/$tdir/dev1 ]] || [[ ! -b $TGT2/$tdir/dev1 ]]; then
    #   ls -l $DIR/$tdir/dev1 $TGT/$tdir/dev1 $TGT2/$tdir/dev1
    #   error "Error replicating block devices"
    #   RC=1

    if [[ "$xattr" != "no" ]] &&
       [[ "$xval1" != "$value" || "$xval2" != "$value" ]]; then
        error "Error in replicating xattrs."
        RC=1
    fi

	# Use diff to compare the source and the destination
	check_diff $DIR/$tdir $TGT/$tdir
	check_diff $DIR/$tdir $TGT2/$tdir

    fini_changelog
    cleanup_src_tgt
    return $RC
}
run_test 1 "Simple Replication"

# Test 1a - test create/delete operations in ROOT directory
test_1a() { # LU-5005
	rm -rf $TGT/root-* 2> /dev/null
	rm -rf $DIR/root-* 2> /dev/null
	init_changelog

	# Directory create
	mkdir $DIR/root-dir

	# File create
	touch $DIR/root-file
	touch $DIR/root-file2

	# File rename
	mv $DIR/root-file2 $DIR/root-file3

	# File and directory delete
	touch $DIR/root-file4
	mkdir $DIR/root-dir1
	rm $DIR/root-file4
	rm -rf $DIR/root-dir1

	# Replicate
	local LRSYNC_LOG=$(generate_logname "lrsync_log")
	echo "Replication"
	$LRSYNC -s $DIR -t $TGT -m $MDT0 -u $CL_USER -l $LREPL_LOG \
		-D $LRSYNC_LOG

	# Verify
	stat $TGT/root-dir || error "Dir create not replicated"
	stat $TGT/root-file || error "File create not replicated"
	stat $TGT/root-file2 && error "Rename not replicated (src)"
	stat $TGT/root-file3 || error "Rename not replicated (tgt)"
	stat $TGT/root-dir1 && error "Dir delete not replicated"
	stat $TGT/root-file4 && error "File delete not replicated"

	fini_changelog
	rm -fr $TGT/root-*
	rm -fr $DIR/root-*
	return 0
}
run_test 1a "Replicate create/delete operations in ROOT directory"

# Test 2a - Replicate files created by dbench
test_2a() {
	init_src
	init_changelog

	# Run dbench
	sh rundbench -C -D $DIR/$tdir 2 -t $DBENCH_TIME || error "dbench failed"

	local LRSYNC_LOG=$(generate_logname "lrsync_log")
	# Replicate the changes to $TGT
	$LRSYNC -s $DIR -t $TGT -t $TGT2 -m $MDT0 -u $CL_USER -l $LREPL_LOG \
		-D $LRSYNC_LOG

	# Use diff to compare the source and the destination
	check_diff $DIR/$tdir $TGT/$tdir
	check_diff $DIR/$tdir $TGT2/$tdir

	fini_changelog
	cleanup_src_tgt
	return 0
}
run_test 2a "Replicate files created by dbench."


# Test 2b - Replicate files changed by dbench.
test_2b() {
	local child_pid
	init_src
	init_changelog

	# Run dbench
	sh rundbench -C -D $DIR/$tdir 2 -t $DBENCH_TIME &
	# wait for dbench to start
	wait_for_function 'child_pid=$(pgrep dbench)' 360
	# let dbench run for a bit
	sleep 10

	echo PIDs: $child_pid
	echo Stopping dbench
	$KILL -SIGSTOP $child_pid

	local LRSYNC_LOG=$(generate_logname "lrsync_log")
	echo Starting replication
	$LRSYNC -s $DIR -t $TGT -t $TGT2 -m $MDT0 -u $CL_USER -l $LREPL_LOG \
		-D $LRSYNC_LOG
	check_diff $DIR/$tdir $TGT/$tdir

    echo Resuming dbench
    $KILL -SIGCONT $child_pid
    sleep 10

    echo Stopping dbench
    $KILL -SIGSTOP $child_pid

	echo Starting replication
	$LRSYNC -l $LREPL_LOG -D $LRSYNC_LOG
	check_diff $DIR/$tdir $TGT/$tdir

    echo "Wait for dbench to finish"
    $KILL -SIGCONT $child_pid
    wait

	# Replicate the changes to $TGT
	echo Starting replication
	$LRSYNC -l $LREPL_LOG -D $LRSYNC_LOG

	check_diff $DIR/$tdir $TGT/$tdir
	check_diff $DIR/$tdir $TGT2/$tdir

    fini_changelog
    cleanup_src_tgt
    return 0
}
run_test 2b "Replicate files changed by dbench."

# Test 2c - Replicate files while dbench is running
test_2c() {
	init_src
	init_changelog

	# Run dbench
	sh rundbench -C -D $DIR/$tdir 2 -t $DBENCH_TIME &

	local LRSYNC_LOG=$(generate_logname "lrsync_log")
	# Replicate the changes to $TGT
	sleep 10 # give dbench a headstart
	local quit=0
	while [ $quit -le 1 ];
	do
		echo "Running lustre_rsync"
		$LRSYNC -s $DIR -t $TGT -t $TGT2 -m ${mds1_svc} -u $CL_USER \
			-l $LREPL_LOG -D $LRSYNC_LOG
		sleep 5
		pgrep dbench
		if [ $? -ne 0 ]; then
			quit=$(expr $quit + 1)
		fi
	done

	# Use diff to compare the source and the destination
	check_diff $DIR/$tdir $TGT/$tdir
	check_diff $DIR/$tdir $TGT2/$tdir

	fini_changelog
	cleanup_src_tgt
	return 0
}
run_test 2c "Replicate files while dbench is running."

# Test 3a - Replicate files created by createmany
test_3a() {
	init_src
	init_changelog

	local numfiles=1000
	createmany -o $DIR/$tdir/$tfile $numfiles || error "createmany failed"

	local LRSYNC_LOG=$(generate_logname "lrsync_log")
	# Replicate the changes to $TGT
	$LRSYNC -s $DIR -t $TGT -t $TGT2 -m $MDT0 -u $CL_USER -l $LREPL_LOG \
		-D $LRSYNC_LOG
	check_diff $DIR/$tdir $TGT/$tdir
	check_diff $DIR/$tdir $TGT2/$tdir

	fini_changelog
	cleanup_src_tgt
	return 0
}
run_test 3a "Replicate files created by createmany"


# Test 3b - Replicate files created by writemany
test_3b() {
	init_src
	init_changelog

	local time=60
	local threads=5
	writemany -q -a $DIR/$tdir/$tfile $time $threads ||
		error "writemany failed"

	local LRSYNC_LOG=$(generate_logname "lrsync_log")
	# Replicate the changes to $TGT
	$LRSYNC -s $DIR -t $TGT -t $TGT2 -m $MDT0 -u $CL_USER -l $LREPL_LOG \
		-D $LRSYNC_LOG

	check_diff $DIR/$tdir $TGT/$tdir
	check_diff $DIR/$tdir $TGT2/$tdir

	fini_changelog
	cleanup_src_tgt
	return 0
}
run_test 3b "Replicate files created by writemany"

# Test 3c - Replicate files created by createmany/unlinkmany
test_3c() {
	init_src
	init_changelog

	local numfiles=1000
	createmany -o $DIR/$tdir/$tfile $numfiles || error "createmany failed"
	unlinkmany $DIR/$tdir/$tfile $numfiles || error "unlinkmany failed"

	local LRSYNC_LOG=$(generate_logname "lrsync_log")
	# Replicate the changes to $TGT
	$LRSYNC -s $DIR -t $TGT -t $TGT2 -m $MDT0  -u $CL_USER -l $LREPL_LOG \
		-D $LRSYNC_LOG
	check_diff $DIR/$tdir $TGT/$tdir
	check_diff $DIR/$tdir $TGT2/$tdir

	fini_changelog
	cleanup_src_tgt
	return 0
}
run_test 3c "Replicate files created by createmany/unlinkmany"

# Test 4 - Replicate files created by iozone
test_4() {
    which iozone > /dev/null 2>&1
    if [ $? -ne 0 ]; then
	skip "iozone not found. Skipping test"
	return
    fi

    init_src
    init_changelog

    END_RUN_FILE=${DIR}/$tdir/run LOAD_PID_FILE=${DIR}/$tdir/pid \
        MOUNT=${DIR}/$tdir run_iozone.sh &
    sleep 30
    child_pid=$(pgrep iozone)
    $KILL -SIGSTOP $child_pid

	local LRSYNC_LOG=$(generate_logname "lrsync_log")
	# Replicate the changes to $TGT
	$LRSYNC -s $DIR -t $TGT -t $TGT2 -m $MDT0  -u $CL_USER -l $LREPL_LOG \
		-D $LRSYNC_LOG
	check_diff $DIR/$tdir $TGT/$tdir
	check_diff $DIR/$tdir $TGT2/$tdir

    $KILL -SIGCONT $child_pid
    sleep 60
    $KILL -SIGKILL $(pgrep run_iozone.sh)
    $KILL -SIGKILL $(pgrep iozone)

    # After killing 'run_iozone.sh', process 'iozone' becomes the
    # child of PID 1. Hence 'wait' does not wait for it. Killing
    # iozone first, means more iozone processes are spawned off which
    # is not desirable. So, after sending a sigkill, the test goes
    # into a wait loop for iozone to cleanup and exit.
    wait
    while [ "$(pgrep "iozone")" != "" ];
    do
      ps -ef | grep iozone | grep -v grep
      sleep 1;
    done

	$LRSYNC -l $LREPL_LOG -D $LRSYNC_LOG
	check_diff $DIR/$tdir $TGT/$tdir
	check_diff $DIR/$tdir $TGT2/$tdir

    fini_changelog
    cleanup_src_tgt
    return 0
}
run_test 4 "Replicate files created by iozone"

# Test 5a - Stop / start lustre_rsync
test_5a() {
	init_src
	init_changelog

	NUMTEST=2000
	createmany -o $DIR/$tdir/$tfile $NUMTEST

	# Replicate the changes to $TGT
	local LRSYNC_LOG=$(generate_logname "lrsync_log")
	$LRSYNC -s $DIR -t $TGT -t $TGT2 -m $MDT0 -u $CL_USER -l $LREPL_LOG \
		-D $LRSYNC_LOG &
	local child_pid=$!
	sleep 30
	$KILL -SIGHUP $child_pid
	wait
	$LRSYNC -l $LREPL_LOG -D $LRSYNC_LOG

	check_diff $DIR/$tdir $TGT/$tdir
	check_diff $DIR/$tdir $TGT2/$tdir

	fini_changelog
	cleanup_src_tgt
	return 0
}
run_test 5a "Stop / start lustre_rsync"

# Test 5b - Kill / restart lustre_rsync
test_5b() {
	init_src
	init_changelog

	NUMTEST=2000
	createmany -o $DIR/$tdir/$tfile $NUMTEST

	# Replicate the changes to $TGT
	local LRSYNC_LOG=$(generate_logname "lrsync_log")
	$LRSYNC -s $DIR -t $TGT -t $TGT2 -m $MDT0 -u $CL_USER -l $LREPL_LOG \
		-D $LRSYNC_LOG &
	local child_pid=$!
	sleep 30
	$KILL -SIGKILL $child_pid
	wait
	$LRSYNC -l $LREPL_LOG -D $LRSYNC_LOG

	check_diff $DIR/$tdir $TGT/$tdir
	check_diff $DIR/$tdir $TGT2/$tdir

	fini_changelog
	cleanup_src_tgt
	return 0
}
run_test 5b "Kill / restart lustre_rsync"

# Test 6 - lustre_rsync large no of hard links
test_6() {
	init_src
	init_changelog

	local num_links=128
	local i

	touch $DIR/$tdir/link0
	for ((i = 1; i < num_links - 1; i++)); do
		ln $DIR/$tdir/link0 $DIR/$tdir/link$i
	done
	# create an extra hard link of src name ending with dest name
	ln $DIR/$tdir/link0 $DIR/$tdir/ink0

	local LRSYNC_LOG=$(generate_logname "lrsync_log")
	# Replicate the changes to $TGT
	$LRSYNC -s $DIR -t $TGT -t $TGT2 -m $MDT0 -u $CL_USER -l $LREPL_LOG \
		-D $LRSYNC_LOG
	check_diff $DIR/$tdir $TGT/$tdir
	check_diff $DIR/$tdir $TGT2/$tdir

	local count1=$(stat --format=%h $TGT/$tdir/link0)
	local count2=$(stat --format=%h $TGT2/$tdir/link0)
	if ((count1 != num_links || count2 != num_links)); then
		ls -l $TGT/$tdir/link0 $TGT2/$tdir/link0
		error "Incorrect no of hard links found $count1, $count2"
	fi

	fini_changelog
	cleanup_src_tgt
	return 0
}
run_test 6 "lustre_rsync large no of hard links"

# Test 7 - lustre_rsync stripesize
test_7() {
    init_src
    mkdir -p ${DIR}/tgt/$tdir
    init_changelog

    local NUMFILES=100
    lfs setstripe -c $OSTCOUNT $DIR/$tdir
    createmany -o $DIR/$tdir/$tfile $NUMFILES

	# To simulate replication to another lustre filesystem, replicate
	# the changes to $DIR/tgt. We can't turn off the changelogs
	# while we are registered, so lustre_rsync better not try to
	# replicate the replication steps.  It seems ok :)

	local LRSYNC_LOG=$(generate_logname "lrsync_log")
	$LRSYNC -s $DIR -t $DIR/tgt -m $MDT0 -u $CL_USER -l $LREPL_LOG \
		-D $LRSYNC_LOG
	check_diff ${DIR}/$tdir $DIR/tgt/$tdir

	local i=0
	while [ $i -lt $NUMFILES ];
	do
		local count=$(lfs getstripe $DIR/tgt/$tdir/${tfile}$i | \
			      awk '/stripe_count/ {print $2}')
		if [ $count -ne $OSTCOUNT ]; then
			error "Stripe size not replicated"
		fi
		i=$(expr $i + 1)
	done
	fini_changelog
	cleanup_src_tgt
	return 0
}
run_test 7 "lustre_rsync stripesize"

# Test 8 - Replicate multiple file/directory moves
test_8() {
    init_src
    init_changelog

    for i in 1 2 3 4 5 6 7 8 9; do
	mkdir $DIR/$tdir/d$i
	    for j in 1 2 3 4 5 6 7 8 9; do
		mkdir $DIR/$tdir/d$i/d$i$j
		createmany -o $DIR/$tdir/d$i/d$i$j/a 10 \
		    > /dev/null
		mv $DIR/$tdir/d$i/d$i$j $DIR/$tdir/d$i/d0$i$j
		createmany -o $DIR/$tdir/d$i/d0$i$j/b 10 \
	            > /dev/null
		mv $DIR/$tdir/d$i/d0$i$j/a0 $DIR/$tdir/d$i/d0$i$j/c0
	    done
	    mv $DIR/$tdir/d$i $DIR/$tdir/d0$i
    done

	local LRSYNC_LOG=$(generate_logname "lrsync_log")
	$LRSYNC -s $DIR -t $TGT -m $MDT0 -u $CL_USER -l $LREPL_LOG \
		-D $LRSYNC_LOG

	check_diff ${DIR}/$tdir $TGT/$tdir

    fini_changelog
    cleanup_src_tgt
    return 0
}
run_test 8 "Replicate multiple file/directory moves"

test_9() {
    init_src
    init_changelog

    mkdir $DIR/$tdir/foo
    touch $DIR/$tdir/foo/a1

	local LRSYNC_LOG=$(generate_logname "lrsync_log")
	$LRSYNC -s $DIR -t $TGT -m $MDT0 -u $CL_USER -l $LREPL_LOG \
		-D $LRSYNC_LOG

	check_diff ${DIR}/$tdir $TGT/$tdir

	rm -rf $DIR/$tdir/foo

	$LRSYNC -s $DIR -t $TGT -m $MDT0 -u $CL_USER -l $LREPL_LOG \
		-D $LRSYNC_LOG

	check_diff ${DIR}/$tdir $TGT/$tdir

    fini_changelog
    cleanup_src_tgt
    return 0
}
run_test 9 "Replicate recursive directory removal"

cd $ORIG_PWD
complete $SECONDS
check_and_cleanup_lustre
exit_status
