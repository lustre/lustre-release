#!/bin/bash

# A Metadata Update Test tests that
# metadata updates are properly completed when
# multiple clients create/delete files and modify the attributes of files.

set -e

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

TRACE=${TRACE:-"+x"}

TESTDIR=${TESTDIR:-$DIR/d0.$(basename $0 .sh)}

NODES_TO_USE=${NODES_TO_USE:-$CLIENTS}

[ -z $CLIENTS ] && NODES_TO_USE=$(hostname)

# hostname could differ from a network interface
# configured for NODES_TO_USE, bug 23961
# the test dir on each host is created based on `hostname` of this host
HOSTS=$(comma_list $(do_nodes $NODES_TO_USE "echo \\\$(hostname)"))

FILE=testfile
FILE_SIZE=1024
CURRENT_MODE=0644
NEW_MODE=0222
NEW_ATIME="2001-01-01 GMT"
NEW_MTIME="2005-05-05 GMT"

test_USER=$(id -u -n)
test_GROUP=$(id -g -n)

SUMFILE=$TESTDIR/mdsum

NUM_FILES=1000

WRITE_DISJOINT=${WRITE_DISJOINT:-$(which write_disjoint 2> /dev/null)} || true
WRITE_DISJOINT_FILE=$TESTDIR/f0.write_disjoint_file
NUMLOOPS=1000

log "===== $0 ====== "

check_and_setup_lustre

cleanup_prepare () {

    do_nodes $NODES_TO_USE "set $TRACE;
DIR=$TESTDIR/\\\$(hostname);
TESTFILE=\\\$DIR/$FILE;
rm -f \\\$TESTFILE;
rm -f $SUMFILE;
rmdir \\\$DIR 2>/dev/null;
mkdir -p \\\$DIR" || return ${PIPESTATUS[0]}
    return 0;
}

do_mknod () {
    echo "Creating file(s) by mknod (2) ... "

    do_nodes $NODES_TO_USE "set $TRACE;
TESTFILE=$TESTDIR/\\\$(hostname)/$FILE;
mcreate \\\$TESTFILE; " || return ${PIPESTATUS[0]}
    return 0
}

do_write () {
    do_nodes $NODES_TO_USE "set $TRACE;
TESTFILE=$TESTDIR/\\\$(hostname)/$FILE;
dd if=/dev/zero of=\\\$TESTFILE bs=$FILE_SIZE count=1 2>/dev/null || exit 54;
echo \\\$(hostname) | dd of=\\\$TESTFILE conv=notrunc 2>/dev/null || exit 55; 
md5sum \\\$TESTFILE >> $SUMFILE; " || return ${PIPESTATUS[0]}
    return 0
}

do_check_data () {
    echo "Checking file(s) data ... md5sum : "
    cat $SUMFILE

    do_nodesv $NODES_TO_USE "md5sum --check $SUMFILE" || \
        return ${PIPESTATUS[0]}
    return 0
}

do_truncate () {
    echo "Truncating file(s) ... "

     do_nodes $NODES_TO_USE "set $TRACE;
TESTFILE=$TESTDIR/\\\$(hostname)/$FILE;
$TRUNCATE \\\$TESTFILE 0" || return ${PIPESTATUS[0]} 

    FILE_SIZE=0
    return 0
}

# check st_uid, st_gid, st_size, st_mode
get_stat () {
	local attr="$test_USER $test_GROUP $FILE_SIZE $CURRENT_MODE"

	echo "Checking file(s) attributes ... "

    do_nodesv $NODES_TO_USE "set $TRACE;
for HOST in ${HOSTS//,/ } ; do
    TESTFILE=$TESTDIR/\\\$HOST/$FILE;
    tmp=\\\$(stat -c \\\"%U %G %s 0%a\\\" \\\$TESTFILE);
    echo \\\"\\\$TESTFILE [ uid gid size mode ] expected : $attr ;  got : \\\$tmp \\\";
    if [ x\\\"\\\$tmp\\\" != x\\\"$attr\\\" ] ; then
        echo \\\"Wrong file attributes\\\";
        exit 56;
    fi;
done " || return ${PIPESTATUS[0]}
	return 0
}

do_chmod () {
    echo "Performing chmod 0$NEW_MODE ..."

    do_nodes $NODES_TO_USE "set $TRACE;
TESTFILE=$TESTDIR/\\\$(hostname)/$FILE;
chmod $NEW_MODE \\\$TESTFILE" || return ${PIPESTATUS[0]}
 
    CURRENT_MODE=$NEW_MODE
    return 0
}

do_change_timestamps () {
    echo "Changing atime, mtime ..."

    do_nodes $NODES_TO_USE " set $TRACE;
TESTFILE=$TESTDIR/\\\$(hostname)/$FILE;
touch -c --date=\\\"$NEW_ATIME\\\" -a \\\$TESTFILE;
touch -c --date=\\\"$NEW_MTIME\\\" -m \\\$TESTFILE " || return ${PIPESTATUS[0]}
    return 0
}

# check st_atime, st_mtime
do_check_timestamps () {
    local atime=$(date --date="$NEW_ATIME" +%s)
    local mtime=$(date --date="$NEW_MTIME" +%s)

    local times="$atime $mtime"

    echo "Checking atime, mtime ... "

    do_nodesv $NODES_TO_USE "set $TRACE;
for HOST in ${HOSTS//,/ } ; do
    TESTFILE=$TESTDIR/\\\$HOST/$FILE;
    tmp=\\\$(stat -c \\\"%X %Y\\\" \\\$TESTFILE);
    if [ x\\\"\\\$tmp\\\" != x\\\"$times\\\" ] ; then
       echo \\\"\\\$TESTFILE [ atime mtime ] expected : $times ;  got : \\\$tmp \\\";
       RC=57;
    fi;
done;
exit \\\$RC" || return ${PIPESTATUS[0]}
    return 0 
}

do_fill_dir () {
    echo "Filling up directories ... files : f1 ... f$NUM_FILES) ... "

    do_nodes $NODES_TO_USE "set $TRACE;
TESTFILE=$TESTDIR/\\\$(hostname)/$FILE;
rm -f \\\$TESTFILE;
DIR=$TESTDIR/\\\$(hostname);
for i in \\\$(seq $NUM_FILES) ; do
    touch \\\$DIR/f\\\$i;
done " || return ${PIPESTATUS[0]}
    return 0
}

check_dir_contents () {
    local num_files=${1:-1}

    echo "Checking dir contents ... (should exist files : f$num_files ... f$NUM_FILES) ... "
    do_nodes $NODES_TO_USE "set $TRACE;
for HOST in ${HOSTS//,/ } ; do
    DIR=$TESTDIR/\\\$HOST;
    for i in \\\$(seq $NUM_FILES -1 $num_files) ; do
        if ! [ -f \\\$DIR/f\\\$i ] ; then
            echo \\\"ERROR: file \\\$DIR/f\\\$i should exist\\\";
            RC=1;
        fi;
    done;
    for i in \\\$(seq $(($num_files - 1 ))) ; do
        if [ -f \\\$DIR/f\\\$i ] ; then
            echo \\\"ERROR: deleted file \\\$DIR/f\\\$i exists\\\";
            RC=1;
        fi;
    done;
done;
exit \\\$RC " || return ${PIPESTATUS[0]}
    return 0
}

do_partial_delete () {
    local num_files=$1

    echo "Deleting files ... f1 ... f$num_files ... "
    do_nodes $NODES_TO_USE "set $TRACE;
DIR=$TESTDIR/\\\$(hostname);
for i in \\\$(seq $num_files) ; do
    if ! rm -f \\\$DIR/f\\\$i ; then
        exit 1;
    fi;
done " || return ${PIPESTATUS[0]}
    return 0
}

STATUS=0

chmod 0777 $MOUNT   || exit 1
mkdir -p $TESTDIR   || exit 1
chmod 0777 $TESTDIR || exit 1

cleanup_prepare     || error_exit "cleanup failed"

# create file(s) (mknod (2)), write data, check data, check file attributes
echo "Part 1. create file(s) (mknod (2)), write data, check data, check file attributes."
do_mknod              || error_exit "mknod failed"
echo "Writing data to file(s) ... store md5sum ... "
do_write              || error_exit "write data failed"
do_check_data         || error_exit "md5sum verification failed"
get_stat              || { error_noexit "attributes check failed" ; STATUS=1; }

# file(s) attributes modification
echo "Part 2. file(s) attributes modification."
do_chmod              || error_exit "chmod failed"
get_stat              || { error_noexit "wrong attributes after chmod"; STATUS=1; }

do_change_timestamps  || error_exit "timestamps change failed"
do_check_timestamps   || { error_noexit "wrong timestamps"; STATUS=1; }

# truncate file(s) to 0 size, check new file size
echo "Part 3. truncate file(s) to 0 size, check new file size."
do_truncate     || error_exit"truncate failed"
get_stat        || { error_noexit "wrong attributes after truncate"; STATUS=1; }

# directory content solidity
echo "Part 4. directory content solidity: fill up directory, check dir content, remove some files, check dir content."
do_fill_dir        || error_exit "dir creation failed"
check_dir_contents || { error_noexit "dir contents check failed"; STATUS=1; }

do_partial_delete $(($NUM_FILES / 2))      || error_exit "delete failed"
check_dir_contents $(($NUM_FILES / 2 + 1)) ||
    { error_noexit "dir contents check after delete failed"; STATUS=1; }

# "write_disjoint" test
echo "Part 5. write_disjoint test: see lustre/tests/mpi/write_disjoint.c for details"
if [ -f "$WRITE_DISJOINT" ]; then
	set $TRACE
	MACHINEFILE=${MACHINEFILE:-$TMP/$(basename $0 .sh).machines}
	generate_machine_file $NODES_TO_USE $MACHINEFILE
	mpi_run ${MACHINEFILE_OPTION} $MACHINEFILE \
		-np $(get_node_count ${NODES_TO_USE//,/ }) $WRITE_DISJOINT \
		-f $WRITE_DISJOINT_FILE -n $NUMLOOPS || STATUS=1
else
    skip_env "$0 : write_disjoint not found "
fi

complete $SECONDS
rm -rf $TESTDIR
rm -f $MACHINEFILE
check_and_cleanup_lustre
exit_status
