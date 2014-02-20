#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# e.g. ONLY="22 23" or ONLY="`seq 32 39`" or EXCEPT="31"
set -e

ONLY=${ONLY:-"$*"}
# bug number for skipped test:
ALWAYS_EXCEPT=${ALWAYS_EXCEPT:-"$SANITY_GSS_EXCEPT"}
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

SRCDIR=`dirname $0`

export MULTIOP=${MULTIOP:-multiop}

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

require_dsh_mds || exit 0

[ "$SLOW" = "no" ] && EXCEPT_SLOW="100 101"

# $RUNAS_ID may get set incorrectly somewhere else
[ $UID -eq 0 -a $RUNAS_ID -eq 0 ] && error "\$RUNAS_ID set to 0, but \$UID is also 0!"

# remove $SEC, we'd like to control everything by ourselves
unset SEC

#
# global variables of this sanity
#
DBENCH_PID=0

# set manually
GSS=true

# we want double mount
MOUNT_2=${MOUNT_2:-"yes"}
check_and_setup_lustre

rm -rf $DIR/[df][0-9]*

check_runas_id $RUNAS_ID $RUNAS_ID $RUNAS

build_test_filter

start_dbench()
{
    NPROC=`cat /proc/cpuinfo 2>/dev/null | grep ^processor | wc -l`
    [ $NPROC -gt 2 ] && NPROC=2
    sh rundbench $NPROC 1>/dev/null &
    DBENCH_PID=$!
    sleep 2

    num=`ps --no-headers -p $DBENCH_PID 2>/dev/null | wc -l`
    if [ $num -ne 1 ]; then
        error "failed to start dbench $NPROC"
    else
        echo "started dbench with $NPROC processes at background"
    fi

    return 0
}

check_dbench()
{
    num=`ps --no-headers -p $DBENCH_PID 2>/dev/null | wc -l`
    if [ $num -eq 0 ]; then
        echo "dbench $DBENCH_PID already finished"
        wait $DBENCH_PID || error "dbench $PID exit with error"
        start_dbench
    elif [ $num -ne 1 ]; then
        killall -9 dbench
        error "found $num instance of pid $DBENCH_PID ???"
    fi

    return 0
}

stop_dbench()
{
    for ((;;)); do
        killall dbench 2>/dev/null
        num=`ps --no-headers -p $DBENCH_PID | wc -l`
        if [ $num -eq 0 ]; then
            echo "dbench finished"
            break
        fi
        echo "dbench $DBENCH_PID is still running, waiting 2s..."
        sleep 2
    done

    wait $DBENCH_PID || true
    sync || true
}

calc_connection_cnt
umask 077

set_flavor_all gssnull

test_1() {
	local file=$DIR/$tfile

	chmod 0777 $DIR || error "chmod $DIR failed"
	# access w/o context
	$RUNAS $LFS flushctx $MOUNT || error "can't flush context on $MOUNT"
	$RUNAS touch $DIR
	$RUNAS touch $file || error "should not fail"
	[ -f $file ] || error "$file not found"
}
run_test 1 "create file"

test_2() {
    local file1=$DIR/$tfile-1
    local file2=$DIR/$tfile-2

    chmod 0777 $DIR || error "chmod $DIR failed"
    # current access should be ok
    $RUNAS touch $file1 || error "can't touch $file1"
    [ -f $file1 ] || error "$file1 not found"

	# cleanup all cred/ctx and touch
	$RUNAS $LFS flushctx $MOUNT || error "can't flush context on $MOUNT"
	$RUNAS touch $file2 && error "unexpected success"
}
run_test 2 "lfs flushctx"

test_3() {
    local file=$DIR/$tfile

    # create file
    echo "aaaaaaaaaaaaaaaaa" > $file
    chmod 0666 $file
    $CHECKSTAT -p 0666 $file || error "$UID checkstat error"
    $RUNAS $CHECKSTAT -p 0666 $file || error "$RUNAS_ID checkstat error"
    $RUNAS cat $file > /dev/null || error "$RUNAS_ID cat error"

    # start multiop
    $RUNAS $MULTIOP $file o_r &
    OPPID=$!
    # wait multiop finish its open()
    sleep 1

    # cleanup all cred/ctx and check
    # metadata check should fail, but file data check should success
    # because we always use root credential to OSTs
    $RUNAS $LFS flushctx $MOUNT || error "can't flush context on $MOUNT"
    echo "destroied credentials/contexs for $RUNAS_ID"
    $RUNAS $CHECKSTAT -p 0666 $file && error "checkstat succeed"
    kill -s 10 $OPPID
    wait $OPPID || error "read file data failed"
    echo "read file data OK"
}
run_test 3 "local cache under DLM lock"

test_6() {
    local nfile=10

    mkdir $DIR/d6 || error "mkdir $DIR/d6 failed"
    for ((i=0; i<$nfile; i++)); do
        dd if=/dev/zero of=$DIR/d6/file$i bs=8k count=1 || error "dd file$i failed"
    done
    ls -l $DIR/d6/* > /dev/null || error "ls failed"
    rm -rf $DIR2/d6/* || error "rm failed"
    rmdir $DIR2/d6/ || error "rmdir failed"
}
run_test 6 "test basic DLM callback works"

test_7() {
	local tdir=$DIR/d7
	local num_osts

	# for open(), client only reserve space for default stripe count lovea,
	# and server may return larger lovea in reply (because of larger stripe
	# count), client need call enlarge_reqbuf() and save the replied lovea
	# in request for future possible replay.
	#
	# Note: current script does NOT guarantee enlarge_reqbuf() will be in
	# the path, however it does work in local test which has 2 OSTs and
	# default stripe count is 1.
	num_osts=$($LFS getstripe $MOUNT | egrep "^[0-9]*:.*ACTIVE" | wc -l)
	echo "found $num_osts active OSTs"
	[ $num_osts -lt 2 ] &&
		echo "skipping $TESTNAME (must have >= 2 OSTs)" && return

	mkdir $tdir || error "mkdir $tdir failed"
	$LFS setstripe -c $num_osts $tdir || error "setstripe -c $num_osts"

	echo "creating..."
	for ((i = 0; i < 20; i++)); do
		dd if=/dev/zero of=$tdir/f$i bs=4k count=16 2>/dev/null
	done
	echo "reading..."
	for ((i = 0; i < 20; i++)); do
		dd if=$tdir/f$i of=/dev/null bs=4k count=16 2>/dev/null
	done
	rm -rf $tdir
}
run_test 7 "exercise enlarge_reqbuf()"

test_8()
{
    local ATHISTORY=$(do_facet $SINGLEMDS "find /sys/ -name at_history")
    local ATOLDBASE=$(do_facet $SINGLEMDS "cat $ATHISTORY")
    local REQ_DELAY
    do_facet $SINGLEMDS "echo 8 >> $ATHISTORY"

    mkdir -p $DIR/d8
    chmod a+w $DIR/d8

    $LCTL dk > /dev/null
    debugsave
    sysctl -w lnet.debug="+other"

    # wait for the at estimation come down, this is faster
    while [ true ]; do
        REQ_DELAY=`lctl get_param -n mdc.${FSNAME}-MDT0000-mdc-*.timeouts |
                   awk '/portal 12/ {print $5}' | tail -1`
        [ $REQ_DELAY -le 5 ] && break
        echo "current AT estimation is $REQ_DELAY, wait a little bit"
        sleep 8
    done
    REQ_DELAY=$((${REQ_DELAY} + ${REQ_DELAY} / 4 + 5))

    # sleep sometime in ctx handle
    do_facet $SINGLEMDS lctl set_param fail_val=$REQ_DELAY
#define OBD_FAIL_SEC_CTX_HDL_PAUSE       0x1204
    do_facet $SINGLEMDS lctl set_param fail_loc=0x1204

    $RUNAS $LFS flushctx $MOUNT || error "can't flush context on $MOUNT"

    $RUNAS touch $DIR/d8/f &
    TOUCHPID=$!
    echo "waiting for touch (pid $TOUCHPID) to finish..."
    sleep 2 # give it a chance to really trigger context init rpc
    do_facet $SINGLEMDS $LCTL set_param fail_loc=0
    wait $TOUCHPID || error "touch should have succeeded"

    $LCTL dk | grep "Early reply #" || error "No early reply"

    debugrestore
    do_facet $SINGLEMDS "echo $ATOLDBASE >> $ATHISTORY" || true
}
run_test 8 "Early reply sent for slow gss context negotiation"

#
# following tests will manipulate flavors and may end with any flavor set,
# so each test should not assume any start flavor.
#

test_90() {
    if [ "$SLOW" = "no" ]; then
        total=10
    else
        total=60
    fi

    restore_to_default_flavor
	set_rule $FSNAME any any gssnull
	wait_flavor all2all gssnull

    start_dbench

    for ((n=0;n<$total;n++)); do
        sleep 2
        check_dbench
        echo "flush ctx ($n/$total) ..."
        $LFS flushctx $MOUNT || error "can't flush context on $MOUNT"
    done
    check_dbench
    #sleep to let ctxs be re-established
    sleep 10
    stop_dbench
}
run_test 90 "recoverable from losing contexts under load"

test_99() {
    local nrule_old=0
    local nrule_new=0
    local max=64

    #
    # general rules
    #
    nrule_old=`do_facet mgs lctl get_param -n mgs.MGS.live.$FSNAME 2>/dev/null \
               | grep "$FSNAME.srpc.flavor." | wc -l`
    echo "original general rules: $nrule_old"

    for ((i = $nrule_old; i < $max; i++)); do
        set_rule $FSNAME elan$i any gssnull || error "set rule $i"
    done
    for ((i = $nrule_old; i < $max; i++)); do
        set_rule $FSNAME elan$i any || error "remove rule $i"
    done

    nrule_new=`do_facet mgs lctl get_param -n mgs.MGS.live.$FSNAME 2>/dev/null \
               | grep "$FSNAME.srpc.flavor." | wc -l`
    if [ $nrule_new != $nrule_old ]; then
        error "general rule: $nrule_new != $nrule_old"
    fi
}
run_test 99 "set large number of sptlrpc rules"

error_dbench()
{
    local err_str=$1

    killall -9 dbench
    sleep 1

    error $err_str
}

test_100() {
	# started from default flavors
	restore_to_default_flavor

	# running dbench background
	start_dbench

	#
	# all: null -> gssnull -> plain
	#
	set_rule $FSNAME any any gssnull
	wait_flavor all2all gssnull || error_dbench "1"
	check_dbench

	set_rule $FSNAME any any plain
	wait_flavor all2all plain || error_dbench "2"
	check_dbench

	#
	# M - M: gssnull
	# C - M: gssnull
	# M - O: gssnull
	# C - O: gssnull
	#
	set_rule $FSNAME any mdt2mdt gssnull
	wait_flavor mdt2mdt gssnull || error_dbench "3"
	check_dbench

	set_rule $FSNAME any cli2mdt gssnull
	wait_flavor cli2mdt gssnull || error_dbench "4"
	check_dbench

	set_rule $FSNAME any mdt2ost gssnull
	wait_flavor mdt2ost gssnull || error_dbench "5"
	check_dbench

	set_rule $FSNAME any cli2ost gssnull
	wait_flavor cli2ost gssnull || error_dbench "6"
	check_dbench

	#
	# * - MDT0: plain
	# * - OST0: plain
	#
	# nothing should be changed because they are override by above dir rules
	#
	set_rule $FSNAME-MDT0000 any any plain
	set_rule $FSNAME-OST0000 any any plain
	wait_flavor mdt2mdt gssnull || error_dbench "7"
	wait_flavor cli2mdt gssnull || error_dbench "8"
	check_dbench
	wait_flavor mdt2ost gssnull || error_dbench "9"
	wait_flavor cli2ost gssnull || error_dbench "10"

	#
	# delete all dir-specific rules
	#
	set_rule $FSNAME any mdt2mdt
	set_rule $FSNAME any cli2mdt
	set_rule $FSNAME any mdt2ost
	set_rule $FSNAME any cli2ost
	wait_flavor mdt2mdt gssnull $((MDSCOUNT - 1)) || error_dbench "11"
	wait_flavor cli2mdt gssnull $(get_clients_mount_count) ||
		error_dbench "12"
	check_dbench
	wait_flavor mdt2ost gssnull $MDSCOUNT || error_dbench "13"
	wait_flavor cli2ost gssnull $(get_clients_mount_count) ||
		error_dbench "14"
	check_dbench

	#
	# remove:
	#  * - MDT0: gssnull
	#  * - OST0: gssnull
	#
	set_rule $FSNAME-MDT0000 any any
	set_rule $FSNAME-OST0000 any any || error_dbench "15"
	wait_flavor all2all plain || error_dbench "16"
	check_dbench

	stop_dbench
}
run_test 100 "change security flavor on the fly under load"

switch_sec_test()
{
    local flavor0=$1
    local flavor1=$2
    local filename=$DIR/$tfile
    local multiop_pid
    local num

    #
    # after set to flavor0, start multop which use flavor0 rpc, and let
    # server drop the reply; then switch to flavor1, the resend should be
    # completed using flavor1. To exercise the code of switching ctx/sec
    # for a resend request.
    #
    log ">>>>>>>>>>>>>>> Testing $flavor0 -> $flavor1 <<<<<<<<<<<<<<<<<<<"

    set_rule $FSNAME any cli2mdt $flavor0
    wait_flavor cli2mdt $flavor0
    rm -f $filename || error "remove old $filename failed"

#MDS_REINT = 36
#define OBD_FAIL_PTLRPC_DROP_REQ_OPC     0x513
    do_facet $SINGLEMDS lctl set_param fail_val=36
    do_facet $SINGLEMDS lctl set_param fail_loc=0x513
    log "starting multiop"
    $MULTIOP $filename m &
    multiop_pid=$!
    echo "multiop pid=$multiop_pid"
    sleep 1

    set_rule $FSNAME any cli2mdt $flavor1
    wait_flavor cli2mdt $flavor1

    num=`ps --no-headers -p $multiop_pid 2>/dev/null | wc -l`
    [ $num -eq 1 ] || error "multiop($multiop_pid) already ended ($num)"
    echo "process $multiop_pid is still hanging there... OK"

    do_facet $SINGLEMDS lctl set_param fail_loc=0
    log "waiting for multiop ($multiop_pid) to finish"
    wait $multiop_pid || error "multiop returned error"
}

test_101()
{
	# started from default flavors
	restore_to_default_flavor

	switch_sec_test null    plain
	switch_sec_test plain   gssnull
	switch_sec_test gssnull null
	switch_sec_test null    gssnull
	switch_sec_test gssnull plain
	switch_sec_test plain   gssnull
}
run_test 101 "switch ctx/sec for resending request"

error_102()
{
    local err_str=$1

    killall -9 dbench
    sleep 1

    error $err_str
}

test_102() {
    # started from default flavors
    restore_to_default_flavor

    # run dbench background
    start_dbench

	echo "Testing null->gssnull->plain->null"
	set_rule $FSNAME any any gssnull
	set_rule $FSNAME any any plain
	set_rule $FSNAME any any null

    check_dbench
    wait_flavor all2all null || error_dbench "1"
    check_dbench

    echo "waiting for 15s and check again"
    sleep 15
    check_dbench

	echo "Testing null->gssnull->null->gssnull->null..."
	for ((i=0; i<10; i++)); do
		set_rule $FSNAME any any gssnull
		set_rule $FSNAME any any null
	done
	set_rule $FSNAME any any gssnull

	check_dbench
	wait_flavor all2all gssnull || error_dbench "2"
	check_dbench

    echo "waiting for 15s and check again"
    sleep 15
    check_dbench

    stop_dbench
}
run_test 102 "survive from insanely fast flavor switch"

test_150() {
    local mount_opts
    local count
    local clients=$CLIENTS

    [ -z $clients ] && clients=$HOSTNAME

    # started from default flavors
    restore_to_default_flavor

    # at this time no rules has been set on mgs; mgc use null
    # flavor connect to mgs.
    count=`flvr_cnt_mgc2mgs null`
    [ $count -eq 1 ] || error "$count mgc connection use null flavor"

    zconf_umount_clients $clients $MOUNT || return 1

    # mount client with conflict flavor - should fail
    mount_opts="${MOUNT_OPTS:+$MOUNT_OPTS,}mgssec=gssnull"
    zconf_mount_clients $clients $MOUNT $mount_opts &&
        error "mount with conflict flavor should have failed"

    # mount client with same flavor - should succeed
    mount_opts="${MOUNT_OPTS:+$MOUNT_OPTS,}mgssec=null"
    zconf_mount_clients $clients $MOUNT $mount_opts ||
        error "mount with same flavor should have succeeded"
    zconf_umount_clients $clients $MOUNT || return 2

    # mount client with default flavor - should succeed
    zconf_mount_clients $clients $MOUNT || \
        error "mount with default flavor should have succeeded"
}
run_test 150 "secure mgs connection: client flavor setting"

test_151() {
	local save_opts

	# set mgs only accept gssnull
	set_rule _mgs any any gssnull

    # umount everything, modules still loaded
    stopall

    # mount mgs with default flavor, in current framework it means mgs+mdt1.
    # the connection of mgc of mdt1 to mgs is expected fail.
    DEVNAME=$(mdsdevname 1)
    start mds1 $DEVNAME $MDS_MOUNT_OPTS && error "mount with default flavor should have failed"

    # mount with unauthorized flavor should fail
    save_opts=$MDS_MOUNT_OPTS
    MDS_MOUNT_OPTS="$MDS_MOUNT_OPTS,mgssec=null"
    start mds1 $DEVNAME $MDS_MOUNT_OPTS && error "mount with unauthorized flavor should have failed"
    MDS_MOUNT_OPTS=$save_opts

    # mount with designated flavor should succeed
    save_opts=$MDS_MOUNT_OPTS
	MDS_MOUNT_OPTS="$MDS_MOUNT_OPTS,mgssec=gssnull"
	start mds1 $DEVNAME $MDS_MOUNT_OPTS ||
		error "mount with designated flavor should have succeeded"
	MDS_MOUNT_OPTS=$save_opts

	stop mds1 -f
}
run_test 151 "secure mgs connection: server flavor control"

complete $SECONDS
check_and_cleanup_lustre
exit_status
