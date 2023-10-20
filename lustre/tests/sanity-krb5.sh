#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# e.g. ONLY="22 23" or ONLY="`seq 32 39`" or EXCEPT="31"
set -e

ONLY=${ONLY:-"$*"}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
init_logging

ALWAYS_EXCEPT="$SANITY_GSS_EXCEPT"

[ "$SLOW" = "no" ] && EXCEPT_SLOW="100 101"

build_test_filter

require_dsh_mds || exit 0

# $RUNAS_ID may get set incorrectly somewhere else
[ $UID -eq 0 -a $RUNAS_ID -eq 0 ] &&
    error "RUNAS_ID set to 0, but UID is also 0!"

# remove $SEC, we'd like to control everything by ourselves
unset SEC

#
# global variables of this sanity
#
DBENCH_PID=0

# set manually
GSS=true
GSS_KRB5=true

check_krb_env() {
	which klist || skip "Kerberos env not setup"
	which kinit || skip "Kerberos env not setup"
}

prepare_krb5_creds() {
	echo prepare krb5 cred
	echo RUNAS=$RUNAS
	$RUNAS krb5_login.sh || exit 1
}

check_krb_env
prepare_krb5_creds

# we want double mount
MOUNT_2=${MOUNT_2:-"yes"}
check_and_setup_lustre

rm -rf $DIR/[df][0-9]*

check_runas_id $RUNAS_ID $RUNAS_ID $RUNAS

start_dbench()
{
	local NPROC=$(grep -c ^processor /proc/cpuinfo)
	[ $NPROC -gt 2 ] && NPROC=2
	bash rundbench -D $DIR/$tdir $NPROC 1>/dev/null &
	DBENCH_PID=$!
	sleep 2

	num=$(ps --no-headers -p $DBENCH_PID 2>/dev/null | wc -l)
	if [ $num -ne 1 ]; then
		error "failed to start dbench $NPROC"
	else
		echo "started dbench with $NPROC processes at background"
	fi

	return 0
}

check_dbench()
{
	num=$(ps --no-headers -p $DBENCH_PID 2>/dev/null | wc -l)
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
		local num=$(ps --no-headers -p $DBENCH_PID | wc -l)
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

error_dbench()
{
	local err_str=$1

	killall -9 dbench
	sleep 1

	error $err_str
}

# obtain and cache Kerberos ticket-granting ticket
refresh_krb5_tgt() {
	local myRUNAS_UID=$1
	local myRUNAS_GID=$2
	shift 2
	local myRUNAS=$@
	if [ -z "$myRUNAS" ]; then
		error_exit "myRUNAS command must be specified for refresh_krb5_tgt"
	fi

	CLIENTS=${CLIENTS:-$HOSTNAME}
	do_nodes $CLIENTS "set -x
if ! $myRUNAS krb5_login.sh; then
    echo "Failed to refresh Krb5 TGT for UID/GID $myRUNAS_UID/$myRUNAS_GID."
    exit 1
fi"
}

restore_krb5_cred() {
	local keys=$(keyctl show | awk '$6 ~ "^lgssc:" {print $1}')

	for key in $keys; do
		keyctl unlink $key
	done
	echo RUNAS=$RUNAS
	$RUNAS krb5_login.sh || exit 1
}

check_multiple_gss_daemons() {
	local facet=$1
	local gssd=$2
	local gssd_name=$(basename $gssd)

	for ((i = 0; i < 10; i++)); do
		do_facet $facet "$gssd -vvv"
	done

	# wait daemons entering "stable" status
	sleep 5

	local num=$(do_facet $facet ps -o cmd -C $gssd_name |
		grep -c $gssd_name)
	echo "$num instance(s) of $gssd_name are running"

	if [ $num -ne 1 ]; then
		error "$gssd_name not unique"
	fi
}

calc_connection_cnt
umask 077

test_0() {
	local my_facet=mds

	echo "bring up gss daemons..."
	start_gss_daemons

	echo "check with someone already running..."
	check_multiple_gss_daemons $my_facet $LSVCGSSD

	echo "check with someone run & finished..."
	do_facet $my_facet killall -q -2 lgssd $LSVCGSSD || true
	sleep 5 # wait fully exit
	check_multiple_gss_daemons $my_facet $LSVCGSSD

	echo "check refresh..."
	do_facet $my_facet killall -q -2 lgssd $LSVCGSSD || true
	sleep 5 # wait fully exit
	do_facet $my_facet ipcrm -S 0x3b92d473
	check_multiple_gss_daemons $my_facet $LSVCGSSD
}
run_test 0 "start multiple gss daemons"

set_flavor_all krb5p

test_1a() {
	local file=$DIR/$tdir/$tfile

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	chmod 0777 $DIR/$tdir || error "chmod $DIR/$tdir failed"
	$RUNAS ls -ld $DIR/$tdir

	# access w/o cred
	$RUNAS $LFS flushctx -k -r $MOUNT || error "can't flush context"
	$RUNAS touch $file && error "unexpected success"

	# access w/ cred
	restore_krb5_cred
	$RUNAS touch $file || error "should not fail"
	[ -f $file ] || error "$file not found"
}
run_test 1a "access with or without krb5 credential"

test_1b() {
	local file=$DIR/$tdir/$tfile
	local lgssconf=/etc/request-key.d/lgssc.conf
	local clients=$CLIENTS
	local realm

	[ -z $clients ] && clients=$HOSTNAME
	zconf_umount_clients $clients $MOUNT || error "umount clients failed"

	echo "stop gss daemons..."
	stop_gss_daemons

	# get local realm from krb5.conf, assume the same for all nodes
	realm=$(grep default_realm /etc/krb5.conf | awk '{print $3}')

	# add -R option to lgss_keyring on local client
	cp $lgssconf $TMP/lgssc.conf
	stack_trap "yes | cp $TMP/lgssc.conf $lgssconf" EXIT
	sed -i s+lgss_keyring+\&\ \-R\ $realm+ $lgssconf

	# add -R option to lsvcgssd
	echo "bring up gss daemons..."
	start_gss_daemons '' '' "-R $realm"
	stack_trap "stop_gss_daemons ; start_gss_daemons" EXIT

	zconf_mount_clients $clients $MOUNT || error "mount clients failed"

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	chmod 0777 $DIR/$tdir || error "chmod $DIR/$tdir failed"
	$RUNAS touch $file || error "touch $file failed"
	[ -f $file ] || error "$file not found"
}
run_test 1b "Use specified realm"

test_2() {
	local file1=$DIR/$tdir/$tfile-1
	local file2=$DIR/$tdir/$tfile-2

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	chmod 0777 $DIR/$tdir || error "chmod $DIR/$tdir failed"

	# current access should be ok
	$RUNAS touch $file1 || error "can't touch $file1"
	[ -f $file1 ] || error "$file1 not found"

	# cleanup all cred/ctx and touch
	$RUNAS $LFS flushctx -k -r $MOUNT || error "can't flush context"
	$RUNAS touch $file2 && error "unexpected success"

	# restore and touch
	restore_krb5_cred
	$RUNAS touch $file2 || error "should not fail"
	[ -f $file2 ] || error "$file2 not found"
}
run_test 2 "lfs flushctx"

test_3() {
	local file=$DIR/$tdir/$tfile

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	chmod 0777 $DIR/$tdir || error "chmod $DIR/$tdir failed"

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
	# metadata check should fail, but file data check should succeed
	# because we always use root credential to OSTs
	$RUNAS $LFS flushctx -k -r $MOUNT || error "can't flush context"
	echo "destroyed credentials/contexs for $RUNAS_ID"
	$RUNAS $CHECKSTAT -p 0666 $file && error "checkstat succeed"
	kill -s 10 $OPPID
	wait $OPPID || error "read file data failed"
	echo "read file data OK"

	# restore and check again
	restore_krb5_cred
	echo "restored credentials for $RUNAS_ID"
	$RUNAS $CHECKSTAT -p 0666 $file || error "$RUNAS_ID checkstat (2) error"
	echo "$RUNAS_ID checkstat OK"
	$CHECKSTAT -p 0666 $file || error "$UID checkstat (2) error"
	echo "$UID checkstat OK"
	$RUNAS cat $file > /dev/null || error "$RUNAS_ID cat (2) error"
	echo "$RUNAS_ID read file data OK"
}
run_test 3 "local cache under DLM lock"

test_5() {
	local file1=$DIR/$tdir/$tfile-1
	local file2=$DIR/$tdir/$tfile-2
	local wait_time=$((TIMEOUT + TIMEOUT / 2))

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	chmod 0777 $DIR/$tdir || error "chmod $DIR/$tdir failed"

	# current access should be ok
	$RUNAS touch $file1 || error "can't touch $file1"
	[ -f $file1 ] || error "$file1 not found"

	# flush context
	$RUNAS $LFS flushctx $MOUNT || error "can't flush context"

	# stop lsvcgssd
	send_sigint $(comma_list $(mdts_nodes)) $LSVCGSSD
	sleep 5
	check_gss_daemon_nodes $(comma_list $(mdts_nodes)) $LSVCGSSD &&
		error "$LSVCGSSD still running"

	$RUNAS touch $file2 && error "should fail without $LSVCGSSD"

	# restart lsvcgssd, expect touch succeed
	echo "restart $LSVCGSSD and recovering"
	start_gss_daemons $(comma_list $(mdts_nodes)) "$LSVCGSSD -vvv"
	sleep 5
	check_gss_daemon_nodes $(comma_list $(mdts_nodes)) $LSVCGSSD
	$RUNAS touch $file2 || error "should not fail now"
	[ -f $file2 ] || error "$file2 not found"
}
run_test 5 "lsvcgssd dead, operations fail"

test_6() {
	local nfile=10

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	for ((i=0; i<$nfile; i++)); do
		dd if=/dev/zero of=$DIR/$tdir/$tfile-$i bs=8k count=1 ||
		    error "dd $tfile-$i failed"
	done
	ls -l $DIR/$tdir/* > /dev/null || error "ls failed"
	rm -rf $DIR2/$tdir/* || error "rm failed"
	rmdir $DIR2/$tdir || error "rmdir failed"
}
run_test 6 "test basic DLM callback works"

test_7() {
	local num_osts

	# for open(), client only reserve space for default stripe count lovea,
	# and server may return larger lovea in reply (because of larger stripe
	# count), client need call enlarge_reqbuf() and save the replied lovea
	# in request for future possible replay.
	#
	# Note: current script does NOT guarantee enlarge_reqbuf() will be in
	# the path, however it does work in local test which has 2 OSTs and
	# default stripe count is 1.
	[[ $OSTCOUNT -ge 2 ]] || skip_env "needs >= 2 OSTs"

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	$LFS setstripe -c $OSTCOUNT $DIR/$tdir || error "setstripe -c $OSTCOUNT"

	echo "creating..."
	for ((i = 0; i < 20; i++)); do
		dd if=/dev/zero of=$DIR/$tdir/f$i bs=4k count=16 2>/dev/null
	done
	echo "reading..."
	for ((i = 0; i < 20; i++)); do
		dd if=$DIR/$tdir/f$i of=/dev/null bs=4k count=16 2>/dev/null
	done
}
run_test 7 "exercise enlarge_reqbuf()"

test_8()
{
	local atoldbase=$(do_facet $SINGLEMDS "$LCTL get_param -n at_history")
	local req_delay

	do_facet $SINGLEMDS "$LCTL set_param at_history=8" || true
	stack_trap \
		"do_facet $SINGLEMDS $LCTL set_param at_history=$atoldbase" EXIT

	mkdir -p $DIR/$tdir
	chmod a+w $DIR/$tdir

	$LCTL dk > /dev/null
	debugsave
	stack_trap debugrestore EXIT
	$LCTL set_param debug=+other

	# wait for the at estimation come down, this is faster
	while [ true ]; do
		req_delay=$($LCTL get_param -n \
			mdc.${FSNAME}-MDT0000-mdc-*.timeouts |
			awk '/portal 12/ {print $5}' | tail -1)
		[ $req_delay -le 5 ] && break
		echo "current AT estimation is $req_delay, wait a little bit"
		sleep 8
	done
	req_delay=$((${req_delay} + ${req_delay} / 4 + 5))

	# sleep sometime in ctx handle
	do_facet $SINGLEMDS $LCTL set_param fail_val=$req_delay
	#define OBD_FAIL_SEC_CTX_HDL_PAUSE	 0x1204
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1204

	$RUNAS $LFS flushctx -k -r $MOUNT ||
		error "can't flush context on $MOUNT"
	restore_krb5_cred

	$RUNAS touch $DIR/$tdir/$tfile &
	TOUCHPID=$!
	echo "waiting for touch (pid $TOUCHPID) to finish..."
	sleep 30 # give it a chance to really trigger context init rpc
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
	wait $TOUCHPID || error "touch should have succeeded"

	$LCTL dk | grep -i "Early reply #" || error "No early reply"
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

	mkdir $DIR/$tdir

	restore_to_default_flavor
	set_flavor_all krb5p

	start_dbench

	for ((n = 1; n <= $total; n++)); do
		sleep 2
		check_dbench
		echo "flush ctx ($n/$total) ..."
		$LFS flushctx -k -r $MOUNT ||
			error "can't flush context on $MOUNT"
	done
	check_dbench
	#sleep to let ctxs be re-established
	sleep 10
	stop_dbench
}
run_test 90 "recoverable from losing contexts under load"

test_99() {
	local nrule_old
	local nrule_new=0
	local max=32

	#
	# general rules
	#
	nrule_old=$(do_facet mgs lctl get_param -n mgs.MGS.live.$FSNAME \
	    2>/dev/null | grep -c "$FSNAME.srpc.flavor.")
	echo "original general rules: $nrule_old"

	for ((i = $nrule_old; i < $max; i++)); do
		set_rule $FSNAME ${NETTYPE}$i cli2mdt krb5n ||
			error "set rule $i (1)"
		set_rule $FSNAME ${NETTYPE}$i cli2ost krb5n ||
			error "set rule $i (2)"
		set_rule $FSNAME ${NETTYPE}$i mdt2ost null ||
			error "set rule $i (3)"
		set_rule $FSNAME ${NETTYPE}$i mdt2mdt null ||
			error "set rule $i (4)"
	done
	for ((i = $nrule_old; i < $max; i++)); do
		set_rule $FSNAME ${NETTYPE}$i cli2mdt ||
			error "remove rule $i (1)"
		set_rule $FSNAME ${NETTYPE}$i cli2ost ||
			error "remove rule $i (2)"
		set_rule $FSNAME ${NETTYPE}$i mdt2ost ||
			error "remove rule $i (3)"
		set_rule $FSNAME ${NETTYPE}$i mdt2mdt ||
			error "remove rule $i (4)"

	done

	nrule_new=$(do_facet mgs lctl get_param -n mgs.MGS.live.$FSNAME \
	    2>/dev/null | grep -c "$FSNAME.srpc.flavor.")
	if [ $nrule_new != $nrule_old ]; then
		error "general rule: $nrule_new != $nrule_old"
	fi

	#
	# target-specific rules
	#
	nrule_old=$(do_facet mgs lctl get_param -n mgs.MGS.live.$FSNAME \
	    2>/dev/null | grep -c "$FSNAME-MDT0000.srpc.flavor.")
	echo "original target rules: $nrule_old"

	for ((i = $nrule_old; i < $max; i++)); do
		set_rule $FSNAME-MDT0000 ${NETTYPE}$i cli2mdt krb5i ||
			error "set new rule $i (1)"
		set_rule $FSNAME-MDT0000 ${NETTYPE}$i mdt2ost null ||
			error "set new rule $i (2)"
		set_rule $FSNAME-MDT0000 ${NETTYPE}$i mdt2mdt null ||
			error "set new rule $i (3)"
	done
	for ((i = $nrule_old; i < $max; i++)); do
		set_rule $FSNAME-MDT0000 ${NETTYPE}$i cli2mdt ||
			error "remove new rule $i (1)"
		set_rule $FSNAME-MDT0000 ${NETTYPE}$i mdt2ost ||
			error "remove new rule $i (2)"
		set_rule $FSNAME-MDT0000 ${NETTYPE}$i mdt2mdt ||
			error "remove new rule $i (3)"
	done

	nrule_new=$(do_facet mgs lctl get_param -n mgs.MGS.live.$FSNAME \
	    2>/dev/null \ | grep -c "$FSNAME-MDT0000.srpc.flavor.")
	if [ $nrule_new != $nrule_old ]; then
		error "general rule: $nrule_new != $nrule_old"
	fi
}
run_test 99 "set large number of sptlrpc rules"

test_100() {
	# started from default flavors
	restore_to_default_flavor

	mkdir $DIR/$tdir

	# running dbench in background
	start_dbench

	#
	# all: null -> krb5n -> krb5a -> krb5i -> krb5p
	#
	set_flavor_all krb5n
	check_dbench

	set_flavor_all krb5a
	check_dbench

	set_flavor_all krb5i
	check_dbench

	set_flavor_all krb5p
	check_dbench

	#
	# * - MDT0: krb5a
	# * - OST0: krb5i
	#
	# nothing should be changed because they are overridden by above rules
	#
	set_rule $FSNAME-MDT0000 any cli2mdt krb5a
	set_rule $FSNAME-OST0000 any cli2ost krb5i
	wait_flavor cli2mdt krb5p || error_dbench "1"
	check_dbench
	wait_flavor cli2ost krb5p || error_dbench "2"

	#
	# remove:
	#  * - MDT0: krb5a
	#  * - OST0: krb5i
	#
	set_rule $FSNAME-MDT0000 any cli2mdt
	set_rule $FSNAME-OST0000 any cli2ost
	check_dbench

	#
	# delete all rules
	#
	set_rule $FSNAME any mdt2mdt
	set_rule $FSNAME any cli2mdt
	set_rule $FSNAME any mdt2ost
	set_rule $FSNAME any cli2ost
	restore_to_default_flavor
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
	# after setting flavor0, start multiop which uses flavor0 rpc, and let
	# server drop the reply; then switch to flavor1, the resend should be
	# completed using flavor1. To exercise the code of switching ctx/sec
	# for a resend request.
	#
	log ">>>>>>>>>>>>>>> Testing $flavor0 -> $flavor1 <<<<<<<<<<<<<<<<<<<"

	set_rule $FSNAME any cli2mdt $flavor0
	wait_flavor cli2mdt $flavor0
	rm -f $filename || error "remove old $filename failed"

	#MDS_REINT = 36
	#define OBD_FAIL_PTLRPC_DROP_REQ_OPC	 0x513
	do_facet $SINGLEMDS lctl set_param fail_val=36
	do_facet $SINGLEMDS lctl set_param fail_loc=0x513
	log "starting multiop"
	$MULTIOP $filename m &
	multiop_pid=$!
	echo "multiop pid=$multiop_pid"
	sleep 1

	set_rule $FSNAME any cli2mdt $flavor1
	wait_flavor cli2mdt $flavor1

	num=$(ps --no-headers -p $multiop_pid 2>/dev/null | wc -l)
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

	switch_sec_test null  krb5n
	switch_sec_test krb5n krb5a
	switch_sec_test krb5a krb5i
	switch_sec_test krb5i krb5p
	switch_sec_test krb5p null
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

	mkdir $DIR/$tdir

	# run dbench background
	start_dbench

	echo "Testing null->krb5n->krb5a->krb5i->krb5p->null"
	set_flavor_all krb5n
	set_flavor_all krb5a
	set_flavor_all krb5i
	set_flavor_all krb5p
	set_flavor_all null

	check_dbench

	echo "waiting for 15s and check again"
	sleep 15
	check_dbench

	echo "Testing null->krb5i->null->krb5i->null..."
	for ((idx = 0; idx < 5; idx++)); do
		set_flavor_all krb5i
		set_flavor_all null
	done
	set_flavor_all krb5i

	check_dbench

	echo "waiting for 15s and check again"
	sleep 15
	check_dbench

	stop_dbench
}
run_test 102 "survive from fast flavor switch"

test_150() {
	local mount_opts
	local count
	local clients=$CLIENTS

	[ -z $clients ] && clients=$HOSTNAME

	# started from default flavors
	restore_to_default_flavor

	# at this time no rules has been set on mgs; mgc use null
	# flavor to connect to mgs
	count=$(flvr_cnt_mgc2mgs null)
	[ $count -eq 1 ] || error "$count mgc connections use null flavor"

	zconf_umount_clients $clients $MOUNT || error "umount failed (1)"

	# mount client with conflict flavor - should fail
	mount_opts="${MOUNT_OPTS:+$MOUNT_OPTS,}mgssec=krb5p"
	zconf_mount_clients $clients $MOUNT $mount_opts &&
		error "mount with conflict flavor should have failed"

	# mount client with same flavor - should succeed
	mount_opts="${MOUNT_OPTS:+$MOUNT_OPTS,}mgssec=null"
	zconf_mount_clients $clients $MOUNT $mount_opts ||
		error "mount with same flavor should have succeeded"
	zconf_umount_clients $clients $MOUNT || error "umount failed (2)"

	# mount client with default flavor - should succeed
	zconf_mount_clients $clients $MOUNT ||
		error "mount with default flavor should have succeeded"
}
run_test 150 "secure mgs connection: client flavor setting"

exit_151() {
	# remove mgs rule
	set_rule _mgs any any

	# umount everything, then remount
	stopall
	setupall
}

test_151() {
	local new_opts

	stack_trap exit_151 EXIT

	# set mgs rule to only accept krb5p
	set_rule _mgs any any krb5p

	# umount everything, modules still loaded
	stopall

	# start gss daemon on mgs node
	combined_mgs_mds || start_gss_daemons $mgs_HOST "$LSVCGSSD -vvv"

	# start mgs
	start mgs $(mgsdevname 1) $MDS_MOUNT_OPTS

	# mount with default flavor, expected to fail
	start ost1 "$(ostdevname 1)" $OST_MOUNT_OPTS
	wait_mgc_import_state ost1 FULL 0 &&
		error "mount with default flavor should have failed"
	stop ost1

	# mount with unauthorized flavor should fail
	if [ -z "$OST_MOUNT_OPTS" ]; then
		new_opts="-o mgssec=null"
	else
		new_opts="$OST_MOUNT_OPTS,mgssec=null"
	fi
	start ost1 "$(ostdevname 1)" $new_opts
	wait_mgc_import_state ost1 FULL 0 &&
		error "mount with unauthorized flavor should have failed"
	stop ost1

	# mount with designated flavor should succeed
	if [ -z "$OST_MOUNT_OPTS" ]; then
		new_opts="-o mgssec=krb5p"
	else
		new_opts="$OST_MOUNT_OPTS,mgssec=krb5p"
	fi
	start ost1 "$(ostdevname 1)" $new_opts
	wait_mgc_import_state ost1 FULL 0 ||
		error "mount with designated flavor should have succeeded"

	stop ost1 -f
}
run_test 151 "secure mgs connection: server flavor control"

complete_test $SECONDS
set_flavor_all null
cleanup_gss
check_and_cleanup_lustre
exit_status
