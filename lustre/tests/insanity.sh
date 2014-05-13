#!/bin/bash
# -*- mode: Bash; tab-width: 4; indent-tabs-mode: t; -*-
# vim:shiftwidth=4:softtabstop=4:tabstop=4:
#
# Test multiple failures, AKA Test 17

set -e

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh

init_test_env $@

. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging
#              
ALWAYS_EXCEPT="15  $INSANITY_EXCEPT"

if [ "$FAILURE_MODE" = "HARD" ]; then
	skip_env "$TESTSUITE: is not functional with FAILURE_MODE = HARD, " \
		"please use recovery-double-scale, bz20407"
	exit 0
fi

[ "$SLOW" = "no" ] && EXCEPT_SLOW=""

SETUP=${SETUP:-""}
CLEANUP=${CLEANUP:-""}

build_test_filter

SINGLECLIENT=${SINGLECLIENT:-$HOSTNAME}
LIVE_CLIENT=${LIVE_CLIENT:-$SINGLECLIENT}
FAIL_CLIENTS=${FAIL_CLIENTS:-$RCLIENTS}

assert_env mds_HOST MDSCOUNT
assert_env ost_HOST OSTCOUNT
assert_env LIVE_CLIENT FSNAME

require_dsh_mds || exit 0
require_dsh_ost || exit 0

# FAIL_CLIENTS list should not contain the LIVE_CLIENT
FAIL_CLIENTS=$(echo " $FAIL_CLIENTS " | sed -re "s/\s+$LIVE_CLIENT\s+/ /g")

DIR=${DIR:-$MOUNT}
TESTDIR=$DIR/d0.$TESTSUITE

#####
# fail clients round robin

# list of failable clients
FAIL_LIST=($FAIL_CLIENTS)
FAIL_NUM=${#FAIL_LIST[*]}
FAIL_NEXT=0
typeset -i  FAIL_NEXT
DOWN_NUM=0   # number of nodes currently down

# set next client to fail
set_fail_client() {
    FAIL_CLIENT=${FAIL_LIST[$FAIL_NEXT]}
    FAIL_NEXT=$(( (FAIL_NEXT+1) % FAIL_NUM ))
    echo "fail $FAIL_CLIENT, next is $FAIL_NEXT"
}

fail_clients() {
	num=$1

	log "Request fail clients: $num, to fail: $FAIL_NUM, failed: $DOWN_NUM"
	if [ -z "$num"  ] || [ "$num" -gt $((FAIL_NUM - DOWN_NUM)) ]; then
		num=$((FAIL_NUM - DOWN_NUM))
	fi
    
    if [ -z "$num" ] || [ "$num" -le 0 ]; then
        log "No clients failed!"
        return
    fi

    client_mkdirs

    for i in `seq $num`; do
       set_fail_client
       client=$FAIL_CLIENT
       DOWN_CLIENTS="$DOWN_CLIENTS $client"
       shutdown_client $client
    done

    echo "down clients: $DOWN_CLIENTS"

	for client in $DOWN_CLIENTS; do
		boot_node $client
	done
	DOWN_NUM=`echo $DOWN_CLIENTS | wc -w`
	client_rmdirs
}

reintegrate_clients() {
	for client in $DOWN_CLIENTS; do
		wait_for_host $client
		echo "Restarting $client"
		zconf_mount $client $MOUNT || return 1
	done

	DOWN_CLIENTS=""
	DOWN_NUM=0
}

start_ost() {
	start ost$1 `ostdevname $1` $OST_MOUNT_OPTS
}

start_mdt() {
	start mds$1 $(mdsdevname $1) $MDS_MOUNT_OPTS
}

trap exit INT

client_touch() {
	file=$1
	for c in $LIVE_CLIENT $FAIL_CLIENTS; do
		echo $DOWN_CLIENTS | grep -q $c && continue
		$PDSH $c touch $TESTDIR/${c}_$file || return 1
	done
}

client_rm() {
	file=$1
	for c in $LIVE_CLIENT $FAIL_CLIENTS; do
		$PDSH $c rm $TESTDIR/${c}_$file
	done
}

client_mkdirs() {
	for c in $LIVE_CLIENT $FAIL_CLIENTS; do
		echo "$c mkdir $TESTDIR/$c"
		$PDSH $c "mkdir $TESTDIR/$c && ls -l $TESTDIR/$c"
	done
}

client_rmdirs() {
	for c in $LIVE_CLIENT $FAIL_CLIENTS; do
		echo "rmdir $TESTDIR/$c"
		$PDSH $LIVE_CLIENT "rmdir $TESTDIR/$c"
	done
}

clients_recover_osts() {
    facet=$1
#    do_node $CLIENTS "$LCTL "'--device %OSC_`hostname`_'"${facet}_svc_MNT_client_facet recover"
}

check_and_setup_lustre

rm -rf $TESTDIR
mkdir -p $TESTDIR

# 9 Different Failure Modes Combinations
echo "Starting Test 17 at `date`"

test_0() {
	for i in $(seq $MDSCOUNT) ; do
		fail mds$i
	done

    for i in $(seq $OSTCOUNT) ; do
        fail ost$i
    done
    return 0
}
run_test 0 "Fail all nodes, independently"

############### First Failure Mode ###############
test_1() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return

	[ "$(facet_fstype mds2)" = "zfs" ] &&
		skip "LU-2059: no local config for ZFS MDTs" && return

	clients_up

	shutdown_facet mds1
	reboot_facet mds1

	# prepare for MDS failover
	change_active mds1
	reboot_facet mds1

	clients_up &
	DFPID=$!
	sleep 5

	shutdown_facet mds2

	echo "Reintegrating MDS2"
	reboot_facet mds2
	wait_for_facet mds2
	start_mdt 2 || return 2

	wait_for_facet mds1
	start_mdt 1 || return $?

	#Check FS
	wait $DFPID
	echo "Verify reintegration"
	clients_up || return 1
}
run_test 1 "MDS/MDS failure"
###################################################

############### Second Failure Mode ###############
test_2() {
	echo "Verify Lustre filesystem is up and running"
	[ -z "$(mounted_lustre_filesystems)" ] && error "Lustre is not running"

	clients_up

	for i in $(seq $MDSCOUNT) ; do
		shutdown_facet mds$i
		reboot_facet mds$i

		# prepare for MDS failover
		change_active mds$i
		reboot_facet mds$i
	done

    clients_up &
    DFPID=$!
    sleep 5

    shutdown_facet ost1

    echo "Reintegrating OST"
    reboot_facet ost1
    wait_for_facet ost1
    start_ost 1 || return 2

	for i in $(seq $MDSCOUNT) ; do
		wait_for_facet mds$i
		start_mdt $i || return $?
	done

    #Check FS
    wait $DFPID
    clients_recover_osts ost1
    echo "Verify reintegration"
    clients_up || return 1

}
run_test 2 "Second Failure Mode: MDS/OST `date`"
###################################################

############### Third Failure Mode ###############
test_3() {
    #Create files
    echo "Verify Lustre filesystem is up and running"
    [ -z "$(mounted_lustre_filesystems)" ] && error "Lustre is not running"

    #MDS Portion
	for i in $(seq $MDSCOUNT) ; do
		fail mds$i
	done
    #Check FS

    echo "Test Lustre stability after MDS failover"
    clients_up

    #CLIENT Portion
    echo "Failing 2 CLIENTS"
    fail_clients 2
    
    #Check FS
    echo "Test Lustre stability after CLIENT failure"
    clients_up
    
    #Reintegration
    echo "Reintegrating CLIENTS"
    reintegrate_clients || return 1

    clients_up || return 3
    sleep 2 # give it a little time for fully recovered before next test
}
run_test 3  "Thirdb Failure Mode: MDS/CLIENT `date`"
###################################################

############### Fourth Failure Mode ###############
test_4() {
	echo "Fourth Failure Mode: OST/MDS `date`"

    #OST Portion
    shutdown_facet ost1

    #Check FS
    echo "Test Lustre stability after OST failure"
    clients_up &
    DFPIDA=$!
    sleep 5

	for i in $(seq $MDSCOUNT) ; do
    		shutdown_facet mds$i
		reboot_facet mds$i

		# prepare for MDS failover
		change_active mds$i
		reboot_facet mds$i
	done

    clients_up &
    DFPIDB=$!
    sleep 5

    #Reintegration
    echo "Reintegrating OST"
    reboot_facet ost1
    wait_for_facet ost1
    start_ost 1

	for i in $(seq $MDSCOUNT) ; do
		wait_for_facet mds$i
		start_mdt $i || return $?
	done
    #Check FS

    wait $DFPIDA
    wait $DFPIDB
    clients_recover_osts ost1
    echo "Test Lustre stability after MDS failover"
    clients_up || return 1
}
run_test 4 "Fourth Failure Mode: OST/MDS `date`"
###################################################

############### Fifth Failure Mode ###############
test_5() {
    [ $OSTCOUNT -lt 2 ] && skip_env "$OSTCOUNT < 2, not enough OSTs" && return 0

    echo "Fifth Failure Mode: OST/OST `date`"

    #Create files
    echo "Verify Lustre filesystem is up and running"
    [ -z "$(mounted_lustre_filesystems)" ] && error "Lustre is not running"

    clients_up
    
    #OST Portion
    shutdown_facet ost1
    reboot_facet ost1
    
    #Check FS
    echo "Test Lustre stability after OST failure"
    clients_up &
    DFPIDA=$!
    sleep 5
    
    #OST Portion
    shutdown_facet ost2
    reboot_facet ost2

    #Check FS
    echo "Test Lustre stability after OST failure"
    clients_up &
    DFPIDB=$!
    sleep 5

    #Reintegration
    echo "Reintegrating OSTs"
    wait_for_facet ost1
    start_ost 1
    wait_for_facet ost2
    start_ost 2
    
    clients_recover_osts ost1
    clients_recover_osts ost2
    sleep $TIMEOUT

    wait $DFPIDA
    wait $DFPIDB
    clients_up || return 2
}
run_test 5 "Fifth Failure Mode: OST/OST `date`"
###################################################

############### Sixth Failure Mode ###############
test_6() {
    echo "Sixth Failure Mode: OST/CLIENT `date`"

    #Create files
    echo "Verify Lustre filesystem is up and running"
    [ -z "$(mounted_lustre_filesystems)" ] && error "Lustre is not running"

    clients_up
    client_touch testfile || return 2
	
    #OST Portion
    shutdown_facet ost1
    reboot_facet ost1

    #Check FS
    echo "Test Lustre stability after OST failure"
    clients_up &
    DFPIDA=$!
    echo DFPIDA=$DFPIDA
    sleep 5

    #CLIENT Portion
    echo "Failing CLIENTs"
    fail_clients
    
    #Check FS
    echo "Test Lustre stability after CLIENTs failure"
    clients_up &
    DFPIDB=$!
    echo DFPIDB=$DFPIDB
    sleep 5
    
    #Reintegration
    echo "Reintegrating OST/CLIENTs"
    wait_for_facet ost1
    start_ost 1
    reintegrate_clients || return 1
    sleep 5 

    wait_remote_prog "stat -f" $((TIMEOUT * 3 + 20)) 
    wait $DFPIDA
    wait $DFPIDB

    echo "Verifying mount"
    [ -z "$(mounted_lustre_filesystems)" ] && return 3
    clients_up
}
run_test 6 "Sixth Failure Mode: OST/CLIENT `date`"
###################################################


############### Seventh Failure Mode ###############
test_7() {
    echo "Seventh Failure Mode: CLIENT/MDS `date`"

    #Create files
    echo "Verify Lustre filesystem is up and running"
    [ -z "$(mounted_lustre_filesystems)" ] && error "Lustre is not running"

    clients_up
    client_touch testfile  || return 1

    #CLIENT Portion
    echo "Part 1: Failing CLIENT"
    fail_clients 2
    
    #Check FS
    echo "Test Lustre stability after CLIENTs failure"
    clients_up
    $PDSH $LIVE_CLIENT "ls -l $TESTDIR"
    $PDSH $LIVE_CLIENT "rm -f $TESTDIR/*_testfile"
    
    #Sleep
    echo "Wait 1 minutes"
    sleep 60

    #Create files
    echo "Verify Lustre filesystem is up and running"
    [ -z "$(mounted_lustre_filesystems)" ] && return 2

    clients_up
    client_rm testfile

    #MDS Portion
	for i in $(seq $MDSCOUNT) ; do
		fail mds$i
	done

    $PDSH $LIVE_CLIENT "ls -l $TESTDIR"
    $PDSH $LIVE_CLIENT "rm -f $TESTDIR/*_testfile"

    #Reintegration
    echo "Reintegrating CLIENTs"
    reintegrate_clients || return 2
    clients_up
    
    #Sleep
    echo "wait 1 minutes"
    sleep 60
}
run_test 7 "Seventh Failure Mode: CLIENT/MDS `date`"
###################################################


############### Eighth Failure Mode ###############
test_8() {
    echo "Eighth Failure Mode: CLIENT/OST `date`"

    #Create files
    echo "Verify Lustre filesystem is up and running"
    [ -z "$(mounted_lustre_filesystems)" ] && error "Lustre is not running"

    clients_up
    client_touch testfile
	
    #CLIENT Portion
    echo "Failing CLIENTs"
    fail_clients 2

    #Check FS
    echo "Test Lustre stability after CLIENTs failure"
    clients_up
    $PDSH $LIVE_CLIENT "ls -l $TESTDIR"
    $PDSH $LIVE_CLIENT "rm -f $TESTDIR/*_testfile"

    #Sleep
    echo "Wait 1 minutes"
    sleep 60

    #Create files
    echo "Verify Lustre filesystem is up and running"
    [ -z "$(mounted_lustre_filesystems)" ] && error "Lustre is not running"

    clients_up
    client_touch testfile


    #OST Portion
    shutdown_facet ost1
    reboot_facet ost1

    #Check FS
    echo "Test Lustre stability after OST failure"
    clients_up &
    DFPID=$!
    sleep 5
    #non-failout hangs forever here
    #$PDSH $LIVE_CLIENT "ls -l $TESTDIR"
    #$PDSH $LIVE_CLIENT "rm -f $TESTDIR/*_testfile"
    
    #Reintegration
    echo "Reintegrating CLIENTs/OST"
    reintegrate_clients || return 3
    wait_for_facet ost1
    start_ost 1
    wait $DFPID
    clients_up || return 1
    client_touch testfile2 || return 2

    #Sleep
    echo "Wait 1 minutes"
    sleep 60
}
run_test 8 "Eighth Failure Mode: CLIENT/OST `date`"
###################################################


############### Ninth Failure Mode ###############
test_9() {
    echo 

    #Create files
    echo "Verify Lustre filesystem is up and running"
    [ -z "$(mounted_lustre_filesystems)" ] && error "Lustre is not running"

    clients_up
    client_touch testfile || return 1
	
    #CLIENT Portion
    echo "Failing CLIENTs"
    fail_clients 2

    #Check FS
    echo "Test Lustre stability after CLIENTs failure"
    clients_up
    $PDSH $LIVE_CLIENT "ls -l $TESTDIR" || return 1
    $PDSH $LIVE_CLIENT "rm -f $TESTDIR/*_testfile" || return 2

    #Sleep
    echo "Wait 1 minutes"
    sleep 60

    #Create files
    echo "Verify Lustre filesystem is up and running"
    client_up $LIVE_CLIENT || return 3
    client_touch testfile || return 4

    #CLIENT Portion
    echo "Failing CLIENTs"
    fail_clients 2
    
    #Check FS
    echo "Test Lustre stability after CLIENTs failure"
    clients_up
    $PDSH $LIVE_CLIENT "ls -l $TESTDIR" || return 5
    $PDSH $LIVE_CLIENT "rm -f $TESTDIR/*_testfile" || return 6

    #Reintegration
    echo "Reintegrating  CLIENTs/CLIENTs"
    reintegrate_clients || return 7
    clients_up
    
    #Sleep
    echo "Wait 1 minutes"
    sleep 60
}
run_test 9 "Ninth Failure Mode: CLIENT/CLIENT `date`"
###################################################

############### Tenth Failure Mode ###############
test_10() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return

	shutdown_facet mds1
	reboot_facet mds1

	# prepare for MDS failover
	change_active mds1
	reboot_facet mds1

	clients_up &
	DFPID=$!
	sleep 5

	shutdown_facet ost1

	echo "Reintegrating OST"
	reboot_facet ost1
	wait_for_facet ost1
	start_ost 1 || return 2

	shutdown_facet mds2
	reboot_facet mds2

	# prepare for MDS failover
	change_active mds2
	reboot_facet mds2

	wait_for_facet mds1
	start_mdt 1 || return $?

	wait_for_facet mds2
	start_mdt 2 || return $?

	#Check FS
	wait $DFPID
	clients_recover_osts ost1
	echo "Verify reintegration"
	clients_up || return 1
}
run_test 10 "Tenth Failure Mode: MDT0/OST/MDT1 `date`"
###################################################

############### Seventh Failure Mode ###############
test_11() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	echo "Verify Lustre filesystem is up and running"
	[ -z "$(mounted_lustre_filesystems)" ] && error "Lustre is not running"

	#MDS Portion
	fail mds1
	#Check FS

	echo "Test Lustre stability after MDS failover"
	clients_up

	#CLIENT Portion
	echo "Failing 2 CLIENTS"
	fail_clients 2

	#Check FS
	echo "Test Lustre stability after CLIENT failure"
	clients_up

	#Reintegration
	echo "Reintegrating CLIENTS"
	reintegrate_clients || return 1

	fail mds2

	clients_up || return 3
	sleep 2 # give it a little time for fully recovered before next test
}
run_test 11 "Eleventh Failure Mode: MDS0/CLIENT/MDS1 `date`"
###################################################

test_12() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	echo "Verify Lustre filesystem is up and running"
	[ -z "$(mounted_lustre_filesystems)" ] && error "Lustre is not running"

	#MDS Portion
	fail mds1,mds2
	clients_up

	#OSS Portion
	fail ost1,ost2
	clients_up

	#CLIENT Portion
	echo "Failing 2 CLIENTS"
	fail_clients 2

	#Check FS
	echo "Test Lustre stability after CLIENT failure"
	clients_up

	#Reintegration
	echo "Reintegrating CLIENTS"
	reintegrate_clients || return 1

	clients_up || return 3
	sleep 2 # give it a little time for fully recovered before next test
}
run_test 12 "Twelve Failure Mode: MDS0,MDS1/OST0, OST1/CLIENTS `date`"
###################################################

test_13() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	echo "Verify Lustre filesystem is up and running"
	[ -z "$(mounted_lustre_filesystems)" ] && error "Lustre is not running"

	#MDS Portion
	fail mds1,mds2
	clients_up

	#CLIENT Portion
	echo "Failing 2 CLIENTS"
	fail_clients 2

	#Check FS
	echo "Test Lustre stability after CLIENT failure"
	clients_up

	#Reintegration
	echo "Reintegrating CLIENTS"
	reintegrate_clients || return 1

	clients_up || return 3
	sleep 2 # give it a little time for fully recovered before next test

	#OSS Portion
	fail ost1,ost2
	clients_up || return 4
}
run_test 13 "Thirteen Failure Mode: MDS0,MDS1/CLIENTS/OST0,OST1 `date`"
###################################################

test_14() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	echo "Verify Lustre filesystem is up and running"
	[ -z "$(mounted_lustre_filesystems)" ] && error "Lustre is not running"

	#OST Portion
	fail ost1,ost2
	clients_up

	#CLIENT Portion
	echo "Failing 2 CLIENTS"
	fail_clients 2

	#Check FS
	echo "Test Lustre stability after CLIENT failure"
	clients_up

	#Reintegration
	echo "Reintegrating CLIENTS"
	reintegrate_clients || return 1

	clients_up || return 3
	sleep 2 # give it a little time for fully recovered before next test

	#OSS Portion
	fail mds1,mds2
	clients_up || return 4
}
run_test 14 "Fourteen Failure Mode: OST0,OST1/CLIENTS/MDS0,MDS1 `date`"
###################################################

test_15() {
    #Run availability after all failures
    DURATION=${DURATION:-$((2 * 60 * 60))} # 6 hours default
    LOADTEST=${LOADTEST:-metadata-load.py}
    $PWD/availability.sh $CONFIG $DURATION $CLIENTS || return 1
}
run_test 15 "Running Availability for 6 hours..."

complete $SECONDS
check_and_cleanup_lustre
exit_status
