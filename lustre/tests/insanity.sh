#!/bin/sh
# Test multiple failures, AKA Test 17

set -e

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh

init_test_env $@

. ${CONFIG:=$LUSTRE/tests/cfg/insanity-local.sh}

ALWAYS_EXCEPT="7 8 9 10"

build_test_filter

assert_env mds_HOST ost1_HOST ost2_HOST client_HOST LIVE_CLIENT 

# This can be a regexp, to allow more clients
CLIENTS=${CLIENTS:-"`comma_list $LIVE_CLIENT $FAIL_CLIENTS`"}

CLIENTLIST="$LIVE_CLIENT $FAIL_CLIENTS"

DIR=${DIR:-$MOUNT}

#####
# fail clients round robin

# list of failable clients
FAIL_LIST=($FAIL_CLIENTS)
FAIL_NUM=${#FAIL_LIST[*]}
FAIL_NEXT=0
DOWN_NUM=0   # number of nodes currently down

# return next client to fail
fail_client() {
    ret=${FAIL_LIST[$FAIL_NEXT]}
    FAIL_NEXT=$(( (FAIL_NEXT+1) % FAIL_NUM ))
    echo $ret
}

fail_clients() {
    num=$1
    if [ -z "$num" -o $num -gt $((FAIL_NUM - DOWN_NUM)) ]; then
	num=$((FAIL_NUM - DOWN_NUM)) 
    fi
    
    if [ -z "$num"  -o $num -le 0 ]; then
        return
    fi

    for i in `seq $num`; do
       client=`fail_client`
       DOWN_CLIENTS="$DOWN_CLIENTS $client"
       client_mkdirs
       shutdown_client $client
    done

    for client in $DOWN_CLIENTS; do
	restart_node $client
    done
    DOWN_NUM=`echo $DOWN_CLIENTS | wc -w`
    $PDSH $LIVE_CLIENT "cd $MOUNT && rmdir $CLIENTLIST"
}

reintegrate_clients() {
    for client in $DOWN_CLIENTS; do
	wait_for $client
	$PDSH $client "$LCONF --node client --select mds_svc=`facet_active mds` $CLIENTOPTS $XMLCONFIG"
    done
    DOWN_CLIENTS=""
    DOWN_NUM=0
}

gen_config() {
    rm -f $XMLCONFIG
    add_mds mds --dev $MDSDEV --size $MDSSIZE

    if [ ! -z "$mdsfailover_HOST" ]; then
	 add_mdsfailover mds --dev $MDSDEV --size $MDSSIZE
    fi

    add_lov lov1 mds --stripe_sz $STRIPE_BYTES\
	--stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
    add_ost ost1 --lov lov1 --dev $OSTDEV --size $OSTSIZE
    add_ost ost2 --lov lov1 --dev ${OSTDEV}-2 --size $OSTSIZE
    add_client client mds --lov lov1 --path $MOUNT
}

setup() {
    start ost1 ${REFORMAT} $OSTLCONFARGS 
    start ost2 ${REFORMAT} $OSTLCONFARGS 
    [ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE
    start mds $MDSLCONFARGS ${REFORMAT}
    for node in $CLIENTS; do
	$PDSH $node lconf --node client_facet --ptldebug $PTLDEBUG --select mds_service=$ACTIVEMDS $XMLCONFIG
    done
}

cleanup() {
    # make sure we are using the primary MDS, so the config log will
    # be able to clean up properly.
    activemds=`facet_active mds`
    if [ $activemds != "mds" ]; then
        fail mds
    fi
    for node in $CLIENTS; do
	$PDSH $node lconf ${FORCE} --cleanup --node client_facet $XMLCONFIG
    done

    stop mds ${FORCE} $MDSLCONFARGS
    stop ost1 ${FORCE}
    stop ost2 ${FORCE} --dump cleanup.log
}

wait_for() {
   facet=$1
   check_network `facet_active_host $facet` 900
   while ! $PDSH $NODE "ls -ld $LUSTRE"; do sleep 5; done
}

client_df() {
    $PDSH $CLIENTS "df $MOUNT" | dshbak -c
}

trap exit INT

client_mkdirs() {
   $PDSH $CLIENTLIST "mkdir $MOUNT/\`hostname\`; ls $MOUNT/\`hostname\` > /dev/null"
}

facet_failover() {
    facet=$1
    echo "Failing $facet node `facet_active_host $facet`"
    shutdown_facet $facet
    sleep 2
    reboot_facet $facet
    client_df &
    DFPID=$!
    change_active $facet
    TO=`facet_active_host $facet`
    echo "Failover MDS to $TO"
    wait_for $facet
    start $facet
}


clients_recover_osts() {
    facet=$1
    $PDSH $CLIENTS "$LCTL "'--device %OSC_`hostname`_OST_'"${facet}_svc_MNT_client recover"
}

if [ "$ONLY" == "cleanup" ]; then
    cleanup
    exit
fi

gen_config
setup

if [ "$ONLY" == "setup" ]; then
    exit 0
fi

# 9 Different Failure Modes Combinations
echo "Starting Test 17 at `date`"

test_0() {
    echo "Failover MDS"
    shutdown_facet mds
    reboot_facet mds
    # prepare for MDS failover
    change_active mds
    reboot_facet mds
    start mds
    client_df

    echo "Failing OST1"
    shutdown_facet ost1
    reboot_facet ost1
    wait_for ost1
    start ost1
    client_df
    # should force the MDS to reconnect to the ost
    echo "ost1 recover" >> $DIR/$tfile

    echo "Failing OST2"
    shutdown_facet ost2
    reboot_facet ost2
    wait_for ost2
    start ost2
    client_df
    # should force the MDS to reconnect to the ost
    echo "ost2 recover" >> $DIR/${tfile}2

}
run_test 0 "Fail all nodes, independently"

############### First Failure Mode ###############
test_1() {
echo "Don't do a MDS - MDS Failure Case"
echo "This makes no sense"
# FIXME every test makes sense
}
run_test 1 "MDS/MDS failure"
###################################################

############### Second Failure Mode ###############
test_2() {
    echo "Verify Lustre filesystem is up and running"
    client_df

    echo "Failing MDS"
    shutdown_facet mds
    reboot_facet mds

    # prepare for MDS failover
    change_active mds
    reboot_facet mds

    client_df &
    DFPID=$!
    sleep 5

    echo "Failing OST"
    shutdown_facet ost1

    echo "Reintegrating OST"
    reboot_facet ost1
    wait_for ost1
    start ost1

    echo "Failover MDS"
    wait_for mds
    start mds

    #Check FS
    wait $DFPID
    clients_recover_osts ost1
    echo "Verify reintegration"
    client_df

}
run_test 2 "Second Failure Mode: MDS/OST `date`"
###################################################


############### Third Failure Mode ###############
test_3() {
    #Create files
    echo "Verify Lustre filesystem is up and running"
    
    #MDS Portion
    facet_failover mds
    wait $DFPID || echo df failed: $?
    #Check FS

    echo "Test Lustre stability after MDS failover"
    client_df

    #CLIENT Portion
    echo "Failing 2 CLIENTS"
    fail_clients 2
    
    #Check FS
    echo "Test Lustre stability after CLIENT failure"
    client_df
    
    #Reintegration
    echo "Reintegrating CLIENTS"
    reintegrate_clients

    client_df
}
run_test 3  "Thirdb Failure Mode: MDS/CLIENT `date`"
###################################################

############### Fourth Failure Mode ###############
test_4() {
    echo "Fourth Failure Mode: OST/MDS `date`"

    #OST Portion
    echo "Failing OST ost1"
    shutdown_facet ost1
 
    #Check FS
    echo "Test Lustre stability after OST failure"
    client_df

    #MDS Portion
    echo "Failing MDS"
    shutdown_facet mds
    reboot_facet mds

    # prepare for MDS failover
    change_active mds
    reboot_facet mds

    client_df &
    DFPID=$!
    sleep 5

    #Reintegration
    echo "Reintegrating OST"
    reboot_node ost1
    wait_for ost1
    start ost1
    
    echo "Failover MDS"
    wait_for mds
    start mds
    #Check FS
    
    wait $DFPID
    clients_recover_osts ost1
    echo "Test Lustre stability after MDS failover"
    client_df
}
run_test 4 "Fourth Failure Mode: OST/MDS `date`"
###################################################

############### Fifth Failure Mode ###############
test_5() {
    echo "Fifth Failure Mode: OST/OST `date`"

    #Create files
    echo "Verify Lustre filesystem is up and running"
    client_df
    
    #OST Portion
    echo "Failing OST"
    shutdown_facet ost1
    reboot_node ost1
    
    #Check FS
    echo "Test Lustre stability after OST failure"
    client_df
    
    #OST Portion
    echo "Failing OST"
    shutdown_node ost2
    reboot_node ost2

    #Check FS
    echo "Test Lustre stability after OST failure"
    client_df

    #Reintegration
    echo "Reintegrating OSTs"
    wait_for ost1
    wait_for ost1
    start ost1
    start ost2
    
    clients_recover_osts ost1
    clients_recover_osts ost2
    client_df
}
run_test 5 "Fifth Failure Mode: OST/OST `date`"
###################################################

############### Sixth Failure Mode ###############
test_6() {
    echo "Sixth Failure Mode: OST/CLIENT `date`"

    #Create files
    echo "Verify Lustre filesystem is up and running"
    client_df
    $PDSH $CLIENTS "/bin/touch $MOUNT/\`hostname\`_testfile"
	
    #OST Portion
    echo "Failing OST"
    shutdown_node ost1
    reboot_node ost1

    #Check FS
    echo "Test Lustre stability after OST failure"
    client_df

    #CLIENT Portion
    echo "Failing CLIENTs"
    fail_clients
    
    #Check FS
    echo "Test Lustre stability after CLIENTs failure"
    client_df
    
    #Reintegration
    echo "Reintegrating OST/CLIENTs"
    wait_for ost1
    start ost1
    reintegrate_clients
    
    echo "Verifying mount"
    client_df
}
run_test 6 "Sixth Failure Mode: OST/CLIENT `date`"
###################################################


############### Seventh Failure Mode ###############
test_7() {
    echo "Seventh Failure Mode: CLIENT/MDS `date`"

    #Create files
    echo "Verify Lustre filesystem is up and running"
    client_df
    $PDSH $CLIENTS "/bin/touch $MOUNT/\`hostname\`_testfile"

    #CLIENT Portion
    echo "Part 1: Failing CLIENT"
    fail_clients 2
    
    #Check FS
    echo "Test Lustre stability after CLIENTs failure"
    client_df
    $PDSH $LIVE_CLIENT "ls -l $MOUNT"
    $PDSH $LIVE_CLIENT "rm -f $MOUNT/*_testfile"
    
    #Sleep
    echo "Wait 1 minutes"
    sleep 60

    #Create files
    echo "Verify Lustre filesystem is up and running"
    client_df
    $PDSH $CLIENTS "/bin/touch $MOUNT/\`hostname\`_testfile"

    #MDS Portion
    echo "Failing MDS"
    facet_failover mds

    #Check FS
    echo "Test Lustre stability after MDS failover"
    client_df
    $PDSH $LIVE_CLIENT "ls -l $MOUNT"
    $PDSH $LIVE_CLIENT "rm -f $MOUNT/*_testfile"

    #Reintegration
    echo "Reintegrating CLIENTs"
    reintegrate_clients
    client_df
    
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
    client_df
    $PDSH $CLIENTS "/bin/touch $MOUNT/\`hostname\`_testfile"
	
    #CLIENT Portion
    echo "Failing CLIENTs"
    fail_clients 2

    #Check FS
    echo "Test Lustre stability after CLIENTs failure"
    client_df
    $PDSH $LIVE_CLIENT "ls -l $MOUNT"
    $PDSH $LIVE_CLIENT "rm -f $MOUNT/*_testfile"

    #Sleep
    echo "Wait 1 minutes"
    sleep 60

    #Create files
    echo "Verify Lustre filesystem is up and running"
    client_df
    $PDSH $CLIENTS "/bin/touch $MOUNT/\`hostname\`_testfile"

    #OST Portion
    echo "Failing OST"
    shutdown_node ost1
    reboot_node ost1

    #Check FS
    echo "Test Lustre stability after OST failure"
    client_df
    $PDSH $LIVE_CLIENT "ls -l $MOUNT"
    $PDSH $LIVE_CLIENT "rm -f $MOUNT/*_testfile"
    
    #Reintegration
    echo "Reintegrating CLIENTs/OST"
    reintegrate_clients
    start ost1
    client_df
    $PDSH $CLIENTS "/bin/touch $MOUNT/CLIENT_OST_2\`hostname\`_testfile"

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
    client_df
    $PDSH $CLIENTS "/bin/touch $MOUNT/\`hostname\`_testfile"
	
    #CLIENT Portion
    echo "Failing CLIENTs"
    fail_clients 2

    #Check FS
    echo "Test Lustre stability after CLIENTs failure"
    client_df
    $PDSH $LIVE_CLIENT "ls -l $MOUNT"
    $PDSH $LIVE_CLIENT "rm -f $MOUNT/*_testfile"

    #Sleep
    echo "Wait 1 minutes"
    sleep 60

    #Create files
    echo "Verify Lustre filesystem is up and running"
    client_df
    $PDSH $CLIENTS "/bin/touch $MOUNT/\`hostname\`_testfile"

    #CLIENT Portion
    echo "Failing CLIENTs"
    fail_clients 2
    
    #Check FS
    echo "Test Lustre stability after CLIENTs failure"
    client_df
    $PDSH $LIVE_CLIENT "ls -l $MOUNT"
    $PDSH $LIVE_CLIENT "rm -f $MOUNT/*_testfile"

    #Reintegration
    echo "Reintegrating  CLIENTs/CLIENTs"
    reintegrate_clients
    client_df
    
    #Sleep
    echo "Wait 1 minutes"
    sleep 60
}
run_test 9 "Ninth Failure Mode: CLIENT/CLIENT `date`"
###################################################

test_10() {
    #Run availability after all failures
    ./availability.sh  21600
}
run_test 10 "Running Availability for 6 hours..."

equals_msg "Done, cleaning up"
cleanup
