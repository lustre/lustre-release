#!/bin/sh
# Test multiple failures, AKA Test 17

set -e

# command line
set - - `getopt -o r -l ostdev:,mdsdev:,stripecnt:,reformat -- $*`

for i in $*; do
    case $i in
	--ostdev) OSTDEV=$2; shift;;
	--mdsdev) MDSDEV=$2; shift;;
	--stripecnt) STRIPECNT=$2; shift;;
	-r|--reformat) REFORMAT=--reformat;;
    esac
    shift
done

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh

init_test_env

# . ./config-uml.sh

ALWAYS_EXCEPT="3 4 5 6 7 8 9 10"

build_test_filter

assert_env OSTDEV MDSDEV STRIPECNT

MDS1=${MDS1:-"mdev4"}
MDS2=${MDS2:-"mdev5"}
OST1=${OST1:-"mdev2"}
OST2=${OST2:-"mdev3"}
LIVE_CLIENT=${LIVE_CLIENT:-"mdev6"}
CLIENT1=${CLIENT1:-"mdev7"}
CLIENT2=${CLIENT2:-"mdev8"}
CLIENT3=${CLIENT3:-"mdev9"}
CLIENT4=${CLIENT4:-"mdev11"}
CLIENTS=${CLIENTS:-"mdev[6-9,11]"}

SERVERS="$MDS1 $MDS2 $OST1 $OST2"
CLIENTLIST="$LIVE_CLIENT $CLIENT1 $CLIENT2 $CLIENT3 $CLIENT4"

TIMEOUT=${TIMEOUT:-30}
PTLDEBUG=${PTLDEBUG:-0}
MOUNTPT=${MOUNTPT:-"/mnt/lustre"}
CLIENT_UPCALL=${CLIENT_UPCALL:-`pwd`/client-upcall-mdev.sh}


gen_config() {
    rm -f $XMLCONFIG
    # Add all nodes
    for node in $SERVERS; do
	${LMC} -m $XMLCONFIG --add net --node $node  --timeout $TIMEOUT\
            --nid `h2$NETTYPE $node` --nettype $NETTYPE
    done

    ${LMC} -m $XMLCONFIG --add net --node client \
            --timeout $TIMEOUT --upcall $CLIENT_UPCALL \
	    --nid '*' --nettype $NETTYPE

    # Configure MDS nodes
    for node in $MDS1 $MDS2; do
	$LMC -m $XMLCONFIG --node $node --add mds --mds mds_service  \
	     --fstype ext3 --dev $MDSDEV --size ${MDSSIZE:=50000000}
    done

    $LMC -m $XMLCONFIG --add lov --lov lov1 --mds mds_service \
        --stripe_sz 1048576 --stripe_cnt $STRIPECNT --stripe_pattern 0

    # Configure ost
    for node in $OST1 $OST2; do
	$LMC -m $XMLCONFIG --add ost --node $node --lov lov1 \
           --fstype ext3 --dev $OSTDEV --size ${OSTSIZE:=50000000}
    done

    $LMC -m $XMLCONFIG --node client --add mtpt --path $MOUNTPT \
	--mds mds_service --lov lov1
}

setup() {
    echo "$MDS1" > CURRENT_MDS
    ACTIVEMDS=$MDS1
    set -xv
    $DSH $OST1,$OST2 "$LCONF --ptldebug $PTLDEBUG $REFORMAT $XMLCONFIG"
    $DSH $MDS1 "$LCONF --select mds_service=$ACTIVEMDS --ptldebug $PTLDEBUG $REFORMAT $XMLCONFIG"
    $DSH $CLIENTS "$LCONF --node client --ptldebug $PTLDEBUG --select mds_service=$ACTIVEMDS $CLIENTOPTS $XMLCONFIG"
    set -+v
}

cleanup() {
    ACTIVEMDS=`cat CURRENT_MDS`
    $DSH $CLIENTS "$LCONF --cleanup --node client --select mds_service=$ACTIVEMDS  $XMLCONFIG"
    $DSH $ACTIVEMDS "$LCONF --cleanup --select mds_service=$ACTIVE_MDS $XMLCONFIG"
    $DSH $OST1,$OST2 "$LCONF --cleanup $XMLCONFIG"
}

wait_for() {
   NODE=$1
   set +x
   check_network $NODE 900
   while ! $DSH2 $NODE "ls -ld $LUSTRE"; do sleep 5; done
   set -x
}

client_df() {
    $DSH2 $CLIENTS "df $MOUNTPT" | dshbak -c
}

trap exit INT

client_mkdirs() {
   $DSH2 $CLIENTS "mkdir $MOUNTPT/\`hostname\`; ls $MOUNTPT/\`hostname\` > /dev/null"
}

fail_mds() {
    FROM=$1
    TO=$2
    echo "Failing MDS $FROM"
    rm CURRENT_MDS
    shutdown_node $FROM
    sleep 2
    client_df &
    DFPID=$!
    echo "Failover MDS is $TO"
    wait_for $TO
    $DSH2 $TO "$LCONF --select mds_service=$TO $XMLCONFIG"

    #pdsh -w $MDS1 nodeup
    #cd /usr/local/admin/lustre-alc/cfg
    #../bin/mount-lustre-shaver.sh -f alc-ga1-ddn-llp-2mds.cfg -s mds -m alc2 -c alc36
    #cd /home/jodorizz

    restart_node $FROM
    echo "$TO" > CURRENT_MDS
}

fail_clients() {
    client_mkdirs
    shutdown_node $CLIENT1
    shutdown_node $CLIENT2
    restart_node $CLIENT1
    restart_node $CLIENT2
    $DSH2 $LIVE_CLIENT "cd $MOUNTPT && rmdir $CLIENTLIST"
}

reintegrate_clients() {
    ACTIVEMDS=`cat CURRENT_MDS`
    wait_for $CLIENT1
    wait_for $CLIENT2
    $DSH2 $CLIENT1 "$LCONF --node client --select mds_service=$ACTIVEMDS $CLIENTOPTS $XMLCONFIG"
    $DSH2 $CLIENT2 "$LCONF --node client --select mds_service=$ACTIVEMDS $CLIENTOPTS $XMLCONFIG"
}

clients_recover_osts() {
    OST=$1
    $DSH2 $CLIENTS "$LCTL "'--device %OSC_`hostname`_OST_'"${OST}_MNT_client recover"
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
    rm CURRENT_MDS
    shutdown_node $MDS1
    restart_node $MDS2

    client_df &
    DFPID=$!
    sleep 5

    echo "Failing OST"
    shutdown_node $OST1

    echo "Reintegrating OST"
    restart_node $OST1
    wait_for $OST1
    $DSH2 $OST1 "$LCONF $XMLCONFIG"

    echo "Failover MDS"
    wait_for $MDS2
    $DSH2 $MDS2 "$LCONF --select mds_service=$MDS2 $XMLCONFIG"
    echo "$MDS2" > CURRENT_MDS
    restart_node $MDS1
    #Check FS

    wait $DFPID
    clients_recover_osts $OST1
    echo "Verify reintegration"
    client_df

}
run_test 2 "Second Failure Mode: MDS/OST `date`"
###################################################


############### Third Failure Mode ###############
test_3() {
    echo "Third Failure Mode: MDS/CLIENT `date`"

    #Create files
    echo "Verify Lustre filesystem is up and running"
    $DSH2 $CLIENTS "df -h $MOUNTPT" | dshbak -c
    
    #MDS Portion
    fail_mds $MDS2 $MDS1
    wait $DFPID || echo df failed: $?
    restart_node $MDS2
    #Check FS

    echo "Test Lustre stability after MDS failover"
    client_df

    #CLIENT Portion
    echo "Failing 2 CLIENTS"
    fail_clients
    
    #Check FS
    echo "Test Lustre stability after CLIENT failure"
    client_df
    
    #Reintegration
    echo "Reintegrating CLIENTS"
    reintegrate_clients $MDS1

    client_df

    #Sleep
}
run_test 3  "Thirdb Failure Mode: MDS/CLIENT `date`"
###################################################

############### Fourth Failure Mode ###############
test_4() {
    echo "Fourth Failure Mode: OST/MDS `date`"

    #OST Portion
    echo "Failing OST $OST1"
    shutdown_node $OST1
 
    #Check FS
    echo "Test Lustre stability after OST failure"
    client_df

    #MDS Portion
    echo "Failing MDS"
    rm CURRENT_MDS
    shutdown_node $MDS1
    restart_node $MDS2

    client_df &
    DFPID=$!
    sleep 5

    #Reintegration
    echo "Reintegrating OST"
    restart_node $OST1
	wait_for $OST1
    $DSH2 $OST1 "$LCONF $XMLCONFIG"
    
    echo "Failover MDS"
    wait_for $MDS2
    $DSH2 $MDS2 "$LCONF--select mds_service=$MDS2 $XMLCONFIG"
    echo "$MDS2" > CURRENT_MDS
    #Check FS
    
    wait $DFPID
    clients_recover_oscs
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
    shutdown_node $OST1
    restart_node $OST1
    
    #Check FS
    echo "Test Lustre stability after OST failure"
    client_df
    
    #OST Portion
    echo "Failing OST"
    shutdown_node $OST2
    restart_node $OST1

    #Check FS
    echo "Test Lustre stability after OST failure"
    client_df

    #Reintegration
    echo "Reintegrating OSTs"
    wait_for $OST1
    wait_for $OST2
    $DSH2 $OST1 "$LCONF $XMLCONFIG"
    $DSH2 $OST2 "$LCONF $XMLCONFIG"
    
    clients_recover_osts $OST1
    clients_recover_osts $OST2
    client_df
}
run_test 5 "Fifth Failure Mode: OST/OST `date`"
###################################################

############### Sixth Failure Mode ###############
test_6() {
    echo "Sixth Failure Mode: OST/CLIENT `date`"

    #Create files
    echo "Verify Lustre filesystem is up and running"
    $DSH2 $CLIENTS "df $MOUNTPT"
    $DSH2 $CLIENTS "/bin/touch $MOUNTPT/\`hostname\`_testfile"
	
    #OST Portion
    echo "Failing OST"
    shutdown_node $OST1
    restart_node $OST1

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
    wait_for $OST1
    $DSH2 $OST1 "$LCONF $XMLCONFIG"
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
    $DSH2 $CLIENTS "df $MOUNTPT"
    $DSH2 $CLIENTS "/bin/touch $MOUNTPT/\`hostname\`_testfile"

    #CLIENT Portion
    echo "Part 1: Failing CLIENT"
    shutdown_node $CLIENT1
    shutdown_node $CLIENT2
    restart_node $CLIENT1
    restart_node $CLIENT2
    check_network $CLIENT1 900
    check_network $CLIENT2 900
    
    #Check FS
    echo "Test Lustre stability after CLIENTs failure"
    $DSH2 $CLIENTS "df $MOUNTPT"
    $DSH2 $LIVE_CLIENT "ls -l $MOUNTPT"
    $DSH2 $LIVE_CLIENT "rm -f $MOUNTPT/*_testfile"
    
    #Sleep
    echo "Wait 1 minutes"
    sleep 60

    #Create files
    echo "Verify Lustre filesystem is up and running"
    $DSH2 $CLIENTS "df $MOUNTPT"
    $DSH2 $CLIENTS "/bin/touch $MOUNTPT/\`hostname\`_testfile"

    #MDS Portion
    echo "Failing MDS"
    shutdown_node $MDS2
    sleep 5
    restart_node $MDS2
    echo "Failover MDS"
    check_port $MDS1 988
    $DSH2 $MDS1 "hostname"
    sleep 2
    $DSH2 $MDS1 "$LCONF --select mds_service=$MDS1 $XMLCONFIG"
    #pdsh -w $MDS1 nodeup
    #cd /usr/local/admin/lustre-alc/cfg
    #../bin/mount-lustre-shaver.sh -f alc-ga1-ddn-llp-2mds.cfg -s mds -m alc2 -c alc36
    #cd /home/jodorizz
    echo "$MDS1" > CURRENT_MDS

    #Check FS
    echo "Test Lustre stability after MDS failover"
    $DSH2 $CLIENTS "df $MOUNTPT"
    $DSH2 $LIVE_CLIENT "ls -l $MOUNTPT"
    $DSH2 $LIVE_CLIENT "rm -f $MOUNTPT/*_testfile"

    #Reintegration
    echo "Reintegrating CLIENTs"
    $DSH2 $CLIENT1 "hostname"
    sleep 2
    $DSH2 $CLIENT1 "$LCONF $CLIENTOPTS $XMLCONFIG"
    $DSH2 $CLIENT2 "hostname"
    sleep 2
    $DSH2 $CLIENT2 "$LCONF $CLIENTOPTS $XMLCONFIG"
    $DSH2 $CLIENTS "hostname"
    sleep 2
    $DSH2 $CLIENTS "df $MOUNTPT"
    
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
    $DSH2 $CLIENTS "df $MOUNTPT"
    $DSH2 $CLIENTS "/bin/touch $MOUNTPT/\`hostname\`_testfile"
	
    #CLIENT Portion
    echo "Failing CLIENTs"
    shutdown_node $CLIENT1
    shutdown_node $CLIENT2
    restart_node $CLIENT1
    restart_node $CLIENT2
    check_network $CLIENT1 900
    check_network $CLIENT2 900

    #Check FS
    echo "Test Lustre stability after CLIENTs failure"
    $DSH2 $CLIENTS "df $MOUNTPT"
    $DSH2 $LIVE_CLIENT "ls -l $MOUNTPT"
    $DSH2 $LIVE_CLIENT "rm -f $MOUNTPT/*_testfile"

    #Sleep
    echo "Wait 1 minutes"
    sleep 60

    #Create files
    echo "Verify Lustre filesystem is up and running"
    $DSH2 $CLIENTS "df $MOUNTPT"
    $DSH2 $CLIENTS "/bin/touch $MOUNTPT/\`hostname\`_testfile"

    #OST Portion
    echo "Failing OST"
    shutdown_node $OST1
    restart_node $OST1

    #Check FS
    echo "Test Lustre stability after OST failure"
    $DSH2 $CLIENTS "df $MOUNTPT"
    $DSH2 $LIVE_CLIENT "ls -l $MOUNTPT"
    $DSH2 $LIVE_CLIENT "rm -f $MOUNTPT/*_testfile"
    
    #Reintegration
    echo "Reintegrating CLIENTs/OST"
    $DSH2 $CLIENT1 "hostname"
    sleep 2
    $DSH2 $CLIENT1 "$LCONF $CLIENTOPTS $XMLCONFIG"
    $DSH2 $CLIENT2 "hostname"
    sleep 2
    $DSH2 $CLIENT2 "$LCONF $CLIENTOPTS $XMLCONFIG"
    check_network $OST1 900
    check_port $OST1 988
    $DSH2 $OST1 "hostname"
    sleep 2
    $DSH2 $OST1 "$LCONF $XMLCONFIG"
    $DSH2 $CLIENTS "df $MOUNTPT"
    $DSH2 $CLIENTS "/bin/touch $MOUNTPT/CLIENT_OST_2\`hostname\`_testfile"

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
    $DSH2 $CLIENTS "df $MOUNTPT"
    $DSH2 $CLIENTS "/bin/touch $MOUNTPT/\`hostname\`_testfile"
	
    #CLIENT Portion
    echo "Failing CLIENTs"
    shutdown_node $CLIENT1
    shutdown_node $CLIENT2
    restart_node $CLIENT1
    restart_node $CLIENT2
    check_network $CLIENT1 900
    check_network $CLIENT2 900

    #Check FS
    echo "Test Lustre stability after CLIENTs failure"
    $DSH2 $CLIENTS "df $MOUNTPT"
    $DSH2 $LIVE_CLIENT "ls -l $MOUNTPT"
    $DSH2 $LIVE_CLIENT "rm -f $MOUNTPT/*_testfile"

    #Sleep
    echo "Wait 1 minutes"
    sleep 60

    #Create files
    echo "Verify Lustre filesystem is up and running"
    $DSH2 $CLIENTS "df $MOUNTPT"
    $DSH2 $CLIENTS "/bin/touch $MOUNTPT/\`hostname\`_testfile"

    #CLIENT Portion
    echo "Failing CLIENTs"
    shutdown_node $CLIENT3
    shutdown_node $CLIENT4
    restart_node $CLIENT3
    restart_node $CLIENT4
    check_network $CLIENT3 900
    check_network $CLIENT4 900

    #Check FS
    echo "Test Lustre stability after CLIENTs failure"
    $DSH2 $CLIENTS "df $MOUNTPT"
    $DSH2 $LIVE_CLIENT "ls -l $MOUNTPT"
    $DSH2 $LIVE_CLIENT "rm -f $MOUNTPT/*_testfile"

    #Reintegration
    echo "Reintegrating  CLIENTs/CLIENTs"
    $DSH2 $CLIENT1 "hostname"
    sleep 2
    $DSH2 $CLIENT1 "$LCONF $CLIENTOPTS $XMLCONFIG"
    $DSH2 $CLIENT2 "hostname"
    sleep 2
    $DSH2 $CLIENT2 "$LCONF $CLIENTOPTS $XMLCONFIG"
    $DSH2 $CLIENT3 "hostname"
    sleep 2
    $DSH2 $CLIENT3 "$LCONF $CLIENTOPTS $XMLCONFIG"
    $DSH2 $CLIENT4 "hostname"
    sleep 2
    $DSH2 $CLIENT4 "$LCONF $CLIENTOPTS $XMLCONFIG"
    sleep 5
    $DSH2 $CLIENTS "hostname"
    $DSH2 $CLIENTS "df $MOUNTPT"
    
    #Sleep
    echo "Wait 1 minutes"
    sleep 60
}
run_test 9 "Ninth Failure Mode: CLIENT/CLIENT `date`"
###################################################

test_10 {
    #Run availability after all failures
    ./availability.sh  21600
}
run_test 10 "Running Availability for 6 hours..."
