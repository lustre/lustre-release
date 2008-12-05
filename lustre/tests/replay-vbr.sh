#!/bin/bash

set -e

# bug number:
ALWAYS_EXCEPT="3c 4b 4c 10 $REPLAY_VBR_EXCEPT"

SAVE_PWD=$PWD
PTLDEBUG=${PTLDEBUG:--1}
LUSTRE=${LUSTRE:-`dirname $0`/..}
SETUP=${SETUP:-""}
CLEANUP=${CLEANUP:-""}
. $LUSTRE/tests/test-framework.sh

init_test_env $@

. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

[ -n "$CLIENTS" ] || { skip "Need two or more clients" && exit 0; }
[ $CLIENTCOUNT -ge 2 ] || \
    { skip "Need two or more clients, have $CLIENTCOUNT" && exit 0; }
remote_mds_nodsh && skip "remote MDS with nodsh" && exit 0

[ "$SLOW" = "no" ] && EXCEPT_SLOW=""


[ ! "$NAME" = "ncli" ] && ALWAYS_EXCEPT="$ALWAYS_EXCEPT"
[ "$NAME" = "ncli" ] && MOUNT_2=""
MOUNT_2=""
build_test_filter

check_and_setup_lustre
rm -rf $DIR/[df][0-9]*

[ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE

[ "$CLIENTS" ] && zconf_umount_clients $CLIENTS $DIR

test_1() {
    echo "mount client $CLIENT1,$CLIENT2..."
    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    do_node $CLIENT2 mkdir -p $DIR/$tdir
    replay_barrier mds
    do_node $CLIENT1 createmany -o $DIR/$tfile- 25
    do_node $CLIENT2 createmany -o $DIR/$tdir/$tfile-2- 1
    do_node $CLIENT1 createmany -o $DIR/$tfile-3- 25
    zconf_umount $CLIENT2 $DIR

    facet_failover mds
    # recovery shouldn't fail due to missing client 2
    do_node $CLIENT1 df $DIR || return 1

    # All 50 files should have been replayed
    do_node $CLIENT1 unlinkmany $DIR/$tfile- 25 || return 2
    do_node $CLIENT1 unlinkmany $DIR/$tfile-3- 25 || return 3

    zconf_mount $CLIENT2 $DIR || error "mount $CLIENT2 $DIR fail"
    [ -e $DIR/$tdir/$tfile-2-0 ] && error "$tfile-2-0 exists"

    zconf_umount_clients $CLIENTS $DIR
    return 0
}
run_test 1 "VBR: client during replay doesn't affect another one"

test_2() {
    #ls -al $DIR/$tdir/$tfile

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    do_node $CLIENT2 mkdir -p $DIR/$tdir
    replay_barrier mds
    do_node $CLIENT2 mcreate $DIR/$tdir/$tfile
    do_node $CLIENT1 createmany -o $DIR/$tfile- 25
    #do_node $CLIENT2 createmany -o $DIR/$tdir/$tfile-2- 1
    do_node $CLIENT1 $CHECKSTAT $DIR/$tdir/$tfile
    do_node $CLIENT1 createmany -o $DIR/$tfile-3- 25
    zconf_umount $CLIENT2 $DIR

    facet_failover mds
    # recovery shouldn't fail due to missing client 2
    do_node $CLIENT1 df $DIR || return 1

    # All 50 files should have been replayed
    do_node $CLIENT1 unlinkmany $DIR/$tfile- 25 || return 2
    do_node $CLIENT1 unlinkmany $DIR/$tfile-3- 25 || return 3

    do_node $CLIENT1 $CHECKSTAT $DIR/$tdir/$tfile && return 4

    zconf_mount $CLIENT2 $DIR || error "mount $CLIENT2 $DIR fail"

    zconf_umount_clients $CLIENTS $DIR
    return 0
}
run_test 2 "VBR: lost data due to missed REMOTE client during replay"

test_3a() {
    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    #make sure the time will change
    do_facet mds "$LCTL set_param mds.${mds_svc}.atime_diff=0" || return
    do_node $CLIENT1 touch $DIR/$tfile
    do_node $CLIENT2 $CHECKSTAT $DIR/$tfile
    sleep 1
    replay_barrier mds
    #change time
    do_node $CLIENT2 touch $DIR/$tfile
    do_node $CLIENT2 $CHECKSTAT $DIR/$tfile
    #another change
    do_node $CLIENT1 touch $DIR/$tfile
    #remove file
    do_node $CLIENT2 rm $DIR/$tfile
    zconf_umount $CLIENT2 $DIR

    facet_failover mds
    # recovery shouldn't fail due to missing client 2
    do_node $CLIENT1 df $DIR || return 1
    do_node $CLIENT1 $CHECKSTAT $DIR/$tfile && return 2

    zconf_mount $CLIENT2 $DIR || error "mount $CLIENT2 $DIR fail"

    zconf_umount_clients $CLIENTS $DIR

    return 0
}
run_test 3a "VBR: setattr of time/size doesn't change version"

test_3b() {
    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    #make sure the time will change
    do_facet mds "$LCTL set_param mds.${mds_svc}.atime_diff=0" || return
    do_facet mds "$LCTL set_param mds.${mds_svc}.sync_permission=0" || return
    do_node $CLIENT1 touch $DIR/$tfile
    do_node $CLIENT2 $CHECKSTAT $DIR/$tfile
    sleep 1
    replay_barrier mds
    #change mode
    do_node $CLIENT2 chmod +x $DIR/$tfile
    do_node $CLIENT2 $CHECKSTAT $DIR/$tfile
    #abother chmod
    do_node $CLIENT1 chmod -x $DIR/$tfile
    zconf_umount $CLIENT2 $DIR

    facet_failover mds
    # recovery should fail due to missing client 2
    do_node $CLIENT1 df $DIR && return 1

    do_node $CLIENT1 $CHECKSTAT -p 755 $DIR/$tfile && return 2
    zconf_mount $CLIENT2 $DIR || error "mount $CLIENT2 $DIR fail"

    zconf_umount_clients $CLIENTS $DIR

    return 0
}
run_test 3b "VBR: setattr of permissions changes version"

test_3c() {
    [ "$FAILURE_MODE" = HARD ] || \
        { skip "The HARD failure is needed" && return 0; }

    [ $RUNAS_ID -eq $UID ] && skip "RUNAS_ID = UID = $UID -- skipping" && return

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    # check that permission changes are synced
    do_facet mds "$LCTL set_param mds.${mds_svc}.sync_permission=1"

    do_node $CLIENT1 mkdir -p $DIR/d3c/sub || error
    #chown -R $RUNAS_ID $MOUNT1/d3
    do_node $CLIENT1 ls -la $DIR/d3c

    # only HARD failure will work as we use sync operation
    replay_barrier mds
    do_node $CLIENT2 mcreate $DIR/d3c/$tfile-2
    #set permissions
    do_node $CLIENT1 chmod 0700 $UID $DIR/d3c
    #secret file
    do_node $CLIENT1 mcreate $DIR/d3c/sub/$tfile
    do_node $CLIENT1 echo "Top Secret" > $DIR/d3c/sub/$tfile
    #check user can't access new file
    do_node $CLIENT2 $RUNAS ls $DIR/d3c && return 3
    do_node $CLIENT1 $RUNAS ls $DIR/d3c && return 4
    do_node $CLIENT1 $RUNAS cat $DIR/d3c/sub/$tfile && return 5

    zconf_umount $CLIENT2 $DIR

    facet_failover mds
    # recovery shouldn't fail due to missing client 2
    do_node $CLIENT1 df $DIR || return 1
    sleep 1

    zconf_mount $CLIENT2 $DIR || error "mount $CLIENT2 $DIR fail"
    do_node $CLIENT1 $RUNAS cat $DIR/d3c/sub/$tfile && return 6
    do_node $CLIENT2 $RUNAS cat $DIR/d3c/sub/$tfile && return 7
    do_facet mds "$LCTL set_param mds.${mds_svc}.sync_permission=0"

    return 0
}
run_test 3c "VBR: permission dependency failure"

vbr_deactivate_client() {
    local client=$1
    echo "Deactivating client $client";
    do_node $client "sysctl -w lustre.fail_loc=0x50d"
}

vbr_activate_client() {
    local client=$1
    echo "Activating client $client";
    do_node $client "sysctl -w lustre.fail_loc=0x0"
}

remote_server ()
{
    local client=$1
    [ -z "$(do_node $client lctl dl | grep mdt)" ] && \
    [ -z "$(do_node $client lctl dl | grep ost)" ]
}

test_4a() {
    remote_server $CLIENT2 || \
        { skip "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    do_node $CLIENT2 mkdir -p $DIR/$tdir
    replay_barrier mds
    do_node $CLIENT1 createmany -o $DIR/$tfile- 25
    do_node $CLIENT2 createmany -o $DIR/$tdir/$tfile-2- 25
    do_node $CLIENT1 createmany -o $DIR/$tfile-3- 25
    vbr_deactivate_client $CLIENT2

    facet_failover mds
    do_node $CLIENT1 df $DIR || return 1

    # All 50 files should have been replayed
    do_node $CLIENT1 unlinkmany $DIR/$tfile- 25 || return 2
    do_node $CLIENT1 unlinkmany $DIR/$tfile-3- 25 || return 3

    vbr_activate_client $CLIENT2
    do_node $CLIENT2 df $DIR || return 4
    # All 25 files from client2 should have been replayed
    do_node $CLIENT2 unlinkmany $DIR/$tdir/$tfile-2- 25 || return 5

    zconf_umount_clients $CLIENTS $DIR
    return 0
}
run_test 4a "fail MDS, delayed recovery"

test_4b() {
    remote_server $CLIENT2 || \
        { skip "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    replay_barrier mds
    do_node $CLIENT1 createmany -o $DIR/$tfile- 25
    do_node $CLIENT2 createmany -o $DIR/$tdir/$tfile-2- 25
    vbr_deactivate_client $CLIENT2

    facet_failover mds
    do_node $CLIENT1 df $DIR || return 1

    # create another set of files
    do_node $CLIENT1 createmany -o $DIR/$tfile-3- 25

    vbr_activate_client $CLIENT2
    do_node $CLIENT2 df $DIR || return 2

    # All files from should have been replayed
    do_node $CLIENT1 unlinkmany $DIR/$tfile- 25 || return 3
    do_node $CLIENT1 unlinkmany $DIR/$tfile-3- 25 || return 4
    do_node $CLIENT2 unlinkmany $DIR/$tdir/$tfile-2- 25 || return 5

    zconf_umount_clients $CLIENTS $DIR
}
run_test 4b "fail MDS, normal operation, delayed open recovery"

test_4c() {
    remote_server $CLIENT2 || \
        { skip "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    replay_barrier mds
    do_node $CLIENT1 createmany -m $DIR/$tfile- 25
    do_node $CLIENT2 createmany -m $DIR/$tdir/$tfile-2- 25
    vbr_deactivate_client $CLIENT2

    facet_failover mds
    do_node $CLIENT1 df $DIR || return 1

    # create another set of files
    do_node $CLIENT1 createmany -m $DIR/$tfile-3- 25

    vbr_activate_client $CLIENT2
    do_node $CLIENT2 df $DIR || return 2

    # All files from should have been replayed
    do_node $CLIENT1 unlinkmany $DIR/$tfile- 25 || return 3
    do_node $CLIENT1 unlinkmany $DIR/$tfile-3- 25 || return 4
    do_node $CLIENT2 unlinkmany $DIR/$tdir/$tfile-2- 25 || return 5

    zconf_umount_clients $CLIENTS $DIR
}
run_test 4c "fail MDS, normal operation, delayed recovery"

test_5a() {
    remote_server $CLIENT2 || \
        { skip "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    replay_barrier mds
    do_node $CLIENT1 createmany -o $DIR/$tfile- 25
    do_node $CLIENT2 createmany -o $DIR/$tfile-2- 1
    do_node $CLIENT1 createmany -o $DIR/$tfile-3- 1
    vbr_deactivate_client $CLIENT2

    facet_failover mds
    do_node $CLIENT1 df $DIR && return 1

    vbr_activate_client $CLIENT2
    do_node $CLIENT2 df $DIR || return 2

    # First 25 files should have been replayed
    do_node $CLIENT1 unlinkmany $DIR/$tfile- 25 || return 3
    # Third file is failed due to missed client2
    do_node $CLIENT1 $CHECKSTAT $DIR/$tfile-3-0 && error "$tfile-3-0 exists"
    # file from client2 should exists
    do_node $CLIENT2 unlinkmany $DIR/$tfile-2- 1 || return 4

    zconf_umount_clients $CLIENTS $DIR
}
run_test 5a "fail MDS, delayed recovery should fail"

test_5b() {
    remote_server $CLIENT2 || \
        { skip "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    replay_barrier mds
    do_node $CLIENT1 createmany -o $DIR/$tfile- 25
    do_node $CLIENT2 createmany -o $DIR/$tfile-2- 1
    vbr_deactivate_client $CLIENT2

    facet_failover mds
    do_node $CLIENT1 df $DIR || return 1
    do_node $CLIENT1 $CHECKSTAT $DIR/$tfile-2-0 && error "$tfile-2-0 exists"

    # create another set of files
    do_node $CLIENT1 createmany -o $DIR/$tfile-3- 25

    vbr_activate_client $CLIENT2
    do_node $CLIENT2 df $DIR && return 4
    # file from client2 should fail
    do_node $CLIENT2 $CHECKSTAT $DIR/$tfile-2-0 && error "$tfile-2-0 exists"

    # All 50 files from client 1 should have been replayed
    do_node $CLIENT1 unlinkmany $DIR/$tfile- 25 || return 2
    do_node $CLIENT1 unlinkmany $DIR/$tfile-3- 25 || return 3

    zconf_umount_clients $CLIENTS $DIR
}
run_test 5b "fail MDS, normal operation, delayed recovery should fail"

test_6a() {
    remote_server $CLIENT2 || \
        { skip "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    do_node $CLIENT2 mkdir -p $DIR/$tdir
    replay_barrier mds
    do_node $CLIENT1 createmany -o $DIR/$tfile- 25
    do_node $CLIENT2 createmany -o $DIR/$tdir/$tfile-2- 25
    do_node $CLIENT1 createmany -o $DIR/$tfile-3- 25
    vbr_deactivate_client $CLIENT2

    facet_failover mds
    # replay only 5 requests
    do_node $CLIENT2 "sysctl -w lustre.fail_val=5"
#define OBD_FAIL_PTLRPC_REPLAY        0x50e
    do_node $CLIENT2 "sysctl -w lustre.fail_loc=0x2000050e"
    do_node $CLIENT2 df $DIR
    # vbr_activate_client $CLIENT2
    # need way to know that client stops replays
    sleep 5

    facet_failover mds
    do_node $CLIENT1 df $DIR || return 1

    # All files should have been replayed
    do_node $CLIENT1 unlinkmany $DIR/$tfile- 25 || return 2
    do_node $CLIENT1 unlinkmany $DIR/$tfile-3- 25 || return 3
    do_node $CLIENT2 unlinkmany $DIR/$tdir/$tfile-2- 25 || return 5

    zconf_umount_clients $CLIENTS $DIR
    return 0
}
run_test 6a "fail MDS, delayed recovery, fail MDS"

test_7a() {
    remote_server $CLIENT2 || \
        { skip "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    do_node $CLIENT2 mkdir -p $DIR/$tdir
    replay_barrier mds
    do_node $CLIENT1 createmany -o $DIR/$tfile- 25
    do_node $CLIENT2 createmany -o $DIR/$tdir/$tfile-2- 25
    do_node $CLIENT1 createmany -o $DIR/$tfile-3- 25
    vbr_deactivate_client $CLIENT2

    facet_failover mds
    vbr_activate_client $CLIENT2
    do_node $CLIENT2 df $DIR || return 4

    facet_failover mds
    do_node $CLIENT1 df $DIR || return 1

    # All files should have been replayed
    do_node $CLIENT1 unlinkmany $DIR/$tfile- 25 || return 2
    do_node $CLIENT1 unlinkmany $DIR/$tfile-3- 25 || return 3
    do_node $CLIENT2 unlinkmany $DIR/$tdir/$tfile-2- 25 || return 5

    zconf_umount_clients $CLIENTS $DIR
    return 0
}
run_test 7a "fail MDS, delayed recovery, fail MDS"

rmultiop_start() {
    local client=$1
    local file=$2

    # We need to run do_node in bg, because pdsh does not exit
    # if child process of run script exists.
    # I.e. pdsh does not exit when runmultiop_bg_pause exited,
    # because of multiop_bg_pause -> $MULTIOP_PROG &
    # By the same reason we need sleep a bit after do_nodes starts 
    # to let runmultiop_bg_pause start muliop and
    # update /tmp/multiop_bg.pid ;
    # The rm /tmp/multiop_bg.pid guarantees here that 
    # we have the updated by runmultiop_bg_pause
    # /tmp/multiop_bg.pid file

    local pid_file=$TMP/multiop_bg.pid.$$
    do_node $client "rm -f $pid_file && MULTIOP_PID_FILE=$pid_file LUSTRE= runmultiop_bg_pause $file O_tSc" & 
    local pid=$!
    sleep 3
    local multiop_pid
    multiop_pid=$(do_node $client cat $pid_file)
    [ -n "$multiop_pid" ] || error "$client : Can not get multiop_pid from $pid_file "
    eval export ${client}_multiop_pid=$multiop_pid
    eval export ${client}_do_node_pid=$pid
    local var=${client}_multiop_pid
    echo client $client multiop_bg started multiop_pid=${!var}
    return $?
}

rmultiop_stop() {
    local client=$1
    local multiop_pid=${client}_multiop_pid
    local do_node_pid=${client}_do_node_pid

    echo "Stopping multiop_pid=${!multiop_pid} (kill ${!multiop_pid} on $client)"
    do_node $client kill -USR1 ${!multiop_pid}

    wait ${!do_node_pid} || true
}

test_8a() {
    remote_server $CLIENT2 || \
        { skip "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    rmultiop_start $CLIENT2 $DIR/$tfile || return 1
    do_node $CLIENT2 rm -f $DIR/$tfile
    replay_barrier mds
    rmultiop_stop $CLIENT2 || return 2

    vbr_deactivate_client $CLIENT2
    facet_failover mds
    do_node $CLIENT1 df $DIR || return 3
    #client1 is back and will try to open orphan
    vbr_activate_client $CLIENT2
    do_node $CLIENT2 df $DIR || return 4

    do_node $CLIENT2 $CHECKSTAT $DIR/$tfile && error "$tfile exists"
    zconf_umount_clients $CLIENTS $DIR
    return 0
}
run_test 8a "orphans are kept until delayed recovery"

test_8b() {
    remote_server $CLIENT2 || \
        { skip "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    rmultiop_start $CLIENT2 $DIR/$tfile || return 1
    replay_barrier mds
    do_node $CLIENT1 rm -f $DIR/$tfile

    vbr_deactivate_client $CLIENT2
    facet_failover mds
    do_node $CLIENT1 df $DIR || return 2
    #client1 is back and will try to open orphan
    vbr_activate_client $CLIENT2
    do_node $CLIENT2 df $DIR || return 3

    rmultiop_stop $CLIENT2 || return 1
    do_node $CLIENT2 $CHECKSTAT $DIR/$tfile && error "$tfile exists"
    zconf_umount_clients $CLIENTS $DIR
    return 0
}
run_test 8b "open1 | unlink2 X delayed_replay1, close1"

test_8c() {
    remote_server $CLIENT2 || \
        { skip "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    rmultiop_start $CLIENT2 $DIR/$tfile || return 1
    replay_barrier mds
    do_node $CLIENT1 rm -f $DIR/$tfile
    rmultiop_stop $CLIENT2 || return 2

    vbr_deactivate_client $CLIENT2
    facet_failover mds
    do_node $CLIENT1 df $DIR || return 3
    #client1 is back and will try to open orphan
    vbr_activate_client $CLIENT2
    do_node $CLIENT2 df $DIR || return 4

    do_node $CLIENT2 $CHECKSTAT $DIR/$tfile && error "$tfile exists"
    zconf_umount_clients $CLIENTS $DIR
    return 0
}
run_test 8c "open1 | unlink2, close1 X delayed_replay1"

test_8d() {
    remote_server $CLIENT2 || \
        { skip "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    rmultiop_start $CLIENT1 $DIR/$tfile || return 1
    rmultiop_start $CLIENT2 $DIR/$tfile || return 2
    replay_barrier mds
    do_node $CLIENT1 rm -f $DIR/$tfile
    rmultiop_stop $CLIENT2 || return 3
    rmultiop_stop $CLIENT1 || return 4

    vbr_deactivate_client $CLIENT2
    facet_failover mds
    do_node $CLIENT1 df $DIR || return 6

    #client1 is back and will try to open orphan
    vbr_activate_client $CLIENT2
    do_node $CLIENT2 df $DIR || return 8

    do_node $CLIENT2 $CHECKSTAT $DIR/$tfile && error "$tfile exists"
    zconf_umount_clients $CLIENTS $DIR
    return 0
}
run_test 8d "open1, open2 | unlink2, close1, close2 X delayed_replay1"

test_8e() {
    zconf_mount $CLIENT1 $DIR
    zconf_mount $CLIENT2 $DIR

    do_node $CLIENT1 mcreate $DIR/$tfile
    do_node $CLIENT1 mkdir $DIR/$tfile-2
    replay_barrier mds
    # missed replay from client1 will lead to recovery by versions
    do_node $CLIENT1 touch $DIR/$tfile-2/$tfile
    do_node $CLIENT2 rm $DIR/$tfile || return 1
    do_node $CLIENT2 touch $DIR/$tfile || return 2

    zconf_umount $CLIENT1 $DIR
    facet_failover mds
    do_node $CLIENT2 df $DIR || return 6

    do_node $CLIENT2 rm $DIR/$tfile || error "$tfile doesn't exists"
    zconf_umount_clients $CLIENTS $DIR
    return 0
}
run_test 8e "create | unlink, create shouldn't fail"

test_8f() {
    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    do_node $CLIENT1 touch $DIR/$tfile
    do_node $CLIENT1 mkdir $DIR/$tfile-2
    replay_barrier mds
    # missed replay from client1 will lead to recovery by versions
    do_node $CLIENT1 touch $DIR/$tfile-2/$tfile
    do_node $CLIENT2 rm -f $DIR/$tfile || return 1
    do_node $CLIENT2 mcreate $DIR/$tfile || return 2

    zconf_umount $CLIENT1 $DIR
    facet_failover mds
    do_node $CLIENT2 df $DIR || return 6

    do_node $CLIENT2 rm $DIR/$tfile || error "$tfile doesn't exists"
    zconf_umount $CLIENT2 $DIR
    return 0
}
run_test 8f "create | unlink, create shouldn't fail"

test_8g() {
    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    do_node $CLIENT1 touch $DIR/$tfile
    do_node $CLIENT1 mkdir $DIR/$tfile-2
    replay_barrier mds
    # missed replay from client1 will lead to recovery by versions
    do_node $CLIENT1 touch $DIR/$tfile-2/$tfile
    do_node $CLIENT2 rm -f $DIR/$tfile || return 1
    do_node $CLIENT2 mkdir $DIR/$tfile || return 2

    zconf_umount $CLIENT1 $DIR
    facet_failover mds
    do_node $CLIENT2 df $DIR || return 6

    do_node $CLIENT2 rmdir $DIR/$tfile || error "$tfile doesn't exists"
    zconf_umount $CLIENT2 $DIR
    return 0
}
run_test 8g "create | unlink, create shouldn't fail"

test_10 () {
    [ -z "$DBENCH_LIB" ] && skip "DBENCH_LIB is not set" && return 0

    zconf_mount_clients $CLIENTS $DIR

    local duration="-t 60"
    local cmd="rundbench 1 $duration "
    local PID=""
    for CLIENT in ${CLIENTS//,/ }; do
        $PDSH $CLIENT "set -x; PATH=:$PATH:$LUSTRE/utils:$LUSTRE/tests/:${DBENCH_LIB} DBENCH_LIB=${DBENCH_LIB} $cmd" &
        PID=$!
        echo $PID >pid.$CLIENT
        echo "Started load PID=`cat pid.$CLIENT`"
    done

    replay_barrier mds
    sleep 3 # give clients a time to do operations

    vbr_deactivate_client $CLIENT2

    log "$TESTNAME fail mds 1"
    fail mds

# wait for client to reconnect to MDS
    sleep $TIMEOUT

    vbr_activate_client $CLIENT2
    do_node $CLIENT2 df $DIR || return 4

    for CLIENT in ${CLIENTS//,/ }; do
        PID=`cat pid.$CLIENT`
        wait $PID
        rc=$?
        echo "load on ${CLIENT} returned $rc"
    done

    zconf_umount_clients $CLIENTS $DIR
}
run_test 10 "mds version recovery; $CLIENTCOUNT clients"

equals_msg `basename $0`: test complete, cleaning up
#SLEEP=$((`date +%s` - $NOW))
#[ $SLEEP -lt $TIMEOUT ] && sleep $SLEEP
check_and_cleanup_lustre
[ -f "$TESTSUITELOG" ] && cat $TESTSUITELOG && grep -q FAIL $TESTSUITELOG && exit 1 || true
