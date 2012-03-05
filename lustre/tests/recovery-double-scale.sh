#!/bin/bash

# All pairwise combinations of node failures.
# Was cmd3-17
#
# Author: Chris Cooper <ccooper@clusterfs.com>
#
# Script fails pair of nodes:
# --  in parallel by default
# --  in series if SERIAL is set

LUSTRE=${LUSTRE:-`dirname $0`/..}
SETUP=${SETUP:-""}
CLEANUP=${CLEANUP:-""}
. $LUSTRE/tests/test-framework.sh

init_test_env $@

. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

DEBUGLOG=$TESTLOG_PREFIX.suite_debug_log.$(hostname -s).log

exec 2>$DEBUGLOG
echo "--- env ---" >&2
env >&2
echo "--- env ---" >&2
set -x

[ "$SHARED_DIRECTORY" ] || \
    { FAIL_ON_ERROR=true skip_env "$0 Empty SHARED_DIRECTORY" && exit 0; }

check_shared_dir $SHARED_DIRECTORY ||
    error "$SHARED_DIRECTORY isn't a shared directory"

[ -n "$CLIENTS" ] || \
    { FAIL_ON_ERROR=true skip_env "$0 Need two or more remote clients" && exit 0; }

[ $CLIENTCOUNT -ge 3 ] || \
    { FAIL_ON_ERROR=true skip_env "$0 Need two or more remote clients, have $((CLIENTCOUNT - 1))" && exit 0; }

END_RUN_FILE=${END_RUN_FILE:-$SHARED_DIRECTORY/end_run_file}
LOAD_PID_FILE=${LOAD_PID_FILE:-$TMP/client-load.pid}

remote_mds_nodsh && skip "remote MDS with nodsh" && exit 0
remote_ost_nodsh && skip "remote OST with nodsh" && exit 0

check_timeout || exit 1

[[ $FAILURE_MODE = SOFT ]] && \
    log "WARNING: $0 is not functional with FAILURE_MODE = SOFT, bz22797"

build_test_filter

check_and_setup_lustre
rm -rf $DIR/[df][0-9]*

# the test node needs to be insulated from a lustre failure as much as possible,
# so not even loading the lustre modules is ideal.
# -- umount lustre
# -- remove hostname from clients list
zconf_umount $(hostname) $MOUNT
NODES_TO_USE=${NODES_TO_USE:-$CLIENTS}
NODES_TO_USE=$(exclude_items_from_list $NODES_TO_USE $(hostname))

check_progs_installed $NODES_TO_USE ${CLIENT_LOADS[@]}

MDTS=$(get_facets MDS)
OSTS=$(get_facets OST)

rm -f $END_RUN_FILE

reboot_recover_node () {
    # item var contains a pair of clients if nodetype=clients
    # I would prefer to have a list here
    local item=$1
    local nodetype=$2	
    local timeout=$($LCTL get_param  -n timeout)

    # MDS, OST item contains the facet
    case $nodetype in
       MDS|OST )    facet_failover $item
                [ "$SERIAL" ] && wait_recovery_complete $item || true
                ;;
       clients) for c in ${item//,/ }; do
                      # make sure the client loads die
                      do_nodes $c "set -x; test -f $LOAD_PID_FILE &&
                          { kill -s TERM \\\$(cat $LOAD_PID_FILE);
                          rm -f $LOAD_PID_FILE || true; }"
                      shutdown_client $c
                      boot_node $c
                      echo "Reintegrating $c"
                      # one client fails; need dk logs from this client only 
                      zconf_mount $c $MOUNT || NODES="$c $(mdts_nodes) $(osts_nodes)" error_exit "zconf_mount failed"
                 done
                 start_client_loads $item
                 ;;
                # script failure:
                # don't use error (), the logs from all nodes not needed
       * )      echo "reboot_recover_node: nodetype=$nodetype. Must be one of 'MDS', 'OST', or 'clients'."
                exit 1;;
    esac
}

get_item_type () {
    local type=$1
    local excluded=${2:-""}

    local list
    case $type in
       MDS )    list=$MDTS;;
       OST )    list=$OSTS;;
       clients) list=$NODES_TO_USE
                ;;
                # script failure:
                # don't use error (), the logs from all nodes not needed
       * )      echo "Invalid type=$type. Must be one of 'MDS', 'OST', or 'clients'."
                exit 1;;
    esac

    [ "$excluded" ] && list=$(exclude_items_from_list $list $excluded)
    # empty list
    if [ ! "$(echo $list)" ]; then
        echo
        return
    fi

    item=$(get_random_entry $list)
    if [ "$type" = clients ] ; then
        item="$item $(get_random_entry $(exclude_items_from_list $list $item))"
        item=$(comma_list $item)
    fi
    echo $item
}

# failover_pair
#
# for the two nodetypes specified, chooses a random node(s) from each
# class, reboots the nodes sequentially, and then restarts lustre on
# the nodes.
failover_pair() {
    local type1=$1
    local type2=$2
    local title=$3

    local client_nodes=""
    local item1=
    local item2=
    local client1=
    local client2=

    log "
==== START === $title "

    item1=$(get_item_type $type1)
    [ "$item1" ] || \
        { echo "type1=$type1 item1 is empty" && return 0; }
    item2=$(get_item_type $type2 $item1)
    [ "$item2" ] || \
        { echo "type1=$type1 item1=$item1 type2=$type2 item2=$item2 is empty" && return 0; }

    # Check that our client loads are still running. If any have died,
    # that means they have died outside of recovery, which is unacceptable.
    log "==== Checking the clients loads BEFORE failover -- failure NOT OK"

    # FIXME. need print summary on exit
    if ! check_client_loads $NODES_TO_USE; then
        exit 4
    fi

    log "Done checking client loads. Failing type1=$type1 item1=$item1 ... "

    reboot_recover_node $item1 $type1

    # Hendrix test17 description: 
    # Introduce a failure, wait at
    # least 5 minutes (for recovery),
    # introduce a 2nd
    # failure, and wait another 5
    # minutes

    # reboot_recover_node waits recovery in according to
    # SERIAL value.
    # We have a "double failures" if SERIAL is not set,
    # do not need a sleep between failures for "double failures"

    log "                            Failing type2=$type2 item2=$item2 ... "    
    reboot_recover_node $item2 $type2

    # Client loads are allowed to die while in recovery, so we just
    # restart them.
    log "==== Checking the clients loads AFTER  failovers -- ERRORS_OK=$ERRORS_OK"
    restart_client_loads $NODES_TO_USE $ERRORS_OK || return $? 
    log "Done checking / re-Starting client loads. PASS"
    return 0
}

summary_and_cleanup () {
    local rc=$?
    local var
    trap 0

    # Having not empty END_RUN_FILE means the failed loads only
    if [ -s $END_RUN_FILE ]; then
        echo "Found the END_RUN_FILE file: $END_RUN_FILE"
        cat $END_RUN_FILE
        local END_RUN_NODE=
        read END_RUN_NODE < $END_RUN_FILE

        # A client load will stop if it found the END_RUN_FILE file.
        # That does not mean the client load actually failed though.
        # The first node in END_RUN_FILE is the one we are interested in.
        if [ -n "$END_RUN_NODE" ]; then
            var=$(node_var_name $END_RUN_NODE)_load
            echo "Client load failed on node $END_RUN_NODE"
            echo
            echo "Client $END_RUN_NODE load stdout and debug files:
                $TESTLOG_PREFIX.run_${!var}_stdout.$END_RUN_NODE.log
                $TESTLOG_PREFIX.run_${!var}_debug.$END_RUN_NODE.log"
        fi
        rc=1
    fi

    echo $(date +'%F %H:%M:%S') Terminating clients loads ...
    echo "$0" >> $END_RUN_FILE
    local result=PASS
    [ $rc -eq 0 ] || result=FAIL

    log "
Server failover period: $FAILOVER_PERIOD seconds
Exited after:           $ELAPSED seconds
Status: $result: rc=$rc"

    # make sure the client loads die
    do_nodes $NODES_TO_USE "set -x; test -f $LOAD_PID_FILE &&
        { kill -s TERM \\\$(cat $LOAD_PID_FILE);
        rm -f $LOAD_PID_FILE || true; }"

    # and free up the pdshes that started them, if any are still around
    if [ -n "$CLIENT_LOAD_PIDS" ]; then
        kill $CLIENT_LOAD_PIDS || true
        sleep 5
        kill -9 $CLIENT_LOAD_PIDS || true
    fi

    if [ $rc -ne 0 ]; then
        # we are interested in only on failed clients and servers
        local failedclients=$(cat $END_RUN_FILE | grep -v $0)
        # FIXME: need ostfailover-s nodes also for FLAVOR=OST
        local product=$(gather_logs $(comma_list $(osts_nodes) \
                        $(mdts_nodes) $mdsfailover_HOST $failedclients) 1)
        echo $product
    fi

    [ $rc -eq 0 ] && zconf_mount $(hostname) $MOUNT
    exit $rc
}

trap summary_and_cleanup EXIT TERM INT

#
# MAIN
#
log "-----============= $0 starting =============-----"

START_TS=$(date +%s)
CURRENT_TS=$START_TS
ELAPSED=0

# Set SERIAL to serialize the failure through a recovery of the first failure. 
SERIAL=${SERIAL:-""}
ERRORS_OK="yes"

[ "$SERIAL" ] && ERRORS_OK="" 

FAILOVER_PERIOD=${FAILOVER_PERIOD:-$((60*5))} # 5 minutes

# Start client loads.
start_client_loads $NODES_TO_USE

echo clients load pids:
if ! do_nodesv $NODES_TO_USE "cat $LOAD_PID_FILE"; then
    exit 3
fi

# FIXME: Do we want to have an initial sleep period where the clients 
# just run before introducing a failure?
sleep $FAILOVER_PERIOD

#CMD_TEST_NUM=17.1
failover_pair MDS OST     "test 1: failover MDS, then OST =========="
sleep $FAILOVER_PERIOD

#CMD_TEST_NUM=17.2
failover_pair MDS clients "test 2: failover MDS, then 2 clients ===="
sleep $FAILOVER_PERIOD

#CMD_TEST_NUM=17.3
if [ $MDSCOUNT -gt 1 ]; then
    failover_pair MDS MDS     "test 3: failover MDS, then another MDS =="
    sleep $FAILOVER_PERIOD
else
    skip "$0 : $MDSCOUNT < 2 MDTs, test 3 skipped"
fi 

#CMD_TEST_NUM=17.4
if [ $OSTCOUNT -gt 1 ]; then
    failover_pair OST OST     "test 4: failover OST, then another OST =="
    sleep $FAILOVER_PERIOD
else
    skip "$0 : $OSTCOUNT < 2 OSTs, test 4 skipped"
fi 

#CMD_TEST_NUM=17.5
failover_pair OST clients "test 5: failover OST, then 2 clients ===="
sleep $FAILOVER_PERIOD

#CMD_TEST_NUM=17.6
failover_pair OST MDS     "test 6: failover OST, then MDS =========="
sleep $FAILOVER_PERIOD

#CMD_TEST_NUM=17.7
failover_pair clients MDS "test 7: failover 2 clients, then MDS ===="
sleep $FAILOVER_PERIOD

#CMD_TEST_NUM=17.8
#failover_pair clients OST "test 8: failover 2 clients, then OST ===="
sleep $FAILOVER_PERIOD

#CMD_TEST_NUM=17.9
if [ $CLIENTCOUNT -ge 5 ]; then
    failover_pair clients clients "test 9: failover 2 clients, then 2 different clients =="
    sleep $FAILOVER_PERIOD
fi
log "==== Checking the clients loads AFTER  all failovers -- failure NOT OK"
if ! check_client_loads $NODES_TO_USE; then
    log "Client load failed after failover. Exiting"
    exit 5
fi

CURRENT_TS=$(date +%s)
ELAPSED=$((CURRENT_TS - START_TS))

log "Completed successfully in $ELAPSED seconds"

exit 0
