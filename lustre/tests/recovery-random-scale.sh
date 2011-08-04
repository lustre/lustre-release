#!/bin/bash

# client failure does not affect other clients

# Start load on clients (each client works on it's own directory).
# At defined (5-10 minutes) interval fail one random client and then fail mds.
# Reintegrate failed client after recovery completed,
# application errors are allowed for that client but not on other clients.
# 10 minute intervals and verify that no application errors occur.

# Test runs one of CLIENT_LOAD progs on remote clients.

LUSTRE=${LUSTRE:-`dirname $0`/..}
SETUP=${SETUP:-""}
CLEANUP=${CLEANUP:-""}
. $LUSTRE/tests/test-framework.sh

init_test_env $@

. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

TESTSUITELOG=${TESTSUITELOG:-$TMP/$(basename $0 .sh)}
DEBUGLOG=$TESTSUITELOG.debug

cleanup_logs

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

[[ $FAILURE_MODE = SOFT ]] && \
    log "WARNING: $0 is not functional with FAILURE_MODE = SOFT, bz22797"

build_test_filter

check_and_setup_lustre
rm -rf $DIR/[df][0-9]*

max_recov_time=$(max_recovery_time)

# the test node needs to be insulated from a lustre failure as much as possible,
# so not even loading the lustre modules is ideal.
# -- umount lustre
# -- remove hostname from clients list
zconf_umount $(hostname) $MOUNT
NODES_TO_USE=${NODES_TO_USE:-$CLIENTS}
NODES_TO_USE=$(exclude_items_from_list $NODES_TO_USE $(hostname))

check_progs_installed $NODES_TO_USE ${CLIENT_LOADS[@]}

MDTS=$(get_facets MDS)

if [ "$SLOW" = "no" ]; then
    DURATION=${DURATION:-$((60 * 30))}
    SERVER_FAILOVER_PERIOD=${SERVER_FAILOVER_PERIOD:-$((60 * 5))}
else
    DURATION=${DURATION:-$((60 * 60 * 24))}
    SERVER_FAILOVER_PERIOD=${SERVER_FAILOVER_PERIOD:-$((60 * 10))} # 10 minutes
fi

rm -f $END_RUN_FILE

vmstatLOG=${TESTSUITELOG}_$(basename $0 .sh).vmstat

numfailovers () {
    local facet
    local var

    for facet in $MDTS ${failed_clients//,/ }; do
        var=${facet}_nums
        val=${!var}
        if [ "$val" ] ; then
            echo "$facet failed  over  $val times"
        fi
    done
}

# list is comma separated
print_logs () {
    local list=$1

    do_nodes $list "node=\\\$(hostname)
var=\\\${node}_load
log=${TESTSUITELOG}_run_${!var}.sh-\\\$node.debug
if [ -e \\\$log ] ; then
echo Node \\\$node debug log:
cat \\\$log
fi"
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

    # a client load will end (i.e. fail) if it finds
    # the end run file.  that does not mean that that client load
    # actually failed though.  the first node in the END_RUN_NODE is
    # the one we are really interested in.
        if [ -n "$END_RUN_NODE" ]; then
            var=$(node_var_name $END_RUN_NODE)_load
            echo "Client load failed on node $END_RUN_NODE"
            echo
            echo "client $END_RUN_NODE load stdout and debug files :
              ${TESTSUITELOG}_run_${!var}.sh-${END_RUN_NODE}
              ${TESTSUITELOG}_run_${!var}.sh-${END_RUN_NODE}.debug"
        fi
        rc=1
    fi


    echo $(date +'%F %H:%M:%S') Terminating clients loads ...
    echo "$0" >> $END_RUN_FILE
    local result=PASS
    [ $rc -eq 0 ] || result=FAIL

    log "Duration:                $DURATION
Server failover period: $SERVER_FAILOVER_PERIOD seconds
Exited after:           $ELAPSED seconds
Number of failovers before exit:
$(numfailovers)
Status: $result: rc=$rc"

    # stop the vmstats on the OSTs
    if [ "$VMSTAT" ]; then
        do_nodes $(comma_list $(osts_nodes)) "test -f /tmp/vmstat.pid && \
            { kill -s TERM \$(cat /tmp/vmstat.pid); rm -f /tmp/vmstat.pid; \
            gzip -f9 $vmstatLOG-\$(hostname); }"
    fi

    # make sure the client loads die
    do_nodes $NODES_TO_USE "set -x; test -f $LOAD_PID_FILE && \
        { kill -s TERM \$(cat $LOAD_PID_FILE) || true; }"

    # and free up the pdshes that started them, if any are still around
    if [ -n "$CLIENT_LOAD_PIDS" ]; then
        kill $CLIENT_LOAD_PIDS || true
        sleep 5
        kill -9 $CLIENT_LOAD_PIDS || true
    fi

    if [ $rc -ne 0 ]; then
        print_logs $NODES_TO_USE
        # we are interested in only on failed clients and servers
        local failedclients=$(cat $END_RUN_FILE | grep -v $0)
        # FIXME: need ostfailover-s nodes also for FLAVOR=OST
        local product=$(gather_logs $(comma_list $(osts_nodes) \
                                 $(mdts_nodes) $mdsfailover_HOST $failedclients))
        echo logs files $product
    fi

    [ $rc -eq 0 ] && zconf_mount $(hostname) $MOUNT

    exit $rc
}

#
# MAIN 
#
log "-----============= $0 starting =============-----"

trap summary_and_cleanup EXIT # INT

ELAPSED=0

# vmstat the osts
if [ "$VMSTAT" ]; then
    do_nodes $(comma_list $(osts_nodes)) "vmstat 1 > $vmstatLOG-\$(hostname) 2>/dev/null </dev/null & echo \$! > /tmp/vmstat.pid"
fi

# Start client loads.
start_client_loads $NODES_TO_USE

echo clients load pids:
if ! do_nodesv $NODES_TO_USE "cat $LOAD_PID_FILE"; then
        exit 3
fi

START_TS=$(date +%s)
CURRENT_TS=$START_TS

MINSLEEP=${MINSLEEP:-120}
REQFAIL_PERCENT=${REQFAIL_PERCENT:-3}	# bug17839 comment 62
REQFAIL=${REQFAIL:-$(( DURATION / SERVER_FAILOVER_PERIOD * REQFAIL_PERCENT / 100))}
reqfail=0
sleep=0

# This is used for FAIL_CLIENT only
ERRORS_OK="yes"
while [ $ELAPSED -lt $DURATION -a ! -e $END_RUN_FILE ]; do

    # In order to perform the 
    # expected number of failovers, we need to account the following :
    # 1) the time that has elapsed during the client load checking
    # 2) time takes for failover

    it_time_start=$(date +%s)
    
    FAIL_CLIENT=$(get_random_entry $NODES_TO_USE)
    client_var=$(node_var_name $FAIL_CLIENT)_nums

    # store the list of failed clients
    # lists are comma separated
    failed_clients=$(expand_list $failed_clients $FAIL_CLIENT)

    SERVERFACET=$(get_random_entry $MDTS)
    var=${SERVERFACET}_nums

    # Check that our client loads are still running. If any have died, 
    # that means they have died outside of recovery, which is unacceptable.    

    log "==== Checking the clients loads BEFORE failover -- failure NOT OK \
    ELAPSED=$ELAPSED DURATION=$DURATION PERIOD=$SERVER_FAILOVER_PERIOD" 

    if ! check_client_loads $NODES_TO_USE; then
        exit 4
    fi

    log "FAIL CLIENT $FAIL_CLIENT ... "
    shutdown_client $FAIL_CLIENT

    log "Starting failover on $SERVERFACET"

    facet_failover "$SERVERFACET" || exit 1
    if ! wait_recovery_complete $SERVERFACET ; then
        echo "$SERVERFACET recovery is not completed!"
        exit 7
    fi

    boot_node $FAIL_CLIENT
    echo "Reintegrating $FAIL_CLIENT"
    zconf_mount $FAIL_CLIENT $MOUNT || exit $?

    # Increment the number of failovers
    val=$((${!var} + 1))
    eval $var=$val
    val=$((${!client_var} + 1))
    eval $client_var=$val

    # load script on failed clients could create END_RUN_FILE
    # We shuold remove it and ignore the failure if this
    # file contains the failed client only.
    # We can not use ERRORS_OK when start all loads at the start of this script
    # because the application errors allowed for random failed client only, but
    # not for all clients.
    if [ -e $END_RUN_FILE ]; then
        read END_RUN_NODE < $END_RUN_FILE
        [[ $END_RUN_NODE = $FAIL_CLIENT ]] &&
            rm -f $END_RUN_FILE || exit 13
    fi

    restart_client_loads $FAIL_CLIENT $ERRORS_OK || exit $?

    # Check that not failed clients loads are still running.
    # No application failures should occur on clients that was not failed.

    log "==== Checking the clients loads AFTER failed client reintegrated -- failure NOT OK"
    if ! ERRORS_OK= check_client_loads $(exclude_items_from_list $NODES_TO_USE $FAIL_CLIENT); then
        log "Client load failed. Exiting"
        exit 5
    fi

    CURRENT_TS=$(date +%s)
    ELAPSED=$((CURRENT_TS - START_TS))
    sleep=$((SERVER_FAILOVER_PERIOD-(CURRENT_TS - it_time_start)))

    # keep count the number of itterations when
    # time spend to failover and two client loads check exceeded 
    # the value ( SERVER_FAILOVER_PERIOD - MINSLEEP )
    if [ $sleep -lt $MINSLEEP ]; then
        reqfail=$((reqfail +1))
        log "WARNING: failover, client reintegration and check_client_loads time exceeded SERVER_FAILOVER_PERIOD - MINSLEEP !
Failed to load the filesystem with I/O for a minimum period of $MINSLEEP $reqfail times ( REQFAIL=$REQFAIL ).
This iteration, the load was only applied for sleep=$sleep seconds.
Estimated max recovery time : $max_recov_time
Probably the hardware is taking excessively long to boot.
Try to increase SERVER_FAILOVER_PERIOD (current is $SERVER_FAILOVER_PERIOD), bug 20918"
        [ $reqfail -gt $REQFAIL ] && exit 6
    fi

    log " Number of failovers:
$(numfailovers)                and counting..."

    if [ $((ELAPSED + sleep)) -ge $DURATION ]; then
         break
    fi

    if [ $sleep -gt 0 ]; then
        echo "sleeping $sleep seconds ... "
        sleep $sleep
    fi
done

exit 0
