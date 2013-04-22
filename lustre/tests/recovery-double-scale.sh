#!/bin/bash
# vim:shiftwidth=4:softtabstop=4:tabstop=4:

# All pairwise combinations of node failures.
# Was cmd3-17
#
# Author: Chris Cooper <ccooper@clusterfs.com>
#
# Script fails pair of nodes:
# --  in parallel by default
# --  in series if SERIAL is set
set -e

ONLY=${ONLY:-"$*"}

# bug number for skipped test:
ALWAYS_EXCEPT="$RECOVERY_DOUBLE_SCALE_EXCEPT"
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

remote_mds_nodsh && skip_env "remote MDS with nodsh" && exit 0
remote_ost_nodsh && skip_env "remote OST with nodsh" && exit 0

[ -z "$CLIENTS" -o $CLIENTCOUNT -lt 3 ] &&
    skip_env "need three or more clients" && exit 0

if [ -z "$SHARED_DIRECTORY" ] || ! check_shared_dir $SHARED_DIRECTORY; then
    skip_env "SHARED_DIRECTORY should be specified with a shared directory \
which is accessable on all of the nodes"
    exit 0
fi

[[ $FAILURE_MODE = SOFT ]] && \
    log "WARNING: $0 is not functional with FAILURE_MODE = SOFT, bz22797"

# Set SERIAL to serialize the failure through a recovery of the first failure.
SERIAL=${SERIAL:-""}
ERRORS_OK="yes"

[ "$SERIAL" ] && ERRORS_OK=""

FAILOVER_PERIOD=${FAILOVER_PERIOD:-$((60 * 5))} # 5 minutes

END_RUN_FILE=${END_RUN_FILE:-$SHARED_DIRECTORY/end_run_file}
LOAD_PID_FILE=${LOAD_PID_FILE:-$TMP/client-load.pid}

reboot_recover_node () {
    # item var contains a pair of clients if nodetype=clients
    # I would prefer to have a list here
    local item=$1
    local nodetype=$2
    local c

    # MDS, OST item contains the facet
    case $nodetype in
        MDS|OST )   facet_failover $item
                    [ "$SERIAL" ] && wait_recovery_complete $item || true
                    ;;
        clients)    for c in ${item//,/ }; do
                        # make sure the client loads die
                        stop_process $c $LOAD_PID_FILE
                        shutdown_client $c
                        boot_node $c
                        echo "Reintegrating $c"
                        zconf_mount $c $MOUNT ||
                            error "mount $MOUNT on $c failed"
                        client_up $c || error "start client on $c failed"
                    done
                    start_client_loads $item
                    ;;
        * )         echo "ERROR: invalid nodetype=$nodetype." \
                         "Must be one of 'MDS', 'OST', or 'clients'."
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
       clients) list=$NODES_TO_USE;;
       * )      echo "ERROR: invalid type=$type." \
                     "Must be one of 'MDS', 'OST', or 'clients'."
                exit 1;;
    esac

    [ "$excluded" ] && list=$(exclude_items_from_list $list $excluded)
    # empty list
    if [ ! "$(echo $list)" ]; then
        echo
        return
    fi

    local item=$(get_random_entry $list)
    if [ "$type" = "clients" ]; then
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
==== START === $title"

    item1=$(get_item_type $type1)
    [ "$item1" ] || \
        { echo "type1=$type1 item1 is empty" && return 0; }
    item2=$(get_item_type $type2 $item1)
    [ "$item2" ] || \
        { echo "type1=$type1 item1=$item1 type2=$type2 item2=$item2 is empty" \
          && return 0; }

    # Check that our client loads are still running. If any have died,
    # that means they have died outside of recovery, which is unacceptable.
    log "==== Checking the clients loads BEFORE failover -- failure NOT OK"
    # FIXME. need print summary on exit
    check_client_loads $NODES_TO_USE || exit $?

    log "Done checking client loads. Failing type1=$type1 item1=$item1 ... "
    reboot_recover_node $item1 $type1 || exit $?

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
    reboot_recover_node $item2 $type2 || exit $?

    # Client loads are allowed to die while in recovery, so we just
    # restart them.
    log "==== Checking the clients loads AFTER failovers -- ERRORS_OK=$ERRORS_OK"
    restart_client_loads $NODES_TO_USE $ERRORS_OK || exit $?
    log "Done checking / re-starting client loads. PASS"
    return 0
}

summary_and_cleanup () {
    local rc=$?
    trap 0

    CURRENT_TS=$(date +%s)
    ELAPSED=$((CURRENT_TS - START_TS))

    # Having not empty END_RUN_FILE means the failed loads only
    if [ -s $END_RUN_FILE ]; then
        print_end_run_file $END_RUN_FILE
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

    # stop the client loads
    stop_client_loads $NODES_TO_USE $LOAD_PID_FILE

	if [ $rc -ne 0 ]; then
		# we are interested in only on failed clients and servers
		local failedclients=$(cat $END_RUN_FILE | grep -v $0)
		gather_logs $(comma_list $(all_server_nodes) $failedclients)
	fi

    exit $rc
}

################################## Main Flow ###################################
build_test_filter

check_and_setup_lustre
rm -rf $DIR/[Rdfs][0-9]*

check_timeout || exit 1

# The test node needs to be insulated from a lustre failure as much as possible,
# so not even loading the lustre modules is ideal.
# -- umount lustre
# -- remove hostname from clients list
zconf_umount $HOSTNAME $MOUNT
NODES_TO_USE=${NODES_TO_USE:-$CLIENTS}
NODES_TO_USE=$(exclude_items_from_list $NODES_TO_USE $HOSTNAME)

check_progs_installed $NODES_TO_USE ${CLIENT_LOADS[@]}

MDTS=$(get_facets MDS)
OSTS=$(get_facets OST)

ELAPSED=0
START_TS=$(date +%s)
CURRENT_TS=$START_TS

# Every pairwise combination of client failures (2 clients),
# MDS failure, and OST failure will be tested.
test_pairwise_fail() {
    trap summary_and_cleanup EXIT TERM INT

    # Start client loads.
    rm -f $END_RUN_FILE
    start_client_loads $NODES_TO_USE

    echo clients load pids:
    do_nodesv $NODES_TO_USE "cat $LOAD_PID_FILE" || exit 3

    # FIXME: Do we want to have an initial sleep period where the clients
    # just run before introducing a failure?
    sleep $FAILOVER_PERIOD

    # CMD_TEST_NUM=17.1
    failover_pair MDS OST "test 1: failover MDS, then OST =========="
    sleep $FAILOVER_PERIOD

    # CMD_TEST_NUM=17.2
    failover_pair MDS clients "test 2: failover MDS, then 2 clients ===="
    sleep $FAILOVER_PERIOD

    # CMD_TEST_NUM=17.3
    if [ $MDSCOUNT -gt 1 ]; then
        failover_pair MDS MDS "test 3: failover MDS, then another MDS =="
        sleep $FAILOVER_PERIOD
    else
        skip_env "has less than 2 MDTs, test 3 skipped"
    fi

    # CMD_TEST_NUM=17.4
    if [ $OSTCOUNT -gt 1 ]; then
        failover_pair OST OST "test 4: failover OST, then another OST =="
        sleep $FAILOVER_PERIOD
    else
        skip_env "has less than 2 OSTs, test 4 skipped"
    fi

    # CMD_TEST_NUM=17.5
    failover_pair OST clients "test 5: failover OST, then 2 clients ===="
    sleep $FAILOVER_PERIOD

    # CMD_TEST_NUM=17.6
    failover_pair OST MDS "test 6: failover OST, then MDS =========="
    sleep $FAILOVER_PERIOD

    # CMD_TEST_NUM=17.7
    failover_pair clients MDS "test 7: failover 2 clients, then MDS ===="
    sleep $FAILOVER_PERIOD

    # CMD_TEST_NUM=17.8
    failover_pair clients OST "test 8: failover 2 clients, then OST ===="
    sleep $FAILOVER_PERIOD

    # CMD_TEST_NUM=17.9
    if [ $CLIENTCOUNT -gt 4 ]; then
        failover_pair clients clients \
            "test 9: failover 2 clients, then 2 different clients =="
        sleep $FAILOVER_PERIOD
    else
        skip_env "has less than 5 Clients, test 9 skipped"
    fi

    log "==== Checking the clients loads AFTER all failovers -- failure NOT OK"
    if ! check_client_loads $NODES_TO_USE; then
        log "Client load failed after failover. Exiting..."
        exit 5
    fi

    exit 0
}
run_test pairwise_fail "pairwise combination of clients, MDS, and OST failures"

zconf_mount $HOSTNAME $MOUNT || error "mount $MOUNT on $HOSTNAME failed"
client_up || error "start client on $HOSTNAME failed"

complete $SECONDS
check_and_cleanup_lustre
exit_status
