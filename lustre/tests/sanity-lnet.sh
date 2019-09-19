#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#

set -e

ONLY=${ONLY:-"$*"}
# bug number for skipped test:
ALWAYS_EXCEPT="$SANITY_LNET_EXCEPT "
[ "$SLOW" = "no" ] && EXCEPT_SLOW=""
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}

. $LUSTRE/tests/test-framework.sh
CLEANUP=${CLEANUP:-:}
SETUP=${SETUP:-:}
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

build_test_filter

[[ -z $LNETCTL ]] && skip "Need lnetctl"

load_lnet() {
	load_module ../libcfs/libcfs/libcfs
	# Prevent local MODOPTS_LIBCFS being passed as part of environment
	# variable to remote nodes
	unset MODOPTS_LIBCFS

	set_default_debug
	load_module ../lnet/lnet/lnet "$@"

	LNDPATH=${LNDPATH:-"../lnet/klnds"}
	if [ -z "$LNETLND" ]; then
		case $NETTYPE in
		o2ib*)  LNETLND="o2iblnd/ko2iblnd" ;;
		tcp*)   LNETLND="socklnd/ksocklnd" ;;
		*)      local lnd="${NETTYPE%%[0-9]}lnd"
			[ -f "$LNDPATH/$lnd/k$lnd.ko" ] &&
				LNETLND="$lnd/k$lnd" ||
				LNETLND="socklnd/ksocklnd"
		esac
	fi
	load_module ../lnet/klnds/$LNETLND
}

cleanup_lnet() {
	echo "Cleaning up LNet"
	lsmod | grep -q lnet &&
		$LNETCTL lnet unconfigure 2>/dev/null
	unload_modules
}

do_lnetctl() {
	echo "$LNETCTL $@"
	$LNETCTL "$@"
}

TESTNS='test_ns'
FAKE_IF="test1pg"
FAKE_IP="10.1.2.3"
do_ns() {
	echo "ip netns exec $TESTNS $@"
	ip netns exec $TESTNS "$@"
}

setup_netns() {
	cleanup_netns

	ip netns add $TESTNS
	ip link add 'test1pl' type veth peer name $FAKE_IF netns $TESTNS
	ip link set 'test1pl' up
	do_ns ip addr add "${FAKE_IP}/31" dev $FAKE_IF
	do_ns ip link set $FAKE_IF up
}

cleanup_netns() {
	(ip netns list | grep -q $TESTNS) && ip netns del $TESTNS
	ip link show test1pl >& /dev/null && ip link del test1pl || return 0
}

cleanupall -f

setup_netns
load_lnet

test_1() {
	do_lnetctl lnet configure
}
run_test 1 "configure lnet with lnetctl"


### load lnet in default namespace, configure in target namespace

test_2() {
	cleanup_lnet || exit 1
	load_lnet "networks=\"\""
	do_ns $LNETCTL lnet configure --all || exit 1
	$LNETCTL net show --net tcp | grep -q "nid: ${FAKE_IP}@tcp$"
}
run_test 2 "load lnet w/o module option, configure in a non-default namespace"

test_3() {
	cleanup_lnet || exit 1
	load_lnet "networks=tcp($FAKE_IF)"
	do_ns $LNETCTL lnet configure --all || exit 1
	$LNETCTL net show --net tcp | grep -q "nid: ${FAKE_IP}@tcp$"
}
run_test 3 "load lnet using networks module options in a non-default namespace"

test_4() {
	cleanup_lnet || exit 1
	load_lnet "networks=\"\" ip2nets=\"tcp0($FAKE_IF) ${FAKE_IP}\""
	do_ns $LNETCTL lnet configure --all || exit 1
	$LNETCTL net show | grep -q "nid: ${FAKE_IP}@tcp$"
}
run_test 4 "load lnet using ip2nets in a non-default namespace"


### Add the interfaces in the target namespace

test_5() {
	cleanup_lnet || exit 1
	load_lnet
	do_lnetctl lnet configure || exit 1
	do_ns $LNETCTL net add --net tcp0 --if $FAKE_IF
}
run_test 5 "add a network using an interface in the non-default namespace"

test_212() {
	local rnodes=$(remote_nodes_list)
	[[ -z $rnodes ]] && skip "Need at least 1 remote node"

	cleanup_lnet || error "Failed to cleanup before test execution"

	# Loading modules should configure LNet with the appropriate
	# test-framework configuration
	load_modules || error "Failed to load modules"

	local my_nid=$($LCTL list_nids | head -n 1)
	[[ -z $my_nid ]] &&
		error "Failed to get primary NID for local host $HOSTNAME"

	local rnode=$(awk '{print $1}' <<<$rnodes)
	local rnodenids=$(do_node $rnode $LCTL list_nids | xargs echo)
	local rloaded=false

	if [[ -z $rnodenids ]]; then
		do_rpc_nodes $rnode load_modules_local
		rloaded=true
		rnodenids=$(do_node $rnode $LCTL list_nids | xargs echo)
	fi

	local rnodepnid=$(awk '{print $1}' <<< $rnodenids)

	[[ -z $rnodepnid ]] &&
		error "Failed to get primary NID for remote host $rnode"

	log "Initial discovery"
	$LNETCTL discover --force $rnodepnid ||
		error "Failed to discover $rnodepnid"

	do_node $rnode "$LNETCTL discover --force $my_nid" ||
		error "$rnode failed to discover $my_nid"

	log "Fail local discover ping to set LNET_PEER_REDISCOVER flag"
	$LCTL net_drop_add -s "*@$NETTYPE" -d "*@$NETTYPE" -r 1 -e local_error
	$LNETCTL discover --force $rnodepnid &&
		error "Discovery should have failed"
	$LCTL net_drop_del -a

	local nid
	for nid in $rnodenids; do
		# We need GET (PING) delay just long enough so we can trigger
		# discovery on the remote peer
		$LCTL net_delay_add -s "*@$NETTYPE" -d $nid -r 1 -m GET -l 3
		$LCTL net_drop_add -s "*@$NETTYPE" -d $nid -r 1 -m GET -e local_error
		# We need PUT (PUSH) delay just long enough so we can process
		# the PING failure
		$LCTL net_delay_add -s "*@$NETTYPE" -d $nid -r 1 -m PUT -l 6
	done

	log "Force $HOSTNAME to discover $rnodepnid (in background)"
	# We want to get a PING sent that we know will eventually fail.
	# The delay rules we added will ensure the ping is not sent until
	# the PUSH is also in flight (see below), and the drop rule ensures that
	# when the PING is eventually sent it will error out
	$LNETCTL discover --force $rnodepnid &
	local pid1=$!

	# We want a discovery PUSH from rnode to put rnode back on our
	# discovery queue. This should cause us to try and send a PUSH to rnode
	# while the PING is still outstanding.
	log "Force $rnode to discover $my_nid"
	do_node $rnode $LNETCTL discover --force $my_nid

	# At this point we'll have both PING_SENT and PUSH_SENT set for the
	# rnode peer. Wait for the PING to error out which should terminate the
	# discovery process that we backgrounded.
	log "Wait for $pid1"
	wait $pid1
	log "Finished wait on $pid1"

	# The PING send failure clears the PING_SENT flag and puts the peer back
	# on the discovery queue. When discovery thread processes the peer it
	# will mistakenly clear the PUSH_SENT flag (and set PUSH_FAILED).
	# Discovery will then complete for this peer even though we have an
	# outstanding PUSH.
	# When PUSH is actually unlinked it will be forced back onto the
	# discovery queue, but we no longer have a ref on the peer. When
	# discovery completes again, we'll trip the ASSERT in
	# lnet_destroy_peer_locked()

	# Delete the delay rules to send the PUSH
	$LCTL net_delay_del -a
	# Delete the drop rules
	$LCTL net_drop_del -a

	unload_modules ||
		error "Failed to unload modules"
	if $rloaded; then
		do_rpc_nodes $rnode unload_modules_local ||
			error "Failed to unload modules on $rnode"
	fi

	return 0
}
run_test 212 "Check discovery refcount loss bug (LU-14627)"


cleanup_netns
cleanup_lnet
exit_status
