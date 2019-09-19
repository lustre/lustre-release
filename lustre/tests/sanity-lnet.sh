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

export LNETCTL=${LNETCTL:-"$LUSTRE/../lnet/utils/lnetctl"}
[ ! -f "$LNETCTL" ] &&
	export LNETCTL=$(which lnetctl 2> /dev/null)
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
	if ip link show test1pl >/dev/null 2>&1; then
		ip link del test1pl
	fi
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

cleanup_netns
cleanup_lnet
exit_status
