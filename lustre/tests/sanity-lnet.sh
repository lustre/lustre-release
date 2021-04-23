#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#

set -e

ONLY=${ONLY:-"$*"}

# bug number for skipped test:
ALWAYS_EXCEPT="$SANITY_LNET_EXCEPT "
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

# skip the grant tests for ARM until they are fixed
if [[ $(uname -m) = aarch64 ]]; then
	# bug number:	 LU-14067
	ALWAYS_EXCEPT+=" 300"
fi

[ "$SLOW" = "no" ] && EXCEPT_SLOW=""

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}

. $LUSTRE/tests/test-framework.sh
CLEANUP=${CLEANUP:-:}
SETUP=${SETUP:-:}
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

build_test_filter

[[ -z $LNETCTL ]] && skip "Need lnetctl"

restore_mounts=false

if is_mounted $MOUNT || is_mounted $MOUNT2; then
	cleanupall || error "Failed cleanup prior to test execution"
	restore_mounts=true
fi

cleanup_lnet() {
	echo "Cleaning up LNet"
	lsmod | grep -q lnet &&
		$LNETCTL lnet unconfigure 2>/dev/null
	unload_modules
}

restore_modules=false
if module_loaded lnet ; then
	cleanup_lnet || error "Failed to unload modules before test execution"
	restore_modules=true
fi

cleanup_testsuite() {
	trap "" EXIT
	rm -f $TMP/sanity-dlc*
	cleanup_netns
	cleanup_lnet
	if $restore_mounts; then
		setupall || error "Failed to setup Lustre after test execution"
	elif $restore_modules; then
		load_modules ||
			error "Couldn't load modules after test execution"
	fi
	return 0
}

load_lnet() {
	load_module ../libcfs/libcfs/libcfs
	# Prevent local MODOPTS_LIBCFS being passed as part of environment
	# variable to remote nodes
	unset MODOPTS_LIBCFS

	set_default_debug "neterror net nettrace malloc"
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

setup_fakeif() {
	local netns="$1"

	local netns_arg=""
	[[ -n $netns ]] &&
		netns_arg="netns $netns"

	ip link add 'test1pl' type veth peer name $FAKE_IF $netns_arg
	ip link set 'test1pl' up
	if [[ -n $netns ]]; then
		do_ns ip addr add "${FAKE_IP}/31" dev $FAKE_IF
		do_ns ip link set $FAKE_IF up
	else
		ip addr add "${FAKE_IP}/31" dev $FAKE_IF
		ip link set $FAKE_IF up
	fi
}

cleanup_fakeif() {
	ip link show test1pl >& /dev/null && ip link del test1pl || return 0
}

setup_netns() {
	cleanup_netns

	ip netns add $TESTNS
	setup_fakeif $TESTNS
}

cleanup_netns() {
	(ip netns list | grep -q $TESTNS) && ip netns del $TESTNS
	cleanup_fakeif
}

configure_dlc() {
	echo "Loading LNet and configuring DLC"
	load_lnet
	do_lnetctl lnet configure
}

GLOBAL_YAML_FILE=$TMP/sanity-lnet-global.yaml
define_global_yaml() {
	$LNETCTL export --backup >${GLOBAL_YAML_FILE} ||
		error "Failed to export global yaml $?"
}

reinit_dlc() {
	if lsmod | grep -q lnet; then
		do_lnetctl lnet unconfigure ||
			error "lnetctl lnet unconfigure failed $?"
		do_lnetctl lnet configure ||
			error "lnetctl lnet configure failed $?"
	else
		configure_dlc || error "configure_dlc failed $?"
	fi
	define_global_yaml
}

append_global_yaml() {
	[[ ! -e ${GLOBAL_YAML_FILE} ]] &&
		error "Missing global yaml at ${GLOBAL_YAML_FILE}"

	cat ${GLOBAL_YAML_FILE} >> $TMP/sanity-lnet-$testnum-expected.yaml
}

create_base_yaml_file() {
	append_global_yaml
}

compare_yaml_files() {
	local expected="$TMP/sanity-lnet-$testnum-expected.yaml"
	local actual="$TMP/sanity-lnet-$testnum-actual.yaml"
	local rc=0
	! [[ -e $expected ]] && echo "$expected not found" && return 1
	! [[ -e $actual ]] && echo "$actual not found" && return 1
	diff -upN ${actual} ${expected} || rc=$?
	echo "Expected:"
	cat $expected
	echo "Actual:"
	cat $actual
	return $rc
}

validate_nid() {
	local nid="$1"
	local net="${nid//*@/}"
	local addr="${nid//@*/}"

	local num_re='[0-9]\+'
	local ip_re="[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"

	if [[ $net =~ gni[0-9]* ]]; then
		[[ $addr =~ ${num_re} ]] && return 0
	else
		[[ $addr =~ ${ip_re} ]] && return 0
	fi
}

validate_nids() {
	local yfile=$TMP/sanity-lnet-$testnum-actual.yaml
	local primary_nids=$(awk '/- primary nid:/{print $NF}' $yfile | xargs echo)
	local secondary_nids=$(awk '/- nid:/{print $NF}' $yfile | xargs echo)
	local gateway_nids=$(awk '/gateway:/{print $NF}' $yfile | xargs echo)

	local nid
	for nid in $primary_nids $secondary_nids; do
		validate_nid "$nid" || error "Bad NID \"${nid}\""
	done
	return 0
}

validate_peer_nids() {
	local num_peers="$1"
	local nids_per_peer="$2"

	local expect_p="$num_peers"
	# The primary nid also shows up in the list of secondary nids
	local expect_s="$(($num_peers + $(($nids_per_peer*$num_peers))))"

	local actual_p=$(grep -c -- '- primary nid:' $TMP/sanity-lnet-$testnum-actual.yaml)
	local actual_s=$(grep -c -- '- nid:' $TMP/sanity-lnet-$testnum-actual.yaml)
	if [[ $expect_p -ne $actual_p ]]; then
		compare_yaml_files
		error "Expected $expect_p but found $actual_p primary nids"
	elif [[ $expect_s -ne $actual_s ]]; then
		compare_yaml_files
		error "Expected $expect_s but found $actual_s secondary nids"
	fi
	validate_nids
}

validate_gateway_nids() {
	local expect_gw=$(grep -c -- 'gateway:' $TMP/sanity-lnet-$testnum-expected.yaml)
	local actual_gw=$(grep -c -- 'gateway:' $TMP/sanity-lnet-$testnum-actual.yaml)
	if [[ $expect_gw -ne $actual_gw ]]; then
		compare_yaml_files
		error "Expected $expect_gw gateways but found $actual_gw gateways"
	fi
	validate_nids
}

cleanupall -f
setup_netns || error "setup_netns failed with $?"

stack_trap 'cleanup_testsuite' EXIT

test_0() {
	load_module ../lnet/lnet/lnet || error "Failed to load module rc = $?"
	do_lnetctl lnet configure || error "lnet configure failed rc = $?"
	define_global_yaml
	reinit_dlc || return $?
	do_lnetctl import <  ${GLOBAL_YAML_FILE} || error "Import failed $?"
	$LNETCTL export --backup > $TMP/sanity-lnet-$testnum-actual.yaml
	create_base_yaml_file
	compare_yaml_files || error "Configuration changed after import"
}
run_test 0 "Export empty config, import the config, compare"

compare_peer_add() {
	local prim_nid="${1:+--prim_nid $1}"
	local nid="${2:+--nid $2}"

	local actual="$TMP/sanity-lnet-$testnum-actual.yaml"

	do_lnetctl peer add ${prim_nid} ${nid} || error "peer add failed $?"
	$LNETCTL export --backup > $actual || error "export failed $?"
	compare_yaml_files
	return $?
}

test_1() {
	reinit_dlc || return $?
	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 1.1.1.1@tcp
      Multi-Rail: True
      peer ni:
        - nid: 1.1.1.1@tcp
EOF
	append_global_yaml
	compare_peer_add "1.1.1.1@tcp"
}
run_test 1 "Add peer with single nid (tcp)"

test_2() {
	reinit_dlc || return $?
	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 2.2.2.2@o2ib
      Multi-Rail: True
      peer ni:
        - nid: 2.2.2.2@o2ib
EOF
	append_global_yaml
	compare_peer_add "2.2.2.2@o2ib"
}
run_test 2 "Add peer with single nid (o2ib)"

test_3() {
	reinit_dlc || return $?
	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 3.3.3.3@tcp
      Multi-Rail: True
      peer ni:
        - nid: 3.3.3.3@tcp
        - nid: 3.3.3.3@o2ib
EOF
	append_global_yaml
	compare_peer_add "3.3.3.3@tcp" "3.3.3.3@o2ib"
}
run_test 3 "Add peer with tcp primary o2ib secondary"

test_4() {
	reinit_dlc || return $?
	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 4.4.4.4@tcp
      Multi-Rail: True
      peer ni:
        - nid: 4.4.4.4@tcp
        - nid: 4.4.4.1@tcp
        - nid: 4.4.4.2@tcp
        - nid: 4.4.4.3@tcp
EOF
	append_global_yaml
	echo "Add peer with nidrange (tcp)"
	compare_peer_add "4.4.4.4@tcp" "4.4.4.[1-3]@tcp"

	echo "Add peer with nidrange that overlaps primary nid (tcp)"
	compare_peer_add "4.4.4.4@tcp" "4.4.4.[1-4]@tcp"
}
run_test 4 "Add peer with nidrange (tcp)"

test_5() {
	reinit_dlc || return $?
	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 5.5.5.5@o2ib
      Multi-Rail: True
      peer ni:
        - nid: 5.5.5.5@o2ib
        - nid: 5.5.5.1@o2ib
        - nid: 5.5.5.2@o2ib
        - nid: 5.5.5.3@o2ib
        - nid: 5.5.5.4@o2ib
EOF
	append_global_yaml
	echo "Add peer with nidrange (o2ib)"
	compare_peer_add "5.5.5.5@o2ib" "5.5.5.[1-4]@o2ib"

	echo "Add peer with nidranage that overlaps primary nid (o2ib)"
	compare_peer_add "5.5.5.5@o2ib" "5.5.5.[1-4]@o2ib"
}
run_test 5 "Add peer with nidrange (o2ib)"

test_6() {
	reinit_dlc || return $?
	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 6.6.6.6@tcp
      Multi-Rail: True
      peer ni:
        - nid: 6.6.6.6@tcp
        - nid: 6.6.6.0@tcp
        - nid: 6.6.6.2@tcp
        - nid: 6.6.6.4@tcp
        - nid: 6.6.7.0@tcp
        - nid: 6.6.7.2@tcp
        - nid: 6.6.7.4@tcp
        - nid: 6.6.1.0@o2ib
        - nid: 6.6.1.3@o2ib
        - nid: 6.6.1.6@o2ib
        - nid: 6.6.3.0@o2ib
        - nid: 6.6.3.3@o2ib
        - nid: 6.6.3.6@o2ib
        - nid: 6@gni
        - nid: 10@gni
EOF
	append_global_yaml
	compare_peer_add "6.6.6.6@tcp" \
		"6.6.[6-7].[0-4/2]@tcp,6.6.[1-4/2].[0-6/3]@o2ib,[6-12/4]@gni"
}
run_test 6 "Add peer with multiple nidranges"

compare_peer_del() {
	local prim_nid="${1:+--prim_nid $1}"
	local nid="${2:+--nid $2}"

	local actual="$TMP/sanity-lnet-$testnum-actual.yaml"

	do_lnetctl peer del ${prim_nid} ${nid} || error "peer del failed $?"
	$LNETCTL export --backup > $actual || error "export failed $?"
	compare_yaml_files
	return $?
}

test_7() {
	reinit_dlc || return $?
	create_base_yaml_file

	echo "Delete peer with single nid (tcp)"
	do_lnetctl peer add --prim_nid 7.7.7.7@tcp || error "Peer add failed $?"
	compare_peer_del "7.7.7.7@tcp"

	echo "Delete peer with single nid (o2ib)"
	do_lnetctl peer add --prim_nid 7.7.7.7@o2ib || error "Peer add failed $?"
	compare_peer_del "7.7.7.7@o2ib"

	echo "Delete peer that has multiple nids (tcp)"
	do_lnetctl peer add --prim_nid 7.7.7.7@tcp --nid 7.7.7.[8-12]@tcp ||
		error "Peer add failed $?"
	compare_peer_del "7.7.7.7@tcp"

	echo "Delete peer that has multiple nids (o2ib)"
	do_lnetctl peer add --prim_nid 7.7.7.7@o2ib --nid 7.7.7.[8-12]@o2ib ||
		error "Peer add failed $?"
	compare_peer_del "7.7.7.7@o2ib"

	echo "Delete peer that has both tcp and o2ib nids"
	do_lnetctl peer add --prim_nid 7.7.7.7@tcp \
		--nid 7.7.7.[9-12]@tcp,7.7.7.[13-15]@o2ib ||
		error "Peer add failed $?"
	compare_peer_del "7.7.7.7@tcp"

	echo "Delete peer with single nid (gni)"
	do_lnetctl peer add --prim_nid 7@gni || error "Peer add failed $?"
	compare_peer_del "7@gni"

	echo "Delete peer that has multiple nids (gni)"
	do_lnetctl peer add --prim_nid 7@gni --nid [8-12]@gni ||
		error "Peer add failed $?"
	compare_peer_del "7@gni"

	echo "Delete peer that has tcp, o2ib and gni nids"
	do_lnetctl peer add --prim_nid 7@gni \
		--nid [8-12]@gni,7.7.7.[9-12]@tcp,7.7.7.[13-15]@o2ib ||
		error "Peer add failed $?"
	compare_peer_del "7@gni"
}
run_test 7 "Various peer delete tests"

test_8() {
	reinit_dlc || return $?

	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 8.8.8.8@tcp
      Multi-Rail: True
      peer ni:
        - nid: 8.8.8.8@tcp
        - nid: 8.8.8.10@tcp
        - nid: 8.8.8.11@tcp
        - nid: 8.8.8.12@tcp
        - nid: 8.8.8.14@tcp
        - nid: 8.8.8.15@tcp
EOF
	append_global_yaml

	do_lnetctl peer add --prim_nid 8.8.8.8@tcp --nid 8.8.8.[10-15]@tcp ||
		error "Peer add failed $?"
	compare_peer_del "8.8.8.8@tcp" "8.8.8.13@tcp"
}
run_test 8 "Delete single secondary nid from peer (tcp)"

test_9() {
	reinit_dlc || return $?

	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 9.9.9.9@tcp
      Multi-Rail: True
      peer ni:
        - nid: 9.9.9.9@tcp
EOF
	append_global_yaml

	do_lnetctl peer add --prim_nid 9.9.9.9@tcp \
		--nid 9.9.9.[11-16]@tcp || error "Peer add failed $?"
	compare_peer_del "9.9.9.9@tcp" "9.9.9.[11-16]@tcp"
}
run_test 9 "Delete all secondary nids from peer (tcp)"

test_10() {
	reinit_dlc || return $?

	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 10.10.10.10@tcp
      Multi-Rail: True
      peer ni:
        - nid: 10.10.10.10@tcp
        - nid: 10.10.10.12@tcp
        - nid: 10.10.10.13@tcp
        - nid: 10.10.10.15@tcp
        - nid: 10.10.10.16@tcp
EOF
	append_global_yaml
	do_lnetctl peer add --prim_nid 10.10.10.10@tcp \
		--nid 10.10.10.[12-16]@tcp || error "Peer add failed $?"
	compare_peer_del "10.10.10.10@tcp" "10.10.10.14@tcp"
}
run_test 10 "Delete single secondary nid from peer (o2ib)"

test_11() {
	reinit_dlc || return $?

	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 11.11.11.11@tcp
      Multi-Rail: True
      peer ni:
        - nid: 11.11.11.11@tcp
EOF
	append_global_yaml
	do_lnetctl peer add --prim_nid 11.11.11.11@tcp \
		--nid 11.11.11.[13-17]@tcp || error "Peer add failed $?"
	compare_peer_del "11.11.11.11@tcp" "11.11.11.[13-17]@tcp"
}
run_test 11 "Delete all secondary nids from peer (o2ib)"

test_12() {
	reinit_dlc || return $?

	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 12.12.12.12@o2ib
      Multi-Rail: True
      peer ni:
        - nid: 12.12.12.12@o2ib
        - nid: 13.13.13.13@o2ib
        - nid: 14.13.13.13@o2ib
        - nid: 14.15.13.13@o2ib
        - nid: 15.17.1.5@tcp
        - nid: 15.17.1.10@tcp
        - nid: 15.17.1.20@tcp
EOF
	append_global_yaml
	do_lnetctl peer add --prim_nid 12.12.12.12@o2ib \
		--nid [13-14/1].[13-15/2].13.13@o2ib,[15-16/3].[17-19/4].[1].[5-20/5]@tcp ||
		error "Peer add failed $?"
	compare_peer_del "12.12.12.12@o2ib" "13.15.13.13@o2ib,15.17.1.15@tcp"
}
run_test 12 "Delete a secondary nid from peer (tcp and o2ib)"

test_13() {
	reinit_dlc || return $?

	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 13.13.13.13@o2ib
      Multi-Rail: True
      peer ni:
        - nid: 13.13.13.13@o2ib
EOF
	append_global_yaml
	do_lnetctl peer add --prim_nid 13.13.13.13@o2ib \
		--nid [14-15].[1-2/1].[1].[100-254/10]@tcp,14.14.[254].14@o2ib ||
		error "Peer add failed $?"
	compare_peer_del "13.13.13.13@o2ib" \
		"[14-15].[1-2/1].[1].[100-254/10]@tcp,14.14.[254].14@o2ib"
}
run_test 13 "Delete all secondary nids from peer (tcp and o2ib)"

create_nid() {
	local num="$1"
	local net="$2"

	if [[ $net =~ gni* ]]; then
		echo "${num}@${net}"
	else
		echo "${num}.${num}.${num}.${num}@${net}"
	fi
}

create_mr_peer_yaml() {
	local num_peers="$1"
	local secondary_nids="$2"
	local net="$3"

	echo "Generating peer yaml for $num_peers peers with $secondary_nids secondary nids"
	echo "peer:" >> $TMP/sanity-lnet-$testnum-expected.yaml
	local i
	local total_nids=$((num_peers + $((num_peers * secondary_nids))))
	local created=0
	local nidnum=1
	while [[ $created -lt $num_peers ]]; do
		local primary=$(create_nid ${nidnum} ${net})
	cat <<EOF >> $TMP/sanity-lnet-$testnum-expected.yaml
    - primary nid: $primary
      Multi-Rail: True
      peer ni:
        - nid: $primary
EOF
		local j
		local start=$((nidnum + 1))
		local end=$((nidnum + $secondary_nids))
		for j in $(seq ${start} ${end}); do
			local nid=$(create_nid $j ${net})
			echo "        - nid: $nid" >> $TMP/sanity-lnet-$testnum-expected.yaml
		done
		nidnum=$((end + 1))
		((created++))
	done
}

test_14() {
	reinit_dlc || return $?

	echo "Create single peer, single nid, using import"
	create_mr_peer_yaml 1 0 tcp
	do_lnetctl import < $TMP/sanity-lnet-$testnum-expected.yaml ||
		error "Import failed $?"
	append_global_yaml
	$LNETCTL export --backup > $TMP/sanity-lnet-$testnum-actual.yaml
	compare_yaml_files

	echo "Delete single peer using import --del"
	do_lnetctl import --del < $TMP/sanity-lnet-$testnum-expected.yaml ||
		error "Import failed $?"
	rm -f $TMP/sanity-lnet-$testnum-expected.yaml
	create_base_yaml_file
	$LNETCTL export --backup > $TMP/sanity-lnet-$testnum-actual.yaml
	compare_yaml_files
}
run_test 14 "import peer create/delete with single nid"

test_15() {
	reinit_dlc || return $?

	echo "Create multiple peers, single nid per peer, using import"
	create_mr_peer_yaml 5 0 o2ib
	# The ordering of nids for this use-case is non-deterministic, so we
	# we can't just diff the expected/actual output.
	do_lnetctl import < $TMP/sanity-lnet-$testnum-expected.yaml ||
		error "Import failed $?"
	$LNETCTL export --backup > $TMP/sanity-lnet-$testnum-actual.yaml
	validate_peer_nids 5 0

	echo "Delete multiple peers, single nid per peer, using import --del"
	do_lnetctl import --del < $TMP/sanity-lnet-$testnum-expected.yaml ||
		error "Import failed $?"
	rm -f $TMP/sanity-lnet-$testnum-expected.yaml
	create_base_yaml_file
	$LNETCTL export --backup > $TMP/sanity-lnet-$testnum-actual.yaml
	compare_yaml_files
}
run_test 15 "import multi peer create/delete with single nid per peer"

test_16() {
	reinit_dlc || return $?

	echo "Create single peer, multiple nids, using import"
	create_mr_peer_yaml 1 5 tcp
	do_lnetctl import < $TMP/sanity-lnet-$testnum-expected.yaml ||
		error "Import failed $?"
	$LNETCTL export --backup > $TMP/sanity-lnet-$testnum-actual.yaml
	validate_peer_nids 1 5

	echo "Delete single peer, multiple nids, using import --del"
	do_lnetctl import --del < $TMP/sanity-lnet-$testnum-expected.yaml ||
		error "Import failed $?"
	rm -f $TMP/sanity-lnet-$testnum-expected.yaml
	create_base_yaml_file
	$LNETCTL export --backup > $TMP/sanity-lnet-$testnum-actual.yaml
	compare_yaml_files
}
run_test 16 "import peer create/delete with multiple nids"

test_17() {
	reinit_dlc || return $?

	echo "Create multiple peers, multiple nids per peer, using import"
	create_mr_peer_yaml 5 7 o2ib
	do_lnetctl import < $TMP/sanity-lnet-$testnum-expected.yaml ||
		error "Import failed $?"
	$LNETCTL export --backup > $TMP/sanity-lnet-$testnum-actual.yaml
	validate_peer_nids 5 7

	echo "Delete multiple peers, multiple nids per peer, using import --del"
	do_lnetctl import --del < $TMP/sanity-lnet-$testnum-expected.yaml ||
		error "Import failed $?"
	rm -f $TMP/sanity-lnet-$testnum-expected.yaml
	create_base_yaml_file
	$LNETCTL export --backup > $TMP/sanity-lnet-$testnum-actual.yaml
	compare_yaml_files
}
run_test 17 "import multi peer create/delete with multiple nids"

test_18a() {
	reinit_dlc || return $?

	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 1.1.1.1@tcp
      Multi-Rail: True
      peer ni:
        - nid: 1.1.1.1@tcp
        - nid: 2.2.2.2@tcp
        - nid: 4.4.4.4@tcp
        - nid: 3.3.3.3@o2ib
        - nid: 5@gni
EOF
	echo "Import peer with 5 nids"
	cat $TMP/sanity-lnet-$testnum-expected.yaml
	do_lnetctl import < $TMP/sanity-lnet-$testnum-expected.yaml ||
		error "Import failed $?"
	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 1.1.1.1@tcp
      Multi-Rail: True
      peer ni:
        - nid: 2.2.2.2@tcp
        - nid: 3.3.3.3@o2ib
        - nid: 5@gni
EOF
	echo "Delete three of the nids"
	cat $TMP/sanity-lnet-$testnum-expected.yaml
	do_lnetctl import --del < $TMP/sanity-lnet-$testnum-expected.yaml
	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 1.1.1.1@tcp
      Multi-Rail: True
      peer ni:
        - nid: 1.1.1.1@tcp
        - nid: 4.4.4.4@tcp
EOF
	echo "Check peer has expected nids remaining"
	$LNETCTL export --backup > $TMP/sanity-lnet-$testnum-actual.yaml
	append_global_yaml
	compare_yaml_files
}
run_test 18a "Delete a subset of nids from a single peer using import --del"

test_18b() {
	reinit_dlc || return $?

	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 1.1.1.1@tcp
      Multi-Rail: True
      peer ni:
        - nid: 1.1.1.1@tcp
        - nid: 2.2.2.2@tcp
        - nid: 4.4.4.4@tcp
        - nid: 3.3.3.3@o2ib
        - nid: 5@gni
    - primary nid: 6.6.6.6@o2ib
      Multi-Rail: True
      peer ni:
        - nid: 6.6.6.6@o2ib
        - nid: 7.7.7.7@tcp
        - nid: 8.8.8.8@tcp
        - nid: 9.9.9.9@tcp
        - nid: 10@gni
EOF
	echo "Import two peers with 5 nids each"
	cat $TMP/sanity-lnet-$testnum-expected.yaml
	do_lnetctl import < $TMP/sanity-lnet-$testnum-expected.yaml ||
		error "Import failed $?"
	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 1.1.1.1@tcp
      Multi-Rail: True
      peer ni:
        - nid: 2.2.2.2@tcp
        - nid: 3.3.3.3@o2ib
        - nid: 5@gni
    - primary nid: 6.6.6.6@o2ib
      Multi-Rail: True
      peer ni:
        - nid: 7.7.7.7@tcp
        - nid: 8.8.8.8@tcp
        - nid: 10@gni
EOF
	echo "Delete three of the nids from each peer"
	cat $TMP/sanity-lnet-$testnum-expected.yaml
	do_lnetctl import --del < $TMP/sanity-lnet-$testnum-expected.yaml
	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 6.6.6.6@o2ib
      Multi-Rail: True
      peer ni:
        - nid: 6.6.6.6@o2ib
        - nid: 7.7.7.7@tcp
    - primary nid: 1.1.1.1@tcp
      Multi-Rail: True
      peer ni:
        - nid: 1.1.1.1@tcp
        - nid: 4.4.4.4@tcp
EOF
	append_global_yaml
	echo "Check peers have expected nids remaining"
	$LNETCTL export --backup > $TMP/sanity-lnet-$testnum-actual.yaml
	compare_yaml_files
	validate_peer_nids 2 1
}
run_test 18b "Delete multiple nids from multiple peers using import --del"

test_19() {
	reinit_dlc || return $?
	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 19@gni
      Multi-Rail: True
      peer ni:
        - nid: 19@gni
EOF
	append_global_yaml
	compare_peer_add "19@gni"
}
run_test 19 "Add peer with single nid (gni)"

test_20() {
	reinit_dlc || return $?
	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 20@gni
      Multi-Rail: True
      peer ni:
        - nid: 20@gni
        - nid: 20.20.20.20@tcp
        - nid: 20.20.20.20@o2ib
EOF
	append_global_yaml
	compare_peer_add "20@gni" "20.20.20.20@tcp,20.20.20.20@o2ib"
}
run_test 20 "Add peer with gni primary and tcp, o2ib secondary"

test_21() {
	reinit_dlc || return $?
	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 21@gni
      Multi-Rail: True
      peer ni:
        - nid: 21@gni
        - nid: 22@gni
        - nid: 23@gni
        - nid: 24@gni
        - nid: 25@gni
EOF
	append_global_yaml
	echo "Add peer with nidrange (gni)"
	compare_peer_add "21@gni" "[22-25]@gni" || error
	echo "Add peer with nidrange that overlaps primary nid (gni)"
	compare_peer_add "21@gni" "[21-25]@gni"
}
run_test 21 "Add peer with nidrange (gni)"

test_22() {
	reinit_dlc || return $?
	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 22@gni
      Multi-Rail: True
      peer ni:
        - nid: 22@gni
        - nid: 24@gni
        - nid: 25@gni
        - nid: 27@gni
        - nid: 28@gni
        - nid: 29@gni
EOF
	append_global_yaml
	do_lnetctl peer add --prim_nid 22@gni --nid [24-29]@gni ||
		error "Peer add failed $?"
	compare_peer_del "22@gni" "26@gni"
}
run_test 22 "Delete single secondary nid from peer (gni)"

test_23() {
	reinit_dlc || return $?
	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 23@gni
      Multi-Rail: True
      peer ni:
        - nid: 23@gni
EOF
	append_global_yaml

	do_lnetctl peer add --prim_nid 23@gni --nid [25-29]@gni ||
		error "Peer add failed $?"
	compare_peer_del "23@gni" "[25-29]@gni"
}
run_test 23 "Delete all secondary nids from peer (gni)"

test_24() {
	reinit_dlc || return $?
	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 24@gni
      Multi-Rail: True
      peer ni:
        - nid: 24@gni
        - nid: 11@gni
        - nid: 13.13.13.13@o2ib
        - nid: 14.13.13.13@o2ib
        - nid: 14.15.13.13@o2ib
        - nid: 15.17.1.5@tcp
        - nid: 15.17.1.10@tcp
        - nid: 15.17.1.20@tcp
EOF
	append_global_yaml
	do_lnetctl peer add --prim_nid 24@gni \
		--nid [13-14/1].[13-15/2].13.13@o2ib,[15-16/3].[17-19/4].[1].[5-20/5]@tcp,[5-12/6]@gni ||
		error "Peer add failed $?"
	compare_peer_del "24@gni" "5@gni,13.15.13.13@o2ib,15.17.1.15@tcp"
}
run_test 24 "Delete a secondary nid from peer (tcp, o2ib and gni)"

test_25() {
	reinit_dlc || return $?
	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
peer:
    - primary nid: 25@gni
      Multi-Rail: True
      peer ni:
        - nid: 25@gni
EOF
	append_global_yaml
	do_lnetctl peer add --prim_nid 25@gni \
		--nid [26-27].[4-10/3].26.26@tcp,26.26.26.26@o2ib,[30-35]@gni ||
		error "Peer add failed $?"
	compare_peer_del "25@gni" \
		"[26-27].[4-10/3].26.26@tcp,26.26.26.26@o2ib,[30-35]@gni"
}
run_test 25 "Delete all secondary nids from peer (tcp, gni and o2ib)"

test_99a() {
	reinit_dlc || return $?

	echo "Invalid prim_nid - peer add"
	do_lnetctl peer add --prim_nid foobar &&
		error "Command should have failed"

	echo "Invalid prim_nid - peer del"
	do_lnetctl peer del --prim_nid foobar &&
		error "Command should have failed"

	echo "Delete non-existing peer"
	do_lnetctl peer del --prim_nid 1.1.1.1@o2ib &&
		error "Command should have failed"

	echo "Don't provide mandatory argument for peer del"
	do_lnetctl peer del --nid 1.1.1.1@tcp &&
		error "Command should have failed"

	echo "Don't provide mandatory argument for peer add"
	do_lnetctl peer add --nid 1.1.1.1@tcp &&
		error "Command should have failed"

	echo "Don't provide mandatory arguments peer add"
	do_lnetctl peer add &&
		error "Command should have failed"

	echo "Invalid secondary nids"
	do_lnetctl peer add --prim_nid 1.1.1.1@tcp --nid foobar &&
		error "Command should have failed"

	echo "Exceed max nids per peer"
	do_lnetctl peer add --prim_nid 1.1.1.1@tcp --nid 1.1.1.[2-255]@tcp &&
		error "Command should have failed"

	echo "Invalid net type"
	do_lnetctl peer add --prim_nid 1@foo &&
		error "Command should have failed"

	echo "Invalid nid format"
	local invalid_nids="1@tcp 1@o2ib 1.1.1.1@gni"

	local nid
	for nid in ${invalid_nids}; do
		echo "Check invalid primary nid - '$nid'"
		do_lnetctl peer add --prim_nid $nid &&
			error "Command should have failed"
	done

	local invalid_strs="[2-1]@gni [a-f/x]@gni 256.256.256.256@tcp"
	invalid_strs+=" 1.1.1.1.[2-5/f]@tcp 1.]2[.3.4@o2ib"
	invalid_strs+="1.[2-4,[5-6],7-8].1.1@tcp foobar"

	local nidstr
	for nidstr in ${invalid_strs}; do
		echo "Check invalid nidstring - '$nidstr'"
		do_lnetctl peer add --prim_nid 1.1.1.1@tcp --nid $nidstr &&
			error "Command should have failed"
	done

	echo "Add non-local gateway"
	do_lnetctl route add --net tcp --gateway 1@gni &&
		error "Command should have failed"

	return 0
}
run_test 99a "Check various invalid inputs to lnetctl peer"

test_99b() {
	reinit_dlc || return $?

	create_base_yaml_file

	cat <<EOF > $TMP/sanity-lnet-$testnum-invalid.yaml
peer:
    - primary nid: 99.99.99.99@tcp
      Multi-Rail: Foobar
      peer ni:
        - nid: 99.99.99.99@tcp
EOF
	do_lnetctl import < $TMP/sanity-lnet-$testnum-invalid.yaml &&
		error "import should have failed"
	$LNETCTL export --backup > $TMP/sanity-lnet-$testnum-actual.yaml
	compare_yaml_files
}
run_test 99b "Invalid value for Multi-Rail in yaml import"

have_interface() {
	local if="$1"
	local ip=$(ip addr show dev $if | awk '/ inet /{print $2}')
	[[ -n $ip ]]
}

add_net() {
	local net="$1"
	local if="$2"

	if ! lsmod | grep -q ksocklnd ; then
		load_module ../lnet/klnds/socklnd/ksocklnd ||
			error "Can't load ksocklnd.ko"
	fi

	do_lnetctl net add --net ${net} --if ${if} ||
		error "Failed to add net ${net} on if ${if}"
}

compare_route_add() {
	local rnet="$1"
	local gw="$2"

	local actual="$TMP/sanity-lnet-$testnum-actual.yaml"

	do_lnetctl route add --net ${rnet} --gateway ${gw} ||
		error "route add failed $?"
	# CPT configuration is pruned from the exported yaml, since the default
	# can vary across test systems (unlike default values for things like
	# peer_credits, peer_timeout, etc.)
	$LNETCTL export --backup | grep -v CPT > $actual ||
		error "export failed $?"
	validate_gateway_nids
	return $?
}

test_100() {
	have_interface "eth0" || skip "Need eth0 interface with ipv4 configured"
	reinit_dlc || return $?
	add_net "tcp" "eth0"
	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
net:
    - net type: tcp
      local NI(s):
        - interfaces:
              0: eth0
          tunables:
              peer_timeout: 180
              peer_credits: 8
              peer_buffer_credits: 0
              credits: 256
route:
    - net: tcp7
      gateway: 7.7.7.7@tcp
      hop: -1
      priority: 0
      health_sensitivity: 1
peer:
    - primary nid: 7.7.7.7@tcp
      Multi-Rail: False
      peer ni:
        - nid: 7.7.7.7@tcp
EOF
	append_global_yaml
	compare_route_add "tcp7" "7.7.7.7@tcp" || return $?
	compare_yaml_files
}
run_test 100 "Add route with single gw (tcp)"

test_101() {
	have_interface "eth0" || skip "Need eth0 interface with ipv4 configured"
	reinit_dlc || return $?
	add_net "tcp" "eth0"
	cat <<EOF > $TMP/sanity-lnet-$testnum-expected.yaml
net:
    - net type: tcp
      local NI(s):
        - interfaces:
              0: eth0
          tunables:
              peer_timeout: 180
              peer_credits: 8
              peer_buffer_credits: 0
              credits: 256
route:
    - net: tcp8
      gateway: 8.8.8.10@tcp
      hop: -1
      priority: 0
      health_sensitivity: 1
    - net: tcp8
      gateway: 8.8.8.9@tcp
      hop: -1
      priority: 0
      health_sensitivity: 1
    - net: tcp8
      gateway: 8.8.8.8@tcp
      hop: -1
      priority: 0
      health_sensitivity: 1
peer:
    - primary nid: 8.8.8.9@tcp
      Multi-Rail: False
      peer ni:
        - nid: 8.8.8.9@tcp
    - primary nid: 8.8.8.10@tcp
      Multi-Rail: False
      peer ni:
        - nid: 8.8.8.10@tcp
    - primary nid: 8.8.8.8@tcp
      Multi-Rail: False
      peer ni:
        - nid: 8.8.8.8@tcp
EOF
	append_global_yaml
	compare_route_add "tcp8" "8.8.8.[8-10]@tcp"
}
run_test 101 "Add route with multiple gw (tcp)"

compare_route_del() {
	local rnet="$1"
	local gw="$2"

	local actual="$TMP/sanity-lnet-$testnum-actual.yaml"

	do_lnetctl route del --net ${rnet} --gateway ${gw} ||
		error "route del failed $?"
	$LNETCTL export --backup > $actual ||
		error "export failed $?"
	validate_gateway_nids
}

test_102() {
	have_interface "eth0" || skip "Need eth0 interface with ipv4 configured"
	reinit_dlc || return $?
	add_net "tcp" "eth0"
	$LNETCTL export --backup > $TMP/sanity-lnet-$testnum-expected.yaml
	do_lnetctl route add --net tcp102 --gateway 102.102.102.102@tcp ||
		error "route add failed $?"
	compare_route_del "tcp102" "102.102.102.102@tcp"
}
run_test 102 "Delete route with single gw (tcp)"

test_103() {
	have_interface "eth0" || skip "Need eth0 interface with ipv4 configured"
	reinit_dlc || return $?
	add_net "tcp" "eth0"
	$LNETCTL export --backup > $TMP/sanity-lnet-$testnum-expected.yaml
	do_lnetctl route add --net tcp103 \
		--gateway 103.103.103.[103-120/4]@tcp ||
		error "route add failed $?"
	compare_route_del "tcp103" "103.103.103.[103-120/4]@tcp"
}
run_test 103 "Delete route with multiple gw (tcp)"

test_104() {
	local tyaml="$TMP/sanity-lnet-$testnum-expected.yaml"

	reinit_dlc || return $?

	# Default value is '3'
	local val=$($LNETCTL global show | awk '/response_tracking/{print $NF}')
	[[ $val -ne 3 ]] &&
		error "Expect 3 found $val"

	echo "Set < 0;  Should fail"
	do_lnetctl set response_tracking -1 &&
		 error "should have failed $?"

	reinit_dlc || return $?
	cat <<EOF > $tyaml
global:
    response_tracking: -10
EOF
	do_lnetctl import < $tyaml &&
		error "should have failed $?"

	echo "Check valid values; Should succeed"
	local i
	for ((i = 0; i < 4; i++)); do
		reinit_dlc || return $?
		do_lnetctl set response_tracking $i ||
			 error "should have succeeded $?"
		$LNETCTL global show | grep -q "response_tracking: $i" ||
			error "Failed to set response_tracking to $i"
		reinit_dlc || return $?
		cat <<EOF > $tyaml
global:
    response_tracking: $i
EOF
		do_lnetctl import < $tyaml ||
			error "should have succeeded $?"
		$LNETCTL global show | grep -q "response_tracking: $i" ||
			error "Failed to set response_tracking to $i"
	done

	reinit_dlc || return $?
	echo "Set > 3; Should fail"
	do_lnetctl set response_tracking 4 &&
		 error "should have failed $?"

	reinit_dlc || return $?
	cat <<EOF > $tyaml
global:
    response_tracking: 10
EOF
	do_lnetctl import < $tyaml &&
		error "should have failed $?"
	return 0
}
run_test 104 "Set/check response_tracking param"

### load lnet in default namespace, configure in target namespace

test_200() {
	cleanup_lnet || exit 1
	load_lnet "networks=\"\""
	do_ns $LNETCTL lnet configure --all || exit 1
	$LNETCTL net show --net tcp | grep -q "nid: ${FAKE_IP}@tcp$"
}
run_test 200 "load lnet w/o module option, configure in a non-default namespace"

test_201() {
	cleanup_lnet || exit 1
	load_lnet "networks=tcp($FAKE_IF)"
	do_ns $LNETCTL lnet configure --all || exit 1
	$LNETCTL net show --net tcp | grep -q "nid: ${FAKE_IP}@tcp$"
}
run_test 201 "load lnet using networks module options in a non-default namespace"

test_202() {
	cleanup_lnet || exit 1
	load_lnet "networks=\"\" ip2nets=\"tcp0($FAKE_IF) ${FAKE_IP}\""
	do_ns $LNETCTL lnet configure --all || exit 1
	$LNETCTL net show | grep -q "nid: ${FAKE_IP}@tcp$"
}
run_test 202 "load lnet using ip2nets in a non-default namespace"


### Add the interfaces in the target namespace

test_203() {
	cleanup_lnet || exit 1
	load_lnet
	do_lnetctl lnet configure || exit 1
	do_ns $LNETCTL net add --net tcp0 --if $FAKE_IF
}
run_test 203 "add a network using an interface in the non-default namespace"

LNET_PARAMS_FILE="$TMP/$TESTSUITE.parameters"
function save_lnet_params() {
	$LNETCTL global show | egrep -v '^global:$' |
			       sed 's/://' > $LNET_PARAMS_FILE
}

function restore_lnet_params() {
	local param value
	while read param value; do
		[[ $param == max_intf ]] && continue
		[[ $param == lnd_timeout ]] && continue
		$LNETCTL set ${param} ${value} ||
			error "Failed to restore ${param} to ${value}"
	done < $LNET_PARAMS_FILE
}

function lnet_health_pre() {
	save_lnet_params

	# Lower transaction timeout to speed up test execution
	$LNETCTL set transaction_timeout 10 ||
		error "Failed to set transaction_timeout $?"

	# Increase recovery interval so we have time to capture health values
	$LNETCTL set recovery_interval 20 ||
		error "Failed to set recovery_interval $?"

	RETRY_PARAM=$($LNETCTL global show | awk '/retry_count/{print $NF}')
	RSND_PRE=$($LNETCTL stats show | awk '/resend_count/{print $NF}')
	LO_HVAL_PRE=$($LNETCTL net show -v 2 | awk '/health value/{print $NF}' |
		      xargs echo | sed 's/ /+/g' | bc -l)

	local my_nid=$($LCTL list_nids | head -n 1)

	RMT_HVAL_PRE=$($LNETCTL peer show --nid $my_nid -v 2 2>/dev/null |
		       awk '/health value/{print $NF}' | xargs echo |
		       sed 's/ /+/g' | bc -l)

	# Might not have any peers so initialize to zero.
	RMT_HVAL_PRE=${RMT_HVAL_PRE:-0}

	return 0
}

function lnet_health_post() {
	RSND_POST=$($LNETCTL stats show | awk '/resend_count/{print $NF}')
	LO_HVAL_POST=$($LNETCTL net show -v 2 |
		       awk '/health value/{print $NF}' |
		       xargs echo | sed 's/ /+/g' | bc -l)

	local my_nid=$($LCTL list_nids | head -n 1)

	RMT_HVAL_POST=$($LNETCTL peer show --nid $my_nid -v 2 2>/dev/null |
			awk '/health value/{print $NF}' | xargs echo |
			sed 's/ /+/g' | bc -l)

	# Might not have any peers so initialize to zero.
	RMT_HVAL_POST=${RMT_HVAL_POST:-0}

	${VERBOSE} &&
	echo "Pre resends: $RSND_PRE" &&
	echo "Post resends: $RSND_POST" &&
	echo "Resends delta: $((RSND_POST - RSND_PRE))" &&
	echo "Pre local health: $LO_HVAL_PRE" &&
	echo "Post local health: $LO_HVAL_POST" &&
	echo "Pre remote health: $RMT_HVAL_PRE" &&
	echo "Post remote health: $RMT_HVAL_POST"

	restore_lnet_params

	return 0
}

function check_no_resends() {
	echo "Check that no resends took place"
	[[ $RSND_POST -ne $RSND_PRE ]] &&
		error "Found resends: $RSND_POST != $RSND_PRE"

	return 0
}

function check_resends() {
	local delta=$((RSND_POST - RSND_PRE))

	echo "Check that $RETRY_PARAM resends took place"
	[[ $delta -ne $RETRY_PARAM ]] &&
		error "Expected $RETRY_PARAM resends found $delta"

	return 0
}

function check_no_local_health() {
	echo "Check that local NI health is unchanged"
	[[ $LO_HVAL_POST -ne $LO_HVAL_PRE ]] &&
		error "Local health changed: $LO_HVAL_POST != $LO_HVAL_PRE"

	return 0
}

function check_local_health() {
	echo "Check that local NI health has been changed"
	[[ $LO_HVAL_POST -eq $LO_HVAL_PRE ]] &&
		error "Local health unchanged: $LO_HVAL_POST == $LO_HVAL_PRE"

	return 0
}

function check_no_remote_health() {
	echo "Check that remote NI health is unchanged"
	[[ $RMT_HVAL_POST -ne $RMT_HVAL_PRE ]] &&
		error "Remote health changed: $RMT_HVAL_POST != $RMT_HVAL_PRE"

	return 0
}

function check_remote_health() {
	echo "Check that remote NI health has been changed"
	[[ $RMT_HVAL_POST -eq $RMT_HVAL_PRE ]] &&
		error "Remote health unchanged: $RMT_HVAL_POST == $RMT_HVAL_PRE"

	return 0
}

# See lnet/lnet/lib-msg.c:lnet_health_check()
LNET_LOCAL_RESEND_STATUSES="local_interrupt local_dropped local_aborted"
LNET_LOCAL_RESEND_STATUSES+=" local_no_route local_timeout"
LNET_LOCAL_NO_RESEND_STATUSES="local_error"
test_204() {
	have_interface "eth0" || skip "Need eth0 interface with ipv4 configured"
	reinit_dlc || return $?
	add_net "tcp" "eth0" || return $?

	lnet_health_pre || return $?

	local hstatus
	for hstatus in ${LNET_LOCAL_RESEND_STATUSES} \
		       ${LNET_LOCAL_NO_RESEND_STATUSES}; do
		echo "Simulate $hstatus"
		$LCTL net_drop_add -s *@tcp -d *@tcp -m GET -r 1 -e ${hstatus}
		do_lnetctl discover $($LCTL list_nids | head -n 1) &&
			error "Should have failed"
		$LCTL net_drop_del *
	done

	lnet_health_post

	check_no_resends || return $?
	check_no_local_health || return $?

	return 0
}
run_test 204 "Check no health or resends for single-rail local failures"

test_205() {
	have_interface "eth0" || skip "Need eth0 interface with ipv4 configured"

	local hstatus
	for hstatus in ${LNET_LOCAL_RESEND_STATUSES}; do
		reinit_dlc || return $?
		add_net "tcp" "eth0" || return $?
		add_net "tcp1" "eth0" || return $?

		echo "Simulate $hstatus"
		lnet_health_pre

		$LCTL net_drop_add -s *@tcp -d *@tcp -m GET -r 1 -e ${hstatus}
		$LCTL net_drop_add -s *@tcp1 -d *@tcp1 -m GET -r 1 -e ${hstatus}
		do_lnetctl discover $($LCTL list_nids | head -n 1) &&
			error "Should have failed"
		$LCTL net_drop_del *

		lnet_health_post

		check_resends || return $?
		check_local_health || return $?
	done

	for hstatus in ${LNET_LOCAL_NO_RESEND_STATUSES}; do
		reinit_dlc || return $?
		add_net "tcp" "eth0" || return $?
		add_net "tcp1" "eth0" || return $?

		echo "Simulate $hstatus"
		lnet_health_pre || return $?

		$LCTL net_drop_add -s *@tcp -d *@tcp -m GET -r 1 -e ${hstatus}
		$LCTL net_drop_add -s *@tcp1 -d *@tcp1 -m GET -r 1 -e ${hstatus}
		do_lnetctl discover $($LCTL list_nids | head -n 1) &&
			error "Should have failed"
		$LCTL net_drop_del *

		lnet_health_post

		check_no_resends || return $?
		check_local_health || return $?
	done

	return 0
}
run_test 205 "Check health and resends for multi-rail local failures"

# See lnet/lnet/lib-msg.c:lnet_health_check()
LNET_REMOTE_RESEND_STATUSES="remote_dropped"
LNET_REMOTE_NO_RESEND_STATUSES="remote_error remote_timeout"
test_206() {
	have_interface "eth0" || skip "Need eth0 interface with ipv4 configured"
	reinit_dlc || return $?
	add_net "tcp" "eth0" || return $?

	do_lnetctl discover $($LCTL list_nids | head -n 1) ||
		error "failed to discover myself"

	lnet_health_pre || return $?

	local hstatus
	for hstatus in ${LNET_REMOTE_RESEND_STATUSES} \
		       ${LNET_REMOTE_NO_RESEND_STATUSES}; do
		echo "Simulate $hstatus"
		$LCTL net_drop_add -s *@tcp -d *@tcp -m GET -r 1 -e ${hstatus}
		do_lnetctl discover $($LCTL list_nids | head -n 1) &&
			error "Should have failed"
		$LCTL net_drop_del *
	done

	lnet_health_post

	check_no_resends || return $?
	check_no_local_health || return $?
	check_no_remote_health || return $?

	return 0
}
run_test 206 "Check no health or resends for single-rail remote failures"

test_207() {
	have_interface "eth0" || skip "Need eth0 interface with ipv4 configured"

	local hstatus
	for hstatus in ${LNET_REMOTE_RESEND_STATUSES}; do
		reinit_dlc || return $?
		add_net "tcp" "eth0" || return $?
		add_net "tcp1" "eth0" || return $?

		do_lnetctl discover $($LCTL list_nids | head -n 1) ||
			error "failed to discover myself"

		echo "Simulate $hstatus"
		lnet_health_pre || return $?
		$LCTL net_drop_add -s *@tcp -d *@tcp -m GET -r 1 -e ${hstatus}
		$LCTL net_drop_add -s *@tcp1 -d *@tcp1 -m GET -r 1 -e ${hstatus}
		do_lnetctl discover $($LCTL list_nids | head -n 1) &&
			error "Should have failed"
		$LCTL net_drop_del *

		lnet_health_post

		check_resends || return $?
		check_no_local_health || return $?
		check_remote_health || return $?
	done
	for hstatus in ${LNET_REMOTE_NO_RESEND_STATUSES}; do
		reinit_dlc || return $?
		add_net "tcp" "eth0" || return $?
		add_net "tcp1" "eth0" || return $?

		do_lnetctl discover $($LCTL list_nids | head -n 1) ||
			error "failed to discover myself"

		echo "Simulate $hstatus"
		lnet_health_pre || return $?
		$LCTL net_drop_add -s *@tcp -d *@tcp -m GET -r 1 -e ${hstatus}
		$LCTL net_drop_add -s *@tcp1 -d *@tcp1 -m GET -r 1 -e ${hstatus}
		do_lnetctl discover $($LCTL list_nids | head -n 1) &&
			error "Should have failed"
		$LCTL net_drop_del *

		lnet_health_post

		check_no_resends || return $?
		check_no_local_health || return $?
		check_remote_health || return $?
	done

	return 0
}
run_test 207 "Check health and resends for multi-rail remote errors"

test_208_load_and_check_lnet() {
	local ip2nets="$1"
	local p_nid="$2"
	local s_nid="$3"
	local num_expected=1

	load_lnet "networks=\"\" ip2nets=\"${ip2nets_str}\""

	$LCTL net up ||
		error "Failed to load LNet with ip2nets \"${ip2nets_str}\""

	[[ -n $s_nid ]] &&
		num_expected=2

	declare -a nids
	nids=( $($LCTL list_nids) )

	[[ ${#nids[@]} -ne ${num_expected} ]] &&
		error "Expect ${num_expected} NIDs found ${#nids[@]}"

	[[ ${nids[0]} == ${p_nid} ]] ||
		error "Expect NID \"${p_nid}\" found \"${nids[0]}\""

	[[ -n $s_nid ]] && [[ ${nids[1]} != ${s_nid} ]] &&
		error "Expect second NID \"${s_nid}\" found \"${nids[1]}\""

	$LCTL net down &>/dev/null
	cleanup_lnet
}

test_208() {
	have_interface "eth0" || skip "Need eth0 interface with ipv4 configured"

	cleanup_netns || error "Failed to cleanup netns before test execution"
	cleanup_lnet || error "Failed to unload modules before test execution"
	setup_fakeif || error "Failed to add fake IF"

	have_interface "$FAKE_IF" ||
		error "Expect $FAKE_IF configured but not found"

	local eth0_ip=$(ip --oneline addr show dev eth0 |
			awk '/inet /{print $4}' |
			sed 's:/.*::')
	local ip2nets_str="tcp(eth0) $eth0_ip"

	echo "Configure single NID \"$ip2nets_str\""
	test_208_load_and_check_lnet "${ip2nets_str}" "${eth0_ip}@tcp"

	ip2nets_str="tcp(eth0) $eth0_ip; tcp1($FAKE_IF) $FAKE_IP"
	echo "Configure two NIDs; two NETs \"$ip2nets_str\""
	test_208_load_and_check_lnet "${ip2nets_str}" "${eth0_ip}@tcp" \
				     "${FAKE_IP}@tcp1"

	ip2nets_str="tcp(eth0) $eth0_ip; tcp($FAKE_IF) $FAKE_IP"
	echo "Configure two NIDs; one NET \"$ip2nets_str\""
	test_208_load_and_check_lnet "${ip2nets_str}" "${eth0_ip}@tcp" \
				     "${FAKE_IP}@tcp"
	local addr1=( ${eth0_ip//./ } )
	local addr2=( ${FAKE_IP//./ } )
	local range="[${addr1[0]},${addr2[0]}]"

	local i
	for i in $(seq 1 3); do
		range+=".[${addr1[$i]},${addr2[$i]}]"
	done
	ip2nets_str="tcp(eth0,${FAKE_IF}) ${range}"

	echo "Configured two NIDs; one NET alt syntax \"$ip2nets_str\""
	test_208_load_and_check_lnet "${ip2nets_str}" "${eth0_ip}@tcp" \
				     "${FAKE_IP}@tcp"

	cleanup_fakeif

	echo "alt syntax with missing IF \"$ip2nets_str\""
	load_lnet "networks=\"\" ip2nets=\"${ip2nets_str}\""

	echo "$LCTL net up should fail"
	$LCTL net up &&
		error "LNet bringup should have failed"

	cleanup_lnet
}
run_test 208 "Test various kernel ip2nets configurations"

test_209() {
	have_interface "eth0" || skip "Need eth0 interface with ipv4 configured"

	reinit_dlc || return $?
	add_net "tcp" "eth0" || return $?

	do_lnetctl discover $($LCTL list_nids | head -n 1) ||
		error "failed to discover myself"

	echo "Simulate network_timeout w/SR config"
	lnet_health_pre

	$LCTL net_drop_add -s *@tcp -d *@tcp -m GET -r 1 -e network_timeout
	do_lnetctl discover $($LCTL list_nids | head -n 1) &&
		error "Should have failed"
	$LCTL net_drop_del -a

	lnet_health_post

	check_no_resends || return $?
	check_no_local_health || return $?
	check_no_remote_health || return $?

	reinit_dlc || return $?
	add_net "tcp" "eth0" || return $?
	add_net "tcp1" "eth0" || return $?

	do_lnetctl discover $($LCTL list_nids | head -n 1) ||
		error "failed to discover myself"

	echo "Simulate network_timeout w/MR config"
	lnet_health_pre

	$LCTL net_drop_add -s *@tcp -d *@tcp -m GET -r 1 -e network_timeout
	$LCTL net_drop_add -s *@tcp1 -d *@tcp1 -m GET -r 1 -e network_timeout
	do_lnetctl discover $($LCTL list_nids | head -n 1) &&
		error "Should have failed"
	$LCTL net_drop_del -a

	lnet_health_post

	check_no_resends || return $?
	check_local_health || return $?
	check_remote_health || return $?

	return 0
}
run_test 209 "Check health, but not resends, for network timeout"

test_300() {
	# LU-13274
	local header
	local out=$TMP/$tfile
	local prefix=/usr/include/linux/lnet

	# We use a hard coded prefix so that this test will not fail
	# when run in tree.
	CC=${CC:-cc}
	if ! which $CC > /dev/null 2>&1; then
		skip_env "$CC is not installed"
	fi

	cleanup_lnet || exit 1
	load_lnet

	if ! [[ -d $prefix ]]; then
		# Assume we're running in tree and fixup the include path.
		prefix=$LUSTRE/../lnet/include/uapi/linux/lnet
	fi

	for header in $prefix/*.h; do
		if ! [[ -f "$header" ]]; then
			continue
		fi

		$CC -Wall -Werror -std=c99 -include $header -c -x c /dev/null -o $out ||
			error "cannot compile '$header'"
	done
	rm -f $out
}
run_test 300 "packaged LNet UAPI headers can be compiled"

complete $SECONDS

cleanup_testsuite
exit_status
