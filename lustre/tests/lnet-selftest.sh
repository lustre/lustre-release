#!/usr/bin/bash

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env "$@"
init_logging

ALWAYS_EXCEPT="$LNET_SELFTEST_EXCEPT"

if $FORCE_LARGE_NID; then
	# lst add_group rejects IPv6 NIDs ("Invalid nid: fd33:...@tcp"), so no
	# test that builds a session can run here.
	always_except LU-19364 smoke teardown brw_offset teardown_race \
		teardown_deadpeer
fi

build_test_filter

[ x$LST = x ] && skip_env "lst not found LST=$LST"

# FIXME: what is the reasonable value here?
lst_LOOP=${lst_LOOP:-100000}
lst_CONCR=${lst_CONCR:-"1 2 4 8"}
lst_SIZES=${lst_SIZES:-"4k 8k 256k 1M"}
if [ "$SLOW" = no ]; then
	lst_CONCR="1 8"
	lst_SIZES="4k 1M"
	lst_LOOP=1000
fi

smoke_DURATION=${smoke_DURATION:-1800}
if [ "$SLOW" = no ]; then
	[ $smoke_DURATION -le 300 ] || smoke_DURATION=300
fi

lst_TESTS=${lst_TESTS:-"write read ping"}

# "none" -> LST_BRW_CHECK_NONE
# "full" -> LST_BRW_CHECK_FULL
# "simple" -> LST_BRW_CHECK_SIMPLE
# "discard" -> LST_BRW_CHECK_DISCARD
if (( MDS1_VERSION >= $(version_code 2.17.54) &&
      OST1_VERSION >= $(version_code 2.17.54) &&
      CLIENT_VERSION >= $(version_code 2.17.54) )); then
	lst_CHECK=${lst_CHECK:-"full none discard"}
else
	lst_CHECK=${lst_CHECK:-"full none"}
fi

lst_FROM=${lst_FROM:-"cs"}

LOAD_MODULES_REMOTE=true load_modules

nodes=$(tgts_nodes)
lst_SERVERS=${lst_SERVERS:-$(comma_list "$(host_nids_address $nodes $NETTYPE)")}
lst_CLIENTS=${lst_CLIENTS:-$(comma_list "$(host_nids_address $CLIENTS $NETTYPE)")}
interim_umount=false
interim_umount1=false

#
# _restore_mount(): This function calls restore_mount function for "MOUNT" and
# "MOUNT2" paths to mount clients if they were not mounted and were umounted
# in this file earlier.
# Parameter: None
# Returns: None. Exit with error if client mount fails.
#
_restore_mount () {
	if $interim_umount && ! is_mounted $MOUNT; then
		restore_mount $MOUNT || error "Restore $MOUNT failed"
	fi

	if $interim_umount1 && ! is_mounted $MOUNT2; then
		restore_mount $MOUNT2 || error "Restore $MOUNT2 failed"
	fi
}

if local_mode; then
   lst_SERVERS=`hostname`
   lst_CLIENTS=`hostname`
fi

# FIXME: do we really need to unload lustre modules on all nodes?
# bug 19387, comment 9
# unloading lustre modules is not strictly necessary but unmounting
# /mnt/lustre before running lst would be useful:
# 1) because lustre messages clutter logs - we needn't them for testing LNET
# 2) it's theoretically possible that lst tests congest comm paths so tightly
# that mounted lustre wouldn't able to perform some of its background activities
if is_mounted $MOUNT; then
	cleanup_mount $MOUNT || error "Fail to unmount client $MOUNT"
	interim_umount=true
fi

if is_mounted $MOUNT2; then
	cleanup_mount $MOUNT2 || error "Fail to unmount client $MOUNT2"
	interim_umount1=true
fi

lst_prepare () {
	# Workaround for bug 15619
	lst_cleanup_all
	lst_setup_all
}

# make batch
test_smoke_sub () {
	local servers=$1
	local clients=$2

	local nc=$(echo ${clients//,/ } | wc -w)
	local ns=$(echo ${servers//,/ } | wc -w)
	echo '#!/usr/bin/bash'
	echo 'set -e'

	echo 'cleanup () { trap 0; echo killing $1 ... ; kill -9 $1 || true; }'

	echo "$LST new_session --timeo 100000 hh"
	echo "$LST add_group c $(nids_list $clients)"
	echo "$LST add_group s $(nids_list $servers)"
	echo "echo '====================================='"
	echo "echo 'Listing of bad_group should not crash'"
	echo "echo '====================================='"
	echo "$LST list_group s bad_group c"
	echo "$LST add_batch b"

	declare -a tests

	case $lst_FROM in
		c) tests[0]="${nc}:${ns} --from c --to s";;
		s) tests[0]="${ns}:${nc} --from s --to c";;
		cs)tests[0]="${nc}:${ns} --from c --to s"
		   tests[1]="${ns}:${nc} --from s --to c";;
		*) error Unknown flag $lst_FROM;;
	esac

	pre="$LST add_test --batch b --loop $lst_LOOP "
	for t in $lst_TESTS; do
		for s in $lst_SIZES; do
			for c in $lst_CONCR; do
				for chk in $lst_CHECK; do
					case $chk in
					full|discard)
						check="check=$chk"
						;;
					none)
						check=""
						;;
					*)
						error "Unknown flag $chk"
						;;
					esac
					for ((i=0; i<${#tests[@]}; i++)); do
						echo -n "$pre --concurrency $c"\
							" --distribute ${tests[i]} "
						case $t in
						read|write)
							echo -n "brw $t " \
								"$check size=$s"
							;;
						ping)
							echo -n $t
							;;
						*)
							error "Unknown LST test"
							;;
						esac
						echo
					done
					# Ping ignores check so don't iterate
					# over all lst_CHECK values
					[[ $t != ping ]] || break
				done
			done
		done
	done

	echo $LST run b
	echo sleep 1
	echo "$LST stat --delay 10 --timeout 10 c s &"
	echo 'pid=$!'
	echo 'trap "cleanup $pid" INT TERM'
	echo "for ((t = 0; t < $smoke_DURATION; t += 10)); do"
	echo "	sleep 10"
	echo "	$LST query b | grep -q 'is stopped\$' && break"
	echo "done"
	echo 'cleanup $pid'
}

run_lst () {
	local file=$1

	export LST_SESSION=$$

	# start lst
	bash $file
}

check_lst_err () {
	local log=$1

	grep ^Total $log

	if awk '/^Total.*nodes/ {print $2}' $log | grep -vq '^0$'; then
		_restore_mount
		error 'lst Error found'
	fi
}

test_smoke () {
	lst_prepare

	local servers=$lst_SERVERS
	local clients=$lst_CLIENTS

	local runlst=$TMP/smoke.sh

	local log=$TMP/$tfile.log
	local rc=0

	test_smoke_sub $servers $clients 2>&1 > $runlst

	cat $runlst

	run_lst $runlst | tee $log
	rc=${PIPESTATUS[0]}
	[ $rc = 0 ] || { _restore_mount; error "$runlst failed: $rc"; }

	lst_end_session --verbose | tee -a $log

	# error counters in "lst show_error" should be checked
	check_lst_err $log
	lst_cleanup_all
}
run_test smoke "lst regression test"

#
# lst_end_session_timeout(): how long lstcon_session_end() may legitimately
# take, in seconds.  The console allows the batch-stop and SESEND
# transactions LST_TRANS_TIMEOUT (30s) each, and then bounds the drain in
# lstcon_rpc_cleanup_wait() by LST_CLEANUP_TIMEOUT() - rpc_timeout + 30s, or
# 4 * LST_TRANS_TIMEOUT when rpc_timeout is 0 ("never expire").  A teardown
# that hits those bounds and returns is behaving correctly, so the tests have
# to derive their allowance from them rather than guess: a hardcoded value
# smaller than the bound reports a correct teardown as a deadlock.
# Parameters: None
# Returns: prints the timeout in seconds
#
lst_end_session_timeout () {
	local param=/sys/module/lnet_selftest/parameters/rpc_timeout
	local rpc_to=$(cat $param 2>/dev/null)
	local lnd_to=$($LCTL get_param -n lnet_lnd_timeout 2>/dev/null)
	local cleanup
	local sesend

	[ -n "$rpc_to" ] || rpc_to=64
	[ -n "$lnd_to" ] || lnd_to=50

	if [ "$rpc_to" -gt 0 ]; then
		cleanup=$((rpc_to + 30))
	else
		cleanup=$((4 * 30))
	fi

	# NB the bound also clears the LND drain, since an aborted RPC is
	# pinned until the LND releases its MDs.  Mirrors LST_CLEANUP_TIMEOUT.
	(( cleanup >= 2 * lnd_to )) || cleanup=$((2 * lnd_to))

	# SESEND now waits out the node-side drain, which is bounded by the
	# LND rather than by rpc_timeout: an in-flight bulk MD is pinned until
	# the LND gives up.  Mirrors LST_SESEND_TIMEOUT.
	sesend=$((2 * lnd_to + 30))

	# NB the cleanup bound is armed once per drain phase (transaction
	# termination, then RPC recycle), so allow it twice.
	# batch stop + SESEND + 2 x cleanup, plus slack for scheduling
	echo $((30 + sesend + 2 * cleanup + 30))
}

#
# lst_join_group(): add nodes to an lst group and verify they all joined.
# lst add_group exits 0 even when some nodes fail to answer, so the node
# count has to be checked explicitly or later commands fail with confusing
# errors ("Network is down") on a half-populated group.
# Parameters: group name, comma-separated address list, expected node count
# Returns: 0 if all nodes joined, 1 otherwise
#
lst_join_group () {
	local grp=$1
	local addrs=$2
	local want=$3
	local got

	$LST add_group $grp $(nids_list $addrs) >/dev/null 2>&1

	# NB count from list_group, not from add_group: add_group prints one
	# "are added to session" line per NID argument whether or not that
	# node answered, so its output cannot detect a short group.
	# list_group prints "ACTIVE BUSY DOWN UNKNOWN TOTAL name"; a node that
	# is present but not ACTIVE is not ready to run a test.
	got=$($LST list_group $grp 2>/dev/null |
		awk '$1 ~ /^[0-9]+$/ && NF >= 5 {print $1; exit}')

	[ -n "$got" ] && [ "$got" -eq "$want" ] || return 1
	return 0
}

#
# lst_session_setup(): create a session and populate both groups, retrying
# while nodes are still settling from a previous teardown.
#
# A node that has not finished removing its old session does not answer the
# session-create RPC within LST_TRANS_TIMEOUT, so add_group silently returns
# a short group.  In a test that tears sessions down back to back that is a
# transient of the previous cycle, not a failure of what is being asserted,
# so retry the setup rather than fail on the first short join.  The teardown
# assertions themselves stay strict.
# Parameters: session name, clients, client count, servers, server count
# Returns: 0 once every node has joined, 1 if they never do
#
lst_session_setup () {
	local name=$1
	local clients=$2
	local nc=$3
	local servers=$4
	local ns=$5
	local tries=5
	local attempt=0
	local force=""

	while :; do
		export LST_SESSION=$$

		if $LST new_session $force --timeo 100000 $name \
			>/dev/null 2>&1 &&
		   lst_join_group c "$clients" $nc &&
		   lst_join_group s "$servers" $ns; then
			return 0
		fi

		$LST end_session >/dev/null 2>&1

		# NB count attempts rather than elapsed time.  A single failing
		# attempt costs two LST_TRANS_TIMEOUTs (one per add_group), so
		# a wall-clock budget is spent before the retry it was meant to
		# allow ever runs.
		attempt=$((attempt + 1))
		[ $attempt -lt $tries ] || return 1

		# The first attempt is deliberately unforced, so the normal
		# case still goes through the ordinary path.  After that use
		# --force: tearing a session down while its RPCs are still in
		# flight can leave a node holding the old session - the SESEND
		# transaction times out before reaching it - and a plain
		# new_session answers -EBUSY for as long as that lasts.  That
		# is the expected outcome of a raced teardown, not the thing
		# this test asserts.
		force="--force"
		echo "session setup incomplete, retrying with --force"
		sleep 2
	done
}

#
# lst_skip_interop(): skip a test that must not run against older nodes.
#
# The tests below are LU-20104 reproducers: they drive a session teardown
# that a node without the fix does not survive, so on a mixed cluster they
# panic the old node rather than testing anything.  Every node in the
# session has to carry the fix, not just the console running lst.
# Parameters: None
# Returns: does not return if any node is too old
#
lst_skip_interop () {
	local want=$(version_code 2.17.58)

	(( MDS1_VERSION >= want && OST1_VERSION >= want &&
	   CLIENT_VERSION >= want )) ||
		skip "Need Lustre 2.17.58 on all nodes for LU-20104 tests"
}

# Test rapid session create/destroy cycles with active BRW traffic.
# Reproduces LU-20104 session teardown deadlock: orphaned server RPCs on
# scd_rpc_active list, improper batch drain ordering in sfw_remove_session,
# and zombie session destroy from workitem context (cancel_work_sync
# deadlock on same workqueue).
test_teardown () {
	lst_skip_interop

	# NB set explicitly, independent of the suite-wide default.  Data
	# integrity is not what this test asserts, so discard the payload -
	# it keeps far less bulk in flight.
	local check="check=discard"
	lst_prepare

	local servers=$lst_SERVERS
	local clients=$lst_CLIENTS
	local nc=$(echo ${clients//,/ } | wc -w)
	local ns=$(echo ${servers//,/ } | wc -w)
	local cycles=5
	local rc=0

	[ "$SLOW" = no ] && cycles=3

	for i in $(seq $cycles); do
		echo "=== Teardown cycle $i/$cycles ==="
		export LST_SESSION=$$

		lst_session_setup teardown_$i "$clients" $nc \
			"$servers" $ns ||
			error "cycle $i: session setup never completed"
		$LST add_batch b || error "cycle $i: add_batch failed"

		$LST add_test --batch b --loop 5000 --concurrency 8 \
			--distribute ${nc}:${ns} --from c --to s \
			brw write $check size=1M ||
			error "cycle $i: add_test brw failed"
		$LST add_test --batch b --loop 5000 --concurrency 8 \
			--distribute ${nc}:${ns} --from c --to s \
			ping || error "cycle $i: add_test ping failed"

		$LST run b || error "cycle $i: run failed"
		sleep 2

		# end_session must complete without deadlock.  NB the
		# allowance is derived, not fixed: see
		# lst_end_session_timeout().
		timeout -k 10 $(lst_end_session_timeout) \
			$LST end_session --verbose
		rc=$?
		if [ $rc -eq 124 ]; then
			error "session teardown deadlocked on cycle $i"
		fi
		[ $rc -eq 0 ] || error "end_session failed on cycle $i: rc=$rc"
	done

	lst_cleanup_all
}
run_test teardown "lst session teardown stress (LU-20104)"

# Test BRW with non-zero offsets. Reproduces LU-20104 offset handling bugs
# in brw_client_init:
# 1) an offset outside the first page was silently masked, not rejected
# 2) bulk was allocated without accounting for the offset
# 3) no validation that off+len <= LNET_MTU
# On unpatched kernels, off=4096 causes LBUG (nblk != bk_niov) and
# off=2048 size=1M causes NULL page dereference or LASSERT failure.
test_brw_offset () {
	lst_skip_interop

	# NB set explicitly, independent of the suite-wide default.  This
	# test does assert data handling, so verify it.
	local check="check=full"
	lst_prepare

	local servers=$lst_SERVERS
	local clients=$lst_CLIENTS
	local nc=$(echo ${clients//,/ } | wc -w)
	local ns=$(echo ${servers//,/ } | wc -w)
	local log=$TMP/$tfile.log
	local rc=0

	lst_session_setup brw_offset "$clients" $nc "$servers" $ns ||
		error "session setup never completed"

	# NB truncate: $tfile is the same path on every run of the suite, and
	# check_lst_err below would match an error line left by an earlier one.
	: > $log

	# Valid offsets with various sizes
	for off in 0 512 1024 2048; do
		for size in 4k 64k; do
			echo "=== BRW read off=$off size=$size ==="
			$LST add_batch b_r_${off}_${size} ||
				error "add_batch off=$off size=$size failed"
			$LST add_test --batch b_r_${off}_${size} \
				--concurrency 4 \
				--distribute ${nc}:${ns} \
				--from c --to s \
				brw read $check size=$size off=$off ||
				error "add_test off=$off size=$size failed"
			$LST run b_r_${off}_${size} ||
				error "run off=$off size=$size failed"
			$LST stat --delay 1 --count 10 --timeout 5 c s \
				| tee -a $log
			$LST stop b_r_${off}_${size}
		done
	done

	# NB not lst_end_session: that helper stops a batch named "b", which
	# this test never creates, and the failed stop is itself counted as a
	# console RPC error - which is exactly what check_lst_err reads.
	$LST show_error c s | tee -a $log
	check_lst_err $log
	$LST end_session

	# off + len > LNET_MTU exceeds LNET_MAX_IOV pages, so add_test has to
	# reject it rather than leave a NULL page for srpc_init_bulk.
	#
	# NB a session of its own: the rejection is the assertion here, but it
	# also counts against the session's RPC error stats, which is what
	# check_lst_err above reads.
	lst_session_setup brw_overflow "$clients" $nc "$servers" $ns ||
		error "overflow session setup never completed"

	echo "=== BRW write off=2048 size=1M (off+len > LNET_MTU) ==="
	$LST add_batch b_overflow || error "add_batch b_overflow failed"
	$LST add_test --batch b_overflow \
		--concurrency 2 \
		--distribute ${nc}:${ns} --from c --to s \
		brw write $check size=1M off=2048 &&
		error "off=2048 size=1M should have been rejected"

	# offset >= PAGE_SIZE is rejected rather than silently masked to 0,
	# which would run a different test than the one requested
	echo "=== BRW read off=$PAGE_SIZE size=4k (rejected) ==="
	$LST add_batch b_page || error "add_batch b_page failed"
	$LST add_test --batch b_page \
		--concurrency 4 \
		--distribute ${nc}:${ns} --from c --to s \
		brw read $check size=4k off=$PAGE_SIZE &&
		error "off=$PAGE_SIZE should have been rejected"

	$LST end_session
	lst_cleanup_all
}
run_test brw_offset "lst BRW offset handling (LU-20104)"

# Reproduces the LU-20104 workqueue list-corruption race: server-side
# srpc_handle_rpc's abort/shutdown branch calls LNetMDUnlink on the bulk
# and reply MDs after setting wi->swi_state=DONE; the resulting UNLINK
# events run srpc_lnet_ev_handler, which sets ev_fired and calls
# queue_work on the same srpc_wi that's still executing. Server RPCs
# used to carry a single srpc_ev shared by the bulk and reply MDs, so a
# late bulk UNLINK landed on the event already rewritten for the reply,
# completing the RPC a second time after srpc_server_rpc_done had
# recycled it and queued it for a new request - corrupting the
# workqueue list ("list_add corruption. prev->next should be next ...").
#
# To hit that race reliably we want:
#   * many in-flight bulk MDs (high concurrency, both directions) so the
#     abort path has many MDs to LNetMDUnlink in close succession,
#   * end_session called while traffic is still ramping (no settle
#     sleep) so MDs are actively in-flight rather than drained,
#   * many cycles to keep rolling the dice.
test_teardown_race () {
	lst_skip_interop

	# NB set explicitly, independent of the suite-wide default.  Data
	# integrity is not what this test asserts, so discard the payload -
	# it keeps far less bulk in flight.
	local check="check=discard"
	lst_prepare

	local servers=$lst_SERVERS
	local clients=$lst_CLIENTS
	local nc=$(echo ${clients//,/ } | wc -w)
	local ns=$(echo ${servers//,/ } | wc -w)
	local cycles=$LST_TEARDOWN_RACE_CYCLES
	local rc=0

	if [ -z "$cycles" ]; then
		cycles=20
		[ "$SLOW" = no ] && cycles=5
	fi

	for i in $(seq $cycles); do
		echo "=== Teardown-race cycle $i/$cycles ==="
		export LST_SESSION=$$

		lst_session_setup teardown_race_$i "$clients" $nc \
			"$servers" $ns ||
			error "cycle $i: session setup never completed"
		$LST add_batch b || error "cycle $i: add_batch failed"

		# bidirectional brw + ping at high concurrency: maximises the
		# number of bulk + reply MDs the abort path must LNetMDUnlink
		# while the worker is still running srpc_handle_rpc.
		$LST add_test --batch b --loop 10000 --concurrency 32 \
			--distribute ${nc}:${ns} --from c --to s \
			brw write $check size=1M ||
			error "cycle $i: add_test brw write failed: rc=$?"
		$LST add_test --batch b --loop 10000 --concurrency 32 \
			--distribute ${nc}:${ns} --from c --to s \
			brw read $check size=1M ||
			error "cycle $i: add_test brw read failed: rc=$?"
		$LST add_test --batch b --loop 10000 --concurrency 32 \
			--distribute ${nc}:${ns} --from c --to s \
			ping || error "cycle $i: add_test ping failed"

		$LST run b || error "cycle $i: run failed"
		# No settle sleep: end_session must hit while MDs are
		# actively in flight, not after they've drained.

		timeout -k 10 $(lst_end_session_timeout) \
			$LST end_session --verbose
		rc=$?
		if [ $rc -eq 124 ]; then
			error "end_session deadlocked on cycle $i"
		fi
		[ $rc -eq 0 ] || error "end_session failed on cycle $i: rc=$rc"
	done

	lst_cleanup_all
}
run_test teardown_race "lst teardown wq list-corruption race (LU-20104)"

#
# lst_deadpeer_cleanup(): undo what test_teardown_deadpeer() changed.
# Registered with stack_trap so an error() anywhere in the test does not
# leave rpc_timeout=0 and a blackhole rule behind for later suites.
# Both steps are best effort - the module may already have been unloaded -
# and the explicit return keeps the trap from deciding the test's verdict.
# Parameters: sysfs path of rpc_timeout, value to restore, victim node
# Returns: 0 always
#
lst_deadpeer_cleanup () {
	local param=$1
	local saved=$2
	local victim=$3

	[ -w "$param" ] && echo $saved > $param
	do_node $victim "$LCTL net_drop_del -a" >/dev/null 2>&1

	return 0
}

# Session teardown must stay bounded when a peer stops answering.
#
# end_session has to abort the session RPCs to a peer that has gone silent
# and finish the teardown itself; it cannot wait for those RPCs to complete
# on their own.  Run with rpc_timeout=0 ("never expire") so the client-side
# RPC timers are disabled entirely - if teardown depends on an RPC timer
# rather than its own abort path, it has nothing left to rescue it and
# end_session hangs under ses_mutex, which also blocks module unload.
test_teardown_deadpeer () {
	lst_skip_interop

	# NB set explicitly, independent of the suite-wide default.  Data
	# integrity is not what this test asserts, so discard the payload -
	# it keeps far less bulk in flight.
	local check="check=discard"
	lst_prepare

	local servers=$lst_SERVERS
	local clients=$lst_CLIENTS
	local nc=$(echo ${clients//,/ } | wc -w)
	local ns=$(echo ${servers//,/ } | wc -w)
	local param=/sys/module/lnet_selftest/parameters/rpc_timeout
	local saved=$(cat $param)
	local self=$(host_nids_address $(hostname) $NETTYPE |
		head -n1)@$NETTYPE
	local victim victim_nid n
	local maxwait
	local t0 t1 rc

	# NB the victim must come from the server group the test builds:
	# lst_SERVERS is overridable, and a node picked from $nodes may not
	# be in the session at all, which would let end_session pass without
	# ever meeting an unresponsive peer.
	victim_nid=$(echo ${servers//,/ } | awk '{print $1}')@$NETTYPE
	[ "$victim_nid" != "$self" ] ||
		skip_env "server group starts at the console's own NID"
	for n in $nodes; do
		if host_nids_address $n $NETTYPE |
		   grep -qw "${victim_nid%@*}"; then
			victim=$n
			break
		fi
	done
	[ -n "$victim" ] ||
		skip_env "no cluster node owns server NID $victim_nid"

	stack_trap "lst_deadpeer_cleanup $param $saved $victim || true" EXIT

	echo 0 > $param || error "cannot set rpc_timeout=0"

	# NB after rpc_timeout is changed: the allowance derives from it
	maxwait=$(lst_end_session_timeout)

	export LST_SESSION=$$
	$LST new_session --timeo 100000 deadpeer ||
		error "new_session failed"
	lst_join_group c "$clients" $nc || error "not all clients joined"
	lst_join_group s "$servers" $ns || error "not all servers joined"
	$LST add_batch b || error "add_batch failed"
	$LST add_test --batch b --loop 10000 --concurrency 8 \
		--distribute ${nc}:${ns} --from c --to s \
		brw write $check size=1M || error "add_test failed"
	$LST run b || error "run failed"

	# Silence one peer while its RPCs are in flight.  The rule has to live
	# on the receiving node - drop rules are evaluated on the receive path,
	# so a rule on the console matches nothing.  No -e, so the console gets
	# no completion of any kind back from this peer.
	echo "silencing $victim ($victim_nid)"
	do_node $victim "$LCTL net_drop_add -s $self -d $victim_nid -r 1" ||
		error "failed to add drop rule on $victim"

	t0=$SECONDS
	timeout -k 10 $maxwait $LST end_session
	rc=$?
	t1=$SECONDS

	# NB timeout reports its own expiry as 124 whichever signal it sent,
	# so that - not 128+signal - is what a hang looks like here.
	echo "end_session rc=$rc after $((t1 - t0))s"
	[ $rc -eq 124 ] &&
		error "end_session hung with $victim silent after ${maxwait}s"
	[ $rc -eq 0 ] ||
		error "end_session failed with $victim silent: rc=$rc"

	# Let the silenced peer talk again before tearing down, so the module
	# unload in lst_cleanup_all is not itself racing a dead peer.  The
	# stack_trap above repeats this if an error() got here first.
	lst_deadpeer_cleanup $param $saved $victim

	# NB the session was deliberately ended against a silenced peer, so
	# lst_cleanup_all is unwinding state it does not expect and can
	# report a failure that says nothing about what this test asserts.
	# Log it rather than letting it decide the verdict - the assertion
	# above has already run, and a real problem goes through error().
	lst_cleanup_all || echo "lst_cleanup_all failed (rc=$?), ignored"
}
run_test teardown_deadpeer "lst teardown with an unresponsive peer (LU-20104)"

complete_test $SECONDS
_restore_mount
check_and_cleanup_lustre
exit_status
