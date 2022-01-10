#!/bin/bash

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
init_logging

ALWAYS_EXCEPT="$LNET_SELFTEST_EXCEPT"
if [[ $(uname -m) = ppc64 ]]; then
	# bug number for skipped test: LU-10073
	ALWAYS_EXCEPT+="               smoke "
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
lst_CHECK=${lst_CHECK:-"full"}

lst_FROM=${lst_FROM:-"cs"}

case $lst_CHECK in
	full|simple) check="check=$lst_CHECK";;
	none) check="";;
	*) error Unknown flag $lst_CHECK;;
esac

LOAD_MODULES_REMOTE=true load_modules

nodes=$(comma_list "$(osts_nodes) $(mdts_nodes)")
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
	echo '#!/bin/bash'
	echo 'set -e'

	echo 'cleanup () { trap 0; echo killing $1 ... ; kill -9 $1 || true; }'

	echo "$LST new_session --timeo 100000 hh"
	echo "$LST add_group c $(nids_list $clients)"
	echo "$LST add_group s $(nids_list $servers)"
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
				for ((i=0; i<${#tests[@]}; i++)); do
					echo -n "$pre --concurrency $c"\
						" --distribute ${tests[i]} "
					case $t in
						read|write)
							echo -n "brw $t" \
							" $check size=$s";;
						ping)
							echo -n $t;;
						*) error Unknonwn LST test;;
					esac
					echo
				done
			done
		done
	done

	echo $LST run b
	echo sleep 1
	echo "$LST stat --delay 10 --timeout 10 c s &"
	echo 'pid=$!'
	echo 'trap "cleanup $pid" INT TERM'
	echo sleep $smoke_DURATION
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

complete $SECONDS
_restore_mount
check_and_cleanup_lustre
exit_status
