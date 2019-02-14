#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#

set -e

ONLY=${ONLY:-"$*"}
# bug number for skipped test:
ALWAYS_EXCEPT="$SANITY_DOM_EXCEPT"
[ "$SLOW" = "no" ] && EXCEPT_SLOW=""
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}

. $LUSTRE/tests/test-framework.sh
CLEANUP=${CLEANUP:-:}
SETUP=${SETUP:-:}
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

if [ $(facet_fstype $SINGLEMDS) = "zfs" ]; then
# bug number for skipped test:
	ALWAYS_EXCEPT+=""
	if [ $MDSCOUNT -gt 1 ]; then
# bug number for skipped test:
		ALWAYS_EXCEPT+=""
	fi
fi

[[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.10.56) ]] ||
	{ skip "Need MDS version at least 2.10.56"; exit 0; }

MULTIOP=${MULTIOP:-multiop}
OPENFILE=${OPENFILE:-openfile}
MOUNT_2=${MOUNT_2:-"yes"}
FAIL_ON_ERROR=false

check_and_setup_lustre

# $RUNAS_ID may get set incorrectly somewhere else
if [[ $UID -eq 0 && $RUNAS_ID -eq 0 ]]; then
	skip_env "\$RUNAS_ID set to 0, but \$UID is also 0!" && exit
fi
check_runas_id $RUNAS_ID $RUNAS_GID $RUNAS

build_test_filter

DOM="yes"
DOM_SIZE=${DOM_SIZE:-"$((1024*1024))"}
OSC="mdc"

save_layout_restore_at_exit $DIR1
$LFS setstripe -E $DOM_SIZE -L mdt -E EOF $DIR1

mkdir -p $MOUNT2
mount_client $MOUNT2

test_1() {
	dd if=/dev/zero of=$DIR1/$tfile bs=7k count=1 || error "write 1"
	$TRUNCATE $DIR2/$tfile 1000 || error "truncate"
	dd if=/dev/zero of=$DIR1/$tfile bs=3k count=1 seek=1 || error "write 2"
	$CHECKSTAT -t file -s 6144 $DIR2/$tfile || error "stat"
	rm $DIR1/$tfile
}
run_test 1 "write a file on one mount, truncate on the other, write again"

test_2() {
	SZ1=234852
	dd if=/dev/zero of=$DIR/$tfile bs=1M count=1 seek=4 || return 1
	dd if=/dev/zero bs=$SZ1 count=1 >> $DIR/$tfile || return 2
	dd if=$DIR/$tfile of=$DIR/${tfile}_left bs=1M skip=5 || return 3
	$CHECKSTAT -t file -s $SZ1 $DIR/${tfile}_left ||
		error "Error reading at the end of the file $tfile"
}
run_test 2 "Write with a seek, append, read from a single mountpoint"

test_3() {
	# Write on one node to the DoM stripe and then truncate to over DoM size
	dd if=/dev/zero of=$DIR1/$tfile bs=$((DOM_SIZE-100)) count=1 ||
		return 1
	truncate $DIR1/$tfile $((DOM_SIZE+700)) || return 2
	# read on the second node inside DoM stripe to take a lock data from
	# the first client
	dd if=$DIR2/$tfile of=/dev/null bs=4096 count=1 seek=1 || return 3
	$CHECKSTAT -t file -s $((DOM_SIZE+700)) $DIR2/$tfile ||
		error "Wrong size after first truncate $tfile on first node"
	# now do local truncate over DoM size and check size is correct
	truncate $DIR2/$tfile $((DOM_SIZE+500)) || return 4
	$CHECKSTAT -t file -s $((DOM_SIZE+500)) $DIR2/$tfile ||
		error "Wrong size after second truncate on the same node"
	$CHECKSTAT -t file -s $((DOM_SIZE+500)) $DIR1/$tfile ||
		error "Wrong size after second truncate on other node"
}
run_test 3 "Truncate over DoM size on different nodes"

test_4() {
	local before=0
	local after=0

	dd if=/dev/zero of=$DIR1/$tfile bs=2M count=1
	cancel_lru_locks mdc

	#define OBD_FAIL_MDC_GLIMPSE_DDOS 0x808
	$LCTL set_param fail_loc=0x80000808
	before=$(lctl get_param -n ldlm.namespaces.*mdc*.lock_count |
		gawk '{cnt=cnt+$1}  END{print cnt}')
	for ((i=1; i < 100; i++))
	do
		tail -n100 $DIR1/$tfile > /dev/null
		stat -f $DIR2/$tfile > /dev/null
	done
	after=$(lctl get_param -n ldlm.namespaces.*mdc*.lock_count |
		gawk '{cnt=cnt+$1}  END{print cnt}')
	[[ $((after - before)) -ge 20 ]] &&
		error "Too many locks found $((after - before))"
	return 0
}
run_test 4 "DoM: glimpse doesn't produce duplicated locks"

test_fsx() {
	local file1=$DIR1/$tfile
	local file2=$DIR2/$tfile

	touch $file1
	fsx -c 50 -p 100 -N 1000 -l $((DOM_SIZE*2)) -S 0 -d -d $file1 $file2
}
run_test fsx "Dual-mount fsx with DoM files"

test_sanity()
{
	# XXX: to fix 45. Add 42a, c when LU-9693 fixed.
	# Add 42b when LU-6493 fixed
	ONLY="36 39 40 41 42d 42e 43 46 56r 101e 119a 131 150 155a 155b 155c \
		155d 207 241 251" OSC="mdc" DOM="yes" bash sanity.sh
}
run_test sanity "Run sanity with Data-on-MDT files"

test_sanityn()
{
	# XXX: to fix 60
	ONLY="1 2 4 5 6 7 8 9 10 11 12 14 17 19 20 23 27 39 51a 51c 51d" \
		OSC="mdc" DOM="yes" bash sanityn.sh
}
run_test sanityn "Run sanityn with Data-on-MDT files"

complete $SECONDS
check_and_cleanup_lustre
exit_status
