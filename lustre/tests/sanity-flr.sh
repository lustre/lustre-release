#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# Run test by setting NOSETUP=true when ltest has setup env for us
set -e
set +o posix

SRCDIR=$(dirname $0)
export PATH=$PWD/$SRCDIR:$SRCDIR:$PWD/$SRCDIR/../utils:$PATH:/sbin

ONLY=${ONLY:-"$*"}
# Bug number for skipped test:
ALWAYS_EXCEPT="$SANITY_FLR_EXCEPT"
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

[ "$ALWAYS_EXCEPT$EXCEPT" ] &&
	echo "Skipping tests: $ALWAYS_EXCEPT $EXCEPT"

TMP=${TMP:-/tmp}
CHECKSTAT=${CHECKSTAT:-"checkstat -v"}
LFS=${LFS:-lfs}
LCTL=${LCTL:-lctl}
MULTIOP=${MULTIOP:-multiop}

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

check_and_setup_lustre
DIR=${DIR:-$MOUNT}
assert_DIR

if [[ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.7.64) ]]; then
	skip_env "Need MDS version at least 2.7.64" && exit
fi

build_test_filter

[ $UID -eq 0 -a $RUNAS_ID -eq 0 ] &&
	error "\$RUNAS_ID set to 0, but \$UID is also 0!"
check_runas_id $RUNAS_ID $RUNAS_GID $RUNAS

# global array to store mirror IDs
declare -a mirror_array
get_mirror_ids() {
	local tf=$1
	local id
	local array

	array=()
	for id in $($LFS getstripe $tf | awk '/lcme_id/{print $2}'); do
		array[${#array[@]}]=$((id >> 16))
	done

	mirror_array=($(printf "%s\n" "${array[@]}" | sort -u))

	echo ${#mirror_array[@]}
}

drop_client_cache() {
	echo 3 > /proc/sys/vm/drop_caches
}

stop_osts() {
	local idx

	for idx in "$@"; do
		stop ost$idx
	done

	for idx in "$@"; do
		wait_osc_import_state client ost$idx DISCONN
	done
}

start_osts() {
	local idx

	for idx in "$@"; do
		start ost$idx $(ostdevname $idx) $OST_MOUNT_OPTS ||
			error "start ost$idx failed"
	done

	for idx in "$@"; do
		wait_osc_import_state client ost$idx FULL
	done
}

# command line test cases
test_1() {
	local tf=$DIR/$tfile
	local mirror_count=16 # LUSTRE_MIRROR_COUNT_MAX

	$LFS setstripe -E EOF -c -1 $tf

	local stripes[0]=$OSTCOUNT

	for ((i = 1; i < $mirror_count; i++)); do
		# add mirrors with different stripes to the file
		stripes[$i]=$((RANDOM % OSTCOUNT))
		[ ${stripes[$i]} -eq 0 ] && stripes[$i]=1

		$LFS setstripe --component-add --mirror -c ${stripes[$i]} $tf
	done

	[ $(get_mirror_ids $tf) -ne $mirror_count ] &&
		error "mirror count error"

	# can't create mirrors exceeding LUSTRE_MIRROR_COUNT_MAX
	$LFS setstripe --component-add --mirror $tf &&
		error "Creating the $((mirror_count+1))th mirror succeeded"

	local ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' |
			tr '\n' ' '))

	# verify the range of components and stripe counts
	for ((i = 0; i < $mirror_count; i++)); do
		local sc=$($LFS getstripe -I${ids[$i]} -c $tf)
		local start=$($LFS getstripe -I${ids[$i]} --component-start $tf)
		local end=$($LFS getstripe -I${ids[$i]} --component-end $tf)

		[[ ${stripes[$i]} = $sc ]] || {
			$LFS getstripe -v $tf;
			error "$i: sc error: id: ${ids[$i]}, ${stripes[$i]}";
		}
		[ $start -eq 0 ] || {
			$LFS getstripe -v $tf;
			error "$i: start error id: ${ids[$i]}";
		}
		[ $end = "EOF" ] || {
			$LFS getstripe -v $tf;
			error "$i: end error id: ${ids[$i]}";
		}
	done
}
run_test 1 "create components with setstripe options"

test_2() {
	local tf=$DIR/$tfile
	local tf2=$DIR/$tfile-2

	$LFS setstripe -E 1M -E EOF -c 1 $tf
	$LFS setstripe -E 2M -E EOF -c -1 $tf2

	local layout=$($LFS getstripe $tf2 | grep -A 4 lmm_objects)

	$LFS setstripe --component-add --mirror=$tf2 $tf

	[ $(get_mirror_ids $tf) -ne 2 ] && error "mirror count should be 2"
	$LFS getstripe $tf2 | grep -q 'no stripe info' ||
		error "$tf2 still has stripe info"
}
run_test 2 "create components from existing files"

test_3() {
	[[ $MDSCOUNT -lt 2 ]] && skip "need >= 2 MDTs" && return

	for ((i = 0; i < 2; i++)); do
		$LFS mkdir -i $i $DIR/$tdir-$i
		$LFS setstripe -E -1 $DIR/$tdir-$i/$tfile
	done

	$LFS setstripe --component-add --mirror=$DIR/$tdir-1/$tfile \
		$DIR/$tdir-0/$tfile || error "creating mirrors"

	# mdt doesn't support to cancel layout lock for remote objects, do
	# it here manually.
	cancel_lru_locks mdc

	# make sure the mirrorted file was created successfully
	[[ $($LFS getstripe --component-count $DIR/$tdir-0/$tfile) -eq 2 ]] ||
		{ $LFS getstripe $DIR/$tdir-0/$tfile;
			error "expected 2 components"; }

	# cleanup
	rm -rf $DIR/$tdir-*
}
run_test 3 "create components from files located on different MDTs"

test_21() {
	local tf=$DIR/$tfile
	local tf2=$DIR/$tfile-2

	[[ $OSTCOUNT -lt 2 ]] && skip "need >= 2 OSTs" && return

	$LFS setstripe -E EOF -o 0 $tf
	$LFS setstripe -E EOF -o 1 $tf2

	local dd_count=$((RANDOM % 20 + 1))
	dd if=/dev/zero of=$tf bs=1M count=$dd_count
	dd if=/dev/zero of=$tf2 bs=1M count=1 seek=$((dd_count - 1))
	cancel_lru_locks osc

	local blocks=$(du -kc $tf $tf2 | awk '/total/{print $1}')

	# add component
	$LFS setstripe --component-add --mirror=$tf2 $tf

	# cancel layout lock
	cancel_lru_locks mdc

	local new_blocks=$(du -k $tf | awk '{print $1}')
	[ $new_blocks -eq $blocks ] ||
	error "i_blocks error expected: $blocks, actual: $new_blocks"
}
run_test 21 "glimpse should report accurate i_blocks"

get_osc_lock_count() {
	local lock_count=0

	for idx in "$@"; do
		local osc_name
		local count

		osc_name=${FSNAME}-OST$(printf "%04x" $((idx-1)))-osc-'ffff*'
		count=$($LCTL get_param -n ldlm.namespaces.$osc_name.lock_count)
		lock_count=$((lock_count + count))
	done
	echo $lock_count
}

test_22() {
	local tf=$DIR/$tfile

	$LFS setstripe -E EOF -o 0 $tf
	dd if=/dev/zero of=$tf bs=1M count=$((RANDOM % 20 + 1))

	# add component, two mirrors located on the same OST ;-)
	$LFS setstripe --component-add --mirror -o 0 $tf

	size_blocks=$(stat --format="%b %s" $tf)

	cancel_lru_locks mdc
	cancel_lru_locks osc

	local new_size_blocks=$(stat --format="%b %s" $tf)

	# make sure there is no lock cached
	[ $(get_osc_lock_count 1) -eq 0 ] || error "glimpse requests were sent"

	[ "$new_size_blocks" = "$size_blocks" ] ||
		echo "size expected: $size_blocks, actual: $new_size_blocks"

	rm -f $tmpfile
}
run_test 22 "no glimpse to OSTs for READ_ONLY files"

test_31() {
	local tf=$DIR/$tfile

	$LFS setstripe -E EOF -o 0 $tf
	$LFS setstripe --component-add --mirror -o 1 $tf

	#define OBD_FAIL_GLIMPSE_IMMUTABLE 0x1A00
	$LCTL set_param fail_loc=0x1A00

	local ost_idx
	for ((ost_idx = 1; ost_idx <= 2; ost_idx++)); do
		cancel_lru_locks osc
		stop_osts $ost_idx

		local tmpfile=$(mktemp)
		stat --format="%b %s" $tf > $tmpfile  &
		local pid=$!

		local cnt=0
		while [ $cnt -le 5 ]; do
			kill -0 $pid > /dev/null 2>&1 || break
			sleep 1
			((cnt += 1))
		done
		kill -0 $pid > /dev/null 2>&1 &&
			error "stat process stuck due to unavailable OSTs"

		# make sure glimpse request has been sent
		[ $(get_osc_lock_count 1 2) -ne 0 ] ||
			error "OST $ost_idx: no glimpse request was sent"

		start_osts $ost_idx
	done
}
run_test 31 "make sure glimpse request can be retried"

test_32() {
	[[ $OSTCOUNT -lt 2 ]] && skip "need >= 2 OSTs" && return
	rm -f $DIR/$tfile $DIR/$tfile-2

	$LFS setstripe -E EOF -o 0 $DIR/$tfile
	dd if=/dev/urandom of=$DIR/$tfile bs=1M count=$((RANDOM % 10 + 2))

	local fsize=$(stat -c %s $DIR/$tfile)
	[[ $fsize -ne 0 ]] || error "file size is (wrongly) zero"

	local cksum=$(md5sum $DIR/$tfile)

	# create a new mirror in sync mode
	$LFS setstripe --component-add --mirror -o 1 $DIR/$tfile

	# make sure the mirrored file was created successfully
	[ $(get_mirror_ids $DIR/$tfile) -eq 2 ] ||
		{ $LFS getstripe $DIR/$tfile; error "expected 2 mirrors"; }

	drop_client_cache
	stop_osts 1

	# check size is correct, glimpse request should go to the 2nd mirror
	$CHECKSTAT -t file -s $fsize $DIR/$tfile ||
		error "file size error $fsize vs. $(stat -c %s $DIR/$tfile)"

	echo "reading file from the 2nd mirror and verify checksum"
	[[ "$cksum" == "$(md5sum $DIR/$tfile)" ]] ||
		error "checksum error: expected $cksum"

	start_osts 1
}
run_test 32 "data should be mirrored to newly created mirror"

test_33() {
	[[ $OSTCOUNT -lt 2 ]] && skip "need >= 2 OSTs" && return

	rm -f $DIR/$tfile $DIR/$tfile-2

	# create a file with two mirrors
	$LFS setstripe -E EOF -o 0 $DIR/$tfile
	local max_count=100
	local count=0
	while [ $count -lt $max_count ]; do
		echo "ost1" >> $DIR/$tfile
		count=$((count + 1));
	done

	# tmp file that will be used as mirror
	$LFS setstripe -E EOF -o 1 $DIR/$tfile-2
	count=0
	while [ $count -lt $max_count ]; do
		echo "ost2" >> $DIR/$tfile-2
		count=$((count + 1));
	done

	# create a mirrored file
	$LFS setstripe --component-add --mirror=$DIR/$tfile-2 $DIR/$tfile

	# make sure that $tfile has two mirrors and $tfile-2 has no stripe
	[ $(get_mirror_ids $DIR/$tfile) -eq 2 ] ||
		{ $LFS getstripe $DIR/$tfile; error "expected count 2"; }
	$LFS getstripe $DIR/$tfile-2 | grep -q "no stripe info" ||
		{ $LFS getstripe $DIR/$tfile; error "expected no stripe"; }

	# execpted file size
	local fsize=$((5 * max_count))
	$CHECKSTAT -t file -s $fsize $DIR/$tfile ||
		error "mirrored file size is not $fsize"

	# read file - all OSTs are available
	echo "reading file (data should be provided by ost1)... "
	local rs=$(cat $DIR/$tfile | head -1)
	[[ "$rs" == "ost1" ]] ||
		error "file content error: expected: \"ost1\", actual: \"$rs\""

	# read file again with ost1 failed
	stop_osts 1
	drop_client_cache

	echo "reading file (data should be provided by ost2)..."
	local rs=$(cat $DIR/$tfile | head -1)
	[[ "$rs" == "ost2" ]] ||
		error "file content error: expected: \"ost2\", actual: \"$rs\""

	# remount ost1
	start_osts 1

	# read file again with ost2 failed
	$LCTL set_param ldlm.namespaces.lustre-*-osc-ffff*.lru_size=clear

	fail ost2 &
	sleep 1

	# check size, glimpse should work
	$CHECKSTAT -t file -s $fsize $DIR/$tfile ||
		error "mirrored file size is not $fsize"

	echo "reading file (data should be provided by ost1)..."
	local rs=$(cat $DIR/$tfile | head -1)
	[[ "$rs" == "ost1" ]] ||
		error "file content error: expected: \"ost1\", actual: \"$rs\""

	wait_osc_import_state client ost2 FULL
}
run_test 33 "read can choose available mirror to read"

test_34a() {
	[[ $OSTCOUNT -lt 4 ]] && skip "need >= 4 OSTs" && return

	rm -f $DIR/$tfile $DIR/$tfile-2 $DIR/$tfile-ref

	# reference file
	$LFS setstripe -o 0 $DIR/$tfile-ref
	dd if=/dev/urandom of=$DIR/$tfile-ref bs=1M count=3

	# create a file with two mirrors
	$LFS setstripe -E -1 -o 0,1 -S 1M $DIR/$tfile
	dd if=$DIR/$tfile-ref of=$DIR/$tfile bs=1M

	$LFS setstripe -E -1 -o 2,3 -S 1M $DIR/$tfile-2
	dd if=$DIR/$tfile-ref of=$DIR/$tfile-2 bs=1M

	$CHECKSTAT -t file -s $((3 * 1024 * 1024)) $DIR/$tfile ||
		error "mirrored file size is not 3M"

	# merge a mirrored file
	$LFS setstripe --component-add --mirror=$DIR/$tfile-2 $DIR/$tfile

	cancel_lru_locks osc

	# stop two OSTs, so the 2nd stripe of the 1st mirror and
	# the 1st stripe of the 2nd mirror will be inaccessible, ...
	stop_osts 2 3

	echo "comparing files ... "

	# however, read can still return the correct data. It should return
	# the 1st stripe from mirror 1 and 2st stripe from mirror 2.
	cmp -n 2097152 <(rwv -f $DIR/$tfile -r -o -n 1 2097152) \
		$DIR/$tfile-ref || error "file reading error"

	start_osts 2 3
}
run_test 34a "read mirrored file with multiple stripes"

test_34b() {
	[[ $OSTCOUNT -lt 4 ]] && skip "need >= 4 OSTs" && return

	rm -f $DIR/$tfile $DIR/$tfile-2 $DIR/$tfile-ref

	# reference file
	$LFS setstripe -o 0 $DIR/$tfile-ref
	dd if=/dev/urandom of=$DIR/$tfile-ref bs=1M count=3

	$LFS setstripe -E 1M -S 1M -o 0 -E eof -o 1 $DIR/$tfile
	dd if=$DIR/$tfile-ref of=$DIR/$tfile bs=1M

	$LFS setstripe -E 1M -S 1M -o 2 -E eof -o 3 $DIR/$tfile-2
	dd if=$DIR/$tfile-ref of=$DIR/$tfile-2 bs=1M

	$CHECKSTAT -t file -s $((3 * 1024 * 1024)) $DIR/$tfile ||
		error "mirrored file size is not 3M"

	# merge a mirrored file
	$LFS setstripe --component-add --mirror=$DIR/$tfile-2 $DIR/$tfile

	cancel_lru_locks osc

	# stop two OSTs, so the 2nd component of the 1st mirror and
	# the 1st component of the 2nd mirror will be inaccessible, ...
	stop_osts 2 3

	echo "comparing files ... "

	# however, read can still return the correct data. It should return
	# the 1st stripe from mirror 1 and 2st stripe from mirror 2.
	cmp -n 2097152 <(rwv -f $DIR/$tfile -r -o -n 1 2097152) \
		$DIR/$tfile-ref || error "file reading error"

	start_osts 2 3
}
run_test 34b "read mirrored file with multiple components"

test_35() {
	local tf=$DIR/$tfile

	$LFS setstripe -E eof $tf

	# add an out-of-sync mirror to the file
	$LFS setstripe --component-add --mirror -c 2 $tf

	$MULTIOP $tf oO_WRONLY:c ||
		error "write open a mirrored file failed"

	# truncate file should return error
	$TRUNCATE $tf 100 || error "error truncating a mirrored file"
}
run_test 35 "allow to write to mirrored files"

verify_ost_layout_version() {
	local tf=$1

	# get file layout version
	local flv=$($LFS getstripe $tf | awk '/lcm_layout_gen/{print $2}')

	# layout version from OST objects
	local olv=$($MULTIOP $tf oXc | awk '/ostlayoutversion/{print $2}')

	[ $flv -eq $olv ] || error "layout version mismatch: $flv vs. $olv"
}

create_file_36() {
	local tf

	for tf in "$@"; do
		$LFS setstripe -E 1M -E 2M -E 4M -E eof -c -1 $tf
		$LFS setstripe -E 3M -E 6M -E eof -c -1 $tf-tmp

		$LFS setstripe --component-add --mirror=$tf-tmp $tf
		rm -f $tf-tmp
	done
}

test_36() {
	local tf=$DIR/$tfile

	create_file_36 $tf $tf-2 $tf-3

	[ $(get_mirror_ids $tf) -gt 1 ] || error "wrong mirror count"

	# test case 1 - check file write and verify layout version
	$MULTIOP $tf oO_WRONLY:c ||
		error "write open a mirrored file failed"

	# write open file should not return error
	$MULTIOP $tf oO_WRONLY:w1024Yc || error "write mirrored file error"

	# instantiate components should work
	dd if=/dev/zero of=$tf bs=1M count=12 || error "write file error"

	# verify OST layout version
	verify_ost_layout_version $tf

	# test case 2
	local mds_idx=mds$(($($LFS getstripe -M $tf-2) + 1))

	local delay_sec=10
	do_facet $mds_idx $LCTL set_param fail_val=$delay_sec

	#define OBD_FAIL_FLR_LV_DELAY 0x1A01
	do_facet $mds_idx $LCTL set_param fail_loc=0x1A01

	# write should take at least $fail_loc seconds and succeed
	local st=$(date +%s)
	$MULTIOP $tf-2 oO_WRONLY:w1024Yc || error "write mirrored file error"

	[ $(date +%s) -ge $((st+delay_sec)) ] ||
		error "write finished before layout version is transmitted"

	# verify OST layout version
	verify_ost_layout_version $tf

	do_facet $mds_idx $LCTL set_param fail_loc=0

	# test case 3
	mds_idx=mds$(($($LFS getstripe -M $tf-3) + 1))

	#define OBD_FAIL_FLR_LV_INC 0x1A02
	do_facet $mds_idx $LCTL set_param fail_loc=0x1A02

	# write open file should return error
	$MULTIOP $tf-3 oO_WRONLY:O_SYNC:w1024c &&
		error "write a mirrored file succeeded" || true

	do_facet $mds_idx $LCTL set_param fail_loc=0
}
run_test 36 "write to mirrored files"

create_files_37() {
	local tf
	local fsize=$1

	echo "create test files with size $fsize .."

	shift
	for tf in "$@"; do
		$LFS setstripe -E 1M -c 1 -E eof -c -1 $tf

		dd if=/dev/urandom of=$tf bs=1M count=16 &> /dev/null
		$TRUNCATE $tf $fsize
	done
}

test_37()
{
	local tf=$DIR/$tfile
	local tf2=$DIR/$tfile-2
	local tf3=$DIR/$tfile-3

	create_files_37 $((RANDOM + 15 * 1048576)) $tf $tf2 $tf3

	# assume the mirror id will be 1, 2, and 3
	declare -A checksums
	checksums[1]=$(md5sum $tf | cut -f 1 -d' ')
	checksums[2]=$(md5sum $tf2 | cut -f 1 -d' ')
	checksums[3]=$(md5sum $tf3 | cut -f 1 -d' ')

	printf '%s\n' "${checksums[@]}"

	# merge these files into a mirrored file
	$LFS setstripe --component-add --mirror=$tf2 $tf
	$LFS setstripe --component-add --mirror=$tf3 $tf

	get_mirror_ids $tf

	# verify mirror read, checksums should equal to the original files'
	echo "Verifying mirror read .."

	local sum
	for i in ${mirror_array[@]}; do
		sum=$(mirror_io dump -i $i $tf | md5sum | cut -f 1 -d' ')
		[ "$sum" = "${checksums[$i]}" ] ||
			error "$i: mismatch: \'${checksums[$i]}\' vs. \'$sum\'"
	done

	# verify mirror copy, write to this mirrored file will invalidate
	# the other two mirrors
	echo "Verifying mirror copy .."

	local osts=$(comma_list $(osts_nodes))

	# define OBD_FAIL_OST_SKIP_LV_CHECK	0x241
	do_nodes $osts lctl set_param fail_loc=0x241

	mirror_io copy -i ${mirror_array[0]} \
		-t $(echo ${mirror_array[@]:1} | tr ' ' ',') $tf ||
			error "mirror copy error"

	do_nodes $osts lctl set_param fail_loc=0

	# verify copying is successful by checking checksums
	remount_client $MOUNT
	for i in ${mirror_array[@]}; do
		sum=$(mirror_io dump -i $i $tf | md5sum | cut -f 1 -d' ')
		[ "$sum" = "${checksums[1]}" ] ||
			error "$i: mismatch checksum after copy"
	done

	rm -f $tf $tf2 $tf3
}
run_test 37 "mirror I/O API verification"

verify_flr_state()
{
	local tf=$1
	local expected_state=$2
	local state_strings=("not_flr" "read_only" "write_pending" \
		"sync_pending")

	local state=$($LFS getstripe -v $tf | awk '/lcm_flags/{ print $2 }')
	[ $expected_state = ${state_strings[$state]} ] ||
		error "expected: $expected_state, " \
			"actual ${state_strings[$state]}($state)"
}

test_38() {
	local tf=$DIR/$tfile
	local ref=$DIR/${tfile}-ref

	$LFS setstripe -E 1M -c 1 -E 4M -c 2 -E eof -c -1 $tf
	$LFS setstripe -E 2M -c 1 -E 6M -c 2 -E 8M -c -1 -E eof -c -1 $tf-2
	$LFS setstripe -E 4M -c 1 -E 8M -c 2 -E eof -c -1 $tf-3

	# instantiate all components
	$LFS setstripe --component-add --mirror=$tf-2 $tf
	$LFS setstripe --component-add --mirror=$tf-3 $tf
	$LFS setstripe --component-add --mirror -c 1 $tf

	verify_flr_state $tf "read_only"

	dd if=/dev/urandom of=$ref  bs=1M count=16 &> /dev/null

	local fsize=$((RANDOM << 8 + 1048576))
	$TRUNCATE $ref $fsize

	local ref_cksum=$(md5sum $ref | cut -f 1 -d' ')

	# case 1: verify write to mirrored file & resync work
	cp $ref $tf || error "copy from $ref to $f error"
	verify_flr_state $tf "write_pending"

	local file_cksum=$(md5sum $tf | cut -f 1 -d' ')
	[ "$file_cksum" = "$ref_cksum" ] || error "write failed, cksum mismatch"

	get_mirror_ids $tf
	echo "mirror IDs: ${mirror_array[@]}"

	local valid_mirror stale_mirror id mirror_cksum
	for id in "${mirror_array[@]}"; do
		mirror_cksum=$(mirror_io dump -i $id $tf |
				md5sum | cut -f 1 -d' ')
		[ "$ref_cksum" == "$mirror_cksum" ] &&
			{ valid_mirror=$id; continue; }

		stale_mirror=$id
	done

	[ -z "$stale_mirror" ] && error "stale mirror doesn't exist"
	[ -z "$valid_mirror" ] && error "valid mirror doesn't exist"

	mirror_io resync $tf || error "resync failed"
	verify_flr_state $tf "read_only"

	mirror_cksum=$(mirror_io dump -i $stale_mirror $tf |
			md5sum | cut -f 1 -d' ')
	[ "$file_cksum" = "$ref_cksum" ] || error "resync failed"

	# case 2: inject an error to make mirror_io exit after changing
	# the file state to sync_pending so that we can start a concurrent
	# write.
	$MULTIOP $tf oO_WRONLY:w$((RANDOM % 1048576 + 1024))c
	verify_flr_state $tf "write_pending"

	mirror_io resync -e resync_start $tf && error "resync succeeded"
	verify_flr_state $tf "sync_pending"

	# from sync_pending to write_pending
	$MULTIOP $tf oO_WRONLY:w$((RANDOM % 1048576 + 1024))c
	verify_flr_state $tf "write_pending"

	mirror_io resync -e resync_start $tf && error "resync succeeded"
	verify_flr_state $tf "sync_pending"

	# from sync_pending to read_only
	mirror_io resync $tf || error "resync failed"
	verify_flr_state $tf "read_only"
}
run_test 38 "resync"

complete $SECONDS
check_and_cleanup_lustre
exit_status
