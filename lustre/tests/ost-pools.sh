#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#

SRCDIR=$(dirname $0)
export PATH=$PWD/$SRCDIR:$SRCDIR:$PWD/$SRCDIR/../utils:$PATH:/sbin

ONLY=${ONLY:-"$*"}
ALWAYS_EXCEPT="$OST_POOLS_EXCEPT"
# bug number for skipped test: -
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

[ "$ALWAYS_EXCEPT$EXCEPT" ] &&
    echo "Skipping tests: $(echo $ALWAYS_EXCEPT $EXCEPT)"

TMP=${TMP:-/tmp}
ORIG_PWD=${PWD}

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

check_and_setup_lustre

if ! combined_mgs_mds; then
	do_facet mgs "mkdir -p $MOUNT"
	zconf_mount $mgs_HOST $MOUNT $MOUNT_OPTS ||
		error "unable to mount $MOUNT on the MGS"
fi

#                                  9  12.5 (min)"
[ "$SLOW" = "no" ] && EXCEPT_SLOW="18 23b"

DIR=${DIR:-$MOUNT}
assert_DIR

build_test_filter

MAXFREE=${MAXFREE:-$((2000000 * OSTCOUNT))}

# OST pools tests
POOL=testpool
POOL2=${POOL2:-${POOL}2}
POOL3=${POOL3:-${POOL}3}
NON_EXISTANT_POOL=nonexistantpool
NON_EXISTANT_FS=nonexistantfs
INVALID_POOL=some_invalid_pool_name
TGT_COUNT=$OSTCOUNT
TGT_FIRST=$(printf %04x 0)
TGT_MAX=$(printf %04x $((TGT_COUNT-1)))
TGT_STEP=1
TGT_LIST=$(seq 0x$TGT_FIRST $TGT_STEP 0x$TGT_MAX)
TGT_LIST2=$(seq 0x$TGT_FIRST 2 0x$TGT_MAX)

TGT_ALL="$FSNAME-OST[$TGT_FIRST-$TGT_MAX/1]"
TGT_HALF="$FSNAME-OST[$TGT_FIRST-$TGT_MAX/2]"

TGT_UUID=$(for i in $TGT_LIST; do printf "$FSNAME-OST%04x_UUID " $i; done)
TGT_UUID2=$(for i in $TGT_LIST2; do printf "$FSNAME-OST%04x_UUID " $i; done)

create_dir() {
	local dir=$1
	local pool=$2
	local count=${3:-"-1"}
	local idx=$4

	mkdir -p $dir
	if [[ -n $idx ]]; then
		$LFS setstripe -c $count -p $pool -i $idx $dir
	else
		$LFS setstripe -c $count -p $pool $dir
	fi
	[[ $? -eq 0 ]] || error "$LFS setstripe -p $pool $dir failed"
	[[ "$($LFS getstripe --pool $dir)" == "$pool" ]] ||
		error "$dir not created in expected pool '$pool'"
}

create_file() {
	local file=$1
	local pool=$2
	local count=${3:-"-1"}
	local index=${4:-"-1"}
	rm -f $file
	$LFS setstripe -i $index -c $count -p $pool $file
	[[ $? -eq 0 ]] || error "$LFS setstripe -p $pool $file failed"
	[[ "$($LFS getstripe --pool $file)" == "$pool" ]] ||
		error "$file not created in '$pool'"
}

osts_in_pool() {
	local pool=$1
	local res
	for i in $(list_pool $FSNAME.$pool |
		sed -e 's/_UUID$//;s/^.*-OST//'); do
		res="$res $(printf "%d" 0x$i)"
	done
	echo $res
}

check_dir_in_pool() {
	local dir=$1
	local pool=$2
	local res=$($LFS getstripe --pool $dir)

	[ -n "$res" ] || error "dir '$dir' not in any pool"

	[ "$res" == "$pool" ] ||
		error "dir '$dir' in pool '$res' instead of '$pool'"
}

check_file_in_pool() {
	local file="$1"
	local pool=$2
	local count=$3
	local osts=$(osts_in_pool $pool)
	local res=$($LFS getstripe --pool $file)

	[ -n "$res" ] || error "file '$file' not in any pool"

	[ "$res" == "$pool" ] ||
		error "file '$file' in pool '$res' instead of '$pool'"

	local osts=$(osts_in_pool $2)
	check_file_in_osts "$file" "$osts" $count
}

check_file_in_osts() {
	local file=$1
	local ost_list=${2:-$TGT_LIST}
	local count=$3
	local res=$($LFS getstripe $file | awk '/0x/ { print $1 }')
	local i

	for i in $res; do
		found=$(echo :$ost_list: | tr " " ":" | grep :$i:)
		if [[ "$found" == "" ]]; then
			echo "ost list: $ost_list"
			echo "striping: $res"
			$LFS getstripe -v $file
			error "$file not allocated from OSTs $ost_list."
		fi
	done

	local ost_count=$($LFS getstripe -c $file)
	[[ -n "$count" ]] && [[ $ost_count -ne $count ]] &&
		error "$file stripe count $count expected; got $ost_count" &&
		return 1

}

check_file_not_in_pool() {
	local file=$1
	local pool=$2
	local res=$($LFS getstripe --pool $file)

	[ "$res" != "$pool" ] || error "File '$file' is in pool: $res"
}

check_dir_not_in_pool() {
	local dir=$1
	local pool=$2
	local res=$($LFS getstripe --pool $dir)

	[ "$res" != "$pool" ] || error "Dir '$dir' is in pool: $res"
}

drain_pool() {
    pool=$1
    wait_update $HOSTNAME "lctl get_param -n lov.$FSNAME-*.pools.$pool" "" ||
        error "Failed to remove targets from pool: $pool"
}

add_pool() {
	local pool=$1
	local osts=$2
	local tgt="${3}$(lctl get_param -n lov.$FSNAME-*.pools.$pool |
		sort -u | tr '\n' ' ')"

	do_facet mgs lctl pool_add $FSNAME.$pool $osts
	local RC=$?
	[[ $RC -ne 0 ]] && return $RC

	# wait for OSTs to be added to the pool
	for mds_id in $(seq $MDSCOUNT); do
		local mdt_id=$((mds_id-1))
		local lodname=$FSNAME-MDT$(printf "%04x" $mdt_id)-mdtlov
		wait_update_facet mds$mds_id \
			"lctl get_param -n lod.$lodname.pools.$pool |
				sort -u | tr '\n' ' ' " "$tgt" >/dev/null ||
			error "mds$mds_id:pool add failed $1; $2"
	done
	wait_update $HOSTNAME "lctl get_param -n lov.$FSNAME-*.pools.$pool |
		sort -u | tr '\n' ' ' " "$tgt" >/dev/null ||
		error "pool_add failed: $1; $2"
	return $RC
}

create_pool_nofail() {
	create_pool $FSNAME.$1
	[[ $? -ne 0 ]] && error "Pool creation of $1 failed"
	return 0
}

create_pool_fail() {
	create_pool $FSNAME.$1
	[[ $? -ne 0 ]] ||
		error "Pool creation of $1 succeeded; should have failed"
	return 0
}

ost_pools_init() {
	destroy_test_pools
}

# Initialization
remote_mds_nodsh && skip "remote MDS with nodsh" && exit 0
remote_ost_nodsh && skip "remote OST with nodsh" && exit 0
ost_pools_init

# Tests for new commands added
test_1a() {
	create_pool_nofail p
	destroy_pool p
}
run_test 1a "Create a pool with a 1 character pool name"

test_1b() {
	create_pool_nofail ${POOL}12
	destroy_pool ${POOL}12
}
run_test 1b "Create a pool with a 10 char pool name"

test_1c() {
	create_pool_nofail ${POOL}1234567
	destroy_pool ${POOL}1234567
}
run_test 1c "Create a pool with a 15 char pool name"

test_1d() {
	create_pool_fail ${POOL}12345678
}
run_test 1d "Create a pool with a 16 char pool name; should fail"

test_1e() {
	local pool_name="$POOL"
	for ((i = 1; i <= 991; i++)); do pool_name=${pool_name}"o"; done
	create_pool_fail $pool_name
}
run_test 1e "Create a pool with a 1000 char pool name; should fail"

test_1f() {
	create_pool .$POOL
	[[ $? -ne 0 ]] ||
		error "pool_new did not fail even though fs-name was missing"
}
run_test 1f "pool_new should fail if fs-name is missing"

test_1g() {
	create_pool $POOL
	[[ $? -ne 0 ]] ||
		error "pool_new did not fail even though fs-name was missing"
}
run_test 1g "pool_new should fail if fs-name is missing"

test_1h() {
	create_pool ${FSNAME}.
	[[ $? -ne 0 ]] ||
		error "pool_new did not fail even though pool name was missing"
}
run_test 1h "pool_new should fail if poolname is missing"

test_1i() {
	create_pool .
	[[ $? -ne 0 ]] ||
		error "pool_new did not fail even if pool/fs-name was missing"
}
run_test 1i "pool_new should fail if poolname and fs-name are missing"

test_1j() {
	create_pool ${FSNAME},$POOL
	[[ $? -ne 0 ]] ||
		error "pool_new did not fail even if poolname format was wrong"
}
run_test 1j "pool_new should fail if poolname format is wrong"

test_1k() {
	create_pool ${FSNAME}/$POOL
	[[ $? -ne 0 ]] ||
		error "pool_new did not fail even if poolname format was wrong"
}
run_test 1k "pool_new should fail if poolname format is wrong"

test_1m() {
	create_pool_nofail $POOL2
	create_pool ${FSNAME}.$POOL2
	[[ $? -ne 0 ]] ||
		error "pool_new did not fail even though $POOL2 existed"
	destroy_pool $POOL2
}
run_test 1m "pool_new did not fail even though $POOL2 existed"

test_1n() {
	create_pool_nofail ${POOL}1234567

	add_pool ${POOL}1234567 "OST0000" "$FSNAME-OST0000_UUID "
	local POOL_ROOT=${POOL_ROOT:-$DIR/$tdir}
	create_dir $POOL_ROOT ${POOL}1234567
	dd if=/dev/zero of=$POOL_ROOT/file bs=1M count=100
	RC=$?; [[ $RC -eq 0 ]] ||
		error "failed to write to $POOL_ROOT/file: $RC"
	do_facet mgs lctl pool_remove $FSNAME.${POOL}1234567 OST0000
	drain_pool ${POOL}1234567

	destroy_pool ${POOL}1234567
}
run_test 1n "Pool with a 15 char pool name works well"

test_2a() {
	destroy_pool $POOL

	do_facet mgs lctl pool_add $FSNAME.$POOL $FSNAME-OST0000 2>/dev/null
	[[ $? -ne 0 ]] ||
		error "pool_add did not fail even though $POOL did not exist"
}
run_test 2a "pool_add: non-existant pool $POOL"

test_2b() {
	do_facet mgs lctl pool_add $FSNAME.${POOL}1234567890 \
		$FSNAME-OST0000 2>/dev/null
	[[ $? -ne 0 ]] ||
		error "pool_add did not fail even though pool name was invalid."
}
run_test 2b "pool_add: Invalid pool name"

# Testing various combinations of OST name list
test_2c() {
	local TGT
	local RC

	lctl get_param -n lov.$FSNAME-*.pools.$POOL 2>/dev/null
	[[ $? -ne 0 ]] || destroy_pool $POOL

	create_pool_nofail $POOL

	# 1. OST0000
	do_facet mgs lctl pool_add $FSNAME.$POOL OST0000
	RC=$?; [[ $RC -eq 0 ]] ||
		error "pool_add failed. $FSNAME $POOL OST0000: $RC"
	do_facet mgs lctl pool_remove $FSNAME.$POOL OST0000
	drain_pool $POOL

	# 2. $FSNAME-OST0000
	do_facet mgs lctl pool_add $FSNAME.$POOL $FSNAME-OST0000
	RC=$?; [[ $RC -eq 0 ]] ||
		error "pool_add failed. $FSNAME $POOL $FSNAME-OST0000: $RC"
	do_facet mgs lctl pool_remove $FSNAME.$POOL $FSNAME-OST0000
	drain_pool $POOL

	# 3. $FSNAME-OST0000_UUID
	do_facet mgs lctl pool_add $FSNAME.$POOL $FSNAME-OST0000_UUID
	RC=$?; [[ $RC -eq 0 ]] ||
		error "pool_add failed. $FSNAME $POOL $FSNAME-OST0000_UUID: $RC"
	do_facet mgs lctl pool_remove $FSNAME.$POOL $FSNAME-OST0000_UUID
	drain_pool $POOL

	# 4. $FSNAME-OST[0,1,2,3,]
	TGT="$FSNAME-OST["
	for i in $TGT_LIST; do TGT=${TGT}$(printf "%04x," $i); done
	TGT="${TGT}]"
	do_facet mgs lctl pool_add $FSNAME.$POOL $TGT
	[[ $? -eq 0 ]] || error "pool_add failed. $FSNAME.$POOL $TGT. $RC"
	do_facet mgs lctl pool_remove $FSNAME.$POOL $TGT
	drain_pool $POOL

	# 5. $FSNAME-OST[0-5/1]
	do_facet mgs lctl pool_add $FSNAME.$POOL $TGT_ALL
	RC=$?; [[ $RC -eq 0 ]] ||
		error "pool_add failed. $FSNAME $POOL" "$TGT_ALL $RC"
	wait_update $HOSTNAME "lctl get_param -n lov.$FSNAME-*.pools.$POOL |
		sort -u | tr '\n' ' ' " "$TGT_UUID" ||
			error "Add to pool failed"
	do_facet mgs lctl pool_remove $FSNAME.$POOL $TGT_ALL
	drain_pool $POOL

	destroy_pool $POOL
}
run_test 2c "pool_add: OST index combinations"

test_2d() {
	local TGT
	local RC

	lctl get_param -n lov.$FSNAME-*.pools.$POOL 2>/dev/null
	[[ $? -ne 0 ]] || destroy_pool $POOL

	create_pool_nofail $POOL

	TGT=$(printf "$FSNAME-OST%04x_UUID " $OSTCOUNT)
	do_facet mgs lctl pool_add $FSNAME.$POOL $TGT
	RC=$?; [[ $RC -ne 0 ]] ||
		error "pool_add succeeded for an OST ($TGT) that does not exist."

	destroy_pool $POOL
}
run_test 2d "pool_add: OSTs that don't exist should be rejected"

test_2e() {
	local TGT
	local RC
	local RESULT

	$LCTL get_param -n lov.$FSNAME-*.pools.$POOL 2>/dev/null
	[[ $? -ne 0 ]] || destroy_pool $POOL

	create_pool_nofail $POOL

	TGT="$FSNAME-OST0000_UUID "
	do_facet mgs lctl pool_add $FSNAME.$POOL $TGT
	wait_update $HOSTNAME "lctl get_param -n lov.$FSNAME-*.pools.$POOL |
		sort -u | tr '\n' ' ' " "$TGT" || error "Add to pool failed"
	RESULT=$(do_facet mgs \
		"LOCALE=C $LCTL pool_add $FSNAME.$POOL $TGT 2>&1")
	RC=$?
	echo $RESULT

	[[ $RC -ne 0 ]] ||
		error "pool_add succeeded for an OST that was already in the pool."

	[[ $(grep "already in pool" <<< $RESULT) ]] ||
		error "pool_add failed as expected but error message not as expected."

	destroy_pool $POOL
}
run_test 2e "pool_add: OST already in a pool should be rejected"

test_3a() {
	lctl get_param -n lov.$FSNAME-*.pools.$POOL 2>/dev/null
	[[ $? -ne 0 ]] || destroy_pool $POOL

	do_facet mgs \
		lctl pool_remove $FSNAME.$POOL $FSNAME-OST0000 2>/dev/null
	[[ $? -ne 0 ]] ||
		error "pool_remove did not fail even though pool did not exist."
}
run_test 3a "pool_remove: non-existant pool"

test_3b() {
	do_facet mgs \
		lctl pool_remove ${NON_EXISTANT_FS}.$POOL OST0000 2>/dev/null
	[[ $? -ne 0 ]] ||
		error "pool_remove did not fail even though fsname did not exist."
}
run_test 3b "pool_remove: non-existant fsname"

test_3c() {
	do_facet mgs lctl pool_remove $FSNAME.p1234567891234567890 \
		$FSNAME-OST0000 2>/dev/null
	[[ $? -ne 0 ]] ||
		error "pool_remove did not fail even though pool name was invalid."
}
run_test 3c "pool_remove: Invalid pool name"

# Testing various combinations of OST name list
test_3d() {
	lctl get_param -n lov.$FSNAME-*.pools.$POOL 2>/dev/null
	[[ $? -ne 0 ]] || destroy_pool $POOL

	create_pool_nofail $POOL
	do_facet mgs lctl pool_add $FSNAME.$POOL OST0000
	do_facet mgs lctl pool_remove $FSNAME.$POOL OST0000
	[[ $? -eq 0 ]] || error "pool_remove failed. $FSNAME $POOL OST0000"
	drain_pool $POOL

	do_facet mgs lctl pool_add $FSNAME.$POOL $FSNAME-OST0000
	do_facet mgs lctl pool_remove $FSNAME.$POOL $FSNAME-OST0000
	[[ $? -eq 0 ]] || error "pool_remove failed. $FSNAME $POOL $FSNAME-OST0000"
	drain_pool $POOL

	do_facet mgs lctl pool_add $FSNAME.$POOL $FSNAME-OST0000_UUID
	do_facet mgs lctl pool_remove $FSNAME.$POOL $FSNAME-OST0000_UUID
	[[ $? -eq 0 ]] ||
		error "pool_remove failed. $FSNAME $POOL $FSNAME-OST0000_UUID"
	drain_pool $POOL

	add_pool $POOL $TGT_ALL "$TGT_UUID"
	do_facet mgs lctl pool_remove $FSNAME.$POOL $TGT_ALL
	[[ $? -eq 0 ]] || error "pool_remove failed. $FSNAME $POOL" $TGT_ALL
	drain_pool $POOL

	destroy_pool $POOL
}
run_test 3d "pool_remove: OST index combinations"

test_4a() {
	lctl get_param -n lov.$FSNAME-*.pools.$POOL 2>/dev/null
	[[ $? -ne 0 ]] || destroy_pool $POOL

	do_facet mgs lctl pool_destroy $FSNAME.$POOL 2>/dev/null
	[[ $? -ne 0 ]] ||
		error "pool_destroy did not fail even though pool did not exist."
}
run_test 4a "pool_destroy: non-existant pool"

test_4b() {
	do_facet mgs lctl pool_destroy ${NON_EXISTANT_FS}.$POOL 2>/dev/null
	[[ $? -ne 0 ]] ||
		error "pool_destroy did not fail even though filesystem did not exist."
}
run_test 4b "pool_destroy: non-existant fs-name"

test_4c() {
	create_pool_nofail $POOL
	add_pool $POOL "OST0000" "$FSNAME-OST0000_UUID "

	do_facet mgs lctl pool_destroy ${FSNAME}.$POOL
	[[ $? -ne 0 ]] || error "pool_destroy succeeded with a non-empty pool."
	destroy_pool $POOL
}
run_test 4c "pool_destroy: non-empty pool"

sub_test_5() {
	local LCMD=$1

	$LCMD pool_list 2>/dev/null
	[[ $? -ne 0 ]] ||
		error "pool_list did not fail even though fsname missing."

	destroy_pool $POOL 2>/dev/null
	destroy_pool $POOL2 2>/dev/null

	create_pool_nofail $POOL
	create_pool_nofail $POOL2
	$LCMD pool_list $FSNAME
	[[ $? -eq 0 ]] || error "pool_list $FSNAME failed."

	do_facet mgs lctl pool_add $FSNAME.$POOL $TGT_ALL

	$LCMD pool_list $FSNAME.$POOL
	[[ $? -eq 0 ]] || error "pool_list $FSNAME.$POOL failed."

	$LCMD pool_list ${NON_EXISTANT_FS} 2>/dev/null
	[[ $? -ne 0 ]] ||
		error "pool_list did not fail for fsname $NON_EXISTANT_FS"

	$LCMD pool_list ${FSNAME}.$NON_EXISTANT_POOL 2>/dev/null
	[[ $? -ne 0 ]] ||
		error "pool_list did not fail for pool $NON_EXISTANT_POOL"

	if [[ ! $(grep $SINGLEMDS <<< $LCMD) ]]; then
		echo $LCMD pool_list $DIR
		$LCMD pool_list $DIR
		[[ $? -eq 0 ]] || error "pool_list failed for $DIR"

		mkdir -p ${DIR}/d1
		$LCMD pool_list ${DIR}/d1
		[[ $? -eq 0 ]] || error "pool_list failed for ${DIR}/d1"
	fi

	rm -rf ${DIR}nonexistant
	$LCMD pool_list ${DIR}nonexistant 2>/dev/null
	[[ $? -ne 0 ]] ||
		error "pool_list did not fail for invalid mountpoint ${DIR}nonexistant"

	destroy_pool $POOL
	destroy_pool $POOL2
}

test_5a() {
	# Issue commands from client
	sub_test_5 $LFS
}
run_test 5a "lfs pool_list from client"

test_5b() {
	sub_test_5 "do_facet $SINGLEMDS lctl"
}
run_test 5b "lctl pool_list from MDS"

test_6() {
	local POOL_ROOT=${POOL_ROOT:-$DIR/$tdir}
	local POOL_DIR=$POOL_ROOT/dir_tst
	local POOL_FILE=$POOL_ROOT/file_tst

	create_pool_nofail $POOL

	do_facet $SINGLEMDS lctl pool_list $FSNAME
	[[ $? -eq 0 ]] || error "pool_list $FSNAME failed."

	add_pool $POOL $TGT_ALL "$TGT_UUID"

	mkdir -p $POOL_DIR
	$SETSTRIPE -c -1 -p $POOL $POOL_DIR
	[[ $? -eq 0 ]] || error "$SETSTRIPE -p $POOL failed."
	check_dir_in_pool $POOL_DIR $POOL

	# If an invalid pool name is specified, the command should fail
	$SETSTRIPE -c 2 -p $INVALID_POOL $POOL_DIR 2>/dev/null
	[[ $? -ne 0 ]] || error "setstripe to invalid pool did not fail."

	# If the pool name does not exist, the command should fail
	$SETSTRIPE -c 2 -p $NON_EXISTANT_POOL $POOL_DIR 2>/dev/null
	[[ $? -ne 0 ]] || error "setstripe to non-existant pool did not fail."

	# lfs setstripe should work as before if a pool name is not specified.
	$SETSTRIPE -c -1 $POOL_DIR
	[[ $? -eq 0 ]] || error "$SETSTRIPE -p $POOL_DIR failed."
	$SETSTRIPE -c -1 $POOL_FILE
	[[ $? -eq 0 ]] || error "$SETSTRIPE -p $POOL_FILE failed."

	# lfs setstripe should fail if a start index that is outside the
	# pool is specified.
	create_pool_nofail $POOL2
	add_pool $POOL2 "OST0000" "$FSNAME-OST0000_UUID "
	$SETSTRIPE -i 1 -p $POOL2 $ROOT_POOL/$tfile 2>/dev/null
	[[ $? -ne 0 ]] ||
	error "$SETSTRIPE with start index outside the pool did not fail."
}
run_test 6 "getstripe/setstripe"

helper_test_7a()
{
	# Create a pool, stripe a directory and file with it
	local pool=$1

	pool_add $pool || error "pool_add failed"
	pool_add_targets $pool 0 1 || error "pool_add_targets failed"

	$SETSTRIPE -c 1 $DIR/$tdir/testfile1 --pool "$pool" || \
		error "setstripe failed"
	$SETSTRIPE -c 1 $DIR/$tdir/testfile2 --pool "$FSNAME.$pool" || \
		error "setstripe failed"

	mkdir $DIR/$tdir/testdir
	$SETSTRIPE -c 1 $DIR/$tdir/testdir  -p "$pool" || \
		error "setstripe failed"
	$SETSTRIPE -c 1 $DIR/$tdir/testdir  -p "$FSNAME.$pool" || \
		error "setstripe failed"

	rm -f $DIR/$tdir/testfile1
	rm -f $DIR/$tdir/testfile2
	rmdir $DIR/$tdir/testdir

	destroy_pool_int $FSNAME.$pool
}

test_7a()
{
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs" && return

	mkdir -p $DIR/$tdir

	# Generate pool with random name from 1 to 15 characters
	for i in 1 9 15 ; do
		POOLNAME=$(echo $$$RANDOM$RANDOM |
			   tr -dc 'a-zA-Z0-9' | fold -w $i |
			   head -n 1)
		echo set poolname to $POOLNAME
		helper_test_7a $POOLNAME
	done
}
run_test 7a "create various pool name"

test_7b()
{
	# No fsname
	create_pool qwerty
	[ $? -ne 22 ] && error "can create a pool with no fsname"

	# No pool name
	create_pool $FSNAME.
	[ $? -ne 22 ] && error "can create a pool with no name"

	# Invalid character
	create_pool $FSNAME.0123456789^bdef
	[ $? -ne 22 ] && error "can create a pool with an invalid name"

	# Too long
	create_pool $FSNAME.0123456789abdefg
	[ $? -ne 36 ] && error "can create a pool with a name too long"

	return 0
}
run_test 7b "try to create pool name with invalid lengths or names"

test_7c()
{
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs" && return

	mkdir -p $DIR/$tdir

	# Create a pool with 15 letters
	local pool=0123456789abcde
	pool_add $pool || error "pool_add failed"
	pool_add_targets $pool 0 1 || error "pool_add_targets failed"

	# setstripe with the same pool name plus 1 letter
	$SETSTRIPE -c 1 $DIR/$tdir/testfile1 --pool "${pool}X" && \
		error "setstripe succedeed"

	# setstripe with the same pool name minus 1 letter
	$SETSTRIPE -c 1 $DIR/$tdir/testfile1 --pool "${pool%?}" && \
		error "setstripe succedeed"

	rm -f $DIR/$tdir/testfile1

	destroy_pool_int $FSNAME.$pool
}
run_test 7c "create a valid pool name and setstripe with a bad one"

test_11() {
	local POOL_ROOT=${POOL_ROOT:-$DIR/$tdir}

	[[ $OSTCOUNT -le 1 ]] && skip_env "needs >= 2 OSTs" && return

	create_pool_nofail $POOL
	create_pool_nofail $POOL2

	local start=$(printf %04x $((TGT_FIRST + 1)))
	do_facet mgs lctl pool_add $FSNAME.$POOL2 \
		$FSNAME-OST[$start-$TGT_MAX/2]

	add_pool $POOL $TGT_HALF "$TGT_UUID2"

	create_dir $POOL_ROOT/dir1  $POOL
	create_dir $POOL_ROOT/dir2  $POOL2

	local numfiles=100
	createmany -o $POOL_ROOT/dir1/$tfile $numfiles ||
		error "createmany $POOL_ROOT/dir1/$tfile failed!"

	for file in $POOL_ROOT/dir1/*; do
		check_file_in_pool $file $POOL
	done

	createmany -o $POOL_ROOT/dir2/$tfile $numfiles ||
		error "createmany $POOL_ROOT/dir2/$tfile failed!"
	for file in $POOL_ROOT/dir2/*; do
		check_file_in_pool $file $POOL2
	done

	rm -rf $POOL_ROOT/dir?

	return 0
}
run_test 11 "OSTs in overlapping/multiple pools"

test_12() {
	local POOL_ROOT=${POOL_ROOT:-$DIR/$tdir}

	[[ $OSTCOUNT -le 2 ]] && skip_env "needs >=3 OSTs" && return

	create_pool_nofail $POOL
	create_pool_nofail $POOL2

	local start=$(printf %04x $((TGT_FIRST + 1)))
	do_facet mgs lctl pool_add $FSNAME.$POOL2 \
		$FSNAME-OST[$start-$TGT_MAX/2]

	add_pool $POOL $TGT_HALF "$TGT_UUID2"

	echo creating some files in $POOL and $POOL2

	create_dir $POOL_ROOT/dir1  $POOL
	create_dir $POOL_ROOT/dir2  $POOL2
	create_file $POOL_ROOT/file1 $POOL
	create_file $POOL_ROOT/file2 $POOL2

	echo Checking the files created
	check_file_in_pool $POOL_ROOT/file1 $POOL
	check_file_in_pool $POOL_ROOT/file2 $POOL2

	echo Changing the pool membership
	do_facet mgs lctl pool_remove $FSNAME.$POOL $FSNAME-OST[$TGT_FIRST]
	do_facet mgs lctl pool_list $FSNAME.$POOL
	FIRST_UUID=$(echo $TGT_UUID | awk '{print $1}')
	add_pool $POOL2 $FSNAME-OST[$TGT_FIRST] "$FIRST_UUID "
	do_facet mgs lctl pool_list $FSNAME.$POOL2

	echo Checking the files again
	check_dir_in_pool $POOL_ROOT/dir1 $POOL
	check_dir_in_pool $POOL_ROOT/dir2 $POOL2
	check_file_in_osts $POOL_ROOT/file1 "$TGT_LIST2"
	check_file_in_osts $POOL_ROOT/file2 "$(seq 0x$start 2 0x$TGT_MAX)"

	echo Creating some more files
	create_dir $POOL_ROOT/dir3 $POOL
	create_dir $POOL_ROOT/dir4 $POOL2
	create_file $POOL_ROOT/file3 $POOL
	create_file $POOL_ROOT/file4 $POOL2

	echo Checking the new files
	check_file_in_pool $POOL_ROOT/file3 $POOL
	check_file_in_pool $POOL_ROOT/file4 $POOL2

	return 0
}
run_test 12 "OST Pool Membership"

test_13() {
	[[ $OSTCOUNT -le 2 ]] && skip_env "needs >= 3 OSTs" && return

	local POOL_ROOT=${POOL_ROOT:-$DIR/$tdir}
	local numfiles=10
	local count=3

	create_pool_nofail $POOL
	add_pool $POOL $TGT_ALL "$TGT_UUID"

	create_dir $POOL_ROOT/dir1 $POOL -1
	createmany -o $POOL_ROOT/dir1/$tfile $numfiles ||
		error "createmany $POOL_ROOT/dir1/$tfile failed!"
	for file in $POOL_ROOT/dir1/*; do
		check_file_in_pool $file $POOL $OSTCOUNT
	done

	create_file $POOL_ROOT/dir1/file1 $POOL 1 $TGT_FIRST
	create_file $POOL_ROOT/dir1/file2 $POOL 1 $((TGT_FIRST + 1))
	create_file $POOL_ROOT/dir1/file3 $POOL 1 $((TGT_FIRST + 2))
	check_file_in_osts $POOL_ROOT/dir1/file1 $((16#$TGT_FIRST))
	check_file_in_osts $POOL_ROOT/dir1/file2 "$((TGT_FIRST + 1))"
	check_file_in_osts $POOL_ROOT/dir1/file3 "$((TGT_FIRST + 2))"

	create_dir $POOL_ROOT/dir2 $POOL $count
	createmany -o $POOL_ROOT/dir2/$tfile- $numfiles ||
		error "createmany $POOL_ROOT/dir2/$tfile- failed!"
	for file in $POOL_ROOT/dir2/*; do
		check_file_in_pool $file $POOL $count
	done

	create_dir $POOL_ROOT/dir3 $POOL $count $((TGT_FIRST + 1))
	createmany -o $POOL_ROOT/dir3/$tfile- $numfiles ||
		error "createmany $POOL_ROOT/dir3/$tfile- failed!"
	for file in $POOL_ROOT/dir3/*; do
		check_file_in_pool $file $POOL $count
	done

	create_dir $POOL_ROOT/dir4 $POOL 1
	createmany -o $POOL_ROOT/dir4/$tfile- $numfiles ||
		error "createmany $POOL_ROOT/dir4/$tfile- failed!"
	for file in $POOL_ROOT/dir4/*; do
		check_file_in_pool $file $POOL 1
	done

	create_dir $POOL_ROOT/dir5 $POOL 1 $((TGT_FIRST + 2))
	createmany -o $POOL_ROOT/dir5/$tfile- $numfiles ||
		error "createmany $POOL_ROOT/dir5/$tfile- failed!"
	for file in $POOL_ROOT/dir5/*; do
		check_file_in_pool $file $POOL 1
	done

	rm -rf $POOL_ROOT/dir[1-5]/

	return 0
}
run_test 13 "Striping characteristics in a pool"

test_14() {
	[[ $OSTCOUNT -le 2 ]] && skip_env "needs >= 3 OSTs" && return

	local POOL_ROOT=${POOL_ROOT:-$DIR/$tdir}
	local numfiles=100
	local i

	[ $OSTSIZE -gt $((MAXFREE / OSTCOUNT)) ] &&
	skip_env "OST size $OSTSIZE is larger than $((MAXFREE / OSTCOUNT))" &&
			return 0

	create_pool_nofail $POOL
	create_pool_nofail $POOL2

	add_pool $POOL $TGT_HALF "$TGT_UUID2"
	add_pool $POOL2 "OST0000" "$FSNAME-OST0000_UUID "

	create_dir $POOL_ROOT/dir1 $POOL 1
	create_file $POOL_ROOT/dir1/file $POOL 1
	local ost=$($LFS getstripe -i $POOL_ROOT/dir1/file)
	i=0
	while [[ $i -lt $numfiles ]]; do
		ost=$((ost + 2))
		[[ $ost -gt $((16#$TGT_MAX)) ]] && ost=$TGT_FIRST

		# echo "Iteration: $i OST: $ost"
		create_file $POOL_ROOT/dir1/file${i} $POOL 1
		check_file_in_pool $POOL_ROOT/dir1/file${i} $POOL
		i=$((i + 1))
	done

	# Fill up OST0 until it is nearly full.
	# Create 9 files of size OST0_SIZE/10 each.
	create_dir $POOL_ROOT/dir2 $POOL2 1
	$LFS df $POOL_ROOT/dir2
	OST0_SIZE=$($LFS df $POOL_ROOT/dir2 | awk '/\[OST:0\]/ { print $4 }')
	FILE_SIZE=$((OST0_SIZE/1024/10))
	echo "Filling OST0 with 9 files of ${FILE_SIZE}MB in $POOL_ROOT/dir2"
	i=1
	while [[ $i -lt 10 ]]; do
		dd if=/dev/zero of=$POOL_ROOT/dir2/f${i} bs=1M count=$FILE_SIZE
		i=$((i + 1))
	done
	sleep 1 # get new statfs info
	$LFS df $POOL_ROOT/dir2

	# OST $TGT_FIRST is no longer favored; but it may still be used.
	create_dir $POOL_ROOT/dir3 $POOL 1
	create_file $POOL_ROOT/dir3/file $POOL 1
	createmany -o $POOL_ROOT/dir3/$tfile- $numfiles ||
		error "createmany $POOL_ROOT/dir3/$tfile- failed!"
	for file in $POOL_ROOT/dir3/*; do
		check_file_in_pool $file $POOL
	done

	rm -rf $POOL_ROOT

	return 0
}
run_test 14 "Round robin and QOS striping within a pool"

test_15() {
	local POOL_ROOT=${POOL_ROOT:-$DIR/$tdir}
	local numfiles=100
	local i=0

	while [[ $i -lt $OSTCOUNT ]]; do
		create_pool_nofail $POOL${i}

		local tgt=$(printf "$FSNAME-OST%04x_UUID " $i)
		add_pool $POOL${i} "$FSNAME-OST[$(printf %04x $i)]" "$tgt"
		create_dir $POOL_ROOT/dir${i} $POOL${i}
		createmany -o $POOL_ROOT/dir$i/$tfile $numfiles ||
			error "createmany $POOL_ROOT/dir$i/$tfile failed!"

		for file in $POOL_ROOT/dir$i/*; do
			check_file_in_osts $file $i
		done

		i=$((i + 1))
	done

	return 0
}
run_test 15 "One directory per OST/pool"

test_16() {
	local POOL_ROOT=${POOL_ROOT:-$DIR/$tdir}
	local numfiles=10
	local i=0

	create_pool_nofail $POOL

	add_pool $POOL $TGT_HALF "$TGT_UUID2"

	local dir=$POOL_ROOT/$tdir
	create_dir $dir $POOL

	for i in $(seq 1 10); do
		dir=${dir}/dir${i}
	done
	mkdir -p $dir

	createmany -o $dir/$tfile $numfiles ||
		error "createmany $dir/$tfile failed!"

	for file in $dir/*; do
		check_file_in_pool $file $POOL
	done

	rm -rf $POOL_ROOT/$tdir

	return 0
}
run_test 16 "Inheritance of pool properties"

test_17() {
	local POOL_ROOT=${POOL_ROOT:-$DIR/$tdir}
	local numfiles=10
	local i=0

	create_pool_nofail $POOL

	add_pool $POOL $TGT_ALL "$TGT_UUID"

	local dir=$POOL_ROOT/dir
	create_dir $dir $POOL

	createmany -o $dir/${tfile}1_ $numfiles ||
		error "createmany $dir/${tfile}1_ failed!"

	for file in $dir/*; do
		check_file_in_pool $file $POOL
	done

	destroy_pool $POOL

	createmany -o $dir/${tfile}2_ $numfiles ||
		error "createmany $dir/${tfile}2_ failed!"

	rm -rf $dir
	return 0
}
run_test 17 "Referencing an empty pool"

create_perf() {
    local cdir=$1/d
    local numsec=$2
    local time

    mkdir -p $cdir
    sync
    wait_delete_completed >/dev/null # give pending IO a chance to go to disk
    stat=$(createmany -o $cdir/${tfile} -$numsec | tail -1)
    files=$(echo $stat | cut -f 2 -d ' ')
    echo $stat 1>&2
    unlinkmany $cdir/${tfile} $files > /dev/null
    sync

    echo $files
}

test_18() {
	local POOL_ROOT=${POOL_ROOT:-$DIR/$tdir}
	local numsec=15
	local iter=3
	local plaindir=$POOL_ROOT/plaindir
	local pooldir=$POOL_ROOT/pooldir
	local f1=0
	local f2=0
	local f3=0
	local diff

	for i in $(seq 1 $iter); do
		echo "Create performance, iteration $i, $numsec seconds x 3"

		local files1=$(create_perf $plaindir $numsec)
		[[ $files1 -eq 0 ]] && error "Zero files created without pool"
		f1=$((f1 + files1))
		echo "iter $i: $files1 creates without pool"

		create_pool_nofail $POOL > /dev/null
		add_pool $POOL $TGT_ALL "$TGT_UUID" > /dev/null
		create_dir $pooldir $POOL
		local files2=$(create_perf $pooldir $numsec)
		[[ $files2 -eq 0 ]] && error "Zero files created with pool"
		f2=$((f2 + files2))
		echo "iter $i: $files2 creates with pool"

		destroy_pool $POOL > /dev/null
		local files3=$(create_perf $pooldir $numsec)
		[[ $files3 -eq 0 ]] &&
			error "Zero files created with missing pool"
		f3=$((f3 + files3))
		echo "iter $i: $files3 creates with missing pool"

		echo
	done

	echo Avg files created in $numsec seconds without pool: $((f1 / iter))
	echo Avg files created in $numsec seconds with pool: $((f2 / iter))
	echo Avg files created in $numsec seconds missing pool: $((f3 / iter))

	# Set this high until we establish a baseline for what the degradation
	# is / should be
	max=30

	diff=$((($f1 - $f2) * 100 / $f1))
	echo  "No pool / wide pool: $diff %."
	[ $diff -gt $max ] &&
		error_ignore bz23408 "Degradation with wide pool is $diff% > $max%"

	max=30
	diff=$((($f1 - $f3) * 100 / $f1))
	echo  "No pool / missing pool: $diff %."
	[ $diff -gt $max ] &&
		error_ignore bz23408 "Degradation with wide pool is $diff% > $max%"

	return 0
}
run_test 18 "File create in a directory which references a deleted pool"

test_19() {
	local POOL_ROOT=${POOL_ROOT:-$DIR/$tdir}
	local numfiles=12
	local dir1=$POOL_ROOT/dir1
	local dir2=$POOL_ROOT/dir2
	local i=0

	create_pool_nofail $POOL

	add_pool $POOL $TGT_HALF "$TGT_UUID2"

	create_dir $dir1 $POOL
	createmany -o $dir1/${tfile} $numfiles ||
		error "createmany $dir1/${tfile} failed!"
	for file in $dir1/*; do
		check_file_in_pool $file $POOL
	done

	mkdir -p $dir2
	createmany -o $dir2/${tfile} $numfiles ||
		error "createmany $dir2/${tfile} failed!"
	for file in $dir2/*; do
		check_file_not_in_pool $file $POOL
	done

	rm -rf $dir1 $dir2

	return 0
}
run_test 19 "Pools should not come into play when not specified"

test_20() {
	local POOL_ROOT=${POOL_ROOT:-$DIR/$tdir}
	local numfiles=12
	local dir1=$POOL_ROOT/dir1
	local dir2=$dir1/dir2
	local dir3=$dir1/dir3
	local i=0
	local TGT

	create_pool_nofail $POOL
	create_pool_nofail $POOL2

	add_pool $POOL $TGT_HALF "$TGT_UUID2"

	local start=$(printf %04x $((TGT_FIRST + 1)))
	TGT=$(for i in $(seq 0x$start 2 0x$TGT_MAX); do \
		printf "$FSNAME-OST%04x_UUID " $i; done)
	add_pool $POOL2 "$FSNAME-OST[$start-$TGT_MAX/2]" "$TGT"

	create_dir $dir1 $POOL
	create_file $dir1/file1 $POOL2
	create_dir $dir2 $POOL2
	touch $dir2/file2
	mkdir $dir3
	$SETSTRIPE -c 1 $dir3 # No pool assignment
	touch $dir3/file3
	$SETSTRIPE -c 1 $dir2/file4 # No pool assignment

	check_file_in_pool $dir1/file1 $POOL2
	check_file_in_pool $dir2/file2 $POOL2

	check_dir_not_in_pool $dir3 $POOL
	check_dir_not_in_pool $dir3 $POOL2

	check_file_not_in_pool $dir3/file3 $POOL
	check_file_not_in_pool $dir3/file3 $POOL2

	check_file_not_in_pool $dir2/file4 $POOL
	check_file_not_in_pool $dir2/file4 $POOL2

	rm -rf $dir1

	return 0
}
run_test 20 "Different pools in a directory hierarchy."

test_21() {
	local POOL_ROOT=${POOL_ROOT:-$DIR/$tdir}
	[[ $OSTCOUNT -le 1 ]] && skip_env "needs >= 2 OSTs" && return

	local numfiles=12
	local i=0
	local dir=$POOL_ROOT/dir

	create_pool_nofail $POOL

	add_pool $POOL $TGT_HALF "$TGT_UUID2"

	create_dir $dir $POOL $OSTCOUNT
	create_file $dir/file1 $POOL $OSTCOUNT
	$LFS getstripe -v $dir/file1
	check_file_in_pool $dir/file1 $POOL

	rm -rf $dir

	return 0
}
run_test 21 "OST pool with fewer OSTs than stripe count"

add_loop() {
	local pool=$1
	local step=$2

	echo loop for $pool

	for c in $(seq 1 10); do
		echo "Pool $pool, iteration $c"
		do_facet mgs lctl pool_add $FSNAME.$pool \
			OST[$TGT_FIRST-$TGT_MAX/$step] 2>/dev/null
		local TGT_SECOND=$(printf %04x $((TGT_FIRST + $step)))
		if [ $((16#$TGT_SECOND)) -le $((16#$TGT_MAX)) ]; then
		do_facet mgs lctl pool_remove $FSNAME.$pool \
			OST[$TGT_SECOND-$TGT_MAX/$step]
		fi
	done
	echo loop for $pool complete
}

test_22() {
	local POOL_ROOT=${POOL_ROOT:-$DIR/$tdir}
	[[ $OSTCOUNT -le 1 ]] && skip_env "needs >= 2 OSTs" && return

	local numfiles=100

	create_pool_nofail $POOL
	add_pool $POOL "OST0000" "$FSNAME-OST0000_UUID "
	create_pool_nofail $POOL2
	add_pool $POOL2 "OST0000" "$FSNAME-OST0000_UUID "

	add_loop $POOL 1 &
	add_loop $POOL2 2 &
	sleep 5
	create_dir $POOL_ROOT $POOL
	createmany -o $POOL_ROOT/${tfile} $numfiles ||
		error "createmany $POOL_ROOT/${tfile} failed!"
	wait

	return 0
}
run_test 22 "Simultaneous manipulation of a pool"

test_23a() {
	local POOL_ROOT=${POOL_ROOT:-$DIR/$tdir}
	[[ $OSTCOUNT -le 1 ]] && skip_env "needs >= 2 OSTs" && return

	mkdir -p $POOL_ROOT
	check_runas_id $RUNAS_ID $RUNAS_GID $RUNAS || {
		skip_env "User $RUNAS_ID does not exist - skipping"
		return 0
	}

	local i=0
	local TGT
	local BUNIT_SZ=1024  # min block quota unit(kB)
	local LIMIT=$((BUNIT_SZ * (OSTCOUNT + 1)))
	local dir=$POOL_ROOT/dir
	local file="$dir/$tfile-quota"

	create_pool_nofail $POOL

	local TGT=$(for i in $(seq 0x$TGT_FIRST 3 0x$TGT_MAX); do \
		printf "$FSNAME-OST%04x_UUID " $i; done)
	add_pool $POOL "$FSNAME-OST[$TGT_FIRST-$TGT_MAX/3]" "$TGT"
	create_dir $dir $POOL

	# XXX remove the interoperability code once we drop the old server
	#     ( < 2.3.50) support.
	if [ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.3.50) ]; then
		$LFS quotaoff -ug $MOUNT
		$LFS quotacheck -ug $MOUNT
	else
		do_facet mgs $LCTL conf_param $FSNAME.quota.ost=ug
		sleep 5
	fi

	$LFS setquota -u $RUNAS_ID -b $LIMIT -B $LIMIT $dir
	sleep 3
	$LFS quota -v -u $RUNAS_ID $dir

	$SETSTRIPE -c 1 -p $POOL $file
	chown $RUNAS_ID.$RUNAS_GID $file
	ls -l $file

	# This does two "dd" runs to ensure that the quota failure is returned
	# to userspace when we check.  The first "dd" might otherwise complete
	# without error if it is only writing into cache.
	stat=$(LOCALE=C $RUNAS dd if=/dev/zero of=$file bs=$BUNIT_SZ \
		count=$((BUNIT_SZ*2)) 2>&1)
	echo $stat | grep "Disk quota exceeded" > /dev/null
	if [ $? -eq 0 ]; then
		$LFS quota -v -u $RUNAS_ID $dir
		cancel_lru_locks osc
		stat=$(LOCALE=C $RUNAS dd if=/dev/zero of=$file bs=$BUNIT_SZ \
			count=$BUNIT_SZ seek=$((BUNIT_SZ*2)) 2>&1)
		RC=$?
		echo $stat
		[[ $RC -eq 0 ]] && error "second dd did not fail."
		echo $stat | grep "Disk quota exceeded" > /dev/null
		[[ $? -eq 1 ]] && error "second dd did not fail with EDQUOT."
	else
		log "first dd failed with EDQUOT."
	fi
	$LFS quota -v -u $RUNAS_ID $dir
}
run_test 23a "OST pools and quota"

test_23b() {
	local POOL_ROOT=${POOL_ROOT:-$DIR/$tdir}
	[[ $OSTCOUNT -le 1 ]] && skip_env "needs >= 2 OSTs" && return 0

	mkdir -p $POOL_ROOT
	check_runas_id $RUNAS_ID $RUNAS_GID $RUNAS || {
		skip_env "User $RUNAS_ID does not exist - skipping"
		return 0
	}

	local i=0
	local TGT
	local dir=$POOL_ROOT/dir
	local file="$dir/$tfile-quota"

	create_pool_nofail $POOL

	local TGT=$(for i in $(seq 0x$TGT_FIRST 3 0x$TGT_MAX); do \
		printf "$FSNAME-OST%04x_UUID " $i; done)
	add_pool $POOL "$FSNAME-OST[$TGT_FIRST-$TGT_MAX/3]" "$TGT"
	create_dir $dir $POOL

	local maxfree=$((1024 * 1024 * 30)) # 30G
	local AVAIL=$(lfs_df -p $POOL $dir | awk '/summary/ { print $4 }')
	[ $AVAIL -gt $maxfree ] &&
		skip_env "Filesystem space $AVAIL is larger than " \
			"$maxfree limit" && return 0

	echo "OSTCOUNT=$OSTCOUNT, OSTSIZE=$OSTSIZE, AVAIL=$AVAIL"
	echo "MAXFREE=$maxfree, SLOW=$SLOW"

	# XXX remove the interoperability code once we drop the old server
	#     ( < 2.3.50) support.
	if [ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.3.50) ]; then
		$LFS quotaoff -ug $MOUNT
	else
		do_facet mgs $LCTL conf_param $FSNAME.quota.ost=none
		sleep 5
	fi

	chown $RUNAS_ID.$RUNAS_ID $dir
	i=0
	local RC=0
	local TOTAL=0 # KB
	local stime=$(date +%s)
	local stat
	local etime
	local elapsed
	local maxtime=300 # minimum speed: 5GB / 300sec ~= 17MB/s
	while [ $RC -eq 0 ]; do
		i=$((i + 1))
		stat=$(LOCALE=C $RUNAS2 dd if=/dev/zero of=${file}$i bs=1M \
			count=$((5 * 1024)) 2>&1)
		RC=$?
		TOTAL=$((TOTAL + 1024 * 1024 * 5))
		echo "[$i iteration] $stat"
		echo "total written: $TOTAL"

		etime=$(date +%s)
		elapsed=$((etime - stime))
		echo "stime=$stime, etime=$etime, elapsed=$elapsed"

		if [ $RC -eq 1 ]; then
			echo $stat | grep -q "Disk quota exceeded"
			[[ $? -eq 0 ]] &&
				error "dd failed with EDQUOT with quota off"

			echo $stat | grep -q "No space left on device"
			[[ $? -ne 0 ]] &&
				error "dd did not fail with ENOSPC"
		elif [ $TOTAL -gt $AVAIL ]; then
			error "dd didn't fail with ENOSPC ($TOTAL > $AVAIL)"
		elif [ $i -eq 1 -a $elapsed -gt $maxtime ]; then
			log "The first 5G write used $elapsed (> $maxtime) " \
				"seconds, terminated"
			RC=1
		fi
	done

	df -h
	rm -rf $POOL_ROOT
}
run_test 23b "OST pools and OOS"

test_24() {
	local POOL_ROOT=${POOL_ROOT:-$DIR/$tdir}
	[[ $OSTCOUNT -le 1 ]] && skip_env "needs >= 2 OSTs" && return

	local server_version=$(lustre_version_code $SINGLEMDS)
		[[ $server_version -ge $(version_code 2.8.56) ]] ||
		{ skip "Need server version newer than 2.8.55"; return 0; }

	local numfiles=10
	local i=0
	local TGT
	local dir
	local res

	create_pool_nofail $POOL

	add_pool $POOL $TGT_ALL "$TGT_UUID"

	create_dir $POOL_ROOT/dir1 $POOL $OSTCOUNT

	mkdir $POOL_ROOT/dir2
	$SETSTRIPE -p $POOL -S 65536 -i 0 -c 1 $POOL_ROOT/dir2 ||
		error "$SETSTRIPE $POOL_ROOT/dir2 failed"

	mkdir $POOL_ROOT/dir3
	$SETSTRIPE -S 65536 -i 0 -c 1 $POOL_ROOT/dir3 ||
		error "$SETSTRIPE $POOL_ROOT/dir3 failed"

	mkdir $POOL_ROOT/dir4

	for i in 1 2 3 4; do
		dir=${POOL_ROOT}/dir${i}
		local pool
		local pool1
		local count
		local count1
		local index
		local size
		local size1

		createmany -o $dir/${tfile} $numfiles ||
			error "createmany $dir/${tfile} failed!"
		pool=$($LFS getstripe --pool $dir)
		index=$($LFS getstripe -i $dir)
		size=$($LFS getstripe -S $dir)
		count=$($LFS getstripe -c $dir)

		for file in $dir/*; do
			if [ "$pool" != "" ]; then
				check_file_in_pool $file $pool
			fi
			pool1=$($LFS getstripe --pool $file)
			count1=$($LFS getstripe -c $file)
			size1=$($LFS getstripe -S $file)
			[[ "$pool" != "$pool1" ]] &&
				error "Pool '$pool' not on $file:$pool1"
			[[ "$count" != "$count1" ]] &&
				error "Stripe count $count not on $file:$count1"
			[[ "$size" != "$size1" ]] && [[ "$size" != "0" ]] &&
				error "Stripe size $size not on $file:$size1"
		done
	done

	rm -rf $POOL_ROOT

	return 0
}
run_test 24 "Independence of pool from other setstripe parameters"

test_25() {
	local POOL_ROOT=${POOL_ROOT:-$DIR/$tdir}

	mkdir -p $POOL_ROOT

	for i in $(seq 10); do
		create_pool_nofail $POOL$i
		do_facet mgs "lctl pool_add $FSNAME.$POOL$i OST0000; sync"
		wait_update $HOSTNAME "lctl get_param -n \
			lov.$FSNAME-*.pools.$POOL$i | sort -u |
			tr '\n' ' ' " "$FSNAME-OST0000_UUID " >/dev/null ||
				error "pool_add failed: $1; $2"

		facet_failover $SINGLEMDS ||
			error "failed to failover $SINGLEMDS"
		wait_osc_import_state $SINGLEMDS ost FULL
		clients_up

		wait_mds_ost_sync
		# Veriy that the pool got created and is usable
		df $POOL_ROOT > /dev/null
		sleep 5

		# Make sure OST0 can be striped on
		$SETSTRIPE -i 0 -c 1 $POOL_ROOT/$tfile
		local STR=$($LFS getstripe -i $POOL_ROOT/$tfile)
		rm $POOL_ROOT/$tfile
		if [[ "$STR" == "0" ]]; then
			echo "Creating a file in pool$i"
			create_file $POOL_ROOT/file$i $POOL$i || break
			check_file_in_pool $POOL_ROOT/file$i $POOL$i || break
		else
			echo "OST 0 seems to be unavailable.  Try later."
		fi
	done

	rm -rf $POOL_ROOT
}
run_test 25 "Create new pool and restart MDS"

test_26() {
	[[ $OSTCOUNT -le 2 ]] && skip_env "needs >= 3 OSTs" && return
	local dev=$(mdsdevname ${SINGLEMDS//mds/})
	local POOL_ROOT=${POOL_ROOT:-$DIR/$tdir}

	mkdir -p $POOL_ROOT

	create_pool_nofail $POOL2

	do_facet mgs "lctl pool_add $FSNAME.$POOL2 OST0000; sync"
	wait_update $HOSTNAME "lctl get_param -n \
		lov.$FSNAME-*.pools.$POOL2 | sort -u |
		grep $FSNAME-OST0000_UUID " "$FSNAME-OST0000_UUID" ||
			error "pool_add failed: $1; $2"

	do_facet mgs "lctl pool_add $FSNAME.$POOL2 OST0002; sync"
	wait_update $HOSTNAME "lctl get_param -n \
		lov.$FSNAME-*.pools.$POOL2 | sort -u |
		grep $FSNAME-OST0002_UUID" "$FSNAME-OST0002_UUID" ||
			error "pool_add failed: $1; $2"

	# Veriy that the pool got created and is usable
	df $POOL_ROOT
	echo "Creating files in $POOL2"

	for ((i = 0; i < 10; i++)); do
		#OBD_FAIL_MDS_OSC_CREATE_FAIL     0x147
		#Fail OST0000 to ensure objects create on
		#the other OST in the pool
		do_facet $SINGLEMDS lctl set_param fail_loc=0x147
		do_facet $SINGLEMDS lctl set_param fail_val=0
		create_file $POOL_ROOT/file$i $POOL2 1 -1 || break
		do_facet $SINGLEMDS lctl set_param fail_loc=0
		check_file_in_pool $POOL_ROOT/file$i $POOL2 || break
	done
	rm -rf $POOL_ROOT
}
run_test 26 "Choose other OSTs in the pool first in the creation remedy"

cd $ORIG_PWD

complete $SECONDS
destroy_test_pools $FSNAME
if ! combined_mgs_mds; then
	zconf_umount $mgs_HOST $MOUNT
	do_facet mgs "rm -rf $MOUNT"
fi
check_and_cleanup_lustre
exit_status
