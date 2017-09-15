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

complete $SECONDS
check_and_cleanup_lustre
exit_status
