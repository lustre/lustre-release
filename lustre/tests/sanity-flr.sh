#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
set -e
set +o posix

SRCDIR=$(dirname $0)
export PATH=$PWD/$SRCDIR:$SRCDIR:$PWD/$SRCDIR/../utils:$PATH:/sbin

ONLY=${ONLY:-"$*"}
# Bug number for skipped test:    LU-11381
ALWAYS_EXCEPT="$SANITY_FLR_EXCEPT 201"
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

[[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.10.56) ]] ||
	{ skip "Need MDS version at least 2.10.56"; exit 0; }

[ $UID -eq 0 -a $RUNAS_ID -eq 0 ] &&
	error "\$RUNAS_ID set to 0, but \$UID is also 0!"
check_runas_id $RUNAS_ID $RUNAS_GID $RUNAS

check_and_setup_lustre
DIR=${DIR:-$MOUNT}
assert_DIR

build_test_filter

assert_DIR
rm -rf $DIR/[Rdfs][0-9]*

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
		wait_osc_import_state client ost$idx "\(DISCONN\|IDLE\)"
	done
}

start_osts() {
	local idx

	for idx in "$@"; do
		start ost$idx $(ostdevname $idx) $OST_MOUNT_OPTS ||
			error "start ost$idx failed"
	done

	for idx in "$@"; do
		wait_recovery_complete ost$idx
	done
}

#
# Verify mirror count with an expected value for a given file.
#
verify_mirror_count() {
	local tf=$1
	local expected=$2
	local mirror_count=$(get_mirror_ids $tf)

	[[ $mirror_count = $expected ]] || {
		$LFS getstripe -v $tf
		error "verify mirror count failed on $tf:" \
		      "$mirror_count != $expected"
	}
}

#
# Verify component count with an expected value for a given file.
#	$1 coposited layout file
#	$2 expected component number
#
verify_comp_count() {
	local tf=$1
	local expected=$2
	local comp_count=$($LFS getstripe --component-count $tf)

	[[ $comp_count = $expected ]] || {
		$LFS getstripe -v $tf
		error "verify component count failed on $tf:" \
		      "$comp_count != $expected"
	}
}

#
# Verify component attribute with an expected value for a given file
# and component ID.
#
verify_comp_attr() {
	local attr=$1
	local tf=$2
	local comp_id=$3
	local expected=$4
	local cmd="$LFS getstripe -I$comp_id"
	local getstripe_cmd="$cmd -v"
	local value

	case $attr in
		stripe-size) cmd+=" -S $tf" ;;
		stripe-count) cmd+=" -c $tf" ;;
		stripe-index) cmd+=" -i $tf" ;;
		pool) cmd+=" -p $tf" ;;
		comp-start) cmd+=" --component-start $tf" ;;
		comp-end) cmd+=" --component-end $tf" ;;
		lcme_flags) cmd+=" $tf | awk '/lcme_flags:/ { print \$2 }'" ;;
		*) error "invalid attribute $attr";;
	esac

	value=$(eval $cmd)

	[ $attr = lcme_flags ] && {
		local fl
		local expected_list=$(comma_list $expected)
		for fl in ${expected_list//,/ }; do
			local neg=0

			[[ ${fl:0:1} = "^" ]] && neg=1
			[[ $neg = 1 ]] && fl=${fl:1}

			$(echo $value | grep -q $fl)
			local match=$?
			# 0: matched; 1: not matched

			if  [[ $neg = 0 && $match != 0 ||
			       $neg = 1 && $match = 0 ]]; then
				$getstripe_cmd $tf
				[[ $neg = 0 ]] && # expect the flag
				    error "expected flag '$fl' not in $comp_id"
				[[ $neg = 1 ]] && # not expect the flag
				    error "not expected flag '$fl' in $comp_id"
			fi
		done
		return
	}

	[[ $value = $expected ]] || {
		$getstripe_cmd $tf
		error "verify $attr failed on $tf: $value != $expected"
	}
}

#
# Verify component extent with expected start and end extent values
# for a given file and component ID.
#
verify_comp_extent() {
	local tf=$1
	local comp_id=$2
	local expected_start=$3
	local expected_end=$4

	verify_comp_attr comp-start $tf $comp_id $expected_start
	verify_comp_attr comp-end $tf $comp_id $expected_end
}

#
# Verify component attribute with parent directory for a given file
# and component ID.
#
verify_comp_attr_with_parent() {
	local attr=$1
	local tf=$2
	local comp_id=$3
	local td=$(cd $(dirname $tf); echo $PWD)
	local tf_cmd="$LFS getstripe -I$comp_id"
	local td_cmd="$LFS getstripe"
	local opt
	local expected
	local value

	case $attr in
		stripe-size) opt="-S" ;;
		stripe-count) opt="-c" ;;
		pool) opt="-p" ;;
		*) error "invalid attribute $attr";;
	esac

	expected=$($td_cmd $opt $td)
	[[ $expected = -1 ]] && expected=$OSTCOUNT

	value=$($tf_cmd $opt $tf)
	[[ $value = -1 ]] && value=$OSTCOUNT

	[[ $value = $expected ]] || {
		$td_cmd -d $td
		$tf_cmd -v $tf
		error "verify $attr failed with parent on $tf:" \
		      "$value != $expected"
	}
}

#
# Verify component attribute with filesystem-wide default value for a given file
# and component ID.
#
verify_comp_attr_with_default() {
	local attr=$1
	local tf=$2
	local comp_id=$3
	local tf_cmd="$LFS getstripe -I$comp_id"
	local opt
	local expected
	local value

	case $attr in
		stripe-size)
			opt="-S"
			expected=$($LCTL get_param -n \
				   lov.$FSNAME-clilov-*.stripesize)
			;;
		stripe-count)
			opt="-c"
			expected=$($LCTL get_param -n \
				   lov.$FSNAME-clilov-*.stripecount)
			[[ $expected = -1 ]] && expected=$OSTCOUNT
			;;
		*) error "invalid attribute $attr";;
	esac

	value=$($tf_cmd $opt $tf)
	[[ $value = -1 ]] && value=$OSTCOUNT

	[[ $value = $expected ]] || {
		$tf_cmd -v $tf
		error "verify $attr failed with default value on $tf:" \
		      "$value != $expected"
	}
}

#
# Verify unspecified component attributes for a given file
# and component ID.
#
# This will only verify the inherited attributes:
# stripe size, stripe count and OST pool name
#
verify_comp_attrs() {
	local tf=$1
	local comp_id=$2

	verify_comp_attr_with_default stripe-size $tf $comp_id
	verify_comp_attr_with_default stripe-count $tf $comp_id
	verify_comp_attr_with_parent pool $tf $comp_id
}

# command line test cases
test_0a() {
	local td=$DIR/$tdir
	local tf=$td/$tfile
	local mirror_count=16 # LUSTRE_MIRROR_COUNT_MAX
	local mirror_cmd="$LFS mirror create"
	local id
	local ids
	local i

	# create parent directory
	mkdir $td || error "mkdir $td failed"

	$mirror_cmd $tf &> /dev/null && error "miss -N option"

	$mirror_cmd -N $tf || error "create mirrored file $tf failed"
	verify_mirror_count $tf 1
	id=$($LFS getstripe -I $tf)
	verify_comp_attrs $tf $id
	verify_comp_extent $tf $id 0 EOF

	$mirror_cmd -N0 $tf-1 &> /dev/null && error "invalid mirror count 0"
	$mirror_cmd -N$((mirror_count + 1)) $tf-1 &> /dev/null &&
		error "invalid mirror count $((mirror_count + 1))"

	$mirror_cmd -N$mirror_count $tf-1 ||
		error "create mirrored file $tf-1 failed"
	verify_mirror_count $tf-1 $mirror_count
	ids=($($LFS getstripe $tf-1 | awk '/lcme_id/{print $2}' | tr '\n' ' '))
	for ((i = 0; i < $mirror_count; i++)); do
		verify_comp_attrs $tf-1 ${ids[$i]}
		verify_comp_extent $tf-1 ${ids[$i]} 0 EOF
	done

	$mirror_cmd -N -N2 -N3 -N4 $tf-2 ||
		error "create mirrored file $tf-2 failed"
	verify_mirror_count $tf-2 10
	ids=($($LFS getstripe $tf-2 | awk '/lcme_id/{print $2}' | tr '\n' ' '))
	for ((i = 0; i < 10; i++)); do
		verify_comp_attrs $tf-2 ${ids[$i]}
		verify_comp_extent $tf-2 ${ids[$i]} 0 EOF
	done
}
run_test 0a "lfs mirror create with -N option"

test_0b() {
	[[ $OSTCOUNT -lt 4 ]] && skip "need >= 4 OSTs" && return

	local td=$DIR/$tdir
	local tf=$td/$tfile
	local mirror_cmd="$LFS mirror create"
	local ids
	local i

	# create a new OST pool
	local pool_name=$TESTNAME
	create_pool $FSNAME.$pool_name ||
		error "create OST pool $pool_name failed"

	# add OSTs into the pool
	pool_add_targets $pool_name 0 $((OSTCOUNT - 1)) ||
		error "add OSTs into pool $pool_name failed"

	# create parent directory
	mkdir $td || error "mkdir $td failed"
	$LFS setstripe -S 8M -c -1 -p $pool_name $td ||
		error "$LFS setstripe $td failed"

	# create a mirrored file with plain layout mirrors
	$mirror_cmd -N -N -S 4M -c 2 -p flash -i 2 -o 2,3 \
		    -N -S 16M -N -c -1 -N -p archive -N -p none $tf ||
		error "create mirrored file $tf failed"
	verify_mirror_count $tf 6
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))
	for ((i = 0; i < 6; i++)); do
		verify_comp_extent $tf ${ids[$i]} 0 EOF
	done

	# verify component ${ids[0]}
	verify_comp_attrs $tf ${ids[0]}

	# verify component ${ids[1]}
	verify_comp_attr stripe-size $tf ${ids[1]} 4194304
	verify_comp_attr stripe-count $tf ${ids[1]} 2
	verify_comp_attr stripe-index $tf ${ids[1]} 2
	verify_comp_attr pool $tf ${ids[1]} flash

	# verify component ${ids[2]}
	verify_comp_attr stripe-size $tf ${ids[2]} 16777216
	verify_comp_attr stripe-count $tf ${ids[2]} 2
	verify_comp_attr pool $tf ${ids[2]} flash

	# verify component ${ids[3]}
	verify_comp_attr stripe-size $tf ${ids[3]} 16777216
	verify_comp_attr stripe-count $tf ${ids[3]} $OSTCOUNT
	verify_comp_attr pool $tf ${ids[3]} flash

	# verify component ${ids[4]}
	verify_comp_attr stripe-size $tf ${ids[4]} 16777216
	verify_comp_attr stripe-count $tf ${ids[4]} $OSTCOUNT
	verify_comp_attr pool $tf ${ids[4]} archive

	# verify component ${ids[5]}
	verify_comp_attr stripe-size $tf ${ids[5]} 16777216
	verify_comp_attr stripe-count $tf ${ids[5]} $OSTCOUNT
	verify_comp_attr_with_parent pool $tf ${ids[5]}

	# destroy OST pool
	destroy_test_pools
}
run_test 0b "lfs mirror create plain layout mirrors"

test_0c() {
	[[ $OSTCOUNT -lt 4 ]] && skip "need >= 4 OSTs" && return

	local td=$DIR/$tdir
	local tf=$td/$tfile
	local mirror_cmd="$LFS mirror create"
	local ids
	local i

	# create a new OST pool
	local pool_name=$TESTNAME
	create_pool $FSNAME.$pool_name ||
		error "create OST pool $pool_name failed"

	# add OSTs into the pool
	pool_add_targets $pool_name 0 $((OSTCOUNT - 1)) ||
		error "add OSTs into pool $pool_name failed"

	# create parent directory
	mkdir $td || error "mkdir $td failed"
	$LFS setstripe -E 32M -S 8M -c -1 -p $pool_name -E eof -S 16M $td ||
		error "$LFS setstripe $td failed"

	# create a mirrored file with composite layout mirrors
	$mirror_cmd -N2 -E 4M -c 2 -p flash -i 1 -o 1,3 -E eof -S 4M \
		    -N -c 4 -p none \
		    -N3 -E 512M -S 16M -p archive -E -1 -i -1 -c -1 $tf ||
		error "create mirrored file $tf failed"
	verify_mirror_count $tf 6
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# verify components ${ids[0]} and ${ids[2]}
	for i in 0 2; do
		verify_comp_attr_with_default stripe-size $tf ${ids[$i]}
		verify_comp_attr stripe-count $tf ${ids[$i]} 2
		verify_comp_attr stripe-index $tf ${ids[$i]} 1
		verify_comp_attr pool $tf ${ids[$i]} flash
		verify_comp_extent $tf ${ids[$i]} 0 4194304
	done

	# verify components ${ids[1]} and ${ids[3]}
	for i in 1 3; do
		verify_comp_attr stripe-size $tf ${ids[$i]} 4194304
		verify_comp_attr stripe-count $tf ${ids[$i]} 2
		verify_comp_attr pool $tf ${ids[$i]} flash
		verify_comp_extent $tf ${ids[$i]} 4194304 EOF
	done

	# verify component ${ids[4]}
	verify_comp_attr stripe-size $tf ${ids[4]} 4194304
	verify_comp_attr stripe-count $tf ${ids[4]} 4
	verify_comp_attr_with_parent pool $tf ${ids[4]}
	verify_comp_extent $tf ${ids[4]} 0 EOF

	# verify components ${ids[5]}, ${ids[7]} and ${ids[9]}
	for i in 5 7 9; do
		verify_comp_attr stripe-size $tf ${ids[$i]} 16777216
		verify_comp_attr stripe-count $tf ${ids[$i]} 4
		verify_comp_attr pool $tf ${ids[$i]} archive
		verify_comp_extent $tf ${ids[$i]} 0 536870912
	done

	# verify components ${ids[6]}, ${ids[8]} and ${ids[10]}
	for i in 6 8 10; do
		verify_comp_attr stripe-size $tf ${ids[$i]} 16777216
		verify_comp_attr stripe-count $tf ${ids[$i]} -1
		verify_comp_attr pool $tf ${ids[$i]} archive
		verify_comp_extent $tf ${ids[$i]} 536870912 EOF
	done

	# destroy OST pool
	destroy_test_pools
}
run_test 0c "lfs mirror create composite layout mirrors"

test_0d() {
	local td=$DIR/$tdir
	local tf=$td/$tfile
	local mirror_count=16 # LUSTRE_MIRROR_COUNT_MAX
	local mirror_cmd="$LFS mirror extend"
	local ids
	local i

	# create parent directory
	mkdir $td || error "mkdir $td failed"

	$mirror_cmd $tf &> /dev/null && error "miss -N option"
	$mirror_cmd -N $tf &> /dev/null && error "$tf does not exist"

	# create a non-mirrored file, convert it to a mirrored file and extend
	touch $tf || error "touch $tf failed"
	$mirror_cmd -N $tf || error "convert and extend $tf failed"
	verify_mirror_count $tf 2
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))
	for ((i = 0; i < 2; i++)); do
		verify_comp_attrs $tf ${ids[$i]}
		verify_comp_extent $tf ${ids[$i]} 0 EOF
	done

	lfsck_verify_pfid $tf || error "PFID is not set"

	# create a mirrored file and extend it
	$LFS mirror create -N $tf-1 || error "create mirrored file $tf-1 failed"
	$LFS mirror create -N $tf-2 || error "create mirrored file $tf-2 failed"

	$mirror_cmd -N -S 4M -N -f $tf-2 $tf-1 &> /dev/null &&
		error "setstripe options should not be specified with -f option"

	$mirror_cmd -N$((mirror_count - 1)) $tf-1 ||
		error "extend mirrored file $tf-1 failed"
	verify_mirror_count $tf-1 $mirror_count
	ids=($($LFS getstripe $tf-1 | awk '/lcme_id/{print $2}' | tr '\n' ' '))
	for ((i = 0; i < $mirror_count; i++)); do
		verify_comp_attrs $tf-1 ${ids[$i]}
		verify_comp_extent $tf-1 ${ids[$i]} 0 EOF
	done

	$mirror_cmd -N $tf-1 &> /dev/null &&
		error "exceeded maximum mirror count $mirror_count" || true
}
run_test 0d "lfs mirror extend with -N option"

test_0e() {
	[[ $OSTCOUNT -lt 4 ]] && skip "need >= 4 OSTs" && return

	local td=$DIR/$tdir
	local tf=$td/$tfile
	local mirror_cmd="$LFS mirror extend"
	local ids
	local i

	# create parent directory
	mkdir $td || error "mkdir $td failed"

	# create a mirrored file with plain layout mirrors
	$LFS mirror create -N -S 32M -c 3 -p ssd -i 1 -o 1,2,3 $tf ||
		error "create mirrored file $tf failed"

	# extend the mirrored file with plain layout mirrors
	$mirror_cmd -N -S 4M -c 2 -p flash -i 2 -o 2,3 \
		    -N -S 16M -N -c -1 -N -p archive -N -p none $tf ||
		error "extend mirrored file $tf failed"
	verify_mirror_count $tf 6
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))
	for ((i = 0; i < 6; i++)); do
		verify_comp_extent $tf ${ids[$i]} 0 EOF
	done

	# verify component ${ids[0]}
	verify_comp_attr stripe-size $tf ${ids[0]} 33554432
	verify_comp_attr stripe-count $tf ${ids[0]} 3
	verify_comp_attr stripe-index $tf ${ids[0]} 1
	verify_comp_attr pool $tf ${ids[0]} ssd

	# verify component ${ids[1]}
	verify_comp_attr stripe-size $tf ${ids[1]} 4194304
	verify_comp_attr stripe-count $tf ${ids[1]} 2
	verify_comp_attr stripe-index $tf ${ids[1]} 2
	verify_comp_attr pool $tf ${ids[1]} flash

	# verify component ${ids[2]}
	verify_comp_attr stripe-size $tf ${ids[2]} 16777216
	verify_comp_attr stripe-count $tf ${ids[2]} 2
	verify_comp_attr pool $tf ${ids[2]} flash

	# verify component ${ids[3]}
	verify_comp_attr stripe-size $tf ${ids[3]} 16777216
	verify_comp_attr stripe-count $tf ${ids[3]} $OSTCOUNT
	verify_comp_attr pool $tf ${ids[3]} flash

	# verify component ${ids[4]}
	verify_comp_attr stripe-size $tf ${ids[4]} 16777216
	verify_comp_attr stripe-count $tf ${ids[4]} $OSTCOUNT
	verify_comp_attr pool $tf ${ids[4]} archive

	# verify component ${ids[5]}
	verify_comp_attr stripe-size $tf ${ids[5]} 16777216
	verify_comp_attr stripe-count $tf ${ids[5]} $OSTCOUNT
	verify_comp_attr_with_parent pool $tf ${ids[5]}
}
run_test 0e "lfs mirror extend plain layout mirrors"

test_0f() {
	[[ $OSTCOUNT -lt 4 ]] && skip "need >= 4 OSTs" && return

	local td=$DIR/$tdir
	local tf=$td/$tfile
	local mirror_cmd="$LFS mirror extend"
	local ids
	local i

	# create parent directory
	mkdir $td || error "mkdir $td failed"

	# create a mirrored file with composite layout mirror
	$LFS mirror create -N -E 32M -S 16M -p ssd -E eof -S 32M $tf ||
		error "create mirrored file $tf failed"

	# extend the mirrored file with composite layout mirrors
	$mirror_cmd -N2 -E 4M -c 2 -p flash -i 1 -o 1,3 -E eof -S 4M \
		    -N -c -1 -p none \
		    -N3 -E 512M -S 16M -p archive -E -1 -i -1 -c -1 $tf ||
		error "extend mirrored file $tf failed"
	verify_mirror_count $tf 7
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# verify component ${ids[0]}
	verify_comp_attr stripe-size $tf ${ids[0]} 16777216
	verify_comp_attr_with_default stripe-count $tf ${ids[0]}
	verify_comp_attr pool $tf ${ids[0]} ssd
	verify_comp_extent $tf ${ids[0]} 0 33554432

	# verify component ${ids[1]}
	verify_comp_attr stripe-size $tf ${ids[1]} 33554432
	verify_comp_attr_with_default stripe-count $tf ${ids[1]}
	verify_comp_attr pool $tf ${ids[1]} ssd
	verify_comp_extent $tf ${ids[1]} 33554432 EOF

	# verify components ${ids[2]} and ${ids[4]}
	for i in 2 4; do
		verify_comp_attr_with_default stripe-size $tf ${ids[$i]}
		verify_comp_attr stripe-count $tf ${ids[$i]} 2
		verify_comp_attr stripe-index $tf ${ids[$i]} 1
		verify_comp_attr pool $tf ${ids[$i]} flash
		verify_comp_extent $tf ${ids[$i]} 0 4194304
	done

	# verify components ${ids[3]} and ${ids[5]}
	for i in 3 5; do
		verify_comp_attr stripe-size $tf ${ids[$i]} 4194304
		verify_comp_attr stripe-count $tf ${ids[$i]} 2
		verify_comp_attr pool $tf ${ids[$i]} flash
		verify_comp_extent $tf ${ids[$i]} 4194304 EOF
	done

	# verify component ${ids[6]}
	verify_comp_attr stripe-size $tf ${ids[6]} 4194304
	verify_comp_attr stripe-count $tf ${ids[6]} $OSTCOUNT
	verify_comp_attr_with_parent pool $tf ${ids[6]}
	verify_comp_extent $tf ${ids[6]} 0 EOF

	# verify components ${ids[7]}, ${ids[9]} and ${ids[11]}
	for i in 7 9 11; do
		verify_comp_attr stripe-size $tf ${ids[$i]} 16777216
		verify_comp_attr stripe-count $tf ${ids[$i]} $OSTCOUNT
		verify_comp_attr pool $tf ${ids[$i]} archive
		verify_comp_extent $tf ${ids[$i]} 0 536870912
	done

	# verify components ${ids[8]}, ${ids[10]} and ${ids[12]}
	for i in 8 10 12; do
		verify_comp_attr stripe-size $tf ${ids[$i]} 16777216
		verify_comp_attr stripe-count $tf ${ids[$i]} -1
		verify_comp_attr pool $tf ${ids[$i]} archive
		verify_comp_extent $tf ${ids[$i]} 536870912 EOF
	done
}
run_test 0f "lfs mirror extend composite layout mirrors"

test_0g() {
	local tf=$DIR/$tfile

	$LFS mirror create -N -E 1M -S 1M -o0 --flags=prefer -E eof -o1 \
			   -N -o1 $tf || error "create mirrored file $tf failed"

	verify_comp_attr lcme_flags $tf 0x10001 prefer
	verify_comp_attr lcme_flags $tf 0x10002 prefer

	# write to the mirrored file and check primary
	cp /etc/hosts $tf || error "error writing file '$tf'"

	verify_comp_attr lcme_flags $tf 0x20003 stale

	# resync file and check prefer flag
	$LFS mirror resync $tf || error "error resync-ing file '$tf'"

	cancel_lru_locks osc
	$LCTL set_param osc.*.stats=clear
	cat $tf &> /dev/null || error "error reading file '$tf'"

	# verify that the data was provided by OST1 where mirror 1 resides
	local nr_read=$($LCTL get_param -n osc.$FSNAME-OST0000-osc-ffff*.stats |
			awk '/ost_read/{print $2}')
	[ -n "$nr_read" ] || error "read was not provided by OST1"
}
run_test 0g "lfs mirror create flags support"

test_0h() {
	local td=$DIR/$tdir
	local tf=$td/$tfile
	local ids
	local i

	# create parent directory
	test_mkdir $td || error "mkdir $td failed"

	$LFS setstripe -N -E 1M -S 1M --flags=prefer -E eof -N2 $td ||
		error "set default mirrored layout on directory $td failed"

	# verify flags are inherited from the directory
	touch $tf

	verify_comp_attr lcme_flags $tf 0x10001 prefer
	verify_comp_attr lcme_flags $tf 0x10002 prefer

	# set flags to the first component
	$LFS setstripe --comp-set -I 0x10001 --comp-flags=^prefer,stale $tf

	verify_comp_attr lcme_flags $tf 0x10001 stale
	verify_comp_attr lcme_flags $tf 0x10002 prefer

	$LFS setstripe --comp-set -I0x10001 --comp-flags=^stale $tf &&
		error "clearing 'stale' should fail"

	# write and resync file. It can't resync the file directly because the
	# file state is still 'ro'
	cp /etc/hosts $tf || error "error writing file '$tf'"
	$LFS mirror resync $tf || error "error resync-ing file '$tf'"

	$LFS setstripe --comp-set -I 0x20003 --comp-flags=prefer $tf ||
		error "error setting flag prefer"

	verify_comp_attr lcme_flags $tf 0x20003 prefer
}
run_test 0h "set, clear and test flags for FLR files"

test_1() {
	local tf=$DIR/$tfile
	local mirror_count=16 # LUSTRE_MIRROR_COUNT_MAX
	local mirror_create_cmd="$LFS mirror create"
	local stripes[0]=$OSTCOUNT

	mirror_create_cmd+=" -N -c ${stripes[0]}"
	for ((i = 1; i < $mirror_count; i++)); do
		# add mirrors with different stripes to the file
		stripes[$i]=$((RANDOM % OSTCOUNT))
		[ ${stripes[$i]} -eq 0 ] && stripes[$i]=1

		mirror_create_cmd+=" -N -c ${stripes[$i]}"
	done

	$mirror_create_cmd $tf || error "create mirrored file $tf failed"
	verify_mirror_count $tf $mirror_count

	# can't create mirrors exceeding LUSTRE_MIRROR_COUNT_MAX
	$LFS mirror extend -N $tf &&
		error "Creating the $((mirror_count+1))th mirror succeeded"

	local ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' |
			tr '\n' ' '))

	# verify the range of components and stripe counts
	for ((i = 0; i < $mirror_count; i++)); do
		verify_comp_attr stripe-count $tf ${ids[$i]} ${stripes[$i]}
		verify_comp_extent $tf ${ids[$i]} 0 EOF
	done
}
run_test 1 "create components with setstripe options"

test_2() {
	local tf=$DIR/$tfile
	local tf2=$DIR/$tfile-2

	$LFS setstripe -E 1M -S 1M -E EOF -c 1 $tf
	$LFS setstripe -E 2M -S 1M -E EOF -c -1 $tf2

	$LFS mirror extend -N -f $tf2 $tf ||
		error "merging $tf2 into $tf failed"

	verify_mirror_count $tf 2
	[[ ! -e $tf2 ]] || error "$tf2 was not unlinked"
}
run_test 2 "create components from existing files"

test_3() {
	[[ $MDSCOUNT -lt 2 ]] && skip "need >= 2 MDTs" && return

	for ((i = 0; i < 2; i++)); do
		$LFS mkdir -i $i $DIR/$tdir-$i
		$LFS setstripe -E -1 $DIR/$tdir-$i/$tfile
	done

	$LFS mirror extend -N -f $DIR/$tdir-1/$tfile \
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

test_4() {
	local tf=$DIR/$tdir/$tfile
	local ids=()

	test_mkdir $DIR/$tdir

	# set mirror with setstripe options to directory
	$LFS mirror create -N2 -E 1M -S 1M -E eof $DIR/$tdir ||
		error "set mirror to directory error"

	[ x$($LFS getstripe -v $DIR/$tdir | awk '/lcm_flags/{print $2}') = \
		x"mirrored" ] || error "failed to create mirrored dir"

	touch $tf
	verify_mirror_count $tf 2

	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))
	verify_comp_extent $tf ${ids[0]} 0 1048576
	verify_comp_extent $tf ${ids[1]} 1048576 EOF

	# sub directory should inherit mirror setting from parent
	test_mkdir $DIR/$tdir/td
	[ x$($LFS getstripe -v $DIR/$tdir/td | awk '/lcm_flags/{print $2}') = \
		x"mirrored" ] || error "failed to inherit mirror from parent"

	# mirror extend won't be applied to directory
	$LFS mirror extend -N2 $DIR/$tdir &&
		error "expecting mirror extend failure"
	true
}
run_test 4 "Make sure mirror attributes can be inhertied from directory"

test_5() {
	local tf=$DIR/$tfile
	local ids=()

	$MULTIOP $tf oO_RDWR:O_CREAT:O_LOV_DELAY_CREATE:T12345c ||
		error "failed to create file with non-empty layout"
	$CHECKSTAT -t file -s 12345 $tf || error "size error: expecting 12345"

	$LFS mirror create -N3 $tf || error "failed to attach mirror layout"
	verify_mirror_count $tf 3

	$CHECKSTAT -t file -s 12345 $tf ||
		error "size error after attaching layout "
}
run_test 5 "Make sure init size work for mirrored layout"

# LU=10112: disable dom+flr for phase 1
test_6() {
	local tf=$DIR/$tfile

	$LFS mirror create -N -E 1M -S 1M -L mdt -E eof -N -E eof $tf &&
		error "expect failure to create mirrored file with DoM"

	$LFS mirror create -N -E 1M -S 1M -E eof -N -E 1M -L mdt -E eof $tf &&
		error "expect failure to create mirrored file with DoM"

	$LFS setstripe -E 1M -S 1M -L mdt -E eof $tf
	$LFS mirror extend -N2 $tf &&
		error "expect failure to extend mirror with DoM"

	$LFS mirror create -N2 -E 1M -S 1M -E eof $tf-2
	$LFS mirror extend -N -f $tf $tf-2 &&
		error "expect failure to extend mirrored file with DoM extent"

	true
}
run_test 6 "DoM and FLR won't co-exist for phase 1"

test_21() {
	local tf=$DIR/$tfile
	local tf2=$DIR/$tfile-2

	[[ $OSTCOUNT -lt 2 ]] && skip "need >= 2 OSTs" && return

	$LFS setstripe -E EOF -o 0 $tf
	$LFS setstripe -E EOF -o 1 $tf2

	local dd_count=$((RANDOM % 20 + 1))
	dd if=/dev/zero of=$tf bs=1M count=$dd_count oflag=sync
	dd if=/dev/zero of=$tf2 bs=1M count=1 seek=$((dd_count - 1)) oflag=sync

	# for zfs - sync OST dataset so that du below will return
	# accurate results
	[ "$FSTYPE" = "zfs" ] &&
		do_nodes $(comma_list $(osts_nodes)) "$ZPOOL sync"

	local blocks=$(du -kc $tf $tf2 | awk '/total/{print $1}')

	# add component
	$LFS mirror extend -N -f $tf2 $tf ||
		error "merging $tf2 into $tf failed"

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
	$LFS mirror extend -N -o 0 $tf ||
		error "extending mirrored file $tf failed"

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

	$LFS mirror create -N -o 0 -N -o 1 $tf ||
		error "creating mirrored file $tf failed"

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
	$LFS mirror extend -N -o 1 $DIR/$tfile ||
		error "extending mirrored file $DIR/$tfile failed"

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
	$LFS mirror extend -N -f $DIR/$tfile-2 $DIR/$tfile &&
		error "merging $DIR/$tfile-2 into $DIR/$tfile" \
		      "with verification should fail"
	$LFS mirror extend --no-verify -N -f $DIR/$tfile-2 $DIR/$tfile ||
		error "merging $DIR/$tfile-2 into $DIR/$tfile" \
		      "without verification failed"

	# make sure that $tfile has two mirrors and $tfile-2 does not exist
	[ $(get_mirror_ids $DIR/$tfile) -eq 2 ] ||
		{ $LFS getstripe $DIR/$tfile; error "expected count 2"; }

	[[ ! -e $DIR/$tfile-2 ]] || error "$DIR/$tfile-2 was not unlinked"

	# execpted file size
	local fsize=$((5 * max_count))
	$CHECKSTAT -t file -s $fsize $DIR/$tfile ||
		error "mirrored file size is not $fsize"

	# read file - all OSTs are available
	echo "reading file (data can be provided by any ost)... "
	local rs=$(cat $DIR/$tfile | head -1)
	[[ "$rs" == "ost1" || "$rs" == "ost2" ]] ||
		error "file content error: expected: \"ost1\" or \"ost2\""

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
	$LFS mirror extend -N -f $DIR/$tfile-2 $DIR/$tfile ||
		error "merging $DIR/$tfile-2 into $DIR/$tfile failed"

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
	$LFS mirror extend -N -f $DIR/$tfile-2 $DIR/$tfile ||
		error "merging $DIR/$tfile-2 into $DIR/$tfile failed"

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
	$LFS mirror extend -N -c 2 $tf ||
		error "extending mirrored file $tf failed"

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
		$LFS setstripe -E 1M -S 1M -E 2M -E 4M -E eof -c -1 $tf
		$LFS setstripe -E 3M -S 1M -E 6M -E eof -c -1 $tf-tmp

		$LFS mirror extend -N -f $tf-tmp $tf ||
			error "merging $tf-tmp into $tf failed"
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
	local mds_idx=mds$(($($LFS getstripe -m $tf-2) + 1))

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
	mds_idx=mds$(($($LFS getstripe -m $tf-3) + 1))

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
		$LFS setstripe -E 1M -S 1M -c 1 -E eof -c -1 $tf

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
	checksums[1]=$(cat $tf | md5sum)
	checksums[2]=$(cat $tf2 | md5sum)
	checksums[3]=$(cat $tf3 | md5sum)

	printf '%s\n' "${checksums[@]}"

	# merge these files into a mirrored file
	$LFS mirror extend --no-verify -N -f $tf2 $tf ||
		error "merging $tf2 into $tf failed"
	$LFS mirror extend --no-verify -N -f $tf3 $tf ||
		error "merging $tf3 into $tf failed"

	get_mirror_ids $tf

	# verify mirror read, checksums should equal to the original files'
	echo "Verifying mirror read .."

	local sum
	for i in ${mirror_array[@]}; do
		sum=$($LFS mirror dump -N $i $tf | md5sum)
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
		sum=$($LFS mirror dump -N $i $tf | md5sum)
		[ "$sum" = "${checksums[1]}" ] ||
			error "$i: mismatch checksum after copy"
	done

	rm -f $tf
}
run_test 37 "mirror I/O API verification"

verify_flr_state()
{
	local tf=$1
	local expected_state=$2

	local state=$($LFS getstripe -v $tf | awk '/lcm_flags/{ print $2 }')
	[ $expected_state = $state ] ||
		error "expected: $expected_state, actual $state"
}

test_38() {
	local tf=$DIR/$tfile
	local ref=$DIR/${tfile}-ref

	$LFS setstripe -E 1M -S 1M -c 1 -E 4M -c 2 -E eof -c -1 $tf ||
		error "creating $tf failed"
	$LFS setstripe -E 2M -S 1M -c 1 -E 6M -c 2 -E 8M -c -1 -E eof -c -1 \
		$tf-2 || error "creating $tf-2 failed"
	$LFS setstripe -E 4M -c 1 -E 8M -c 2 -E eof -c -1 $tf-3 ||
		error "creating $tf-3 failed"

	# instantiate all components
	$LFS mirror extend -N -f $tf-2 $tf ||
		error "merging $tf-2 into $tf failed"
	$LFS mirror extend -N -f $tf-3 $tf ||
		error "merging $tf-3 into $tf failed"
	$LFS mirror extend -N -c 1 $tf ||
		error "extending mirrored file $tf failed"

	verify_flr_state $tf "ro"

	dd if=/dev/urandom of=$ref  bs=1M count=16 &> /dev/null

	local fsize=$((RANDOM << 8 + 1048576))
	$TRUNCATE $ref $fsize

	local ref_cksum=$(cat $ref | md5sum)

	# case 1: verify write to mirrored file & resync work
	cp $ref $tf || error "copy from $ref to $f error"
	verify_flr_state $tf "wp"

	local file_cksum=$(cat $tf | md5sum)
	[ "$file_cksum" = "$ref_cksum" ] || error "write failed, cksum mismatch"

	get_mirror_ids $tf
	echo "mirror IDs: ${mirror_array[@]}"

	local valid_mirror stale_mirror id mirror_cksum
	for id in "${mirror_array[@]}"; do
		mirror_cksum=$($LFS mirror dump -N $id $tf | md5sum)
		[ "$ref_cksum" == "$mirror_cksum" ] &&
			{ valid_mirror=$id; continue; }

		stale_mirror=$id
	done

	[ -z "$stale_mirror" ] && error "stale mirror doesn't exist"
	[ -z "$valid_mirror" ] && error "valid mirror doesn't exist"

	mirror_io resync $tf || error "resync failed"
	verify_flr_state $tf "ro"

	mirror_cksum=$($LFS mirror dump -N $stale_mirror $tf | md5sum)
	[ "$file_cksum" = "$ref_cksum" ] || error "resync failed"

	# case 2: inject an error to make mirror_io exit after changing
	# the file state to sync_pending so that we can start a concurrent
	# write.
	$MULTIOP $tf oO_WRONLY:w$((RANDOM % 1048576 + 1024))c
	verify_flr_state $tf "wp"

	mirror_io resync -e resync_start $tf && error "resync succeeded"
	verify_flr_state $tf "sp"

	# from sync_pending to write_pending
	$MULTIOP $tf oO_WRONLY:w$((RANDOM % 1048576 + 1024))c
	verify_flr_state $tf "wp"

	mirror_io resync -e resync_start $tf && error "resync succeeded"
	verify_flr_state $tf "sp"

	# from sync_pending to read_only
	mirror_io resync $tf || error "resync failed"
	verify_flr_state $tf "ro"
}
run_test 38 "resync"

test_39() {
	local tf=$DIR/$tfile

	rm -f $tf
	$LFS mirror create -N2 -E1m -c1 -S1M -E-1 $tf ||
	error "create PFL file $tf failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 4

	rm -f $tf || error "delete $tf failed"
}
run_test 39 "check FLR+PFL (a.k.a. PFLR) creation"

test_40() {
	local tf=$DIR/$tfile
	local ops

	for ops in "conv=notrunc" ""; do
		rm -f $tf

		$LFS mirror create -N -E 2M -S 1M -E 4M -E -1 --flags=prefer \
				   -N -E 1M -E 2M -E 4M -E -1 $tf ||
			error "create PFLR file $tf failed"
		dd if=/dev/zero of=$tf $ops bs=1M seek=2 count=1 ||
			error "write PFLR file $tf failed"

		lfs getstripe -vy $tf

		local flags

		# file mirror state should be write_pending
		flags=$($LFS getstripe -v $tf | awk '/lcm_flags:/ { print $2 }')
		[ $flags = wp ] ||
		error "file mirror state $flags"
		# the 1st component (in mirror 1) should be inited
		verify_comp_attr lcme_flags $tf 0x10001 init
		# the 2nd component (in mirror 1) should be inited
		verify_comp_attr lcme_flags $tf 0x10002 init
		# the 3rd component (in mirror 1) should be uninited
		verify_comp_attr lcme_flags $tf 0x10003 prefer
		# the 4th component (in mirror 2) should be inited
		verify_comp_attr lcme_flags $tf 0x20004 init
		# the 5th component (in mirror 2) should be uninited
		verify_comp_attr lcme_flags $tf 0x20005 0
		# the 6th component (in mirror 2) should be stale
		verify_comp_attr lcme_flags $tf 0x20006 stale
		# the 7th component (in mirror 2) should be uninited
		if [[ x$ops = "xconv=notrunc" ]]; then
			verify_comp_attr lcme_flags $tf 0x20007 0
		elif [[ x$ops = "x" ]]; then
			verify_comp_attr lcme_flags $tf 0x20007 stale
		fi
	done

	rm -f $tf || error "delete $tf failed"
}
run_test 40 "PFLR rdonly state instantiation check"

test_41() {
	local tf=$DIR/$tfile

	rm -f $tf $tf-1
	echo " **create two FLR files $tf $tf-1"
	$LFS mirror create -N -E 2M -S 1M -E 4M -E -1 \
			   -N -E 1M -E 2M -E 3M -E -1 $tf ||
		error "create PFLR file $tf failed"
	$LFS mirror create -N -E 2M -S 1M -E eof \
			   -N -E 1M -E eof --flags prefer \
			   -N -E 4m -E eof $tf-1 ||
		error "create PFLR file $tf-1 failed"

	# file should be in ro status
	echo " **verify files be RDONLY"
	verify_flr_state $tf "ro"
	verify_flr_state $tf-1 "ro"

	# write data in [0, 2M)
	dd if=/dev/zero of=$tf bs=1M count=2 conv=notrunc ||
		error "writing $tf failed"
	dd if=/dev/urandom of=$tf-1 bs=1M count=4 conv=notrunc ||
		error "writing $tf-1 failed"

	local sum0=$(cat $tf-1 | md5sum)

	echo " **verify files be WRITE_PENDING"
	verify_flr_state $tf "wp"
	verify_flr_state $tf-1 "wp"

	# file should have stale component
	echo " **verify files have stale component"
	$LFS getstripe $tf | grep lcme_flags | grep stale > /dev/null ||
		error "after writing $tf, it does not contain stale component"
	$LFS getstripe $tf-1 | grep lcme_flags | grep stale > /dev/null ||
		error "after writing $tf-1, it does not contain stale component"

	echo " **full resync"
	$LFS mirror resync $tf $tf-1 || error "mirror resync $tf $tf-1 failed"

	echo " **verify $tf-1 data consistency in all mirrors"
	for i in 1 2 3; do
		local sum=$($LFS mirror dump -N$i $tf-1 | md5sum)
		[[ "$sum" = "$sum0" ]] ||
			error "$tf-1.$i: checksum mismatch: $sum != $sum0"
	done

	echo " **verify files be RDONLY"
	verify_flr_state $tf "ro"
	verify_flr_state $tf-1 "ro"

	# file should not have stale component
	echo " **verify files do not contain stale component"
	$LFS getstripe $tf | grep lcme_flags | grep stale &&
		error "after resyncing $tf, it contains stale component"
	$LFS getstripe $tf-1 | grep lcme_flags | grep stale &&
		error "after resyncing $tf, it contains stale component"

	# verify partial resync
	echo " **write $tf-1 for partial resync test"
	dd if=/dev/zero of=$tf-1 bs=1M count=2 conv=notrunc ||
		error "writing $tf-1 failed"

	echo " **only resync mirror 2"
	verify_flr_state $tf-1 "wp"
	$LFS mirror resync --only 2 $tf-1 ||
		error "resync mirror 2 of $tf-1 failed"
	verify_flr_state $tf "ro"

	# resync synced mirror
	echo " **resync mirror 2 again"
	$LFS mirror resync --only 2 $tf-1 ||
		error "resync mirror 2 of $tf-1 failed"
	verify_flr_state $tf "ro"
	echo " **verify $tf-1 contains stale component"
	$LFS getstripe $tf-1 | grep lcme_flags | grep stale > /dev/null ||
		error "after writing $tf-1, it does not contain stale component"

	echo " **full resync $tf-1"
	$LFS mirror resync $tf-1 || error "resync of $tf-1 failed"
	verify_flr_state $tf "ro"
	echo " **full resync $tf-1 again"
	$LFS mirror resync $tf-1 || error "resync of $tf-1 failed"
	echo " **verify $tf-1 does not contain stale component"
	$LFS getstripe $tf | grep lcme_flags | grep stale &&
		error "after resyncing $tf, it contains stale component"

	return 0
}
run_test 41 "lfs mirror resync check"

test_42() {
	[[ $OSTCOUNT -lt 4 ]] && skip "need >= 4 OSTs" && return

	local td=$DIR/$tdir
	local tf=$td/$tfile
	local mirror_cmd="$LFS mirror verify"
	local i

	# create parent directory
	mkdir $td || error "mkdir $td failed"

	$mirror_cmd &> /dev/null && error "no file name given"
	$mirror_cmd $tf &> /dev/null && error "cannot stat file $tf"
	$mirror_cmd $td &> /dev/null && error "$td is not a regular file"

	# create mirrored files
	$LFS mirror create -N -E 4M -S 1M -E 10M -E EOF $tf ||
		error "create mirrored file $tf failed"
	$LFS mirror create -N -E 2M -S 1M -E EOF \
			   -N -E 6M -E 8M -E EOF \
			   -N -E 16M -E EOF $tf-1 ||
		error "create mirrored file $tf-1 failed"
	$LFS mirror create -N -c 2 -o 1,3 -N -S 2M -c -1 $tf-2 ||
		error "create mirrored file $tf-2 failed"

	# write data in [0, 10M)
	for i in $tf $tf-1 $tf-2; do
		yes | dd of=$i bs=1M count=10 iflag=fullblock conv=notrunc ||
			error "write $i failed"
	done

	# resync the mirrored files
	$LFS mirror resync $tf-1 $tf-2 ||
		error "resync $tf-1 $tf-2 failed"

	# verify the mirrored files
	$mirror_cmd $tf-1 $tf-2 ||
		error "verify $tf-1 $tf-2 failed"

	get_mirror_ids $tf-1
	$mirror_cmd --only ${mirror_array[0]} $tf-1 &> /dev/null &&
		error "at least 2 mirror ids needed with '--only' option"
	$mirror_cmd --only ${mirror_array[0]},${mirror_array[1]} $tf-1 $tf-2 \
		&> /dev/null &&
		error "'--only' option cannot be used upon multiple files"
	$mirror_cmd --only 65534,${mirror_array[0]},65535 $tf-1 &&
		error "invalid specified mirror ids"

	# change the content of $tf and merge it into $tf-1
	for i in 6 10; do
		echo a | dd of=$tf bs=1M seek=$i conv=notrunc ||
			error "change $tf with seek=$i failed"
		echo b | dd of=$tf-1 bs=1M seek=$i conv=notrunc ||
			error "change $tf-1 with seek=$i failed"
	done

	$LFS mirror resync $tf-1 || error "resync $tf-1 failed"
	$LFS mirror extend --no-verify -N -f $tf $tf-1 ||
		error "merge $tf into $tf-1 failed"

	# verify the mirrored files
	echo "Verify $tf-1 without -v option:"
	$mirror_cmd $tf-1 &&
		error "verify $tf-1 should fail" || echo "PASS"

	echo "Verify $tf-1 with -v option:"
	$mirror_cmd -v $tf-1 &&
		error "verify $tf-1 should fail"

	get_mirror_ids $tf-1
	echo "Verify $tf-1 with --only option:"
	$mirror_cmd -v --only ${mirror_array[1]},${mirror_array[-1]} $tf-1 &&
		error "verify $tf-1 with mirror ${mirror_array[1]} and" \
		      "${mirror_array[-1]} should fail"

	$mirror_cmd --only ${mirror_array[0]},${mirror_array[1]} $tf-1 ||
		error "verify $tf-1 with mirror ${mirror_array[0]} and" \
		      "${mirror_array[1]} should succeed"

	# set stale components in $tf-1
	for i in 0x40002 0x40003; do
		$LFS setstripe --comp-set -I$i --comp-flags=stale $tf-1 ||
			error "set stale flag on component $i failed"
	done

	# verify the mirrored file
	echo "Verify $tf-1 with stale components:"
	$mirror_cmd -vvv $tf-1 ||
		error "verify $tf-1 with stale components should succeed"

	echo "Verify $tf-1 with stale components and --only option:"
	$mirror_cmd -vvv --only ${mirror_array[1]},${mirror_array[-1]} $tf-1 ||
		error "verify $tf-1 with mirror ${mirror_array[1]} and" \
		      "${mirror_array[-1]} should succeed"
}
run_test 42 "lfs mirror verify"

# inactivate one OST && write && restore the OST
write_file_43() {
	local file=$1
	local ost=$2
	local PARAM="osp.${FSNAME}-OST000${ost}-osc-M*.active"
	local wait

	wait=$(do_facet $SINGLEMDS \
		"$LCTL get_param -n lod.*MDT0000-*.qos_maxage")
	wait=${wait%%[^0-9]*}

	echo "  **deactivate OST$ost, waiting for $((wait*2+2)) seconds"
	$(do_facet $SINGLEMDS "$LCTL set_param -n $PARAM 0")
	# lod_qos_statfs_update needs 2*$wait seconds to refresh targets statfs
	sleep $(($wait * 2 + 2))
	echo "  **write $file"
	dd if=/dev/zero of=$file bs=1M count=1 || error "write $file failed"
	echo "  **restore activating OST$ost, waiting for $((wait*2+2)) seconds"
	$(do_facet $SINGLEMDS "$LCTL set_param -n $PARAM 1")
	sleep $((wait * 2 + 2))

	local flags=$($LFS getstripe -v $file | awk '/lcm_flags:/ { print $2 }')
	[ $flags = wp ] || error "file mirror state $flags != wp"
}

test_43() {
	[ $OSTCOUNT -lt 3 ] && skip "needs >= 3 OSTs" && return

	local tf=$DIR/$tfile
	local flags

	rm -f $tf
	##   mirror 0  ost (0, 1)
	##   mirror 1  ost (1, 2)
	##   mirror 2  ost (2, 0)
	$LFS mirror create -N -Eeof -c2 -o0,1 -N -Eeof -c2 -o1,2 \
		-N -Eeof -c2 -o2,0 $tf ||
		error "create 3 mirrors file $tf failed"

	################## OST0 ###########################################
	write_file_43 $tf 0
	echo "  **verify components"
	verify_comp_attr lcme_flags $tf 0x10001 init,stale
	verify_comp_attr lcme_flags $tf 0x20002 init
	verify_comp_attr lcme_flags $tf 0x30003 init,stale

	# resync
	echo "  **resync $tf"
	$LFS mirror resync $tf
	flags=$($LFS getstripe -v $tf | awk '/lcm_flags:/ { print $2 }')
	[ $flags = ro ] || error "file mirror state $flags != ro"

	################## OST1 ###########################################
	write_file_43 $tf 1
	echo "  **verify components"
	verify_comp_attr lcme_flags $tf 0x10001 init,stale
	verify_comp_attr lcme_flags $tf 0x20002 init,stale
	verify_comp_attr lcme_flags $tf 0x30003 init

	# resync
	echo "  **resync $tf"
	$LFS mirror resync $tf
	flags=$($LFS getstripe -v $tf | awk '/lcm_flags:/ { print $2 }')
	[ $flags = ro ] || error "file mirror state $flags != ro"

	################## OST2 ###########################################
	write_file_43 $tf 2
	echo "  **verify components"
	verify_comp_attr lcme_flags $tf 0x10001 init
	verify_comp_attr lcme_flags $tf 0x20002 init,stale
	verify_comp_attr lcme_flags $tf 0x30003 init,stale
}
run_test 43 "mirror pick on write"

test_44() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	rm -rf $DIR/$tdir
	rm -rf $DIR/$tdir-1
	local tf=$DIR/$tdir/$tfile
	local tf1=$DIR/$tdir-1/$tfile-1

	$LFS setdirstripe -i 0 -c 1 $DIR/$tdir ||
		error "create directory failed"
	$LFS setdirstripe -i 1 -c 1 $DIR/$tdir-1 ||
		error "create remote directory failed"
	rm -f $tf $tf1 $tf.mirror~2
	# create file with 4 mirrors
	$LFS mirror create -N -E 2M -S 1M -E 4M -E -1 \
			   -N -E 1M -E 2M -E 3M -E -1 -N2 $tf ||
		error "create PFLR file $tf failed"

	# file should be in ro status
	verify_flr_state $tf "ro"

	# write data in [0, 3M)
	dd if=/dev/urandom of=$tf bs=1M count=3 conv=notrunc ||
		error "writing $tf failed"

	verify_flr_state $tf "wp"

	# synchronize all mirrors of the file
	$LFS mirror resync $tf || error "mirror resync $tf failed"

	verify_flr_state $tf "ro"

	# split mirror 1
	$LFS mirror split --mirror-id 1 -f $tf1 $tf ||
		error "split to $tf1 failed"

	local idx0=$($LFS getstripe -m $tf)
	local idx1=$($LFS getstripe -m $tf1)

	[[ x$idx0 == x0 ]] || error "$tf is not on MDT0"
	[[ x$idx1 == x1 ]] || error "$tf1 is not on MDT1"

	# verify mirror count
	verify_mirror_count $tf 3
	verify_mirror_count $tf1 1

	$LFS mirror split --mirror-id 2 $tf ||
		error "split mirror 2 failed"

	verify_mirror_count $tf 2
	verify_mirror_count $tf.mirror~2 1

	$LFS mirror split --mirror-id 3 -d $tf ||
		error "split and delte mirror 3 failed"
	verify_mirror_count $tf 1

	# verify splitted file contains the same content as the orig file does
	diff $tf $tf1 || error "splited file $tf1 diffs from $tf"
	diff $tf $tf.mirror~2 ||
		error "splited file $tf.mirror~2 diffs from $tf"
}
run_test 44 "lfs mirror split check"

test_45() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs" && return

	local file=$DIR/$tdir/$tfile
	local dir=$DIR/$tdir/$dir
	local temp=$DIR/$tdir/template
	rm -rf $DIR/$tdir
	test_mkdir $DIR/$tdir

	$LFS setstripe -N -E1m -S1m -c2 -o0,1 -E2m -Eeof -N -E4m -Eeof \
		-N -E3m -S1m -Eeof -N -E8m -Eeof $file ||
			error "Create $file failed"

	echo "getstripe --yaml $file"
	$LFS getstripe --yaml $file > $temp || error "getstripe $file failed"
	echo "setstripe --yaml=$temp $file.2"
	$LFS setstripe --yaml=$temp $file.2 || error "setstripe $file.2 failed"

	echo "compare layout"
	local layout1=$(get_layout_param $file)
	local layout2=$(get_layout_param $file.2)
	[ "$layout1" == "$layout2" ] ||
		error "FLR file $file/$file.2 layouts are not equal"
}
run_test 45 "Verify setstripe/getstripe with YAML with FLR file"

verify_46() {
	local src=$1
	local dst=$2
	local msg_prefix=$3

	$LFS setstripe --copy=$src $dst || error "setstripe $dst failed"

	local layout1=$(get_layout_param $src)
	local layout2=$(get_layout_param $dst)
	# compare their layout info
	[ "$layout1" == "$layout2" ] ||
		error "$msg_prefix $src <=> $dst layouts are not equal"
}

test_46() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs" && return

	local file=$DIR/$tdir/$tfile
	test_mkdir $DIR/$tdir

	########################### 1. PFL file #############################
	echo "  ** 1. PFL file"
	rm -f $file
	$LFS setstripe -E1m -S 1M -c2 -o0,1 -E2m -c2 -E3m -o1,0 -E4m -c1 -E-1 \
		$file || error "1. Create PFL $file failed"

	rm -f $file.copy
	verify_46 $file $file.copy "1. PFL file"

	########################### 2. plain file ###########################
	echo "  ** 2. plain file"
	rm -f $file
	$LFS setstripe -c2 -o0,1 -i1 $file ||
		error "2. Create plain $file failed"

	rm -f $file.copy
	verify_46 $file $file.copy "2. plain file"

	########################### 3. FLR file #############################
	echo "  ** 3. FLR file"
	$LFS setstripe -N -E1m -S 1M -c2 -o0,1 -E4m -c1 -Eeof -N -E16m -Eeof \
		$file || error "3. Create FLR $file failed"

	rm -f $file.copy
	verify_46 $file $file.copy "3. FLR file"

	local dir=$DIR/$tdir/dir
	########################### 4. PFL dir ##############################
	echo "  ** 4. PFL dir"
	test_mkdir $dir
	$LFS setstripe -E1m -S 1M -c2 -E2m -c1 -E-1 $dir ||
		error "4. setstripe PFL $dir failed"

	test_mkdir $dir.copy
	verify_46 $dir $dir.copy "4. PFL dir"

	########################### 5. plain dir ############################
	echo "  ** 5. plain dir"
	$LFS setstripe -c2 -i-1 $dir || error "5. setstripe plain $dir failed"

	verify_46 $dir $dir.copy "5. plain dir"

	########################### 6. FLR dir ##############################
	echo "  ** 6. FLR dir"
	$LFS setstripe -N -E1m -S 1M -c2 -E2m -c1 -Eeof -N -E4m -Eeof $dir ||
		error "6. setstripe FLR $dir failed"

	verify_46 $dir $dir.copy "6. FLR dir"
}
run_test 46 "Verify setstripe --copy option"

test_47() {
	[ $OSTCOUNT -lt 3 ] && skip "needs >= 3 OSTs" && return

	local file=$DIR/$tdir/$tfile
	local ids
	local ost
	local osts

	test_mkdir $DIR/$tdir

	# test case 1:
	rm -f $file
	# mirror1: [comp0]ost0,    [comp1]ost1 and ost2
	# mirror2: [comp2]    ,    [comp3] should not use ost1 or ost2
	$LFS mirror create -N -E2m -c1 -o0 --flags=prefer -Eeof -c2 -o1,2 \
		-N -E2m -c1 -Eeof -c1 $file || error "create FLR $file failed"
	ids=($($LFS getstripe $file | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	dd if=/dev/zero of=$file bs=1M count=3 || error "dd $file failed"
	$LFS mirror resync $file || error "resync $file failed"

	ost=$($LFS getstripe -I${ids[2]} $file | awk '/l_ost_idx/{print $5}')
	if [[ x$ost == "x0," ]]; then
		$LFS getstripe $file
		error "component ${ids[2]} objects allocated on $ost " \
		      "shouldn't on OST0"
	fi

	ost=$($LFS getstripe -I${ids[3]} $file | awk '/l_ost_idx/{print $5}')
	if [[ x$ost == "x1," || x$ost == "x2," ]]; then
		$LFS getstripe $file
		error "component ${ids[3]} objects allocated on $ost " \
		      "shouldn't on OST1 or on OST2"
	fi

	## test case 2:
	rm -f $file
	# mirror1: [comp0]    [comp1]
	# mirror2: [comp2]    [comp3]
	# mirror3: [comp4]    [comp5]
	# mirror4: [comp6]    [comp7]
	$LFS mirror create -N4 -E1m -c1 -Eeof -c1 $file ||
		error "create FLR $file failed"
	ids=($($LFS getstripe $file | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	dd if=/dev/zero of=$file bs=1M count=3 || error "dd $file failed"
	$LFS mirror resync $file || error "resync $file failed"

	for ((i = 0; i < 6; i++)); do
		osts[$i]=$($LFS getstripe -I${ids[$i]} $file |
			awk '/l_ost_idx/{print $5}')
	done
	# comp[0],comp[2],comp[4] should use different osts
	if [[ ${osts[0]} == ${osts[2]} || ${osts[0]} == ${osts[4]} ||
	      ${osts[2]} == ${osts[4]} ]]; then
		$LFS getstripe $file
		error "component ${ids[0]}, ${ids[2]}, ${ids[4]} have objects "\
		      "allocated on duplicated OSTs"
	fi
	# comp[1],comp[3],comp[5] should use different osts
	if [[ ${osts[1]} == ${osts[3]} || ${osts[1]} == ${osts[5]} ||
	      ${osts[3]} == ${osts[5]} ]]; then
		$LFS getstripe $file
		error "component ${ids[1]}, ${ids[3]}, ${ids[5]} have objects "\
		      "allocated on duplicated OSTs"
	fi

	return 0
}
run_test 47 "Verify mirror obj alloc"

test_48() {
	local tf=$DIR/$tfile

	rm -f $tf
	echo " ** create 2 mirrors FLR file $tf"
	$LFS mirror create -N -E2M -Eeof --flags prefer \
			   -N -E1M -Eeof $tf ||
		error "create FLR file $tf failed"

	echo " ** write it"
	dd if=/dev/urandom of=$tf bs=1M count=3 || error "write $tf failed"
	verify_flr_state $tf "wp"

	local sum0=$(md5sum < $tf)

	echo " ** resync the file"
	$LFS mirror resync $tf

	echo " ** snapshot mirror 2"
	$LFS setstripe --comp-set -I 0x20003 --comp-flags=nosync $tf

	echo " ** write it again"
	dd if=/dev/urandom of=$tf bs=1M count=3 || error "write $tf failed"
	echo " ** resync it again"
	$LFS mirror resync $tf

	verify_flr_state $tf "wp"
	verify_comp_attr lcme_flags $tf 0x20003 nosync,stale

	local sum1=$($LFS mirror dump -N1 $tf | md5sum)
	local sum2=$($LFS mirror dump -N2 $tf | md5sum)

	echo " ** verify mirror 2 doesn't change"
	echo "original checksum: $sum0"
	echo "mirror 1 checksum: $sum1"
	echo "mirror 2 checksum: $sum2"
	[[ $sum0 = $sum2 ]] ||
		error "original checksum: $sum0, mirror 2 checksum: $sum2"
	echo " ** mirror 2 stripe info"
	$LFS getstripe -v --mirror-index=2 $tf

	echo " ** resync mirror 2"
	$LFS mirror resync --only 2 $tf

	verify_flr_state $tf "ro"
	verify_comp_attr lcme_flags $tf 0x20003 nosync,^stale

	sum1=$($LFS mirror dump -N1 $tf | md5sum)
	sum2=$($LFS mirror dump -N2 $tf | md5sum)

	echo " ** verify mirror 2 resync-ed"
	echo "original checksum: $sum0"
	echo "mirror 1 checksum: $sum1"
	echo "mirror 2 checksum: $sum2"
	[[ $sum1 = $sum2 ]] ||
		error "mirror 1 checksum: $sum1, mirror 2 checksum: $sum2"
	echo " ** mirror 2 stripe info"
	$LFS getstripe -v --mirror-index=2 $tf
}
run_test 48 "Verify snapshot mirror"

ctrl_file=$(mktemp /tmp/CTRL.XXXXXX)
lock_file=$(mktemp /var/lock/FLR.XXXXXX)

write_file_200() {
	local tf=$1

	local fsize=$(stat --printf=%s $tf)

	while [ -f $ctrl_file ]; do
		local off=$((RANDOM << 8))
		local len=$((RANDOM << 5 + 131072))

		[ $((off + len)) -gt $fsize ] && {
			fsize=$((off + len))
			echo "Extending file size to $fsize .."
		}

		flock -s $lock_file -c \
			"$MULTIOP $tf oO_WRONLY:z${off}w${len}c" ||
				{ rm -f $ctrl_file;
				  error "failed writing to $off:$len"; }
		sleep 0.$((RANDOM % 2 + 1))
	done
}

read_file_200() {
	local tf=$1

	while [ -f $ctrl_file ]; do
		flock -s $lock_file -c "cat $tf &> /dev/null" ||
			{ rm -f $ctrl_file; error "read failed"; }
		sleep 0.$((RANDOM % 2 + 1))
	done
}

resync_file_200() {
	local tf=$1

	options=("" "-e resync_start" "-e delay_before_copy -d 1" "" "")

	exec 200<>$lock_file
	while [ -f $ctrl_file ]; do
		local lock_taken=false
		local index=$((RANDOM % ${#options[@]}))
		local cmd="mirror_io resync ${options[$index]}"

		[ "${options[$index]}" = "" ] && cmd="$LFS mirror resync"

		[ $((RANDOM % 4)) -eq 0 ] && {
			index=0
			lock_taken=true
			echo -n "lock to "
		}

		echo -n "resync file $tf with '$cmd' .."

		if [[ $lock_taken = "true" ]]; then
			flock -x 200 -c "$cmd $tf &> /dev/null" &&
				echo "done" || echo "failed"
			flock -u 200
		else
			$cmd $tf &> /dev/null && echo "done" || echo "failed"
		fi

		sleep 0.$((RANDOM % 8 + 1))
	done
}

test_200() {
	local tf=$DIR/$tfile
	local tf2=$DIR2/$tfile
	local tf3=$DIR3/$tfile

	$LFS setstripe -E 1M -S 1M -E 2M -c 2 -E 4M -E 16M -E eof $tf
	$LFS setstripe -E 2M -S 1M -E 6M -c 2 -E 8M -E 32M -E eof $tf-2
	$LFS setstripe -E 4M -c 2 -E 8M -E 64M -E eof $tf-3

	$LFS mirror extend -N -f $tf-2 $tf ||
		error "merging $tf-2 into $tf failed"
	$LFS mirror extend -N -f $tf-3 $tf ||
		error "merging $tf-3 into $tf failed"

	mkdir -p $MOUNT2 && mount_client $MOUNT2

	mkdir -p $MOUNT3 && mount_client $MOUNT3

	verify_flr_state $tf3 "ro"

	#define OBD_FAIL_FLR_RANDOM_PICK_MIRROR	0x1A03
	$LCTL set_param fail_loc=0x1A03

	local mds_idx=mds$(($($LFS getstripe -m $tf) + 1))
	do_facet $mds_idx $LCTL set_param fail_loc=0x1A03

	declare -a pids

	write_file_200 $tf &
	pids+=($!)

	read_file_200 $tf &
	pids+=($!)

	write_file_200 $tf2 &
	pids+=($!)

	read_file_200 $tf2 &
	pids+=($!)

	resync_file_200 $tf3 &
	pids+=($!)

	local sleep_time=60
	[ "$SLOW" = "yes" ] && sleep_time=360
	while [ $sleep_time -gt 0 -a -f $ctrl_file ]; do
		sleep 1
		((--sleep_time))
	done

	rm -f $ctrl_file

	echo "Waiting ${pids[@]}"
	wait ${pids[@]}

	umount_client $MOUNT2
	umount_client $MOUNT3

	rm -f $lock_file

	# resync and verify mirrors
	mirror_io resync $tf
	get_mirror_ids $tf

	local csum=$($LFS mirror dump -N ${mirror_array[0]} $tf | md5sum)
	for id in ${mirror_array[@]:1}; do
		[ "$($LFS mirror dump -N $id $tf | md5sum)" = "$csum" ] ||
			error "checksum error for mirror $id"
	done

	true
}
run_test 200 "stress test"

cleanup_test_201() {
	trap 0
	do_facet $SINGLEMDS $LCTL --device $MDT0 changelog_deregister $CL_USER

	umount_client $MOUNT2
}

test_201() {
	local delay=${RESYNC_DELAY:-5}

	MDT0=$($LCTL get_param -n mdc.*.mds_server_uuid |
	       awk '{ gsub(/_UUID/,""); print $1 }' | head -n1)

	trap cleanup_test_201 EXIT

	CL_USER=$(do_facet $SINGLEMDS $LCTL --device $MDT0 \
			changelog_register -n)

	mkdir -p $MOUNT2 && mount_client $MOUNT2

	local index=0
	while :; do
		local log=$($LFS changelog $MDT0 $index | grep FLRW)
		[ -z "$log" ] && { sleep 1; continue; }

		index=$(echo $log | awk '{print $1}')
		local ts=$(date -d "$(echo $log | awk '{print $3}')" "+%s" -u)
		local fid=$(echo $log | awk '{print $6}' | sed -e 's/t=//')
		local file=$($LFS fid2path $MOUNT2 $fid 2> /dev/null)

		((++index))
		[ -z "$file" ] && continue

		local now=$(date +%s)

		echo "file: $file $fid was modified at $ts, now: $now, " \
		     "will be resynced at $((ts+delay))"

		[ $now -lt $((ts + delay)) ] && sleep $((ts + delay - now))

		mirror_io resync $file
		echo "$file resync done"
	done

	cleanup_test_201
}
run_test 201 "FLR data mover"

test_202() {
	[[ $OSTCOUNT -lt 2 ]] && skip "need >= 2 OSTs" && return

	local tf=$DIR/$tfile
	local ids

	$LFS setstripe -E 1M -S 1M -c 1 $tf
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))
	verify_comp_attr stripe-count $tf ${ids[0]} 1

	$LFS setstripe --component-add -E 2M -c -1 $tf
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))
	verify_comp_attr stripe-count $tf ${ids[0]} 1
	verify_comp_attr stripe-count $tf ${ids[1]} -1

	dd if=/dev/zero of=$tf bs=1M count=2
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))
	verify_comp_attr stripe-count $tf ${ids[0]} 1
	verify_comp_attr stripe-count $tf ${ids[1]} $OSTCOUNT
}
run_test 202 "lfs setstripe --add-component wide striping"

test_203() {
	[[ $OSTCOUNT -lt 2 ]] && skip "need >= 2 OSTs" && return

	local tf=$DIR/$tfile

	#create 2 mirrors
	$LFS mirror create -N2 -c1 $tf || error "create FLR file $tf"
	#delete first mirror
	$LFS mirror split --mirror-id=1 -d $tf || error "delete first mirror"

	$LFS getstripe $tf
	local old_id=$($LFS getstripe --mirror-id=2 -I $tf)
	local count=$($LFS getstripe --mirror-id=2 -c $tf) ||
		error "getstripe count of mirror 2"
	[[ x$count = x1 ]] || error "mirror 2 stripe count $count is not 1"

	#extend a mirror with 2 OSTs
	$LFS mirror extend -N -c2 $tf || error "extend mirror"
	$LFS getstripe $tf

	local new_id=$($LFS getstripe --mirror-id=2 -I $tf)
	count=$($LFS getstripe --mirror-id=2 -c $tf) ||
		error "getstripe count of mirror 2"
	[[ x$oldid = x$newid ]] ||
		error "mirror 2 changed ID from $old_id to $new_id"
	[[ x$count = x1 ]] || error "mirror 2 stripe count $count is not 1"

	count=$($LFS getstripe --mirror-id=3 -c $tf) ||
		error "getstripe count of mirror 3"
	[[ x$count = x2 ]] || error "mirror 3 stripe count $count is not 2"
}
run_test 203 "mirror file preserve mirror ID"

complete $SECONDS
check_and_cleanup_lustre
exit_status
