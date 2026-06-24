#!/usr/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
set -e
set +o posix


ONLY=${ONLY:-"$*"}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env "$@"
init_logging

ALWAYS_EXCEPT="$SANITY_EC_EXCEPT "

# tests 12a: EC parity calculation produces incorrect content (LU-19631)
# tests 41d: a degraded mmap read never completes.  The OSC alternates
# between "too many resent retries" and osc_brw_redo_request() forever,
# so -EIO never reaches the LOV layer and CIT_FAULT never switches to
# CIT_EC_RD.  The read hangs until the harness kills the node rather
# than failing, so it stays off until the retry loop is fixed.
# tests 53a: a recovery read at a non-zero offset intermittently
# reconstructs wrong data.  Measured at 2 failures in 10 runs, and it
# still fails 1 in 10 with the proactive dead-OST detection applied, so
# it is not the reconstruction bug the other offset tests hit (LU-12668)
always_except LU-19631 12a
always_except LU-20708 41d
always_except LU-20709 53a

# aio EC recovery is not working yet
always_except LU-20566 41j 41k 41l 41m 41n

if [[ "$ost1_FSTYPE" == "zfs" ]]; then
	# test 5b: EC resync hole-punches stale parity, but osd-zfs has no
	# fallocate hole-punch, so resync fails with EOPNOTSUPP (LU-20435)
	always_except LU-20435 5b 12b 12e
fi

build_test_filter

check_and_setup_lustre

(( MDS1_VERSION >= $(version_code 2.17.52) )) ||
	skip "Need MDS version at least 2.17.52 for EC support"
DIR=${DIR:-$MOUNT}
assert_DIR
rm -rf $DIR/[Rdfs][0-9]*

(( UID != 0 || RUNAS_ID != 0 )) ||
	error "\$RUNAS_ID set to 0, but \$UID is also 0!"

check_runas_id $RUNAS_ID $RUNAS_GID $RUNAS

# the EC read-fault helpers select OSTs through a 16-bit fail_val mask
(( OSTCOUNT <= 16 )) ||
	error "limit used OST indexes to <= 15 for EC_FAULT_MASK"

# Enable EC support for testing
export LFS_EC_OK=yes
stack_trap "unset LFS_EC_OK" EXIT

#
# Verify mirror count with an expected value for a given file.
#
verify_mirror_count() {
	local tf=$1
	local expected=$2
	local mirror_count=$($LFS getstripe -N $tf)

	(( mirror_count == expected )) || {
		$LFS getstripe -v $tf
		error "verify mirror count failed on $tf:" \
		      "$mirror_count != $expected"
	}
}

#
# Verify component count with an expected value for a given file.
#	$1 composite layout file
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
# Verify component has the parity flag set
#
verify_comp_parity() {
	local tf=$1
	local comp_id=$2
	local flags=$($LFS getstripe -I$comp_id $tf |
		      awk '/lcme_flags:/ { print $2 }')

	[[ $flags =~ "parity" ]] || {
		$LFS getstripe -I$comp_id -v $tf
		error "verify parity flag failed on $tf component $comp_id:" \
		      "flags=$flags"
	}
}

#
# Enable erasure coding and restore on exit
#
enable_ec() {
	(( OSTCOUNT >= 3 )) || skip "needs >= 3 OSTs for EC"

	local ec_enable=($($LCTL get_param -n llite.*.enable_erasure_coding))

	$LCTL set_param llite.*.enable_erasure_coding=1
	stack_trap "$LCTL set_param -n llite.*.enable_erasure_coding=$ec_enable"

	# Scale a generic EC layout to the number of available OSTs so the
	# tests run on any configuration with a small number of OSTs instead
	# of hard-coding a fixed geometry that needs a large OST count.
	# The raidset allocator requires a unique OST for every data stripe
	# plus one per parity in a single raidset, so keep data + parity <=
	# OSTCOUNT. Tests that need a specific geometry set their own values.
	EC_CSTRIPE=$((OSTCOUNT > 4 ? 2 : 1))
	EC_DSTRIPE=$((OSTCOUNT > 7 ? 6 : OSTCOUNT - EC_CSTRIPE))
	EC_MINSTRIPE=$((EC_DSTRIPE + EC_CSTRIPE))
	EC_ARG="--ec $EC_DSTRIPE+$EC_CSTRIPE"
}

#
# Verify EC stripe counts (data and coding stripes)
#
verify_ec_stripe_count() {
	local tf=$1
	local comp_id=$2
	local expected_dstripe=$3
	local expected_cstripe=$4
	local dstripe=$($LFS getstripe -I$comp_id $tf | \
			awk '/lcme_dstripe_count:/ { print $2 }')
	local cstripe=$($LFS getstripe -I$comp_id $tf | \
			awk '/lcme_cstripe_count:/ { print $2 }')

	[[ $dstripe = $expected_dstripe ]] || {
		$LFS getstripe -I$comp_id -v $tf
		error "verify dstripe count failed on $tf component $comp_id:" \
		      "$dstripe != $expected_dstripe"
	}

	[[ $cstripe = $expected_cstripe ]] || {
		$LFS getstripe -I$comp_id -v $tf
		error "verify cstripe count failed on $tf component $comp_id:" \
		      "$cstripe != $expected_cstripe"
	}
}

#
# Verify EC raidset map on a parity component.
#	$1 file
#	$2 parity component ID (empty to dump whole file)
#	$3 expected raidset count
#	$4+ substrings expected in raidset output lines
#
verify_ec_raidsets() {
	local tf=$1
	local comp_id=$2
	local expected_count=$3
	local output
	local -a cmd

	cmd=($LFS getstripe --ec-map)
	[[ -n "$comp_id" ]] && cmd+=(-I$comp_id)
	cmd+=($tf)

	output=$("${cmd[@]}")
	echo "$output"

	echo "$output" | verify_yaml ||
		error "verify raidset map failed on $tf: invalid YAML"

	echo "$output" | grep -q "lcme_id:" ||
		error "verify raidset map failed on $tf: missing lcme_id"

	local count=$(echo "$output" | awk '/lcme_ec_raidset_count:/ { print $2 }')
	(( count == expected_count )) ||
		error "$tf raidset count on comp $comp_id: $count != $expected_count"

	shift 3
	while (( $# > 0 )); do
		echo "$output" | grep -q "$1" ||
			error "verify raidset map failed on $tf:missing '$1'"
		shift
	done
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
	local start=$($LFS getstripe -I$comp_id --component-start $tf)
	local end=$($LFS getstripe -I$comp_id --component-end $tf)

	[[ $start = $expected_start ]] || {
		$LFS getstripe -I$comp_id -v $tf
		error "verify component start failed on $tf comp $comp_id:" \
		      "$start != $expected_start"
	}

	[[ $end = $expected_end ]] || {
		$LFS getstripe -I$comp_id -v $tf
		error "verify component end failed on $tf comp $comp_id:" \
		      "$end != $expected_end"
	}
}

#
# Verify FLR state (ro, wp, sp) for a given file
#
verify_flr_state() {
	local tf=$1
	local expected_state=$2

	local state=$($LFS getstripe -v $tf | awk '/lcm_flags/{ print $2 }')
	[[ $expected_state = $state ]] ||
		error "expected: $expected_state, actual $state"
}

#
# Verify component has stale flag set
#
verify_comp_stale() {
	local tf=$1
	local comp_id=$2
	local flags=$($LFS getstripe -I$comp_id $tf |
			awk '/lcme_flags:/ { print $2 }')

	[[ $flags =~ "stale" ]] || {
		$LFS getstripe -I$comp_id -v $tf
		error "verify stale flag failed on $tf component $comp_id:" \
		      "flags=$flags"
	}
}

#
# Verify stripe size matches between data and EC components
#
verify_ec_stripe_size() {
	local tf=$1
	local data_comp_id=$2
	local ec_comp_id=$3
	local data_stripe_size=$($LFS getstripe -I$data_comp_id $tf | \
				awk '/lmm_stripe_size:/ { print $2 }')
	local ec_stripe_size=$($LFS getstripe -I$ec_comp_id $tf | \
				awk '/lmm_stripe_size:/ { print $2 }')

	[[ $data_stripe_size = $ec_stripe_size ]] || {
		$LFS getstripe -v $tf
		error "stripe size mismatch on $tf:" \
		      "data component $data_comp_id has $data_stripe_size," \
		      "EC component $ec_comp_id has $ec_stripe_size"
	}
}

#
# Read from parity mirror and check for zeros.
# Usage: check_parity_read <file> <mirror_id> <offset> <expect_zeros>
#
check_parity_read() {
	local file=$1
	local mirror_id=$2
	local offset=$3
	local expect_zeros=$4
	local rc

	# test_parity_read returns 0 if all zeros, 1 if non-zero bytes found
	$LUSTRE/tests/test_parity_read $file $mirror_id $offset > /dev/null 2>&1
	rc=$?

	if [[ $expect_zeros == "yes" ]]; then
		(( rc == 0 )) || error "offset $offset: expected zeros"
	else
		(( rc == 1 )) || error "offset $offset: expected parity data"
	fi
}

#
# Classify the mirrors of an EC file into the globals ec_parity_id (carries the
# parity flag), ec_data_id (the data mirror linked to it via
# lcme_mirror_link_id) and ec_plain_id (a mirror with no link). Any of them is
# empty if the file has no such mirror.
#
identify_ec_mirrors() {
	local tf=$1
	local id flags link

	ec_data_id=""
	ec_parity_id=""
	ec_plain_id=""

	for id in $($LFS getstripe $tf | awk '/lcme_mirror_id:/ {print $2}' |
		    sort -u); do
		flags=$($LFS getstripe --mirror-id=$id $tf |
			awk '/lcme_flags:/ {print $2; exit}')
		if [[ $flags =~ "parity" ]]; then
			ec_parity_id=$id
			continue
		fi
		link=$($LFS getstripe -v $tf | awk -v m=$id '
			/lcme_mirror_id:/ { cur = $2 }
			/lcme_mirror_link_id:/ {
				if (cur == m) { print $2; exit }
			}')
		if [[ -n $link && $link != 0x0 ]]; then
			ec_data_id=$id
		else
			ec_plain_id=$id
		fi
	done
}

#
# lseek on a designated mirror; compare result to @expected.
# Usage: check_mirror_lseek <-l|-d> <file> <mirror_id> <offset> <expected>
#
check_mirror_lseek() {
	local opt=$1
	local file=$2
	local mirror_id=$3
	local offset=$4
	local expected=$5
	local got

	got=$($LUSTRE/tests/lseek_test $opt $offset -m $mirror_id $file 2>&1) ||
		error "mirror lseek $opt at $offset on mirror $mirror_id failed: $got"

	(( got == expected )) ||
		error "mirror $mirror_id lseek $opt at $offset: $expected != $got"
}

test_1a() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	# Single component with EC
	$LFS setstripe -E -1 -c $EC_DSTRIPE $EC_ARG $tf ||
		error "setstripe failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 2

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify data mirror (mirror 1, component 0)
	verify_comp_extent $tf ${ids[0]} 0 EOF

	# Verify parity mirror (mirror 2, component 1)
	verify_comp_parity $tf ${ids[1]}
	verify_ec_stripe_count $tf ${ids[1]} $EC_DSTRIPE $EC_CSTRIPE
	verify_comp_extent $tf ${ids[1]} 0 EOF

	# Verify stripe size matches between data and EC components
	verify_ec_stripe_size $tf ${ids[0]} ${ids[1]}
}
run_test 1a "basic setstripe with single component and EC"

test_1b() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	# Order independence: --ec before -E
	$LFS setstripe $EC_ARG -E -1 -c $EC_DSTRIPE $tf ||
		error "setstripe failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 2

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify data mirror (mirror 1, component 0)
	verify_comp_extent $tf ${ids[0]} 0 EOF

	# Verify parity mirror (mirror 2, component 1)
	verify_comp_parity $tf ${ids[1]}
	verify_ec_stripe_count $tf ${ids[1]} $EC_DSTRIPE $EC_CSTRIPE
	verify_comp_extent $tf ${ids[1]} 0 EOF
}
run_test 1b "setstripe with --ec before -E (order independence)"

test_1c() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	# Test colon separator: --ec 4:2 instead of 4+2
	$LFS setstripe -E -1 -c $EC_DSTRIPE --ec $EC_DSTRIPE:$EC_CSTRIPE $tf ||
		error "setstripe with colon separator failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 2

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify data mirror (mirror 1, component 0)
	verify_comp_extent $tf ${ids[0]} 0 EOF

	# Verify parity mirror (mirror 2, component 1)
	verify_comp_parity $tf ${ids[1]}
	verify_ec_stripe_count $tf ${ids[1]} $EC_DSTRIPE $EC_CSTRIPE
	verify_comp_extent $tf ${ids[1]} 0 EOF
}
run_test 1c "setstripe with colon separator (--ec dstripe:cstripe)"

test_1d() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	# Multiple components, single EC spec
	$LFS setstripe -E 128M -E -1 $EC_ARG $tf ||
		error "setstripe failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 4

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify data mirror components (mirror 1)
	verify_comp_extent $tf ${ids[0]} 0 134217728
	verify_comp_extent $tf ${ids[1]} 134217728 EOF

	# Verify parity mirror components (mirror 2)
	# First parity component
	verify_comp_parity $tf ${ids[2]}
	verify_ec_stripe_count $tf ${ids[2]} $EC_DSTRIPE $EC_CSTRIPE
	verify_comp_extent $tf ${ids[2]} 0 134217728

	# Second parity component
	verify_comp_parity $tf ${ids[3]}
	verify_ec_stripe_count $tf ${ids[3]} $EC_DSTRIPE $EC_CSTRIPE
	verify_comp_extent $tf ${ids[3]} 134217728 EOF
}
run_test 1d "setstripe with multiple components and single EC spec"

test_1e() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	# EC specified on first component, should inherit to second
	$LFS setstripe -E 128M $EC_ARG -E -1 -c 2 $tf ||
		error "setstripe failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 4

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify data mirror components (mirror 1)
	verify_comp_extent $tf ${ids[0]} 0 134217728
	verify_comp_extent $tf ${ids[1]} 134217728 EOF

	# Verify parity mirror components (mirror 2)
	# First component keeps the spec EC($EC_DSTRIPE+$EC_CSTRIPE)
	verify_comp_parity $tf ${ids[2]}
	verify_ec_stripe_count $tf ${ids[2]} $EC_DSTRIPE $EC_CSTRIPE
	verify_comp_extent $tf ${ids[2]} 0 134217728

	# Second component reduced to EC(2+$EC_CSTRIPE) because the data
	# component has -c 2 (fewer than $EC_DSTRIPE data stripes)
	verify_comp_parity $tf ${ids[3]}
	verify_ec_stripe_count $tf ${ids[3]} 2 $EC_CSTRIPE
	verify_comp_extent $tf ${ids[3]} 134217728 EOF
}
run_test 1e "setstripe with EC inheriting to second component"

test_1f() {
	(( $OSTCOUNT >= 6 )) || skip "needs >= 6 OSTs"

	enable_ec
	local tf=$DIR/$tfile
	local ids

	# Different EC for different components: first 2+1, second 4+2 with -c 4
	$LFS setstripe -E 128M --ec 2+1 -E -1 -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 4

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify data mirror components (mirror 1)
	verify_comp_extent $tf ${ids[0]} 0 134217728
	verify_comp_extent $tf ${ids[1]} 134217728 EOF

	# Verify parity mirror components (mirror 2)
	# First component should have EC(2+1)
	verify_comp_parity $tf ${ids[2]}
	verify_ec_stripe_count $tf ${ids[2]} 2 1
	verify_comp_extent $tf ${ids[2]} 0 134217728

	# Second component has EC adjusted to 4+2 (data component has -c 4)
	verify_comp_parity $tf ${ids[3]}
	verify_ec_stripe_count $tf ${ids[3]} 4 2
	verify_comp_extent $tf ${ids[3]} 134217728 EOF
}
run_test 1f "setstripe with different EC for different components"

test_1g() {
	(( OSTCOUNT >= 5 )) || skip "needs >= 5 OSTs"

	enable_ec
	local tf=$DIR/$tfile
	local ids

	# Different parity counts
	# Note: second component has -c 4, so EC will be adjusted to 4+1
	# (can't have 8 data stripes with only 4 total stripes)
	$LFS setstripe -E 128M --ec 4+1 -E -1 -c 4 --ec 8+1 $tf ||
		error "setstripe failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 4

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify data mirror components (mirror 1)
	verify_comp_extent $tf ${ids[0]} 0 134217728
	verify_comp_extent $tf ${ids[1]} 134217728 EOF

	# Verify parity mirror components (mirror 2)
	# First component should have EC(4+1)
	verify_comp_parity $tf ${ids[2]}
	verify_ec_stripe_count $tf ${ids[2]} 4 1
	verify_comp_extent $tf ${ids[2]} 0 134217728

	# Second component has EC adjusted to 4+1 (data component has -c 4)
	verify_comp_parity $tf ${ids[3]}
	verify_ec_stripe_count $tf ${ids[3]} 4 1
	verify_comp_extent $tf ${ids[3]} 134217728 EOF
}
run_test 1g "setstripe with different parity counts"

test_1h() {
	(( OSTCOUNT >= 7 )) || skip "needs >= 7 OSTs"

	enable_ec
	local tf=$DIR/$tfile
	local ids

	# Test -N flag with explicit stripe counts and --ec
	# This should create:
	# Mirror 1: data mirror 2 comps ([0, 1M] with -c 1, [1M, EOF] with -c 1)
	# Mirror 2: data mirror 2 comps ([0, 1M] with -c 4, [1M, EOF] with -c 2)
	# Mirror 3: parity 2 EC comps ([0, 1M] EC(4+2), [1M, EOF] EC(2+1))
	#
	# This test verifies that when using -N with multiple mirrors and --ec,
	# the EC parity components correctly bind to the data components in the
	# mirror they were added with (Mirror 2), not to components from other
	# mirrors (Mirror 1).

	$LFS setstripe -N -E 1M -c 1 -E -1 -c 1 \
		-N -E 1M -c 4 --ec 4+2 -E -1 -c 2 --ec 2+1 $tf ||
		error "setstripe failed"

	verify_mirror_count $tf 3
	verify_comp_count $tf 6

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify Mirror 1: data mirror without EC
	verify_comp_extent $tf ${ids[0]} 0 1048576
	verify_comp_extent $tf ${ids[1]} 1048576 EOF

	# Verify Mirror 2: data mirror with explicit stripe counts
	verify_comp_extent $tf ${ids[2]} 0 1048576
	verify_comp_extent $tf ${ids[3]} 1048576 EOF

	# Verify Mirror 3: parity mirror with EC
	# First component should have EC(4+2) with dstripe=4
	verify_comp_parity $tf ${ids[4]}
	verify_ec_stripe_count $tf ${ids[4]} 4 2
	verify_comp_extent $tf ${ids[4]} 0 1048576

	# Second component should have EC(2+1) with dstripe=2
	verify_comp_parity $tf ${ids[5]}
	verify_ec_stripe_count $tf ${ids[5]} 2 1
	verify_comp_extent $tf ${ids[5]} 1048576 EOF
}
run_test 1h "setstripe with -N flag and explicit stripe counts with --ec"

test_1i() {
	enable_ec
	local td=$DIR/$tdir
	local ids

	test_mkdir $td

	# Set default EC layout on directory
	$LFS setstripe -E 128M -E -1 $EC_ARG $td ||
		error "setstripe on directory failed"

	# Create file in directory - should inherit EC layout
	touch $td/$tfile || error "touch failed"

	verify_mirror_count $td/$tfile 2
	verify_comp_count $td/$tfile 4

	# Get component IDs
	ids=($($LFS getstripe $td/$tfile | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify data mirror components (mirror 1)
	verify_comp_extent $td/$tfile ${ids[0]} 0 134217728
	verify_comp_extent $td/$tfile ${ids[1]} 134217728 EOF

	# Verify parity mirror components (mirror 2)
	verify_comp_parity $td/$tfile ${ids[2]}
	verify_ec_stripe_count $td/$tfile ${ids[2]} $EC_DSTRIPE $EC_CSTRIPE
	verify_comp_extent $td/$tfile ${ids[2]} 0 134217728

	verify_comp_parity $td/$tfile ${ids[3]}
	verify_ec_stripe_count $td/$tfile ${ids[3]} $EC_DSTRIPE $EC_CSTRIPE
	verify_comp_extent $td/$tfile ${ids[3]} 134217728 EOF

	# Create another file to verify inheritance works consistently
	touch $td/${tfile}.2 || error "touch second file failed"
	verify_mirror_count $td/${tfile}.2 2
	verify_comp_count $td/${tfile}.2 4
}
run_test 1i "default EC layout on directory"

test_1j() {
	(( $OSTCOUNT >= 6 )) || skip "needs >= 6 OSTs"

	enable_ec
	local tf=$DIR/$tfile
	local ids
	local data_stripe_size
	local ec_stripe_size

	stack_trap "rm -f $tf"

	# Test with explicit stripe size
	$LFS setstripe -E -1 -S 4M -c 4 --ec 4+2 $tf ||
		error "setstripe with explicit stripe size failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 2

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify data mirror (mirror 1, component 0)
	verify_comp_extent $tf ${ids[0]} 0 EOF

	# Verify parity mirror (mirror 2, component 1)
	verify_comp_parity $tf ${ids[1]}
	verify_ec_stripe_count $tf ${ids[1]} 4 2
	verify_comp_extent $tf ${ids[1]} 0 EOF

	# Verify stripe size matches between data and EC components
	verify_ec_stripe_size $tf ${ids[0]} ${ids[1]}

	# Verify the stripe size is what we set (4M)
	data_stripe_size=$($LFS getstripe -I${ids[0]} $tf | \
			awk '/lmm_stripe_size:/ { print $2 }')
	ec_stripe_size=$($LFS getstripe -I${ids[1]} $tf | \
			awk '/lmm_stripe_size:/ { print $2 }')

	[[ $data_stripe_size = 4194304 ]] || {
		$LFS getstripe -v $tf
		error "data component stripe size should be 4M (4194304)," \
		      "got $data_stripe_size"
	}

	[[ $ec_stripe_size = 4194304 ]] || {
		$LFS getstripe -v $tf
		error "EC component stripe size should be 4M (4194304)," \
		      "got $ec_stripe_size"
	}
}
run_test 1j "verify EC component inherits stripe size from data component"

test_1k() {
	local td=$DIR/$tdir
	local subdir=$td/subdir
	local tf=$subdir/$tfile
	local ef=$subdir/explicit
	local ids

	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"

	enable_ec

	test_mkdir $td

	# Set default EC layout on the parent directory
	$LFS setstripe -E 128M -E -1 --ec 4+2 $td ||
		error "setstripe for $td failed"

	# create another dir layer to verify the link id is inherited correctly
	mkdir $subdir || error "mkdir for $subdir failed"

	# ... and create a file in that subdir
	touch $tf || error "touch for $tf failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 4

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify data mirror components (mirror 1)
	verify_comp_extent $tf ${ids[0]} 0 134217728
	verify_comp_extent $tf ${ids[1]} 134217728 EOF

	# Verify parity mirror components (mirror 2)
	verify_comp_parity $tf ${ids[2]}
	verify_ec_stripe_count $tf ${ids[2]} 4 2
	verify_comp_extent $tf ${ids[2]} 0 134217728

	verify_comp_parity $tf ${ids[3]}
	verify_ec_stripe_count $tf ${ids[3]} 4 2
	verify_comp_extent $tf ${ids[3]} 134217728 EOF

	# verify that explicit EC layouts on new files overwrite dir defaults
	$LFS setstripe -E -1 --ec 2+1 $ef ||
		error "explicit setstripe fir $ef failed"
	verify_mirror_count $ef 2
	verify_comp_count $ef 2
	ids=($($LFS getstripe $ef | awk '/lcme_id/{print $2}' | tr '\n' ' '))
	verify_comp_parity $ef ${ids[1]}
	verify_ec_stripe_count $ef ${ids[1]} 2 1
}
run_test 1k "default EC layout inherited through nested directories"

test_1l() {
	local td=$DIR/$tdir
	local subdir=$td/subdir
	local tf=$subdir/$tfile
	local ids

	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"

	enable_ec

	test_mkdir $td

	# Two EC mirrors, each a PFL with mixed EC params
	#   mirror 1: [0,128M) 2+1, [128M,EOF) 4+2
	#   mirror 2: [0,64M)  4+1, [64M,EOF)  3+2
	# yields 4 mirrors (2 data + 2 parity) and 8 components.
	$LFS setstripe -N -E 128M --ec 2+1 -E -1 --ec 4+2 \
		       -N -E 64M --ec 4+1 -E -1 --ec 3+2 $td ||
		error "setstripe complex EC layout for $td failed"

	# A subdir inherits the complex default, and a file created in it must
	# inherit the full layout (every component/mirror and its EC params).
	mkdir $subdir || error "mkdir for $subdir failed"
	touch $tf || error "touch for $tf failed"

	verify_mirror_count $tf 4
	verify_comp_count $tf 8

	# Get component IDs (4 mirrors x 2 PFL comps, in mirror order)
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Mirror 1 data components
	verify_comp_extent $tf ${ids[0]} 0 134217728
	verify_comp_extent $tf ${ids[1]} 134217728 EOF

	# Mirror 1 parity components (2+1, then 4+2)
	verify_comp_parity $tf ${ids[2]}
	verify_ec_stripe_count $tf ${ids[2]} 2 1
	verify_comp_extent $tf ${ids[2]} 0 134217728

	verify_comp_parity $tf ${ids[3]}
	verify_ec_stripe_count $tf ${ids[3]} 4 2
	verify_comp_extent $tf ${ids[3]} 134217728 EOF

	# Mirror 2 data components
	verify_comp_extent $tf ${ids[4]} 0 67108864
	verify_comp_extent $tf ${ids[5]} 67108864 EOF

	# Mirror 2 parity components (4+1, then 3+2)
	verify_comp_parity $tf ${ids[6]}
	verify_ec_stripe_count $tf ${ids[6]} 4 1
	verify_comp_extent $tf ${ids[6]} 0 67108864

	verify_comp_parity $tf ${ids[7]}
	verify_ec_stripe_count $tf ${ids[7]} 3 2
	verify_comp_extent $tf ${ids[7]} 67108864 EOF
}
run_test 1l "default EC layout inherited through nested dirs (complex)"

test_2a() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	# Single data mirror with EC using -N
	$LFS setstripe -N -E 128M -E -1 $EC_ARG $tf ||
		error "setstripe failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 4

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify data mirror (mirror 1)
	verify_comp_extent $tf ${ids[0]} 0 134217728
	verify_comp_extent $tf ${ids[1]} 134217728 EOF

	# Verify parity mirror (mirror 2)
	verify_comp_parity $tf ${ids[2]}
	verify_ec_stripe_count $tf ${ids[2]} $EC_DSTRIPE $EC_CSTRIPE
	verify_comp_extent $tf ${ids[2]} 0 134217728

	verify_comp_parity $tf ${ids[3]}
	verify_ec_stripe_count $tf ${ids[3]} $EC_DSTRIPE $EC_CSTRIPE
	verify_comp_extent $tf ${ids[3]} 134217728 EOF
}
run_test 2a "setstripe with -N and EC"

test_2b() {
	(( OSTCOUNT >= 7 )) || skip "needs >= 7 OSTs"

	enable_ec
	local tf=$DIR/$tfile
	local ids

	# Two data mirrors, one with EC
	$LFS setstripe -N -E 128M -E -1 --ec 4+2 \
			-N -E 256M -E -1 $tf || error "setstripe failed"

	verify_mirror_count $tf 3
	verify_comp_count $tf 6

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify mirror 1 (data with EC)
	verify_comp_extent $tf ${ids[0]} 0 134217728
	verify_comp_extent $tf ${ids[1]} 134217728 EOF

	# Verify mirror 2 (parity for mirror 1)
	verify_comp_parity $tf ${ids[2]}
	verify_ec_stripe_count $tf ${ids[2]} 4 2
	verify_comp_extent $tf ${ids[2]} 0 134217728

	verify_comp_parity $tf ${ids[3]}
	verify_ec_stripe_count $tf ${ids[3]} 4 2
	verify_comp_extent $tf ${ids[3]} 134217728 EOF

	# Verify mirror 3 (data without EC)
	verify_comp_extent $tf ${ids[4]} 0 268435456
	verify_comp_extent $tf ${ids[5]} 268435456 EOF
}
run_test 2b "setstripe with -N: two data mirrors, one with EC"

test_2c() {
	(( OSTCOUNT >= 8 )) || skip "needs >= 8 OSTs"

	enable_ec
	local tf=$DIR/$tfile
	local ids

	# Two data mirrors, both with EC
	$LFS setstripe -N -E 128M --ec 2+2 -E -1 --ec 4+2 \
			-N -E 256M --ec 3+1 -E -1 \
			$tf || error "setstripe failed"

	verify_mirror_count $tf 4
	verify_comp_count $tf 8

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify mirror 1 (data)
	verify_comp_extent $tf ${ids[0]} 0 134217728
	verify_comp_extent $tf ${ids[1]} 134217728 EOF

	# Verify mirror 2 (parity for mirror 1)
	verify_comp_parity $tf ${ids[2]}
	verify_ec_stripe_count $tf ${ids[2]} 2 2
	verify_comp_extent $tf ${ids[2]} 0 134217728

	verify_comp_parity $tf ${ids[3]}
	verify_ec_stripe_count $tf ${ids[3]} 4 2
	verify_comp_extent $tf ${ids[3]} 134217728 EOF

	# Verify mirror 3 (data)
	verify_comp_extent $tf ${ids[4]} 0 268435456
	verify_comp_extent $tf ${ids[5]} 268435456 EOF

	# Verify mirror 4 (parity for mirror 3)
	verify_comp_parity $tf ${ids[6]}
	verify_ec_stripe_count $tf ${ids[6]} 3 1
	verify_comp_extent $tf ${ids[6]} 0 268435456

	verify_comp_parity $tf ${ids[7]}
	verify_ec_stripe_count $tf ${ids[7]} 3 1
	verify_comp_extent $tf ${ids[7]} 268435456 EOF
}
run_test 2c "setstripe with -N: two data mirrors, both with EC"

test_2d() {
	(( OSTCOUNT >= 6 )) || skip "needs >= 6 OSTs"

	enable_ec
	local tf=$DIR/$tfile
	local ids

	# Multiple identical EC mirrors using -N count
	$LFS setstripe -N2 -E 128M -E -1 --ec 2+1 $tf ||
		error "setstripe failed"

	verify_mirror_count $tf 4
	verify_comp_count $tf 8

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify mirror 1 (data)
	verify_comp_extent $tf ${ids[0]} 0 134217728
	verify_comp_extent $tf ${ids[1]} 134217728 EOF

	# Verify mirror 2 (parity for mirror 1)
	verify_comp_parity $tf ${ids[2]}
	verify_ec_stripe_count $tf ${ids[2]} 2 1
	verify_comp_extent $tf ${ids[2]} 0 134217728

	verify_comp_parity $tf ${ids[3]}
	verify_ec_stripe_count $tf ${ids[3]} 2 1
	verify_comp_extent $tf ${ids[3]} 134217728 EOF

	# Verify mirror 3 (data, identical to mirror 1)
	verify_comp_extent $tf ${ids[4]} 0 134217728
	verify_comp_extent $tf ${ids[5]} 134217728 EOF

	# Verify mirror 4 (parity for mirror 3, identical to mirror 2)
	verify_comp_parity $tf ${ids[6]}
	verify_ec_stripe_count $tf ${ids[6]} 2 1
	verify_comp_extent $tf ${ids[6]} 0 134217728

	verify_comp_parity $tf ${ids[7]}
	verify_ec_stripe_count $tf ${ids[7]} 2 1
	verify_comp_extent $tf ${ids[7]} 134217728 EOF
}
run_test 2d "setstripe with -N2: multiple identical EC mirrors"

test_2e() {
	(( OSTCOUNT >= 8 )) || skip "needs >= 8 OSTs"

	enable_ec
	local tf=$DIR/$tfile
	local ids

	# Mixed: regular mirror + EC mirror
	$LFS setstripe -N -E -1 -c 2 \
			-N -E -1 -c 4 --ec 4+2 \
			$tf || error "setstripe failed"

	verify_mirror_count $tf 3
	verify_comp_count $tf 3

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify mirror 1 (data, no EC)
	verify_comp_extent $tf ${ids[0]} 0 EOF

	# Verify mirror 2 (data with EC)
	verify_comp_extent $tf ${ids[1]} 0 EOF

	# Verify mirror 3 (parity for mirror 2)
	verify_comp_parity $tf ${ids[2]}
	verify_ec_stripe_count $tf ${ids[2]} 4 2
	verify_comp_extent $tf ${ids[2]} 0 EOF
}
run_test 2e "setstripe with -N: mixed regular and EC mirrors"

test_2f() {
	(( OSTCOUNT >= 8 )) || skip "needs >= 8 OSTs"

	enable_ec
	local td=$DIR/$tdir
	local ids

	test_mkdir $td

	# Set default EC layout on directory using mirror mode (-N)
	$LFS setstripe -N -E 128M -E -1 --ec 4+2 $td ||
		error "setstripe with -N on directory failed"

	# Create file in directory - should inherit EC layout
	touch $td/$tfile || error "touch failed"

	verify_mirror_count $td/$tfile 2
	verify_comp_count $td/$tfile 4

	# Get component IDs
	ids=($($LFS getstripe $td/$tfile | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify data mirror (mirror 1)
	verify_comp_extent $td/$tfile ${ids[0]} 0 134217728
	verify_comp_extent $td/$tfile ${ids[1]} 134217728 EOF

	# Verify parity mirror (mirror 2)
	verify_comp_parity $td/$tfile ${ids[2]}
	verify_ec_stripe_count $td/$tfile ${ids[2]} 4 2
	verify_comp_extent $td/$tfile ${ids[2]} 0 134217728

	verify_comp_parity $td/$tfile ${ids[3]}
	verify_ec_stripe_count $td/$tfile ${ids[3]} 4 2
	verify_comp_extent $td/$tfile ${ids[3]} 134217728 EOF

	# Test with multiple data mirrors + EC
	$LFS setstripe -d $td || error "delete default layout failed"
	$LFS setstripe -N -E -1 -c 2 -N -E -1 --ec 4+2 $td ||
		error "setstripe with mixed mirrors on directory failed"

	touch $td/${tfile}.mixed || error "touch mixed file failed"

	# Should have 3 mirrors: 1 regular data + 1 EC data + 1 EC parity
	verify_mirror_count $td/${tfile}.mixed 3
	verify_comp_count $td/${tfile}.mixed 3
}
run_test 2f "default EC layout on directory using mirror mode"

# Test 3: lfs mirror create with EC
test_3a() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	$LFS mirror create -N -E 128M -E -1 $EC_ARG $tf ||
		error "failed to create mirrored file with EC"

	verify_mirror_count $tf 2
	verify_comp_count $tf 4

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify parity components (components 2 and 3 in parity mirror)
	verify_comp_parity $tf ${ids[2]}
	verify_comp_parity $tf ${ids[3]}

	# Verify EC stripe counts
	verify_ec_stripe_count $tf ${ids[2]} $EC_DSTRIPE $EC_CSTRIPE
	verify_ec_stripe_count $tf ${ids[3]} $EC_DSTRIPE $EC_CSTRIPE
}
run_test 3a "lfs mirror create with single EC mirror"

test_3b() {
	(( OSTCOUNT >= 6 )) || skip "needs >= 6 OSTs"

	enable_ec
	local tf=$DIR/$tfile
	local ids

	$LFS mirror create -N2 -E 128M -E -1 --ec 2+1 $tf ||
		error "failed to create mirrored file with -N2"

	verify_mirror_count $tf 4
	verify_comp_count $tf 8

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify parity components (components 2,3 and 6,7)
	verify_comp_parity $tf ${ids[2]}
	verify_comp_parity $tf ${ids[3]}
	verify_comp_parity $tf ${ids[6]}
	verify_comp_parity $tf ${ids[7]}

	# Verify EC stripe counts
	verify_ec_stripe_count $tf ${ids[2]} 2 1
	verify_ec_stripe_count $tf ${ids[3]} 2 1
	verify_ec_stripe_count $tf ${ids[6]} 2 1
	verify_ec_stripe_count $tf ${ids[7]} 2 1
}
run_test 3b "lfs mirror create with -N2 and EC"

test_3c() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	$LFS mirror create -N -E 128M -E -1 $EC_ARG \
			   -N -E 256M -E -1 $tf ||
		error "failed to create mixed mirror file"

	verify_mirror_count $tf 3
	verify_comp_count $tf 6

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify parity components (only first mirror has EC, components 2,3)
	verify_comp_parity $tf ${ids[2]}
	verify_comp_parity $tf ${ids[3]}

	# Verify EC stripe counts
	verify_ec_stripe_count $tf ${ids[2]} $EC_DSTRIPE $EC_CSTRIPE
	verify_ec_stripe_count $tf ${ids[3]} $EC_DSTRIPE $EC_CSTRIPE
}
run_test 3c "lfs mirror create with mixed EC and regular mirrors"

test_3d() {
	(( OSTCOUNT >= 6 )) || skip "needs >= 6 OSTs"

	enable_ec
	local tf=$DIR/$tfile
	local ids

	$LFS mirror create -N -E 128M -E -1 --ec 2+1 \
			   -N -E 256M -E -1 --ec 2+1 $tf ||
		error "failed to create file with different EC configs"

	verify_mirror_count $tf 4
	verify_comp_count $tf 8

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify parity components (components 2,3 and 6,7)
	verify_comp_parity $tf ${ids[2]}
	verify_comp_parity $tf ${ids[3]}
	verify_comp_parity $tf ${ids[6]}
	verify_comp_parity $tf ${ids[7]}

	# Verify EC stripe counts
	verify_ec_stripe_count $tf ${ids[2]} 2 1
	verify_ec_stripe_count $tf ${ids[3]} 2 1
	verify_ec_stripe_count $tf ${ids[6]} 2 1
	verify_ec_stripe_count $tf ${ids[7]} 2 1
}
run_test 3d "lfs mirror create with different EC configs per mirror"

test_3e() {
	(( OSTCOUNT >= 6 )) || skip "needs >= 6 OSTs"

	enable_ec
	local tf=$DIR/$tfile
	local ids

	$LFS mirror create -N -E 64M --ec 4+1 -E 128M --ec 4+2 -E -1 $tf ||
		error "failed to create file with multiple EC specs"

	verify_mirror_count $tf 2
	verify_comp_count $tf 6

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify parity components (components 3,4,5)
	verify_comp_parity $tf ${ids[3]}
	verify_comp_parity $tf ${ids[4]}
	verify_comp_parity $tf ${ids[5]}

	# Verify EC stripe counts
	verify_ec_stripe_count $tf ${ids[3]} 4 1
	verify_ec_stripe_count $tf ${ids[4]} 4 2
	verify_ec_stripe_count $tf ${ids[5]} 4 2
}
run_test 3e "lfs mirror create with multiple EC specs in one mirror"

test_3f() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	# Test EC inheritance with "holes" - the middle component has no --ec
	# and should inherit the EC layout from the first component
	$LFS mirror create -N -E 128M $EC_ARG -E 512M -E -1 $EC_ARG $tf ||
		error "failed to create file with EC holes"

	verify_mirror_count $tf 2
	verify_comp_count $tf 6

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify parity components (components 3,4,5)
	verify_comp_parity $tf ${ids[3]}
	verify_comp_parity $tf ${ids[4]}
	verify_comp_parity $tf ${ids[5]}

	# Verify EC stripe counts
	# First component: 4+2 (explicitly set)
	verify_ec_stripe_count $tf ${ids[3]} $EC_DSTRIPE $EC_CSTRIPE
	# Second component inherits EC from the first
	verify_ec_stripe_count $tf ${ids[4]} $EC_DSTRIPE $EC_CSTRIPE
	# Third component: explicitly set
	verify_ec_stripe_count $tf ${ids[5]} $EC_DSTRIPE $EC_CSTRIPE
}
run_test 3f "EC inheritance with holes"

test_3g() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile
	local pool_name=$TESTNAME
	local ids
	local data_pool
	local ec_pool

	stack_trap "rm -f $tf"

	# create a new OST pool and add all OSTs to it
	create_pool $FSNAME.$pool_name ||
		error "create OST pool $pool_name failed"

	pool_add_targets $pool_name 0 $((OSTCOUNT - 1)) ||
		error "add OSTs into pool $pool_name failed"

	# Create EC file with data + parity mirror. The data mirror is
	# explicitly on pool; parity mirror should inherit it.
	$LFS setstripe -N -E -1 -c 4 -p $pool_name --ec 4+2 $tf ||
		error "create EC file with pool failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 2

	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' |
	     tr '\n' ' '))

	# Component 0: data mirror; Component 1: parity mirror
	data_pool=$($LFS getstripe -I${ids[0]} -p $tf)
	ec_pool=$($LFS getstripe -I${ids[1]} -p $tf)

	[[ $data_pool = $pool_name ]] ||
		error "data mirror pool $data_pool != $pool_name"

	[[ $ec_pool = $pool_name ]] ||
		error "EC mirror pool $ec_pool != $pool_name"

	destroy_test_pools
	}
run_test 3g "EC parity mirror inherits pool from data mirror"

# Test 4: Invalid EC parameters
test_4a() {
	enable_ec
	local tf=$DIR/$tfile

	# Invalid: parity > data
	$LFS setstripe -E -1 --ec 4+5 $tf 2>&1 |
		grep -qi "parity.*must be less than or equal" ||
		error "should reject EC with parity > data"

	! [[ -f $tf ]] || error "file should not have been created"
}
run_test 4a "reject invalid EC parameters: parity > data"

test_4b() {
	enable_ec
	local tf=$DIR/$tfile

	# Invalid: data stripe count = 1 (must be at least 2)
	$LFS setstripe -E -1 --ec 1+0 $tf 2>&1 |
		grep -qi "invalid data stripe count" ||
		error "should reject EC with data count < 2"

	# Invalid: data stripe count = 0
	$LFS setstripe -E -1 --ec 0+1 $tf 2>&1 |
		grep -qi "invalid data stripe count" ||
		error "should reject EC with data count = 0"

	! [[ -f $tf ]] || error "file should not have been created"
}
run_test 4b "reject invalid EC parameters: data count < 2"

test_4c() {
	enable_ec
	local tf=$DIR/$tfile

	# Invalid: parity = 0
	$LFS setstripe -E -1 --ec 4+0 $tf 2>&1 |
		grep -qi "invalid parity stripe count" ||
		error "should reject EC with parity = 0"

	! [[ -f $tf ]] || error "file should not have been created"
}
run_test 4c "reject invalid EC parameters: parity = 0"

test_4d() {
	enable_ec
	local tf=$DIR/$tfile

	# Invalid: malformed EC specification (missing +)
	$LFS setstripe -E -1 --ec 42 $tf 2>&1 | grep -qi "invalid.*format" ||
		error "should reject malformed EC spec (missing +)"

	# Invalid: malformed EC specification (non-numeric)
	$LFS setstripe -E -1 --ec abc+def $tf 2>&1 | grep -qi "invalid" ||
		error "should reject malformed EC spec (non-numeric)"

	! [[ -f $tf ]] || error "file should not have been created"
}
run_test 4d "reject malformed EC specifications"

test_4e() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	stack_trap "rm -f $tf"

	# --ec without -E should automatically create [0,EOF] component
	$LFS setstripe --ec 4+2 $tf || error "setstripe failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 2

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify data component has [0,EOF] extent
	verify_comp_extent $tf ${ids[0]} 0 EOF

	# Verify parity component
	verify_comp_parity $tf ${ids[1]}
	verify_ec_stripe_count $tf ${ids[1]} 4 2
	verify_comp_extent $tf ${ids[1]} 0 EOF
}
run_test 4e "auto-create [0,EOF] component when --ec without -E"

test_4f() {
	enable_ec
	local tf=$DIR/$tfile

	# Invalid: --ec with --foreign
	$LFS setstripe -E -1 --ec 4+2 --foreign=none --xattr=test $tf 2>&1 |
		grep -qi "only.*options are valid with --foreign" ||
		error "should reject --ec with --foreign"

	! [[ -f $tf ]] || error "file should not have been created"
}
run_test 4f "reject --ec with incompatible options (--foreign)"

test_4g() {
	enable_ec
	local tf=$DIR/$tfile
	local output

	stack_trap "rm -f $tf"

	# Test 1: Reject data stripe count > 32 without --ec-expert
	output=$($LFS setstripe -E -1 -c 64 --ec 64+2 $tf 2>&1) ||
		true
	echo "$output" | grep -qi "exceeds supported limit.*--ec-expert" ||
		error "should reject data count > 32 without --ec-expert"
	[[ -f $tf ]] && error "file should not have been created"

	# Test 2: Reject parity stripe count > 4 without --ec-expert
	output=$($LFS setstripe -E -1 -c 16 --ec 16+5 $tf 2>&1) ||
		true
	echo "$output" | grep -qi "exceeds supported limit.*--ec-expert" ||
		error "should reject parity count > 4 without --ec-expert"
	[[ -f $tf ]] && error "file should not have been created"

	# Test 3: Allow data stripe count > 32 with --ec-expert
	# (may fail for other reasons, but not due to limit check)
	output=$($LFS setstripe -E -1 -c 64 --ec-expert 64+2 $tf 2>&1) ||
		true
	echo "$output" | grep -qi "exceeds supported limit" &&
		error "should not reject data count > 32 with --ec-expert"

	rm -f $tf

	# Test 4: Allow parity stripe count > 4 with --ec-expert
	# (may fail for other reasons, but not due to limit check)
	output=$($LFS setstripe -E -1 -c 16 --ec-expert 16+5 $tf 2>&1) ||
		true
	echo "$output" | grep -qi "exceeds supported limit" &&
		error "should not reject parity count > 4 with --ec-expert"
	return 0
}
run_test 4g "reject EC stripe counts exceeding limits without --ec-expert"

test_5a() {
	enable_ec

	local ids
	local tf=$DIR/$tfile

	stack_trap "rm -f $tf $TMP/$tfile.mirror $TMP/$tfile.data"

	# Create EC file with data mirror + parity mirror
	# Layout: N1 = data, N2 = data, N3 = parity (4+1)
	$LFS setstripe -N -E 1M -c 1 -E -1 -c 1 \
		-N -E 1M -c 4 --ec 4+1 -E -1 -c 4 --ec 4+1 $tf ||
		error "create EC file failed"

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify EC parameters on parity components (mirror 3, N3)
	# Components: 0,1=N1(data), 2,3=N2(data), 4,5=N3(parity)
	verify_comp_parity $tf ${ids[4]}
	verify_ec_stripe_count $tf ${ids[4]} 4 1
	verify_comp_parity $tf ${ids[5]}
	verify_ec_stripe_count $tf ${ids[5]} 4 1

	# Test 1: Read from empty parity mirror - should return immediately
	# with 0 bytes (not hang)
	$LFS mirror read -N3 -o $TMP/$tfile.mirror $tf ||
		error "mirror read from empty parity failed"
	local empty_size=$(stat -c %s $TMP/$tfile.mirror)
	(( empty_size == 0 )) ||
		error "empty parity read should return 0 bytes, got $empty_size"
	rm -f $TMP/$tfile.mirror

	# Test 2: Write data, resync, then read from parity
	cp /etc/passwd $tf || error "failed to write data"

	# Resync to compute parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Read from parity mirror (N3) - should work after resync
	$LFS mirror read -N3 -o $TMP/$tfile.mirror $tf ||
		error "mirror read from parity failed"

	# Parity data won't match /etc/passwd directly (it's computed parity),
	# but verify we got non-empty data of reasonable size
	local parity_size=$(stat -c %s $TMP/$tfile.mirror)
	(( parity_size > 0 )) || error "parity mirror read returned empty"

	# Also verify data mirror can be read correctly
	$LFS mirror read -N1 -o $TMP/$tfile.data $tf ||
		error "mirror read from data failed"
	cmp $TMP/$tfile.data /etc/passwd ||
		error "data mirror read mismatch"
}
run_test 5a "EC mirror read/write commands"

test_5b() {
	enable_ec

	local tf=$DIR/$tfile
	local flags
	local ids

	stack_trap "rm -f $tf"

	# Create EC file with lfs setstripe
	# Layout: Mirror 1 has 3 data components [0,128M], [128M,1G], [1G,EOF]
	#         Mirror 2 has 3 EC components at same extents
	$LFS setstripe -E 128M -E 1G -E -1 --ec 4+2 $tf ||
		error "setstripe failed"

	# Verify file starts in RDONLY state
	verify_flr_state $tf "ro"

	# Get component IDs for both mirrors
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))
	echo "Component IDs: ${ids[@]}"

	# Verify EC parameters on parity components (mirror 2)
	verify_comp_parity $tf ${ids[3]}
	verify_ec_stripe_count $tf ${ids[3]} 4 2
	verify_comp_parity $tf ${ids[4]}
	verify_ec_stripe_count $tf ${ids[4]} 4 2
	verify_comp_parity $tf ${ids[5]}
	verify_ec_stripe_count $tf ${ids[5]} 4 2

	# Write to first component (0-1M, within [0,128M] extent)
	dd if=/dev/zero of=$tf conv=notrunc bs=1M count=1 ||
		error "write to first component failed"

	# Verify file is now in WRITE_PENDING state
	verify_flr_state $tf "wp"

	# Verify the corresponding EC component in mirror 2 is stale
	# Mirror 1 components are ids[0], ids[1], ids[2]
	# Mirror 2 components are ids[3], ids[4], ids[5]
	# After writing to first component, ids[3] should be stale
	verify_comp_stale $tf ${ids[3]}

	# Verify other EC components are NOT stale (component-level granularity)
	flags=$($LFS getstripe -I${ids[4]} $tf |
			awk '/lcme_flags:/ { print $2 }')
	[[ ! $flags =~ "stale" ]] ||
		error "component ${ids[4]} should not be stale after write to first component"

	flags=$($LFS getstripe -I${ids[5]} $tf |
			awk '/lcme_flags:/ { print $2 }')
	[[ ! $flags =~ "stale" ]] ||
		error "component ${ids[5]} should not be stale after write to first component"

	# Resync the file
	$LFS mirror resync $tf || error "mirror resync failed"

	# Verify file is back to RDONLY state
	verify_flr_state $tf "ro"

	# Verify component is no longer stale
	local flags=$($LFS getstripe -I${ids[3]} $tf |
			awk '/lcme_flags:/ { print $2 }')
	[[ ! $flags =~ "stale" ]] ||
		error "component ${ids[3]} still stale after resync: $flags"

	echo "** Write to second component **"

	# Write to second component (at offset 256M, within [128M,1G] extent)
	dd if=/dev/zero of=$tf conv=notrunc bs=1M count=1 seek=256 ||
		error "write to second component failed"

	# Verify file is in WRITE_PENDING state
	verify_flr_state $tf "wp"

	# Verify the corresponding EC component in mirror 2 is stale
	# ids[4] is the second EC component
	verify_comp_stale $tf ${ids[4]}

	# Verify other EC components are NOT stale (component-level granularity)
	flags=$($LFS getstripe -I${ids[3]} $tf |
			awk '/lcme_flags:/ { print $2 }')
	[[ ! $flags =~ "stale" ]] ||
		error "component ${ids[3]} should not be stale after write to second component"

	flags=$($LFS getstripe -I${ids[5]} $tf |
			awk '/lcme_flags:/ { print $2 }')
	[[ ! $flags =~ "stale" ]] ||
		error "component ${ids[5]} should not be stale after write to second component"

	# Resync the file
	$LFS mirror resync $tf || error "mirror resync failed"

	# Verify file is back to RDONLY state
	verify_flr_state $tf "ro"

	# Verify component is no longer stale
	flags=$($LFS getstripe -I${ids[4]} $tf |
			awk '/lcme_flags:/ { print $2 }')
	[[ ! $flags =~ "stale" ]] ||
		error "component ${ids[4]} still stale after resync: $flags"
}
run_test 5b "EC FLR state transitions with writes to different components"

test_6a() {
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with two components in each mirror
	# Mirror 1 (data): [0, 1M], [1M, EOF]
	# Mirror 2 (parity): [0, 1M], [1M, EOF] with EC 4+2
	$LFS setstripe -E 1M -c 2 -E -1 -c 4 --ec 4+2 $tf ||
		error "create EC file failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 4

	# Get component IDs
	local ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' |
			tr '\n' ' '))
	echo "Component IDs: ${ids[@]}"

	local data_comp1=${ids[0]}
	local data_comp2=${ids[1]}
	local parity_comp1=${ids[2]}
	local parity_comp2=${ids[3]}

	# Verify EC parameters on all parity components
	verify_comp_parity $tf $parity_comp1
	verify_ec_stripe_count $tf $parity_comp1 2 2
	verify_comp_parity $tf $parity_comp2
	verify_ec_stripe_count $tf $parity_comp2 4 2

	# Test 1: Cannot set prefer on parity component
	$LFS setstripe --comp-set -I $parity_comp1 --comp-flags=prefer \
		$tf 2>&1 |
		grep -q "cannot set prefer flags on parity component" ||
		error "should not allow prefer on parity component"

	# Test 2: Cannot set prefrd on parity component
	$LFS setstripe --comp-set -I $parity_comp2 --comp-flags=prefrd \
		$tf 2>&1 |
		grep -q "cannot set prefer flags on parity component" ||
		error "should not allow prefrd on parity component"

	# Test 3: Cannot set prefwr on parity component
	$LFS setstripe --comp-set -I $parity_comp1 --comp-flags=prefwr \
		$tf 2>&1 |
		grep -q "cannot set prefer flags on parity component" ||
		error "should not allow prefwr on parity component"

	# Test 4: Can set prefwr on data component in data mirror
	$LFS setstripe --comp-set -I $data_comp1 --comp-flags=prefwr \
		$tf || error "should allow prefwr on data component"
	$LFS getstripe -I$data_comp1 $tf | grep -q "prefwr" ||
		error "prefwr flag not set on data component"

	# Test 5: Can set prefer on data component in data mirror
	$LFS setstripe --comp-set -I $data_comp2 --comp-flags=prefer \
		$tf || error "should allow prefer on data component"
	$LFS getstripe -I$data_comp2 $tf | grep -q "prefer" ||
		error "prefer flag not set on data component"

	# Test 6: Can set prefrd on data component in data mirror
	$LFS setstripe --comp-set -I $data_comp1 --comp-flags=^prefwr \
		$tf || error "failed to clear prefwr"
	$LFS setstripe --comp-set -I $data_comp1 --comp-flags=prefrd \
		$tf || error "should allow prefrd on data component"
	$LFS getstripe -I$data_comp1 $tf | grep -q "prefrd" ||
		error "prefrd flag not set on data component"
}
run_test 6a "Block setting prefer flags on parity components"

test_6b() {
	enable_ec

	local tf=$DIR/$tfile

	# Create EC file: data mirror + parity mirror
	$LFS setstripe -E -1 -c $EC_DSTRIPE $EC_ARG $tf ||
		error "create EC file failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 2

	# Find data and parity component IDs via the parity flag rather than
	# relying on mirror id ordering.
	local data_comp_id=$($LFS getstripe $tf |
		awk '/lcme_id:/ {id=$2}
		     /lcme_flags:/ && !/parity/ {print id; exit}')
	local parity_comp_id=$($LFS getstripe $tf |
		awk '/lcme_id:/ {id=$2}
		     /lcme_flags:.*parity/ {print id; exit}')

	echo "Data component: $data_comp_id, Parity component: $parity_comp_id"

	[[ -n "$data_comp_id" ]] || error "could not find data component ID"
	[[ -n "$parity_comp_id" ]] ||
		error "could not find parity component ID"

	# Verify EC parameters on parity component
	verify_comp_parity $tf $parity_comp_id
	verify_ec_stripe_count $tf $parity_comp_id $EC_DSTRIPE $EC_CSTRIPE

	# Write to file - should select data mirror as primary
	dd if=/dev/urandom of=$tf bs=1M count=2 ||
		error "write to EC file failed"

	# After write, data mirror should be non-stale (init),
	# parity mirror should be stale
	$LFS getstripe -I$data_comp_id $tf | grep -q "init" ||
		error "data mirror should be init after write"

	# Verify parity mirror is stale
	$LFS getstripe -I$parity_comp_id $tf | grep -q "stale" ||
		error "parity mirror should be stale after write"

	# Snapshot the data before resync so we can verify integrity across it
	local sum1=$(md5sum $tf | awk '{print $1}')

	# Resync to update parity mirror
	$LFS mirror resync $tf || error "mirror resync failed"

	# After resync, both mirrors should be init (non-stale)
	$LFS getstripe -I$data_comp_id $tf | grep -q "init" ||
		error "data mirror should be init after resync"
	$LFS getstripe -I$parity_comp_id $tf | grep -q "init" ||
		error "parity mirror should be init after resync"

	local sum2=$(md5sum $tf | awk '{print $1}')
	[[ "$sum1" == "$sum2" ]] ||
		error "data changed after resync: $sum1 vs $sum2"
}
run_test 6b "EC write selects data mirror, not parity mirror"

test_6c() {
	(( OSTCOUNT >= 8 )) || skip "needs >= 8 OSTs"

	enable_ec

	local tf=$DIR/$tfile

	# Create file with 2 data mirrors + 1 EC mirror (data + parity)
	# Mirror 1 (data): stripe on OST0,1
	# Mirror 2 (data): stripe on OST2,3
	# Mirror 3 (data): EC data component with 2 stripes
	# Mirror 4 (parity): EC parity component with 2+2
	$LFS setstripe -N -E -1 -c 2 -o 0,1 \
		-N -E -1 -c 2 -o 2,3 \
		-N -E -1 -c 2 --ec 2+2 $tf ||
		error "create multi-mirror EC file failed"

	verify_mirror_count $tf 4
	verify_comp_count $tf 4

	# Get component IDs for EC verification
	local ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' |
			tr '\n' ' '))
	echo "Component IDs: ${ids[@]}"

	# Verify EC parameters on EC parity component (mirror 4)
	verify_comp_parity $tf ${ids[3]}
	verify_ec_stripe_count $tf ${ids[3]} 2 2

	# Write to file - should select one of the data mirrors
	dd if=/dev/urandom of=$tf bs=1M count=2 ||
		error "write to EC file failed"
	$LFS getstripe $tf

	# Get mirror IDs
	local mirror_ids=($($LFS getstripe $tf |
		awk '/lcme_mirror_id:/ {print $2}' | sort -u))
	echo "Mirror IDs: ${mirror_ids[@]}"

	# Count non-stale mirrors (should be 1 - the primary data mirror)
	local non_stale_count=0
	local stale_count=0
	local parity_mirror_id=""

	for mirror_id in "${mirror_ids[@]}"; do
		# Get first component of this mirror
		# lcme_id comes before lcme_mirror_id, so we need to save it
		local comp_id=$($LFS getstripe $tf |
			awk -v mid="$mirror_id" \
			'/lcme_id:/ {id=$2} \
			/lcme_mirror_id:/ {if ($2 == mid) {print id; exit}}')

		if $LFS getstripe -I$comp_id $tf | grep -q "stale"; then
			((stale_count++))
		else
			((non_stale_count++))
		fi

		# Check if this is the parity mirror
		if $LFS getstripe -I$comp_id $tf | grep -q "parity"; then
			parity_mirror_id=$mirror_id
		fi
	done

	echo "Non-stale mirrors: $non_stale_count, Stale mirrors: $stale_count"
	echo "Parity mirror ID: $parity_mirror_id"

	# Should have exactly 1 non-stale mirror (the selected data mirror)
	(( non_stale_count == 1 )) ||
		error "expected 1 non-stale mirror, got $non_stale_count"

	# Should have 3 stale mirrors (2 other data mirrors + parity mirror)
	(( stale_count == 3 )) ||
		error "expected 3 stale mirrors, got $stale_count"

	# Parity mirror should be stale
	[[ -n "$parity_mirror_id" ]] ||
		error "could not find parity mirror"
	local parity_comp_id=$($LFS getstripe $tf |
		awk -v mid="$parity_mirror_id" \
		'/lcme_id:/ {id=$2} \
		/lcme_mirror_id:/ {if ($2 == mid) {print id; exit}}')
	$LFS getstripe -I$parity_comp_id $tf | grep -q "stale" ||
		error "parity mirror should be stale after write"
}
run_test 6c "EC with multiple data mirrors - parity never selected"

test_6d() {
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file: data mirror + parity mirror
	$LFS setstripe -E -1 -c 4 --ec 4+2 $tf ||
		error "create EC file failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 2

	# Find data and parity component IDs via the parity flag rather than
	# relying on mirror id ordering.
	local data_comp_id=$($LFS getstripe $tf |
		awk '/lcme_id:/ {id=$2}
		     /lcme_flags:/ && !/parity/ {print id; exit}')
	local parity_comp_id=$($LFS getstripe $tf |
		awk '/lcme_id:/ {id=$2}
		     /lcme_flags:.*parity/ {print id; exit}')

	echo "Data component: $data_comp_id, Parity component: $parity_comp_id"

	[[ -n "$data_comp_id" ]] || error "could not find data component ID"
	[[ -n "$parity_comp_id" ]] ||
		error "could not find parity component ID"

	# Verify EC parameters on parity component
	verify_comp_parity $tf $parity_comp_id
	verify_ec_stripe_count $tf $parity_comp_id 4 2

	# Write and resync to get both mirrors in sync
	dd if=/dev/urandom of=$tf bs=1M count=2 ||
		error "write to EC file failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	# Verify both mirrors are in sync (init, not stale)
	$LFS getstripe -I$data_comp_id $tf | grep -q "init" ||
		error "data mirror should be init after resync"
	$LFS getstripe -I$parity_comp_id $tf | grep -q "init" ||
		error "parity mirror should be init after resync"

	# Manually mark parity mirror stale
	$LFS setstripe --comp-set -I $parity_comp_id --comp-flags=stale \
		$tf || error "failed to mark parity mirror stale"

	# Verify parity mirror is now stale
	$LFS getstripe -I$parity_comp_id $tf | grep -q "stale" ||
		error "parity mirror should be stale after manual marking"

	# Verify data mirror is still init
	$LFS getstripe -I$data_comp_id $tf | grep -q "init" ||
		error "data mirror should still be init"

	# Resync should restore parity mirror from data mirror
	$LFS mirror resync $tf || error "mirror resync failed"

	# After resync, both should be init again
	$LFS getstripe -I$data_comp_id $tf | grep -q "init" ||
		error "data mirror should be init after resync"
	$LFS getstripe -I$parity_comp_id $tf | grep -q "init" ||
		error "parity mirror should be init after resync"

	# Verify data integrity
	local sum1=$(md5sum $tf | awk '{print $1}')
	$LFS mirror resync $tf || error "final resync failed"
	local sum2=$(md5sum $tf | awk '{print $1}')
	[[ "$sum1" == "$sum2" ]] ||
		error "data changed after resync: $sum1 vs $sum2"
}
run_test 6d "Manually mark parity mirror stale and resync"

test_6e() {
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file: data mirror + parity mirror
	$LFS setstripe -E -1 -c 4 --ec 4+2 $tf ||
		error "create EC file failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 2

	# Find data and parity component IDs via the parity flag rather than
	# relying on mirror id ordering.
	local data_comp_id=$($LFS getstripe $tf |
		awk '/lcme_id:/ {id=$2}
		     /lcme_flags:/ && !/parity/ {print id; exit}')
	local parity_comp_id=$($LFS getstripe $tf |
		awk '/lcme_id:/ {id=$2}
		     /lcme_flags:.*parity/ {print id; exit}')

	echo "Data component: $data_comp_id, Parity component: $parity_comp_id"

	[[ -n "$data_comp_id" ]] || error "could not find data component ID"
	[[ -n "$parity_comp_id" ]] ||
		error "could not find parity component ID"

	# Verify EC parameters on parity component
	verify_comp_parity $tf $parity_comp_id
	verify_ec_stripe_count $tf $parity_comp_id 4 2

	# Write and resync to get both mirrors in sync
	dd if=/dev/urandom of=$tf bs=1M count=2 ||
		error "write to EC file failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	# Verify both mirrors are in sync (init, not stale)
	$LFS getstripe -I$data_comp_id $tf | grep -q "init" ||
		error "data mirror should be init after resync"
	$LFS getstripe -I$parity_comp_id $tf | grep -q "init" ||
		error "parity mirror should be init after resync"

	# Manually mark data mirror stale, leaving only parity mirror valid
	$LFS setstripe --comp-set -I $data_comp_id --comp-flags=stale $tf ||
		error "failed to mark data mirror stale"

	# Verify data mirror is now stale
	$LFS getstripe -I$data_comp_id $tf | grep -q "stale" ||
		error "data mirror should be stale after manual marking"

	# Verify parity mirror is still init (non-stale)
	$LFS getstripe -I$parity_comp_id $tf | grep -q "init" ||
		error "parity mirror should still be init"

	# Attempt to write with only parity mirror non-stale should fail
	# with ENODATA (61 - No data available) because parity mirrors
	# cannot be selected as write targets
	dd if=/dev/urandom of=$tf bs=1M count=1 conv=notrunc 2>&1 |
		grep -q "No data available" ||
		error "write should fail with ENODATA when only parity" \
			"mirror is valid"

	# Verify file state unchanged - data mirror still stale
	$LFS getstripe -I$data_comp_id $tf | grep -q "stale" ||
		error "data mirror should still be stale after failed write"
}
run_test 6e "Write fails when only parity mirror is non-stale"

test_7a() {
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file: data mirror + parity mirror
	$LFS setstripe -E -1 -c 4 --ec 4+2 $tf ||
		error "create EC file failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 2

	# Get component IDs - data mirror is mirror_id 1, parity is mirror_id 2
	local data_comp_id=$($LFS getstripe $tf |
		awk '/lcme_id:/ {id=$2} /lcme_mirror_id:.*1$/ {print id; exit}')
	local parity_comp_id=$($LFS getstripe $tf |
		awk '/lcme_id:/ {id=$2} /lcme_mirror_id:.*2$/ {print id; exit}')

	echo "Data component: $data_comp_id, Parity component: $parity_comp_id"

	[[ -n "$data_comp_id" ]] || error "could not find data component ID"
	[[ -n "$parity_comp_id" ]] ||
		error "could not find parity component ID"

	# Verify EC parameters on parity component
	verify_comp_parity $tf $parity_comp_id
	verify_ec_stripe_count $tf $parity_comp_id 4 2

	# Write initial data and resync
	dd if=/dev/urandom of=$tf bs=1M count=2 ||
		error "write to EC file failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	# Verify both mirrors are in sync (init, not stale)
	$LFS getstripe -I$data_comp_id $tf | grep -q "init" ||
		error "data mirror should be init after resync"
	$LFS getstripe -I$parity_comp_id $tf | grep -q "init" ||
		error "parity mirror should be init after resync"

	# Save checksum of parity mirror
	local sum0=$($LFS mirror read -N2 $tf | dd bs=1M count=2 | md5sum)
	echo "Initial parity mirror checksum: $sum0"

	# Set nosync flag on parity mirror to snapshot it
	$LFS setstripe --comp-set -I $parity_comp_id --comp-flags=nosync \
		$tf || error "failed to set nosync on parity mirror"

	# Verify nosync flag is set
	$LFS getstripe -I$parity_comp_id $tf | grep -q "nosync" ||
		error "nosync flag not set on parity mirror"

	# Write new data - this should update data mirror but not parity
	dd if=/dev/urandom of=$tf bs=1M count=2 ||
		error "second write to EC file failed"

	# Resync - parity mirror should remain stale due to nosync flag
	$LFS mirror resync $tf || error "mirror resync failed"

	# Verify parity mirror is still stale and has nosync flag
	$LFS getstripe -I$parity_comp_id $tf | grep -q "stale" ||
		error "parity mirror should be stale after resync with nosync"
	$LFS getstripe -I$parity_comp_id $tf | grep -q "nosync" ||
		error "nosync flag should still be set on parity mirror"

	# Verify parity mirror content hasn't changed
	local sum1=$($LFS mirror read -N1 $tf | md5sum)
	local sum2=$($LFS mirror read -N2 $tf | dd bs=1M count=2 | md5sum)

	echo "Data mirror checksum: $sum1"
	echo "Parity mirror checksum: $sum2"
	[[ $sum0 = $sum2 ]] ||
		error "parity mirror changed: $sum0 vs $sum2"

	# Clear nosync flag and resync to update parity mirror
	$LFS setstripe --comp-set -I $parity_comp_id \
		--comp-flags=^nosync $tf ||
		error "failed to clear nosync on parity mirror"

	$LFS mirror resync $tf || error "final resync failed"

	# After clearing nosync and resyncing, both mirrors should be init
	$LFS getstripe -I$data_comp_id $tf | grep -q "init" ||
		error "data mirror should be init after final resync"
	$LFS getstripe -I$parity_comp_id $tf | grep -q "init" ||
		error "parity mirror should be init after final resync"

	# Verify parity mirror is now updated
	sum1=$($LFS mirror read -N1 $tf | md5sum)
	sum2=$($LFS mirror read -N2 $tf | md5sum)
	echo "Final data mirror checksum: $sum1"
	echo "Final parity mirror checksum: $sum2"
}
run_test 7a "nosync flag on parity mirror prevents resync updates"

test_7b() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"

	enable_ec

	local tf=$DIR/$tfile
	local victim=$DIR/$tfile.victim

	stack_trap "rm -f $tf $victim"

	$LFS setstripe -E -1 -c 4 --ec 4+2 $tf ||
		error "setstripe failed"
	verify_mirror_count $tf 2

	identify_ec_mirrors $tf
	[[ -n $ec_data_id && -n $ec_parity_id ]] ||
		error "failed to identify data/parity mirrors"

	# A parity mirror holds no file data, so a file left holding only one
	# cannot be read.  Splitting a parity mirror into a file of its own is
	# refused, both with an explicit victim and with the default
	# '<file>.mirror~ID' name.  Its contents are still reachable with
	# 'lfs mirror read -N ID', and 'lfs mirror delete' removes it.
	$LFS mirror split --mirror-id $ec_parity_id -f $victim $tf &&
		error "split of a parity mirror to a file should be refused"
	[[ ! -e $victim ]] ||
		error "refused split left victim file '$victim' behind"

	$LFS mirror split --mirror-id $ec_parity_id $tf &&
		error "split of a parity mirror should be refused"
	[[ ! -e $tf.mirror~$ec_parity_id ]] ||
		error "refused split left a victim file behind"

	verify_mirror_count $tf 2

	return 0
}
run_test 7b "mirror split of a parity mirror to a file is refused"

test_7c() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"

	enable_ec

	local tf=$DIR/$tfile
	local ids

	# Create file with multiple components and EC
	$LFS setstripe -E 128M --ec 4+2 -E -1 --ec 4+2 $tf ||
		error "setstripe failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 4

	# Get mirror IDs
	ids=($($LFS getstripe $tf | awk '/lcme_mirror_id:/ {print $2}' |
		sort -u | tr '\n' ' '))

	(( ${#ids[@]} == 2 )) ||
		error "expected 2 mirrors, got ${#ids[@]}"

	# Find parity mirror
	local parity_mirror_id
	local flags=$($LFS getstripe --mirror-id=${ids[1]} $tf |
		      awk '/lcme_flags:/ {print $2; exit}')

	if [[ $flags =~ "parity" ]]; then
		parity_mirror_id=${ids[1]}
	else
		parity_mirror_id=${ids[0]}
	fi

	# Split parity mirror with -d
	$LFS mirror split --mirror-id $parity_mirror_id -d $tf ||
		error "split -d failed for parity mirror"

	# Verify only data mirror remains with 2 components
	verify_mirror_count $tf 1
	verify_comp_count $tf 2
}
run_test 7c "mirror split -d works for multi-component parity mirrors"

test_7d() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"

	enable_ec

	local tf=$DIR/$tfile
	local ids

	# Create file with regular mirror + EC mirror
	$LFS mirror create -N -E -1 -c 2 \
			   -N -E -1 -c 2 --ec 2+2 $tf ||
		error "mirror create failed"

	verify_mirror_count $tf 3

	# Get all mirror IDs
	ids=($($LFS getstripe $tf | awk '/lcme_mirror_id:/ {print $2}' |
		sort -u | tr '\n' ' '))

	(( ${#ids[@]} == 3 )) ||
		error "expected 3 mirrors, got ${#ids[@]}"

	# Find parity mirror (should be the last one)
	local parity_mirror_id
	for id in "${ids[@]}"; do
		local flags=$($LFS getstripe --mirror-id=$id $tf |
			      awk '/lcme_flags:/ {print $2; exit}')
		if [[ $flags =~ "parity" ]]; then
			parity_mirror_id=$id
			break
		fi
	done

	[[ -n $parity_mirror_id ]] ||
		error "could not find parity mirror"

	# Split parity mirror with -d
	$LFS mirror split --mirror-id $parity_mirror_id -d $tf ||
		error "split -d failed for parity mirror"

	# Verify 2 mirrors remain (2 data mirrors)
	verify_mirror_count $tf 2
}
run_test 7d "mirror split -d works with mixed regular and EC mirrors"

test_7e() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"

	enable_ec

	local tf=$DIR/$tfile

	# Build a 3-mirror file: a plain mirror plus an EC data+parity pair, so
	# co-splitting the data mirror (which drags its parity along) still
	# leaves a mirror behind and does not trip the empty-file guard.
	$LFS mirror create -N -E -1 -c 2 \
			   -N -E -1 -c 2 --ec 2+2 $tf ||
		error "mirror create failed"
	verify_mirror_count $tf 3

	identify_ec_mirrors $tf
	[[ -n $ec_data_id && -n $ec_parity_id && -n $ec_plain_id ]] ||
		error "failed to identify data/parity/plain mirrors"

	local plain_id=$ec_plain_id

	# Splitting the EC data mirror must co-split its parity mirror
	# automatically, leaving only the plain mirror behind.
	$LFS mirror split --mirror-id $ec_data_id -d $tf ||
		error "split -d of EC data mirror failed"

	verify_mirror_count $tf 1
	local remaining_id=$($LFS getstripe $tf |
			     awk '/lcme_mirror_id:/ {print $2; exit}')
	(( remaining_id == plain_id )) ||
		error "expected plain mirror $plain_id, got $remaining_id"

	# A lone data+parity pair cannot be split apart with -d: removing the
	# data mirror would co-split the parity and empty the file, so the MDS
	# must refuse it and leave the file untouched.
	local tf2=$DIR/$tfile.pair
	$LFS setstripe -E -1 -c 2 --ec 2+2 $tf2 ||
		error "setstripe failed"
	verify_mirror_count $tf2 2

	identify_ec_mirrors $tf2
	[[ -n $ec_data_id && -n $ec_parity_id ]] ||
		error "failed to identify data/parity mirrors of $tf2"

	$LFS mirror split --mirror-id $ec_data_id -d $tf2 &&
		error "splitting a lone data+parity pair should be refused"
	verify_mirror_count $tf2 2
}
run_test 7e "split data mirror -d co-splits its EC parity mirror"

test_7f() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"

	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E -1 -c 4 --ec 4+2 $tf ||
		error "setstripe failed"
	verify_mirror_count $tf 2

	identify_ec_mirrors $tf
	[[ -n $ec_data_id && -n $ec_parity_id ]] ||
		error "failed to identify data/parity mirrors"

	# Removing the parity mirror is allowed, and warns while naming the
	# data mirror that is losing EC protection.
	local expect="parity mirror $ec_parity_id .* data mirror $ec_data_id"
	local out

	out=$($LFS mirror delete --mirror-id $ec_parity_id $tf 2>&1) ||
		error "mirror delete of parity mirror $ec_parity_id failed"
	echo "$out" | grep -q "$expect" ||
		error "expected warning naming data mirror $ec_data_id: $out"

	verify_mirror_count $tf 1

	local remaining_id=$($LFS getstripe $tf |
			     awk '/lcme_mirror_id:/ {print $2; exit}')
	(( remaining_id == ec_data_id )) ||
		error "expected data mirror $ec_data_id, got $remaining_id"

	# The data mirror left behind is no longer protected, so its link to
	# the removed parity mirror must be gone.
	local link=$($LFS getstripe -v --mirror-id=$ec_data_id $tf |
		     awk '/lcme_mirror_link_id:/ {print $2; exit}')
	(( ${link:-0} == 0 )) ||
		error "data mirror $ec_data_id still links to '$link'"

	# Removing the parity of a file that keeps another data mirror takes
	# away no redundancy, so it must not warn.
	local tf2=$DIR/$tfile.redundant

	stack_trap "rm -f $tf2"

	$LFS mirror create -N -E -1 -c 2 \
			   -N -E -1 -c 2 --ec 2+2 $tf2 ||
		error "mirror create failed"
	verify_mirror_count $tf2 3

	identify_ec_mirrors $tf2
	[[ -n $ec_parity_id ]] || error "failed to identify parity mirror"

	out=$($LFS mirror delete --mirror-id $ec_parity_id $tf2 2>&1) ||
		error "mirror delete of parity mirror failed"
	echo "$out" | grep -qi "warning" &&
		error "warned though a data mirror remains: $out"
	verify_mirror_count $tf2 2
}
run_test 7f "mirror delete of a parity mirror warns only if redundancy lost"

test_7g() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"

	enable_ec

	local tf=$DIR/$tfile
	local victim=$DIR/$tfile.victim

	stack_trap "rm -f $tf $victim"

	# Build a 3-mirror file: a plain mirror plus an EC data+parity pair,
	# so co-splitting the data mirror to the victim (which drags its
	# parity along) still leaves a mirror behind on the source.
	$LFS mirror create -N -E -1 -c 2 \
			   -N -E -1 -c 2 --ec 2+2 $tf ||
		error "mirror create failed"
	verify_mirror_count $tf 3

	dd if=/dev/urandom of=$tf bs=1M count=2 || error "write failed"
	$LFS mirror resync $tf || error "mirror resync failed"
	local sum=$(md5sum $tf | awk '{print $1}')

	identify_ec_mirrors $tf
	[[ -n $ec_data_id && -n $ec_parity_id && -n $ec_plain_id ]] ||
		error "failed to identify data/parity/plain mirrors"

	local data_id=$ec_data_id
	local parity_id=$ec_parity_id
	local plain_id=$ec_plain_id

	# Splitting the EC data mirror to a victim must move both the data
	# mirror and its parity mirror to the victim, making the victim a
	# standalone read-only 2-mirror EC file.
	$LFS mirror split --mirror-id $data_id -f $victim $tf ||
		error "split -f of EC data mirror failed"

	# Source keeps only the plain mirror.
	verify_mirror_count $tf 1
	local remaining_id=$($LFS getstripe $tf |
			     awk '/lcme_mirror_id:/ {print $2; exit}')
	(( remaining_id == plain_id )) ||
		error "expected plain mirror $plain_id, got $remaining_id"

	# Victim holds exactly the data+parity pair.
	verify_mirror_count $victim 2
	local victim_parity_flags=$($LFS getstripe --mirror-id=$parity_id \
				    $victim |
				    awk '/lcme_flags:/ {print $2; exit}')
	[[ $victim_parity_flags =~ "parity" ]] ||
		error "mirror $parity_id in victim should keep the parity flag"

	local victim_flags=$($LFS getstripe -v $victim |
			     awk '/lcm_flags:/ {print $2; exit}')
	[[ $victim_flags =~ "ro" ]] ||
		error "victim should be read-only, got flags '$victim_flags'"

	# The data<->parity link must survive the split.
	local vlink=$($LFS getstripe -v $victim | awk -v m=$data_id '
		/lcme_mirror_id:/ { cur = $2 }
		/lcme_mirror_link_id:/ { if (cur == m) { print $2; exit } }')
	(( vlink == parity_id )) ||
		error "victim data mirror links to '$vlink', not $parity_id"

	local vsum=$(md5sum $victim | awk '{print $1}')
	[[ $vsum == $sum ]] ||
		error "victim content differs from source ($vsum != $sum)"

	# A lone data+parity pair cannot be co-split to a victim: moving both
	# mirrors would empty the source, so the MDS must refuse it and leave
	# the file untouched.
	local tf2=$DIR/$tfile.pair
	local victim2=$DIR/$tfile.victim2

	stack_trap "rm -f $tf2 $victim2"
	$LFS setstripe -E -1 -c 2 --ec 2+2 $tf2 ||
		error "setstripe failed"
	verify_mirror_count $tf2 2

	identify_ec_mirrors $tf2
	[[ -n $ec_data_id && -n $ec_parity_id ]] ||
		error "failed to identify data/parity mirrors of $tf2"

	local out
	out=$($LFS mirror split --mirror-id $ec_data_id -f $victim2 $tf2 \
	      2>&1) &&
		error "co-splitting a lone data+parity pair should be refused"
	verify_mirror_count $tf2 2
	echo "$out" | grep -q "only data mirror" ||
		error "refusal should name the only data mirror, got: $out"
	[[ ! -e $victim2 ]] ||
		error "refused split left victim file '$victim2' behind"
}
run_test 7g "split data mirror -f co-splits its EC parity mirror to victim"

test_7h() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"

	enable_ec

	local tf=$DIR/$tfile
	local victim=$DIR/$tfile.victim

	stack_trap "rm -f $tf $victim"

	# Build a plain mirror plus an EC data+parity pair, so the plain
	# mirror stays in-sync and the split is not resynced away first.
	$LFS mirror create -N -E -1 -c 2 \
			   -N -E -1 -c 2 --ec 2+2 $tf ||
		error "mirror create failed"
	verify_mirror_count $tf 3

	dd if=/dev/urandom of=$tf bs=1M count=2 || error "write failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	identify_ec_mirrors $tf
	[[ -n $ec_data_id && -n $ec_parity_id && -n $ec_plain_id ]] ||
		error "failed to identify data/parity/plain mirrors"

	local data_id=$ec_data_id
	local parity_id=$ec_parity_id

	# Mark only the EC data mirror stale, leaving its parity in-sync.
	$LFS setstripe --comp-set --mirror-id $data_id --comp-flags=stale \
		$tf || error "failed to mark data mirror $data_id stale"
	$LFS getstripe --mirror-id=$data_id $tf | grep -q "stale" ||
		error "data mirror $data_id should be stale"

	# The victim's data mirror is its only copy of the file, so the split
	# must clear its stale flag.  Its parity was computed from a different
	# version of that data, so the parity is the one that must be marked
	# stale for `lfs mirror resync` to rebuild it.
	$LFS mirror split --mirror-id $data_id -f $victim $tf ||
		error "split of stale EC data mirror failed"

	verify_mirror_count $victim 2

	local dflags=$($LFS getstripe --mirror-id=$data_id $victim |
		       awk '/lcme_flags:/ {print $2; exit}')
	[[ ! $dflags =~ "stale" ]] ||
		error "victim data mirror $data_id is stale: '$dflags'"

	local pflags=$($LFS getstripe --mirror-id=$parity_id $victim |
		       awk '/lcme_flags:/ {print $2; exit}')
	[[ $pflags =~ "stale" ]] ||
		error "victim parity mirror $parity_id not stale: '$pflags'"

	# A victim left with a stale data mirror is unusable: it reads back as
	# a 0-length file, and `lfs mirror resync` cannot repair it because
	# the only non-stale mirror is the parity one.
	$LFS mirror resync $victim || error "resync of victim failed"

	$LFS getstripe $victim | grep -q "stale" &&
		error "victim still has a stale mirror after resync"

	# Both mirrors in-sync on the source must leave both in-sync on the
	# victim: there is nothing for the split to invalidate.
	local tf2=$DIR/$tfile.sync
	local victim2=$DIR/$tfile.victim2

	stack_trap "rm -f $tf2 $victim2"
	$LFS mirror create -N -E -1 -c 2 \
			   -N -E -1 -c 2 --ec 2+2 $tf2 ||
		error "mirror create failed"
	dd if=/dev/urandom of=$tf2 bs=1M count=2 || error "write failed"
	$LFS mirror resync $tf2 || error "mirror resync failed"

	identify_ec_mirrors $tf2
	[[ -n $ec_data_id && -n $ec_parity_id ]] ||
		error "failed to identify data/parity mirrors of $tf2"

	$LFS mirror split --mirror-id $ec_data_id -f $victim2 $tf2 ||
		error "split of in-sync EC data mirror failed"

	$LFS getstripe $victim2 | grep -q "stale" &&
		error "in-sync split should not mark any victim mirror stale"

	return 0
}
run_test 7h "split of a stale EC data mirror leaves a usable victim"

test_7i() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"

	enable_ec

	local tf=$DIR/$tfile
	local tf2=$DIR/$tfile.pair
	local sum new

	stack_trap "rm -f $tf $tf2"

	# A parity mirror holds no copy of the file data, so it must not count
	# as the good copy that lets a split skip the last-good-copy resync.

	# Splitting the only in-sync data mirror while the other data mirror
	# is stale: the in-sync parity keeps the layout from looking all-stale,
	# so nothing downstream refuses the split and the file is destroyed
	# unless the resync runs first.
	$LFS mirror create -N -E -1 -c 2 \
			   -N -E -1 -c 2 --ec 2+2 $tf ||
		error "mirror create failed"
	dd if=/dev/urandom of=$tf bs=1M count=2 || error "write failed"
	$LFS mirror resync $tf || error "mirror resync failed"
	sum=$(md5sum $tf | awk '{print $1}')

	identify_ec_mirrors $tf
	[[ -n $ec_data_id && -n $ec_parity_id && -n $ec_plain_id ]] ||
		error "failed to identify data/parity/plain mirrors"

	$LFS setstripe --comp-set --mirror-id $ec_data_id \
		--comp-flags=stale $tf ||
		error "failed to mark EC data mirror $ec_data_id stale"

	$LFS mirror split --mirror-id $ec_plain_id -d $tf ||
		error "split of the last good copy failed"

	new=$(md5sum $tf 2>/dev/null | awk '{print $1}')
	[[ $new == $sum ]] ||
		error "source content lost after split ('$new' != '$sum')"

	$LFS getstripe $tf | grep -q "stale" &&
		error "source left with a stale mirror after split"

	# Co-splitting the only in-sync data mirror drags its parity along, so
	# the parity left behind cannot stand in for the resync either.
	$LFS mirror create -N -E -1 -c 2 --ec 2+2 \
			   -N -E -1 -c 2 $tf2 ||
		error "mirror create failed"
	dd if=/dev/urandom of=$tf2 bs=1M count=2 || error "write failed"
	$LFS mirror resync $tf2 || error "mirror resync failed"
	sum=$(md5sum $tf2 | awk '{print $1}')

	identify_ec_mirrors $tf2
	[[ -n $ec_data_id && -n $ec_parity_id && -n $ec_plain_id ]] ||
		error "failed to identify mirrors of $tf2"

	$LFS setstripe --comp-set --mirror-id $ec_plain_id \
		--comp-flags=stale $tf2 ||
		error "failed to mark plain mirror $ec_plain_id stale"

	$LFS mirror split --mirror-id $ec_data_id -d $tf2 ||
		error "co-split of the last good copy failed"

	verify_mirror_count $tf2 1

	new=$(md5sum $tf2 2>/dev/null | awk '{print $1}')
	[[ $new == $sum ]] ||
		error "source content lost after co-split ('$new' != '$sum')"

	$LFS getstripe $tf2 | grep -q "stale" &&
		error "source left with a stale mirror after co-split"

	return 0
}
run_test 7i "split resyncs when only parity mirrors are non-stale"

test_10() {
	local tf=${DIR}/${tdir}/$tfile

	# The number of parity stripes in the EC mirror must be equal to or
	# less than the number of data stripes in the same EC mirror.
	(( OSTCOUNT >= 5 )) || skip_env "needs >= 5 OSTs"
	enable_ec

	test_mkdir $DIR/$tdir

	# Test that creating an ec 2+3 mirror fails (parity > data)
	$LFS setstripe -E -1 -S 4M -c 4 --ec 2+3 $tf >/dev/null &&
		error "setstripe --ec 2+3 succeeded when it shouldn't"

	return 0
}
run_test 10 "cannot create overly large ec mirrors"

test_11() {
	# The number of parity stripes in the EC mirror can be equal to
	# the number of data stripes in the same EC mirror.
	(( OSTCOUNT >= 4 )) || skip_env "needs >= 4 OSTs"
	enable_ec

	test_mkdir $DIR/$tdir
	# Test that creating ec 2+2 mirror works
	$LFS setstripe -E -1 -S 4M -c 4 --ec 2+2 $DIR/$tdir/$tfile ||
	    error "setstripe --ec 2+2 failed"
}
run_test 11 "can create --ec 2+2"

test_12a() {
	local tf=${DIR}/${tdir}/$tfile
	local tf_data=${DIR}/${tdir}/${tfile}.data
	local tf_ec=${DIR}/${tdir}/${tfile}.ec

	# test resyncing a stale ec mirror
	(( OSTCOUNT >= 4 )) || skip_env "needs >= 4 OSTs"
	enable_ec


	test_mkdir $DIR/$tdir

	$LFS setstripe -E -1 -S 4M -c 4 --ec 2+2 $tf ||
	    error "setstripe --ec 2+2 failed"

	# Write the first 3 stripes with \001, \002 and \003
	tr "\000" "\001" < /dev/zero | dd bs=64k count=64          \
		iflag=fullblock of=$tf 2>/dev/null
	tr "\000" "\002" < /dev/zero | dd bs=64k count=64 seek=64  \
		iflag=fullblock of=$tf 2>/dev/null
	tr "\000" "\003" < /dev/zero | dd bs=64k count=64 seek=128 \
		iflag=fullblock of=$tf 2>/dev/null

	# Expected file content:
	#  od -t x1 -A x $tf
	#  000000 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
	#  *
	#  400000 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02
	#  *
	#  800000 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03
	#  *
	#  c00000

	echo "fa9fe1782aee74e978e806fb6a0e7a4a1c83610f $tf" \
	    | sha1sum -c - || error "wrong content in $tf after write"

	# resync the ec mirror:
	$LFS mirror resync $tf || error "failed to resync ec mirror"

	# Verify the mirror is no longer stale
	$LFS getstripe $tf | grep lcme_flags | grep stale &&
	    error "after resyncing $tf, it still contains stale component"

	# verify the file content did not change after updating ec mirror
	echo "fa9fe1782aee74e978e806fb6a0e7a4a1c83610f $tf" |
		sha1sum -c - || error "wrong content in $tf after resync"

	# Verify the data mirror is still correct
	rm -f $tf_data
	$LFS mirror read --mirror-id 1 -o $tf_data $tf
	echo "fa9fe1782aee74e978e806fb6a0e7a4a1c83610f $tf_data" |
		sha1sum -c - || error "wrong content in data mirror"

	# Expected content of the ec mirror.
	# With --ec 2+2 on a 4-stripe file, ec_split_stripes creates
	# 2 raid sets of 2 data stripes each, with 2 parity stripes per set
	# (4 parity stripes total, 16 MiB parity mirror).
	#
	# Raid set 0: data stripes 0 (0x01) and 1 (0x02) -> parity stripes 0, 1
	# Raid set 1: data stripes 2 (0x03) and 3 (0x00) -> parity stripes 2, 3
	#
	#  000000 7b 7b 7b ...  (parity stripe 0)
	#  400000 f5 f5 f5 ...  (parity stripe 1)
	#  800000 8f 8f 8f ...  (parity stripe 2)
	#  c00000 01 01 01 ...  (parity stripe 3)

	# Verify we have expected content in the ec mirror
	rm -f $tf_ec
	$LFS mirror read --mirror-id 2 -o $tf_ec $tf
	echo "f1a95d68d4c98de8833bb4ce63756a338df99795 $tf_ec" |
	    sha1sum -c - || error "wrong content in ec mirror"
}
run_test 12a "resync stale parities"

test_12b() {
	# ZFS lseek does not reliably report holes for dirty data
	# (dmu_offset_next() returns EBUSY and the txg_wait_synced() retry in
	# osd_lseek() is not enough), so the resync computes and writes ec
	# parities across the whole sparse region instead of skipping the holes,
	# eventually exhausting OST space and failing with ENOSPC.
	#
	# This seems to be related to LU-14217 where the fix was not enough. It
	# needs to be investigated separately.
	[[ "$ost1_FSTYPE" != "zfs" ]] ||
		skip "LU-14217: lseek holes unreliable on ZFS"

	# test resyncing a stale ec mirror with huge sparse file
	(( OSTCOUNT >= 3 )) || skip_env "needs >= 3 OSTs"
	enable_ec

	test_mkdir $DIR/$tdir

	$LFS setstripe -E -1 -S 4M -c 3 --ec 2+1 $DIR/$tdir/$tfile ||
		error "setstripe --ec 2+1 failed"

	# gauge I/O performance so resync can be bounded relative to it later
	local start=$SECONDS
	# Sparse file: one stripe at the head and one near 4 TiB, gap in between.
	tr "\000" "\001" < /dev/zero | dd bs=64k count=64          \
		iflag=fullblock of=$DIR/$tdir/$tfile 2>/dev/null
	tr "\000" "\002" < /dev/zero | dd bs=64k count=64          \
		seek=64000000  \
		iflag=fullblock of=$DIR/$tdir/$tfile 2>/dev/null
	local elapsed=$((SECONDS - start))
	# SECONDS has 1s resolution; treat sub-second writes as 1s.
	(( elapsed >= 1 )) || elapsed=1

	# Truncate to 10 TiB to have a hole at the end
	$TRUNCATE $DIR/$tdir/$tfile 10995116277760 ||
		error "failed to truncate file to 10 TiB"

	# Resync the EC mirror. Holes in the sparse file cause stale parity
	# regions to be punched on resync. When the OST backend lacks fallocate
	# hole-punch (e.g. osd-zfs), resync falls back to writing zeros; with
	# holes this large that fallback is rejected as unsupported and resync
	# fails with EOPNOTSUPP. Keep this test disabled on ZFS until osd-zfs
	# hole-punch is implemented (LU-20435).
	#
	# When holes are skipped correctly, resync should only touch the two
	# data regions above and finish within 10x of the initial write time.
	# A regression would hit the timeout instead of running for hours.
	local timeout=$((elapsed * 10))
	echo "mirror resync timeout set to $timeout"
	timeout -k 10 $timeout $LFS mirror resync $DIR/$tdir/$tfile ||
		error "failed to resync ec mirror"

	# Verify the mirror is no longer stale
	$LFS getstripe $DIR/$tdir/$tfile | grep lcme_flags | grep stale &&
		error "$DIR/$tdir/$tfile still stale after resync" || true
}
run_test 12b "resync huge sparse file (10 TiB)"

test_12c() {
	# Sparse file like 12b: stripe sets 0 and 3 written, 1 and 2 are holes.
	# Resync must skip holed stripe sets and punch the matching parity
	# regions instead of rewriting them.
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=${DIR}/${tdir}/$tfile
	local stripe_size=$((4 * 1024 * 1024))
	local stripe_set_size=$((4 * stripe_size))
	local ec_set_size=$((2 * stripe_size))

	test_mkdir $DIR/$tdir
	stack_trap "rm -f $tf"

	$LFS setstripe -E -1 -S 4M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	tr "\000" "\001" < /dev/zero | dd bs=$stripe_set_size count=1 \
		iflag=fullblock of=$tf 2>/dev/null ||
		error "failed to write stripe set 0"
	tr "\000" "\001" < /dev/zero | dd bs=$stripe_set_size count=1 seek=3 \
		iflag=fullblock of=$tf 2>/dev/null ||
		error "failed to write stripe set 3"

	(( $($LUSTRE/tests/lseek_test -l 0 $tf) == $stripe_set_size )) ||
		error "expected hole at $stripe_set_size"
	(( $($LUSTRE/tests/lseek_test -d $stripe_set_size $tf) ==
		$((3 * stripe_set_size)) )) ||
		error "expected next data at $((3 * stripe_set_size))"

	$LFS mirror resync $tf || error "failed to resync ec mirror"
	$LFS getstripe $tf | grep lcme_flags | grep stale &&
		error "stale component after resync"

	#  lcme_id:             131074
	#  lcme_mirror_id:      2
	#  lcme_flags:          init,parity
	local parity_mirror_id=$($LFS getstripe $tf |
		grep -B1 "lcme_flags.*parity" |
		grep "lcme_mirror_id" | awk '{print $2}')
	# Parity: [0, ec_set_size) and [3*ec_set_size, ...) have data;
	# [ec_set_size, 3*ec_set_size) is holed for stripe sets 1 and 2.
	check_mirror_lseek -d $tf $parity_mirror_id 0 0
	check_mirror_lseek -l $tf $parity_mirror_id 0 $ec_set_size
	check_mirror_lseek -d $tf $parity_mirror_id $ec_set_size \
		$((3 * ec_set_size))

	$LFS mirror verify $tf || error "mirror verify failed after resync"
}
run_test 12c "resync skips holed stripe sets"

test_12d() {
	# Sparse file at raidset granularity: with 3+2 and -c 6 each stripe
	# set holds two raidsets (k=3). Raidsets 0 and 2 written; raidset
	# 1 is a hole. Resync must skip the holed raidset and punch parity.
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=${DIR}/${tdir}/$tfile
	local stripe_size=$((1024 * 1024))
	local raidset_size=$((3 * stripe_size))
	local ec_raidset_size=$((2 * stripe_size))

	test_mkdir $DIR/$tdir
	stack_trap "rm -f $tf"

	$LFS setstripe -E -1 -S 1M -c 6 --ec 3+2 $tf ||
		error "setstripe --ec 3+2 failed"

	tr "\000" "\001" < /dev/zero | dd bs=$raidset_size count=1 \
		iflag=fullblock of=$tf 2>/dev/null ||
		error "failed to write raidset 0"
	tr "\000" "\001" < /dev/zero | dd bs=$raidset_size count=1 seek=2 \
		iflag=fullblock of=$tf 2>/dev/null ||
		error "failed to write raidset 2"

	(( $($LUSTRE/tests/lseek_test -l 0 $tf) == $raidset_size )) ||
		error "expected hole at $raidset_size"
	(( $($LUSTRE/tests/lseek_test -d $raidset_size $tf) ==
		$((2 * raidset_size)) )) ||
		error "expected next data at $((2 * raidset_size))"

	$LFS mirror resync $tf || error "failed to resync ec mirror"
	$LFS getstripe $tf | grep lcme_flags | grep stale &&
		error "stale component after resync"

	#  lcme_id:             131074
	#  lcme_mirror_id:      2
	#  lcme_flags:          init,parity
	local parity_mirror_id=$($LFS getstripe $tf |
		grep -B1 "lcme_flags.*parity" |
		grep "lcme_mirror_id" | awk '{print $2}')
	# Parity: [0, ec_raidset_size) and [2*ec_raidset_size, ...) have data;
	# [ec_raidset_size, 2*ec_raidset_size) is holed for raidset 1.
	# osd-zfs has no hole-punch, so resync zero-fills that range and
	# SEEK_HOLE/DATA no longer match true sparseness; mirror verify
	# already accepts hole-or-zero content (LU-20435). Drop the zfs
	# guard once osd-zfs hole-punch is implemented.
	if [[ "$ost1_FSTYPE" != "zfs" ]]; then
		check_mirror_lseek -d $tf $parity_mirror_id 0 0
		check_mirror_lseek -l $tf $parity_mirror_id 0 $ec_raidset_size
		check_mirror_lseek -d $tf $parity_mirror_id $ec_raidset_size \
			$((2 * ec_raidset_size))
	fi

	$LFS mirror verify $tf || error "mirror verify failed after resync"
}
run_test 12d "resync skips holed raidsets"

test_12e() {
	# Punch overlapping holes on both data stripes; the overlap [8k, 16k)
	# leaves a matching hole in the parity stripe after resync.
	(( OSTCOUNT >= 3 )) || skip_env "needs >= 3 OSTs"
	enable_ec

	local tf=${DIR}/${tdir}/$tfile
	local stripe_size=$((1024 * 1024))
	local stripe_set_size=$((2 * stripe_size))
	local punch_len=$((12 * 1024))

	test_mkdir $DIR/$tdir
	stack_trap "rm -f $tf"

	$LFS setstripe -E -1 -S 1M -c 2 --ec 2+1 $tf ||
		error "setstripe --ec 2+1 failed"

	tr "\000" "\001" < /dev/zero | dd bs=$stripe_set_size count=1 \
		iflag=fullblock of=$tf 2>/dev/null ||
		error "failed to write one raidset"

	$LFS mirror resync $tf || error "failed to resync ec mirror"
	$LFS getstripe $tf | grep lcme_flags | grep stale &&
		error "stale component after initial resync"

	local parity_mirror_id=$($LFS getstripe $tf |
		grep -B1 "lcme_flags.*parity" |
		grep "lcme_mirror_id" | awk '{print $2}')

	check_mirror_lseek -d $tf $parity_mirror_id 0 0
	check_mirror_lseek -l $tf $parity_mirror_id 0 $stripe_size

	# Punch data0 [4k, 16k) and data1 [8k, 20k); overlap is [8k, 16k).
	local fallocate_out
	fallocate_out=$(fallocate -p --offset 4096 -l $punch_len $tf 2>&1) ||
		skip_eopnotsupp "$fallocate_out|fallocate punch data0 failed"
	fallocate_out=$(fallocate -p --offset $((stripe_size + 8192)) \
		-l $punch_len $tf 2>&1) ||
		skip_eopnotsupp "$fallocate_out|fallocate punch data1 failed"

	$LFS getstripe $tf | grep lcme_flags | grep stale ||
		error "parity should be stale after punching data stripes"

	$LFS mirror resync $tf || error "failed to resync after punch"
	$LFS getstripe $tf | grep lcme_flags | grep stale &&
		error "stale component after resync following punch"

	# Parity: [0, 8k) and [16k, ...) have data; [8k, 16k) is a hole.
	check_mirror_lseek -d $tf $parity_mirror_id 0 0
	check_mirror_lseek -l $tf $parity_mirror_id 0 $((8 * 1024))
	check_mirror_lseek -d $tf $parity_mirror_id $((8 * 1024)) \
		$((16 * 1024))

	$LFS mirror verify $tf || error "mirror verify failed after punch resync"
}
run_test 12e "overlapping data holes punch parity gap verify"

test_12f() {
	# Write 2k (EOF not 4k-aligned), resync, and verify parity is written
	# through the enclosing 4k block: data at [0, 4k), hole from 4k on.
	(( OSTCOUNT >= 3 )) || skip_env "needs >= 3 OSTs"
	enable_ec

	local tf=${DIR}/${tdir}/$tfile
	local write_len=$((2 * 1024))
	local parity_len=$((4 * 1024))

	test_mkdir $DIR/$tdir
	stack_trap "rm -f $tf"

	$LFS setstripe -E -1 -S 1M -c 2 --ec 2+1 $tf || error "setstripe failed"

	tr "\000" "\001" < /dev/zero | dd bs=$write_len count=1 \
		iflag=fullblock of=$tf 2>/dev/null ||
		error "failed to write $write_len bytes"

	$LFS mirror resync $tf || error "failed to resync ec mirror"
	$LFS getstripe $tf | grep lcme_flags | grep stale &&
		error "stale component after resync"

	local parity_mirror_id=$($LFS getstripe $tf |
		grep -B1 "lcme_flags.*parity" |
		grep "lcme_mirror_id" | awk '{print $2}')

	# osd-zfs has no hole-punch, so resync zero-fills the whole parity
	# stripe [0, stripe_size) before writing [0, 4k); SEEK_HOLE then
	# reports stripe_size instead of 4k. Keep SEEK_DATA checks (incl.
	# past i_size) and rely on mirror verify for hole-or-zero (LU-20435).
	# Drop the zfs guard once osd-zfs hole-punch is implemented.
	check_mirror_lseek -d $tf $parity_mirror_id 0 0
	if [[ "$ost1_FSTYPE" != "zfs" ]]; then
		check_mirror_lseek -l $tf $parity_mirror_id 0 $parity_len
	fi
	# SEEK_DATA from i_size: exercises skipping the i_size fast-fail
	check_mirror_lseek -d $tf $parity_mirror_id $write_len $write_len

	$LFS mirror verify $tf || error "mirror verify failed after resync"
}
run_test 12f "short write resync parity spans [0, 4k) verify"

test_12g() {
	# EC-only stale resync must emit --stats YAML (lamigo liveness).
	(( OSTCOUNT >= 3 )) || skip_env "needs >= 3 OSTs"
	enable_ec

	local tf=${DIR}/${tdir}/$tfile
	local output_file=${DIR}/${tdir}/${tfile}.stats

	test_mkdir $DIR/$tdir
	stack_trap "rm -f $tf $output_file"

	$LFS setstripe -E -1 -S 4M -c 2 --ec 2+1 $tf ||
		error "setstripe --ec 2+1 failed"

	tr "\000" "\001" < /dev/zero | dd bs=1M count=8 \
		iflag=fullblock of=$tf 2>/dev/null ||
		error "failed to write $tf"
	[[ "$($LFS getstripe $tf)" =~ lcme_flags:.*stale ]] ||
		error "expected stale parity after write"

	$LFS mirror resync --stats --stats-interval=1 $tf | tee $output_file
	rc=${PIPESTATUS[0]}
	(( rc == 0 )) || error "resync failed rc = $rc"
	[[ ! "$($LFS getstripe $tf)" =~ lcme_flags:.*stale ]] ||
		error "stale component after resync"

	grep -q "copied:" $output_file ||
		error "no stats output from EC resync"
	verify_yaml_available || skip_env "YAML verification not installed"
	verify_yaml < $output_file || error "stats is not valid YAML"
}
run_test 12g "lfs mirror resync --stats for EC parity"

test_12h() {
	# -W must throttle EC parity writes, not only FLR data copies.
	(( OSTCOUNT >= 3 )) || skip_env "needs >= 3 OSTs"
	enable_ec

	local tf=${DIR}/${tdir}/$tfile
	local output_file=${DIR}/${tdir}/${tfile}.stats
	# 16 MiB data, 2+1: two raidsets write ~8 MiB of parity.
	local data_mb=16
	local parity_mb=8

	test_mkdir $DIR/$tdir
	stack_trap "rm -f $tf $output_file"

	$LFS setstripe -E -1 -S 4M -c 2 --ec 2+1 $tf ||
		error "setstripe --ec 2+1 failed"

	tr "\000" "\001" < /dev/zero | dd bs=1M count=$data_mb \
		iflag=fullblock of=$tf 2>/dev/null ||
		error "failed to write $tf"
	[[ "$($LFS getstripe $tf)" =~ lcme_flags:.*stale ]] ||
		error "expected stale parity after write"

	local start=$SECONDS
	$LFS mirror resync --stats --stats-interval=1 -W 1M $tf |
		tee $output_file
	rc=${PIPESTATUS[0]}
	(( rc == 0 )) || error "resync failed rc = $rc"
	local elapsed=$((SECONDS - start))
	[[ ! "$($LFS getstripe $tf)" =~ lcme_flags:.*stale ]] ||
		error "stale component after resync"

	(( elapsed >= parity_mb * 95 / 100 )) ||
		error "'lfs mirror resync -W' too fast ($elapsed < 0.95 * $parity_mb)?"

	(( elapsed <= parity_mb * 120 / 100 )) ||
		error_not_in_vm "'lfs mirror resync -W' slow ($elapsed > 1.2 * $parity_mb)"

	(( elapsed <= parity_mb * 350 / 100 )) ||
		error "'lfs mirror resync -W' too slow in VM ($elapsed > 3.5 * $parity_mb)"
}
run_test 12h "lfs mirror resync -W for EC parity"

test_13() {
	local tf=${DIR}/${tdir}/$tfile
	local tf_data=${DIR}/${tdir}/${tfile}.data
	local tf_ec=${DIR}/${tdir}/${tfile}.ec

	(( OSTCOUNT >= 4 )) || skip_env "needs >= 4 OSTs"
	enable_ec

	test_mkdir $DIR/$tdir

	$LFS setstripe -E -1 -S 4M -c 1 --ec 3+1 $tf ||
	    error "setstripe -c 1 --ec 3+1 failed"

	# Write the first 3 stripes with \001, \002 and \003
	tr "\000" "\001" < /dev/zero | dd bs=64k iflag=fullblock count=64          \
		of=$tf 2>/dev/null
	tr "\000" "\002" < /dev/zero | dd bs=64k iflag=fullblock count=64 seek=64  \
		of=$tf 2>/dev/null
	tr "\000" "\003" < /dev/zero | dd bs=64k iflag=fullblock count=64 seek=128 \
		of=$tf 2>/dev/null

	# resync the ec mirror:
	$LFS mirror resync $tf || error "failed to resync ec mirror"

	# Expected content of both data and "ec" mirror
	#  od -t x1 -A x $tf
	#  000000 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
	#  *
	#  400000 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02
	#  *
	#  800000 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03
	#  *
	#  c00000
	rm -f $tf_data
	stack_trap "rm -f $tf_data"
	$LFS mirror read --mirror-id 1 -o $tf_data $tf
	echo "fa9fe1782aee74e978e806fb6a0e7a4a1c83610f $tf_data" |
	    sha1sum -c - || error "wrong content in data mirror"

	rm -f $tf_ec
	stack_trap "rm -f $tf_ec"
	$LFS mirror read --mirror-id 2 -o $tf_ec $tf
	echo "fa9fe1782aee74e978e806fb6a0e7a4a1c83610f $tf_ec" |
	    sha1sum -c - || error "wrong content in ec mirror"
}
run_test 13 "parity of single stripe data is just a copy"

test_20() {
	local tf=${DIR}/${tdir}/$tfile

	(( OSTCOUNT >= 4 )) || skip_env "needs >= 4 OSTs"
	enable_ec

	test_mkdir $DIR/$tdir

	# 4M stripe size
	$LFS setstripe -E -1 -S 4M -c 1 --ec 3+1 $tf ||
	    error "setstripe -c 1 -S 4M --ec 3+1 failed"

	$LFS getstripe $tf | grep lmm_stripe_size | grep -v 4194304 2>/dev/null &&
		error "Stripe size mismatch for -S 4M"
	rm -f $tf

	# 1M stripe size
	$LFS setstripe -E -1 -S 1M -c 1 --ec 3+1 $tf ||
	    error "setstripe -c 1 -S 1M --ec 3+1 failed"

	$LFS getstripe $tf |
	    grep lmm_stripe_size | grep -v 1048576 2>/dev/null &&
	    error "Stripe size mismatch for -S 1M"
	rm -f $tf

	# 64k stripe size
	$LFS setstripe -E -1 -S 64k -c 1 --ec 3+1 $tf ||
	    error "setstripe -c 1 -S 64k --ec 3+1 failed"

	$LFS getstripe $tf | grep lmm_stripe_size | grep -v 65536 2>/dev/null &&
		error "Stripe size mismatch for -S 64k"

	return 0
}
run_test 20 "test that stripe size of parity mirror is set correctly"

# Test 21: lfs migrate with EC layouts
test_21a() {
	(( OSTCOUNT >= 3 )) || skip_env "needs >= 3 OSTs"
	enable_ec

	local tf=$DIR/$tdir/$tfile

	test_mkdir $DIR/$tdir
	stack_trap "rm -rf $DIR/$tdir"

	# Create a plain (non-EC) file with data
	$LFS setstripe -c 1 $tf || error "setstripe failed"
	dd if=/dev/urandom of=$tf bs=1M count=5 ||
		error "write to plain file failed"
	local old_chksum=$(md5sum $tf | awk '{print $1}')

	# Migrate plain file to EC layout
	$LFS migrate -E -1 -c 2 --ec 2+1 $tf ||
		error "migrate (plain -> EC) failed"

	# Verify EC layout after migration
	verify_mirror_count $tf 2
	verify_comp_count $tf 2

	# Get component IDs
	local ids=($($LFS getstripe $tf |
		awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify parity component layout
	verify_comp_parity $tf ${ids[1]}
	verify_ec_stripe_count $tf ${ids[1]} 2 1

	# Verify data integrity
	local new_chksum=$(md5sum $tf | awk '{print $1}')
	[[ "$old_chksum" == "$new_chksum" ]] ||
		error "data changed after migrate: $old_chksum != $new_chksum"

	# For multi-stripe EC (2+1), parity is XOR across stripes, so
	# parity content must differ from the data mirror content.
	local data_sum=$($LFS mirror read -N1 $tf | md5sum)
	local parity_sum=$($LFS mirror read -N2 $tf | md5sum)
	[[ "$data_sum" != "$parity_sum" ]] ||
		error "parity identical to data - migrate didn't compute parity"
}
run_test 21a "migrate plain file to EC layout"

test_21b() {
	(( OSTCOUNT >= 3 )) || skip_env "needs >= 3 OSTs"
	enable_ec

	local tf=$DIR/$tdir/$tfile

	test_mkdir $DIR/$tdir
	stack_trap "rm -rf $DIR/$tdir"

	# Create EC file with data
	$LFS setstripe -E -1 -c 2 --ec 2+1 $tf ||
		error "setstripe EC failed"
	dd if=/dev/urandom of=$tf bs=1M count=5 ||
		error "write to EC file failed"
	$LFS mirror resync $tf || error "resync failed"

	local old_chksum=$(md5sum $tf | awk '{print $1}')

	# Verify EC layout before migration
	verify_mirror_count $tf 2
	verify_comp_count $tf 2

	# Migrate EC file to plain layout
	$LFS migrate -c 2 $tf || error "migrate (EC -> plain) failed"

	# Verify no parity components remain
	$LFS getstripe $tf | grep -q "parity" &&
		error "parity components should not exist after migrate to plain"

	# Verify no composite/FLR layout remains
	$LFS getstripe $tf | grep -q "lcm_mirror_count" &&
		error "should not have mirror layout after migrate to plain"

	# Verify data integrity
	local new_chksum=$(md5sum $tf | awk '{print $1}')
	[[ "$old_chksum" == "$new_chksum" ]] ||
		error "data changed after migrate: $old_chksum != $new_chksum"
}
run_test 21b "migrate EC file to plain layout"

test_21c() {
	(( OSTCOUNT >= 4 )) || skip_env "needs >= 4 OSTs"
	enable_ec

	local tf=$DIR/$tdir/$tfile

	test_mkdir $DIR/$tdir
	stack_trap "rm -rf $DIR/$tdir"

	# Create EC file with 2+1 and write data
	$LFS setstripe -E -1 -c 2 --ec 2+1 $tf ||
		error "setstripe EC 2+1 failed"
	dd if=/dev/urandom of=$tf bs=1M count=5 ||
		error "write to EC file failed"
	$LFS mirror resync $tf || error "initial resync failed"

	local old_chksum=$(md5sum $tf | awk '{print $1}')

	# Migrate EC 2+1 to EC 3+1
	$LFS migrate -E -1 -c 3 --ec 3+1 $tf ||
		error "migrate (EC 2+1 -> EC 3+1) failed"

	# Verify new EC layout
	verify_mirror_count $tf 2
	verify_comp_count $tf 2

	local ids=($($LFS getstripe $tf |
		awk '/lcme_id/{print $2}' | tr '\n' ' '))

	verify_comp_parity $tf ${ids[1]}
	verify_ec_stripe_count $tf ${ids[1]} 3 1

	# Verify data integrity
	local new_chksum=$(md5sum $tf | awk '{print $1}')
	[[ "$old_chksum" == "$new_chksum" ]] ||
		error "data changed after migrate: $old_chksum != $new_chksum"

	# For multi-stripe EC, parity is XOR across stripes and must
	# differ from data content.
	local data_sum=$($LFS mirror read -N1 $tf | md5sum)
	local parity_sum=$($LFS mirror read -N2 $tf | md5sum)
	[[ "$data_sum" != "$parity_sum" ]] ||
		error "parity identical to data after EC config change"
}
run_test 21c "migrate between different EC configurations"

test_21d() {
	(( OSTCOUNT >= 3 )) || skip_env "needs >= 3 OSTs"
	enable_ec

	local tf=$DIR/$tdir/$tfile

	test_mkdir $DIR/$tdir
	stack_trap "rm -rf $DIR/$tdir"

	# Create multi-component PFL file with data
	$LFS setstripe -E 1M -c 1 -E -1 -c 2 $tf ||
		error "setstripe PFL failed"
	dd if=/dev/urandom of=$tf bs=1M count=5 ||
		error "write to PFL file failed"

	local old_chksum=$(md5sum $tf | awk '{print $1}')

	# Migrate PFL to EC with multiple components
	$LFS migrate -E 1M -c 2 -E -1 -c 2 --ec 2+1 $tf ||
		error "migrate (PFL -> EC) failed"

	# Verify EC layout
	verify_mirror_count $tf 2
	verify_comp_count $tf 4

	local ids=($($LFS getstripe $tf |
		awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify parity components
	verify_comp_parity $tf ${ids[2]}
	verify_comp_parity $tf ${ids[3]}
	verify_ec_stripe_count $tf ${ids[2]} 2 1
	verify_ec_stripe_count $tf ${ids[3]} 2 1

	# Verify data integrity
	local new_chksum=$(md5sum $tf | awk '{print $1}')
	[[ "$old_chksum" == "$new_chksum" ]] ||
		error "data changed after migrate: $old_chksum != $new_chksum"
}
run_test 21d "migrate PFL file to EC layout"

# Test 22: mirror split with EC
test_22a() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tdir/$tfile

	test_mkdir $DIR/$tdir
	stack_trap "rm -rf $DIR/$tdir"

	# Create file with plain data mirror + EC data mirror + parity mirror
	$LFS setstripe -N -E -1 -c 2 \
		-N -E -1 -c 2 --ec 2+2 $tf ||
		error "setstripe failed"
	dd if=/dev/urandom of=$tf bs=1M count=3 ||
		error "write failed"
	$LFS mirror resync $tf || error "resync failed"

	local old_chksum=$(md5sum $tf | awk '{print $1}')

	# Should have 3 mirrors: data, data+EC, parity
	verify_mirror_count $tf 3

	# Split off mirror 1 (plain data mirror) - should work fine
	$LFS mirror split --mirror-id 1 -d $tf ||
		error "split plain data mirror failed"

	# Should now have 2 mirrors: data+EC, parity
	verify_mirror_count $tf 2

	# Parity component should still exist
	$LFS getstripe $tf | grep -q "parity" ||
		error "parity component lost after split"

	# Verify data integrity
	local new_chksum=$(md5sum $tf | awk '{print $1}')
	[[ "$old_chksum" == "$new_chksum" ]] ||
		error "data changed after split: $old_chksum != $new_chksum"

	# Verify remaining EC layout is functional: write new data,
	# resync, and confirm parity is recomputed
	dd if=/dev/urandom of=$tf bs=1M count=1 conv=notrunc ||
		error "write after split failed"
	verify_flr_state $tf "wp"
	$LFS mirror resync $tf || error "resync after split+write failed"
	verify_flr_state $tf "ro"

	# For multi-stripe EC (2+2), parity is computed across stripes and
	# must differ from data content, confirming EC is functional.
	local data_sum=$($LFS mirror read -N1 $tf | md5sum)
	local parity_sum=$($LFS mirror read -N2 $tf | md5sum)
	[[ "$data_sum" != "$parity_sum" ]] ||
		error "parity identical to data after split - EC not functional"
}
run_test 22a "mirror split removes plain mirror, keeps EC"

# Test 23: truncate and fallocate with EC
test_23a() {
	enable_ec

	local tf=$DIR/$tdir/$tfile
	local ids

	test_mkdir $DIR/$tdir
	stack_trap "rm -rf $DIR/$tdir"

	# Create EC file and write data
	$LFS setstripe -E -1 -c 4 --ec 4+2 $tf ||
		error "setstripe failed"
	dd if=/dev/urandom of=$tf bs=1M count=5 ||
		error "write failed"
	$LFS mirror resync $tf || error "resync failed"
	verify_flr_state $tf "ro"

	# Save parity mirror checksum before truncate
	local parity_sum_before=$($LFS mirror read -N2 $tf | md5sum)

	# Truncate to smaller size
	$TRUNCATE $tf 2097152 || error "truncate to 2M failed"

	# After truncate, file should be in write-pending state
	verify_flr_state $tf "wp"

	# Get component IDs
	ids=($($LFS getstripe $tf |
		awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Parity component should be stale after truncate
	verify_comp_stale $tf ${ids[1]}

	# Resync - this should recompute parity for truncated data
	$LFS mirror resync $tf || error "resync after truncate failed"
	verify_flr_state $tf "ro"

	local size=$(stat -c%s $tf)
	(( size == 2097152 )) ||
		error "file size wrong after truncate: $size != 2097152"

	# Verify parity was actually recomputed (checksum should change
	# because parity of 2M of data differs from parity of 5M of data)
	local parity_sum_after=$($LFS mirror read -N2 $tf | md5sum)
	[[ "$parity_sum_before" != "$parity_sum_after" ]] ||
		error "parity mirror unchanged after truncate+resync"

	# Verify data mirror still has correct content
	local data_sum=$($LFS mirror read -N1 $tf | md5sum)
	local file_sum=$(md5sum < $tf)
	[[ "$data_sum" == "$file_sum" ]] ||
		error "data mirror content mismatch after truncate"
}
run_test 23a "truncate EC file to smaller size"

test_23b() {
	enable_ec

	local tf=$DIR/$tdir/$tfile
	local ids

	test_mkdir $DIR/$tdir
	stack_trap "rm -rf $DIR/$tdir"

	# Create EC file and write data
	$LFS setstripe -E -1 -c 4 --ec 4+2 $tf ||
		error "setstripe failed"
	dd if=/dev/urandom of=$tf bs=1M count=2 ||
		error "write failed"
	$LFS mirror resync $tf || error "resync failed"
	verify_flr_state $tf "ro"

	# Truncate to larger size (extends with zeros)
	$TRUNCATE $tf 10485760 || error "truncate to 10M failed"

	# After truncate, file should be in write-pending state
	verify_flr_state $tf "wp"

	# Get component IDs
	ids=($($LFS getstripe $tf |
		awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Parity component should be stale after truncate
	verify_comp_stale $tf ${ids[1]}

	# Resync - parity must be recomputed for the extended data
	$LFS mirror resync $tf || error "resync after truncate failed"
	verify_flr_state $tf "ro"

	local size=$(stat -c%s $tf)
	(( size == 10485760 )) ||
		error "file size wrong after truncate: $size != 10485760"

	# Verify data mirror content matches file read
	local data_sum=$($LFS mirror read -N1 $tf | md5sum)
	local file_sum=$(md5sum < $tf)
	[[ "$data_sum" == "$file_sum" ]] ||
		error "data mirror content mismatch after truncate"

	# Verify parity covers the extended region: write non-zero data
	# into the previously zero-extended area and confirm parity is
	# recomputed (a zero-only extension produces zero parity, which
	# is indistinguishable from unwritten parity storage, so we need
	# real data to meaningfully exercise parity over the new range).
	local parity_sum_before=$($LFS mirror read -N2 $tf | md5sum)
	dd if=/dev/urandom of=$tf bs=1M count=4 seek=4 conv=notrunc ||
		error "write into extended region failed"
	$LFS mirror resync $tf || error "resync after extended write failed"
	verify_flr_state $tf "ro"
	local parity_sum_after=$($LFS mirror read -N2 $tf | md5sum)
	[[ "$parity_sum_before" != "$parity_sum_after" ]] ||
		error "parity mirror unchanged after write into extended region"
}
run_test 23b "truncate EC file to larger size"

test_23c() {
	enable_ec
	check_fallocate_or_skip ost1 alloc # Probe for feature support
	check_set_fallocate_or_skip

	local tf=$DIR/$tdir/$tfile
	local ids

	test_mkdir $DIR/$tdir
	stack_trap "rm -rf $DIR/$tdir"

	# Create EC file
	$LFS setstripe -E -1 -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	# fallocate space - preallocate without writing data
	fallocate -l 5M $tf || error "fallocate failed"

	# After fallocate, parity should be stale
	verify_flr_state $tf "wp"
	ids=($($LFS getstripe $tf |
		awk '/lcme_id/{print $2}' | tr '\n' ' '))
	verify_comp_stale $tf ${ids[1]}

	# Resync parity for the preallocated region
	$LFS mirror resync $tf || error "resync after fallocate failed"
	verify_flr_state $tf "ro"

	# Now write actual data into the preallocated region
	dd if=/dev/urandom of=$tf bs=1M count=5 conv=notrunc ||
		error "write to preallocated file failed"

	# Parity must go stale again from the actual write
	verify_flr_state $tf "wp"
	verify_comp_stale $tf ${ids[1]}

	# Resync parity with real data
	$LFS mirror resync $tf || error "resync after write failed"
	verify_flr_state $tf "ro"

	# Verify data mirror matches file content (proving EC resync
	# correctly processed the preallocated+written region)
	local file_sum=$(md5sum < $tf)
	local data_sum=$($LFS mirror read -N1 $tf | md5sum)
	[[ "$file_sum" == "$data_sum" ]] ||
		error "data mirror content mismatch after fallocate+write"

	# For multi-stripe EC (4+2), parity is XOR across stripes and
	# must differ from data content.
	local parity_sum=$($LFS mirror read -N2 $tf | md5sum)
	[[ "$data_sum" != "$parity_sum" ]] ||
		error "parity mirror identical to data - not real parity"
}
run_test 23c "fallocate on EC file"

# Test 24: comp-add/del with EC
test_24a() {
	enable_ec

	local tf=$DIR/$tdir/$tfile

	test_mkdir $DIR/$tdir
	stack_trap "rm -rf $DIR/$tdir"

	# Create EC file
	$LFS setstripe -E -1 -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	# Attempting --comp-add with --ec should be rejected
	local output
	output=$($LFS setstripe --comp-add -E -1 --ec 4+2 $tf 2>&1) &&
		error "should reject --ec with --comp-add"
	echo "$output" | grep -q "cannot be used with" ||
		error "unexpected error message: $output"

	return 0
}
run_test 24a "reject --ec with --comp-add"

test_24b() {
	enable_ec

	local tf=$DIR/$tdir/$tfile

	test_mkdir $DIR/$tdir
	stack_trap "rm -rf $DIR/$tdir"

	# Create EC file with two components per mirror
	# Mirror 1 (data): [0, 1M], [1M, EOF]
	# Mirror 2 (parity): [0, 1M], [1M, EOF]
	$LFS setstripe -E 1M -c 2 -E -1 -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 4

	local ids=($($LFS getstripe $tf |
		awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# ids[0], ids[1] = data mirror components
	# ids[2], ids[3] = parity mirror components

	# Attempting to delete data component that is protected by
	# parity should fail
	$LFS setstripe --comp-del -I ${ids[1]} $tf 2>&1 &&
		error "should not allow deleting data comp protected by parity"

	# Verify layout unchanged
	verify_comp_count $tf 4

	# Attempting to delete parity component directly should also fail
	$LFS setstripe --comp-del -I ${ids[2]} $tf 2>&1 &&
		error "should not allow deleting parity component directly"

	verify_comp_count $tf 4

	return 0
}
run_test 24b "reject deleting data component protected by parity"

# Test 25: lfs find with EC attributes
test_25a() {
	enable_ec

	local td=$DIR/$tdir

	test_mkdir $td
	stack_trap "rm -rf $td"

	# Create EC file
	$LFS setstripe -E -1 -c 4 --ec 4+2 $td/ec_file ||
		error "setstripe EC failed"

	# Create plain file
	$LFS setstripe -c 1 $td/plain_file ||
		error "setstripe plain failed"

	# Create mirrored file without EC
	$LFS mirror create -N2 -E -1 -c 2 $td/mirror_file ||
		error "mirror create failed"

	# Find files with parity components
	local found=$($LFS find $td --component-flags parity | wc -l)
	(( found == 1 )) ||
		error "expected 1 file with parity, found $found"

	# The found file should be the EC file
	$LFS find $td --component-flags parity | grep -q "ec_file" ||
		error "find did not return the EC file"

	# Verify that plain and mirror files are not returned
	local parity_files=$($LFS find $td --component-flags parity)
	echo "$parity_files" | grep -q "plain_file" &&
		error "find returned plain_file as having parity"
	echo "$parity_files" | grep -q "mirror_file" &&
		error "find returned mirror_file as having parity"

	return 0
}
run_test 25a "lfs find with --component-flags parity"

# Test 26: larger I/O and multi-stripe EC data integrity
test_26a() {
	enable_ec

	local tf=$DIR/$tdir/$tfile
	local tf_data=$DIR/$tdir/${tfile}.data
	local tf_ec=$DIR/$tdir/${tfile}.ec

	test_mkdir $DIR/$tdir
	stack_trap "rm -rf $DIR/$tdir"

	# Create EC file with 4 data stripes and 2 parity stripes
	# Use 1M stripe size so 20M of data spans 5 full stripe rows
	$LFS setstripe -E -1 -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	# Write 20M of random data (5 full rows of 4x1M stripes)
	dd if=/dev/urandom of=$tf bs=1M count=20 ||
		error "write failed"

	local old_chksum=$(md5sum $tf | awk '{print $1}')

	# Resync EC parity
	$LFS mirror resync $tf || error "resync failed"

	# Verify data unchanged after resync
	local new_chksum=$(md5sum $tf | awk '{print $1}')
	[[ "$old_chksum" == "$new_chksum" ]] ||
		error "data changed after resync: $old_chksum != $new_chksum"

	# Read data mirror and verify
	$LFS mirror read --mirror-id 1 -o $tf_data $tf ||
		error "mirror read data failed"
	echo "$old_chksum  $tf_data" | md5sum -c - ||
		error "data mirror content mismatch"

	# Save parity checksum before overwrite
	local parity_sum_before=$($LFS mirror read -N2 $tf | md5sum)

	# Overwrite part of the file (middle 4M of 20M)
	dd if=/dev/urandom of=$tf bs=1M count=4 seek=8 conv=notrunc ||
		error "overwrite failed"

	# After overwrite, parity should be stale
	verify_flr_state $tf "wp"

	# Resync after overwrite - parity must be recomputed
	$LFS mirror resync $tf || error "resync after overwrite failed"
	verify_flr_state $tf "ro"

	# Verify parity was recomputed (data changed so parity must differ)
	local parity_sum_after=$($LFS mirror read -N2 $tf | md5sum)
	[[ "$parity_sum_before" != "$parity_sum_after" ]] ||
		error "parity unchanged after data overwrite+resync"

	# Verify data mirror has correct content after overwrite+resync
	local final_chksum=$(md5sum $tf | awk '{print $1}')
	rm -f $tf_data
	$LFS mirror read --mirror-id 1 -o $tf_data $tf ||
		error "mirror read data after overwrite failed"
	echo "$final_chksum  $tf_data" | md5sum -c - ||
		error "data mirror content mismatch after overwrite"
}
run_test 26a "multi-stripe EC data integrity with 20M file"

test_26b() {
	enable_ec

	local tf=$DIR/$tdir/$tfile
	local tf_data=$DIR/$tdir/${tfile}.data
	local tf_ec=$DIR/$tdir/${tfile}.ec

	test_mkdir $DIR/$tdir
	stack_trap "rm -rf $DIR/$tdir"

	# Create EC file with 2 data stripes and 2 parity stripes
	# Use 4M stripe size for larger stripe coverage
	$LFS setstripe -E -1 -S 4M -c 2 --ec 2+2 $tf ||
		error "setstripe failed"

	# Write a pattern: alternating blocks of \xAA and \x55
	tr "\000" "\252" < /dev/zero | dd of=$tf bs=1M count=8 \
		iflag=fullblock 2>/dev/null
	tr "\000" "\125" < /dev/zero | dd of=$tf bs=1M count=8 seek=8 \
		iflag=fullblock 2>/dev/null

	local old_chksum=$(md5sum $tf | awk '{print $1}')

	# Resync
	$LFS mirror resync $tf || error "resync failed"

	# Verify data
	local new_chksum=$(md5sum $tf | awk '{print $1}')
	[[ "$old_chksum" == "$new_chksum" ]] ||
		error "data changed after resync: $old_chksum != $new_chksum"

	# Read back and verify both mirrors
	$LFS mirror read --mirror-id 1 -o $tf_data $tf ||
		error "mirror read data failed"
	echo "$old_chksum  $tf_data" | md5sum -c - ||
		error "data mirror content mismatch"

	# Read EC parity mirror
	$LFS mirror read --mirror-id 2 -o $tf_ec $tf ||
		error "mirror read ec failed"
	[[ -s $tf_ec ]] || error "EC mirror is empty"

	# For multi-stripe EC (2+2), parity is XOR across data stripes,
	# so parity content must differ from data content.
	local data_sum=$(md5sum < $tf_data)
	local ec_sum=$(md5sum < $tf_ec)
	[[ "$data_sum" != "$ec_sum" ]] ||
		error "parity mirror identical to data mirror - not real parity"

	# Overwrite first half with different pattern, resync,
	# and verify parity changes
	local ec_sum_before=$ec_sum
	tr "\000" "\377" < /dev/zero | dd of=$tf bs=1M count=8 \
		iflag=fullblock conv=notrunc 2>/dev/null
	$LFS mirror resync $tf || error "resync after overwrite failed"
	rm -f $tf_ec
	$LFS mirror read --mirror-id 2 -o $tf_ec $tf ||
		error "mirror read ec after overwrite failed"
	local ec_sum_after=$(md5sum < $tf_ec)
	[[ "$ec_sum_before" != "$ec_sum_after" ]] ||
		error "parity unchanged after data modification"
}
run_test 26b "EC data integrity with patterned data and 4M stripes"

# Test 27: PFL lazy instantiation with EC
test_27a() {
	(( OSTCOUNT >= 5 )) || skip "needs >= 5 OSTs"

	enable_ec

	local tf=$DIR/$tdir/$tfile
	local ids
	local flags

	test_mkdir $DIR/$tdir

	# Create EC file with PFL: [0, 1M], [1M, 8M], [8M, EOF]
	# Use 4+1 so parity count stays valid for all component stripe counts
	$LFS setstripe -E 1M -c 4 -E 8M -c 4 -E -1 -c 4 --ec 4+1 $tf ||
		error "setstripe failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 6

	# Component layout:
	# ids[0]: data [0, 1M]    ids[3]: parity [0, 1M]
	# ids[1]: data [1M, 8M]   ids[4]: parity [1M, 8M]
	# ids[2]: data [8M, EOF]  ids[5]: parity [8M, EOF]

	# Write only to the first component (< 1M)
	dd if=/dev/urandom of=$tf bs=512K count=1 ||
		error "write to first component failed"

	# Get component IDs
	ids=($($LFS getstripe $tf |
		awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# First data component should be init (instantiated by write)
	$LFS getstripe -I${ids[0]} $tf | grep -q "init" ||
		error "first data component should be init"

	# Second and third parity components should NOT be init yet
	# (no data written to those extents, so parity not needed)
	flags=$($LFS getstripe -I${ids[4]} $tf |
		awk '/lcme_flags:/ { print $2 }')
	[[ ! "$flags" =~ "init" ]] ||
		error "second parity component should not be init yet"
	flags=$($LFS getstripe -I${ids[5]} $tf |
		awk '/lcme_flags:/ { print $2 }')
	[[ ! "$flags" =~ "init" ]] ||
		error "third parity component should not be init yet"

	# Resync first component's parity
	$LFS mirror resync $tf || error "resync failed"
	verify_flr_state $tf "ro"

	# First parity component should now be init after resync
	flags=$($LFS getstripe -I${ids[3]} $tf |
		awk '/lcme_flags:/ { print $2 }')
	[[ "$flags" =~ "init" ]] ||
		error "first parity component should be init after resync"

	# Save parity checksum after first resync
	local parity_sum1=$($LFS mirror read -N2 $tf | md5sum)

	# Now write to the second component extent (at 2M)
	dd if=/dev/urandom of=$tf bs=1M count=1 seek=2 conv=notrunc ||
		error "write to second component failed"
	verify_flr_state $tf "wp"

	# Resync
	$LFS mirror resync $tf || error "resync after second write failed"
	verify_flr_state $tf "ro"

	# Parity should have changed (new data in second component)
	local parity_sum2=$($LFS mirror read -N2 $tf | md5sum)
	[[ "$parity_sum1" != "$parity_sum2" ]] ||
		error "parity unchanged after writing to second component"

	# Write to the third component extent (at 10M)
	dd if=/dev/urandom of=$tf bs=1M count=1 seek=10 conv=notrunc ||
		error "write to third component failed"
	verify_flr_state $tf "wp"

	# Resync everything
	$LFS mirror resync $tf || error "final resync failed"
	verify_flr_state $tf "ro"

	# Parity should have changed again
	local parity_sum3=$($LFS mirror read -N2 $tf | md5sum)
	[[ "$parity_sum2" != "$parity_sum3" ]] ||
		error "parity unchanged after writing to third component"

	# Verify data can be read back correctly
	local file_sum=$(md5sum < $tf)
	local data_sum=$($LFS mirror read -N1 $tf | md5sum)
	[[ "$file_sum" == "$data_sum" ]] ||
		error "data mirror content mismatch"
}
run_test 27a "PFL lazy instantiation with EC across multiple components"

test_27b() {
	(( OSTCOUNT >= 6 )) || skip "needs >= 6 OSTs"

	enable_ec

	local tf=$DIR/$tfile

	# Create a a stripeset using all available OSTs and
	# multiple raidsets.
	$LFS setstripe -E -1 -S 1M -c ${OSTCOUNT} --ec 4+2 $tf ||
		error "setstripe failed when using ALL OSTs"
}
run_test 27b "test we can create -c n --ec 4+2 with n OSTs"

test_27c() {
	(( OSTCOUNT >= 6 )) || skip "needs >= 6 OSTs"

	enable_ec

	local tf=$DIR/$tfile
	local aoet=$((OSTCOUNT + 2))
	local sc

	# Without overstriping, -c n+2 is reduced to the available OSTs
	# (75% EC floor / geometry shrink) rather than failing create.
	$LFS setstripe -E -1 -S 1M -c ${aoet} --ec 4+2 $tf ||
		error "setstripe -c ${aoet} --ec 4+2 failed"
	sc=$($LFS getstripe $tf | awk '/lmm_stripe_count:/{print $2; exit}')
	(( sc > 0 && sc <= OSTCOUNT )) ||
		error "expected 0 < stripe count <= $OSTCOUNT, got '$sc'"
	rm -f $tf

	# With overstriping, n+2 stripes are allocated as requested
	$LFS setstripe -E -1 -S 1M -C ${aoet} --ec 4+2 $tf ||
		error "setstripe -C ${aoet} --ec 4+2 failed"
	sc=$($LFS getstripe $tf | awk '/lmm_stripe_count:/{print $2; exit}')
	(( sc == aoet )) ||
		error "expected stripe count $aoet with -C, got '$sc'"
}
run_test 27c "test creating with n+2 OSTs"

#
# Get a range of OSTs from a component.
# NOTE: Tail numbering starts at 1, not 0
#
get_osts_by_comp() {
	local filename="$1"
	local component="$2"
	local stripe_idx="$3"
	local stripe_cnt="$4"

	$LFS getstripe --component-id=$component "$filename" |
	    grep "l_ost_idx" |
	    tail -n +$((stripe_idx + 1)) | head -n +$stripe_cnt |
	    sed -e "s/^.*l_ost_idx: *//" -e "s/\,.*$//"
}

#
# Verifies the allocation of a raidset that OSTS are not reused
#
verify_raidset_allocation() {
	local filename="$1"
	local raidset="$2"
	local dstripe_idx="$3"
	local dstripe_cnt="$4"
	local cstripe_idx="$5"
	local cstripe_cnt="$6"

	local dosts=$(get_osts_by_comp "$filename" 65537 \
		$dstripe_idx $dstripe_cnt)
	local costs=$(get_osts_by_comp "$filename" 131074 \
		$cstripe_idx $cstripe_cnt)
	declare -A all_osts
	for ost in $dosts $costs; do
		all_osts[$ost]=$ost
	done
	local nosts=${#all_osts[*]}

	if (( nosts != cstripe_cnt + dstripe_cnt )); then
		echo "Raidset # $raidset"
		echo "Current allocation:"
		$LFS getstripe "$filename"
		echo "Data stripes:" $dosts
		echo "Parity stripes:" $costs
		return 1
	fi

	return 0
}

test_27d() {
	(( OSTCOUNT >= 6 )) || skip "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	# Test -C 8 --ec 5+2
	# Will result in 2x4+2 raidsets
	$LFS setstripe -E -1 -S 1M -C 8 --ec 4+2 $tf ||
		error "setstripe failed to create test file"

	# First raidset are data stripes 0-3 and parity stripes 0-1
	verify_raidset_allocation $tf 0 0 4 0 2 ||
	    error "Failed. OST reused within a single raidset"

	# Second raidset are data stripes 4-7 and parity stripes 2-3
	verify_raidset_allocation $tf 1 4 4 2 2 ||
	    error "Failed. OST reused within a single raidset"
}
run_test 27d "test raidset OSTs allocations are valid for -C 8 --ec 4+2"

test_27e() {
	(( OSTCOUNT >= 7 )) || skip "needs >= 7 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	# Test -C 13 --ec 5+2
	# Will result in 1x5+2 2x4+2 raidsets
	$LFS setstripe -E -1 -S 1M -C 13 --ec 5+2 $tf ||
		error "setstripe failed to create test file"

	# First raidset are data stripes 0-4 and parity stripes 0-1
	verify_raidset_allocation $tf 0 0 5 0 2 ||
	    error "Failed. OST reused within a single raidset"

	# Second raidset are data stripes 5-8 and parity stripes 2-3
	verify_raidset_allocation $tf 1 5 4 2 2 ||
	    error "Failed. OST reused within a single raidset"

	# Third raidset are data stripes 5-8 and parity stripes 2-3
	verify_raidset_allocation $tf 2 9 4 4 2 ||
	    error "Failed. OST reused within a single raidset"
}
run_test 27e "test raidset OSTs allocations are valid for -C 13 --ec 5+2"

test_27f() {
	(( OSTCOUNT >= 7 )) || skip "needs >= 7 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	# Test -C 20 --ec 5+2
	# Will result in 4x5+2 raidsets
	$LFS setstripe -E -1 -S 1M -C 20 --ec 5+2 $tf ||
		error "setstripe failed to create test file"

	# First raidset are data stripes 0-4 and parity stripes 0-1
	verify_raidset_allocation $tf 0 0 5 0 2 ||
	    error "Failed. OST reused within a single raidset"

	# Second raidset are data stripes 5-9 and parity stripes 2-3
	verify_raidset_allocation $tf 1 5 5 2 2 ||
	    error "Failed. OST reused within a single raidset"

	# Third raidset are data stripes 10-14 and parity stripes 4-6
	verify_raidset_allocation $tf 2 10 5 4 2 ||
	    error "Failed. OST reused within a single raidset"

	# Fourth raidset are data stripes 15-19 and parity stripes 7-8
	verify_raidset_allocation $tf 3 15 5 6 2 ||
	    error "Failed. OST reused within a single raidset"
}
run_test 27f "test raidset OSTs allocations are valid for -C 20 --ec 5+2"

test_27g() {
	(( OSTCOUNT >= 4 )) || skip "needs >= 4 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	# Create a single raidset EC file with data mirror + parity mirror
	local aoet=$(($OSTCOUNT - 2))
	$LFS setstripe -E -1 -S 1M -c ${aoet} --ec ${aoet}+2 $tf ||
		error "setstripe --ec ${aoet}+2 failed"
}
run_test 27g "test we can create -c (n-2) --ec (n-2)+2 with n OSTs"

test_27h() {
	(( OSTCOUNT >= 5 )) || skip "needs >= 5 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	# Create a single raidset EC file with data mirror + parity mirror
	local aoet=$(($OSTCOUNT - 2))
	$LFS setstripe -E -1 -S 1M -c ${aoet} --ec ${aoet}+3 $tf &&
		error "setstripe --ec ${aoet}+3 failed" || true
}
run_test 27h "test stripe creation fails when parity needs one stripe too many"

# Test 28: file operations (hardlink, rename, symlink) on EC files
test_28a() {
	enable_ec

	local tf=$DIR/$tdir/$tfile
	local tf_link=$DIR/$tdir/${tfile}.link

	test_mkdir $DIR/$tdir
	stack_trap "rm -rf $DIR/$tdir"

	# Create EC file with data and sync parity
	$LFS setstripe -E -1 -c 4 --ec 4+2 $tf ||
		error "setstripe failed"
	dd if=/dev/urandom of=$tf bs=1M count=2 ||
		error "write failed"
	$LFS mirror resync $tf || error "resync failed"
	verify_flr_state $tf "ro"

	local old_chksum=$(md5sum $tf | awk '{print $1}')
	local parity_sum_before=$($LFS mirror read -N2 $tf | md5sum)

	# Create hardlink
	ln $tf $tf_link || error "hardlink failed"

	# Verify EC layout accessible through hardlink
	verify_mirror_count $tf_link 2
	$LFS getstripe $tf_link | grep -q "parity" ||
		error "parity not visible through hardlink"

	# Write through the hardlink - should make parity stale
	dd if=/dev/urandom of=$tf_link bs=1M count=1 conv=notrunc ||
		error "write through hardlink failed"
	verify_flr_state $tf "wp"

	# Verify parity is stale when checked through original name
	local ids=($($LFS getstripe $tf |
		awk '/lcme_id/{print $2}' | tr '\n' ' '))
	verify_comp_stale $tf ${ids[1]}

	# Resync through original name
	$LFS mirror resync $tf || error "resync through original name failed"
	verify_flr_state $tf "ro"

	# Verify parity was recomputed (data changed via hardlink write)
	local parity_sum_after=$($LFS mirror read -N2 $tf | md5sum)
	[[ "$parity_sum_before" != "$parity_sum_after" ]] ||
		error "parity unchanged after write-through-hardlink+resync"

	# Verify data readable through both names matches
	local sum_orig=$(md5sum < $tf)
	local sum_link=$(md5sum < $tf_link)
	[[ "$sum_orig" == "$sum_link" ]] ||
		error "data differs between original and hardlink after resync"
}
run_test 28a "EC parity correctly tracks writes through hardlinks"

#
# Failure injection / degraded mode tests (test_29x - test_33x)
#
# These tests exercise EC behavior under OST failures, degraded OSTs,
# and injected I/O errors.
#

drop_client_cache() {
	echo 3 > /proc/sys/vm/drop_caches
}

test_29a() {
	# With 2+1 EC, losing 2 OSTs exceeds parity tolerance.
	# Read must fail (not return corrupt data). This test should
	# pass today -- we expect an error, and we get one.
	(( OSTCOUNT >= 4 )) || skip "need >= 4 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf" EXIT

	# 2+1 EC: can only tolerate 1 failure
	$LFS setstripe -E -1 -S 1M -c 2 --ec 2+1 $tf ||
		error "setstripe failed"

	dd if=/dev/urandom of=$tf bs=1M count=4 || error "write failed"
	$LFS mirror resync $tf || error "resync failed"
	verify_flr_state $tf "ro"

	# Identify two distinct OSTs used by the data stripe
	local ost_indices=($($LFS getstripe $tf |
		awk '/l_ost_idx:/ {print $5}' | head -2 | tr -d ','))

	local facet1=ost$((ost_indices[0] + 1))
	local facet2=ost$((ost_indices[1] + 1))

	echo "Stopping $facet1 and $facet2 (exceeds 2+1 parity tolerance)"
	stop $facet1
	stop $facet2
	wait_osc_import_state client $facet1 "\(DISCONN\|IDLE\)"
	wait_osc_import_state client $facet2 "\(DISCONN\|IDLE\)"
	drop_client_cache

	# Read must fail -- returning success with wrong data would be
	# catastrophic. Either an I/O error or timeout is acceptable.
	if md5sum $tf 2>/dev/null; then
		error "read should have failed with 2 OSTs down on 2+1 EC"
	else
		echo "Read correctly failed when losses exceed parity tolerance"
	fi

	start $facet1 $(ostdevname $((ost_indices[0] + 1))) $OST_MOUNT_OPTS
	start $facet2 $(ostdevname $((ost_indices[1] + 1))) $OST_MOUNT_OPTS
	wait_recovery_complete $facet1
	wait_recovery_complete $facet2
}
run_test 29a "EC read fails when OST losses exceed parity tolerance"

test_30a() {
	# Test that writes still succeed when an OST used by the parity
	# mirror is down. The data mirror write should succeed, and the
	# parity mirror should be marked stale.
	(( OSTCOUNT >= 4 )) || skip "need >= 4 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf" EXIT

	$LFS setstripe -E -1 -S 1M -c 2 --ec 2+1 $tf ||
		error "setstripe failed"

	dd if=/dev/urandom of=$tf bs=1M count=2 || error "initial write failed"
	$LFS mirror resync $tf || error "resync failed"
	verify_flr_state $tf "ro"

	# Write new data - parity becomes stale, no OST failure needed
	dd if=/dev/urandom of=$tf bs=1M count=2 conv=notrunc ||
		error "overwrite failed"
	verify_flr_state $tf "wp"

	# Verify parity mirror is stale
	local ids=($($LFS getstripe $tf |
		awk '/lcme_id/{print $2}' | tr '\n' ' '))
	verify_comp_stale $tf ${ids[1]}

	# Resync should recover parity
	$LFS mirror resync $tf || error "resync after write failed"
	verify_flr_state $tf "ro"

	# Verify data integrity through the whole cycle
	local cksum=$(md5sum $tf | awk '{print $1}')
	[[ -n "$cksum" ]] || error "cannot read file after resync"
}
run_test 30a "write makes parity stale, resync recovers"

test_30b() {
	# Test resync after parity OST recovery. Write data (parity
	# becomes stale), cycle the parity OST down and back up, then
	# verify resync succeeds and data is intact.
	# Note: we do NOT attempt resync while the OST is down because
	# designated writes to a downed OST enter uninterruptible kernel
	# sleep and cannot be timed out.
	(( OSTCOUNT >= 4 )) || skip "need >= 4 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf" EXIT

	$LFS setstripe -E -1 -S 1M -c 2 --ec 2+1 $tf ||
		error "setstripe failed"

	dd if=/dev/urandom of=$tf bs=1M count=4 || error "write failed"
	local cksum_before=$(md5sum $tf | awk '{print $1}')

	# Parity is stale after the write. Cycle the parity OST.
	local parity_ost_idx=$($LFS getstripe --mirror-id=2 $tf |
		awk '/l_ost_idx:/ {print $5; exit}' | tr -d ',')
	[[ -n "$parity_ost_idx" ]] || error "could not find parity OST"
	local parity_facet=ost$((parity_ost_idx + 1))

	echo "Cycling $parity_facet (parity OST index $parity_ost_idx)"
	stop $parity_facet
	wait_osc_import_state client $parity_facet "\(DISCONN\|IDLE\)"

	# Restart the parity OST
	start $parity_facet $(ostdevname $((parity_ost_idx + 1))) \
		$OST_MOUNT_OPTS
	wait_recovery_complete $parity_facet

	# Resync should succeed now that the OST is back
	$LFS mirror resync $tf || error "resync failed after OST recovery"
	verify_flr_state $tf "ro"

	# Verify data integrity is maintained through the whole sequence
	local cksum_after=$(md5sum $tf | awk '{print $1}')
	[[ "$cksum_before" == "$cksum_after" ]] ||
		error "data corrupted: $cksum_before != $cksum_after"
}
run_test 30b "resync succeeds after parity OST recovery"

test_30c() {
	# Test that resync correctly recomputes parity after an OST
	# that was down comes back. The sequence is:
	# 1. Create EC file, write data, resync parity (all good)
	# 2. Stop a data-mirror OST
	# 3. Start it back
	# 4. Verify data is intact and resync still works
	(( OSTCOUNT >= 4 )) || skip "need >= 4 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf" EXIT

	$LFS setstripe -E -1 -S 1M -c 2 --ec 2+1 $tf ||
		error "setstripe failed"

	dd if=/dev/urandom of=$tf bs=1M count=4 || error "write failed"
	$LFS mirror resync $tf || error "initial resync failed"
	verify_flr_state $tf "ro"

	local cksum_before=$(md5sum $tf | awk '{print $1}')

	# Stop a data OST and bring it back
	local data_ost_idx=$($LFS getstripe --mirror-id=1 $tf |
		awk '/l_ost_idx:/ {print $5; exit}' | tr -d ',')
	local data_facet=ost$((data_ost_idx + 1))

	echo "Cycling $data_facet (data OST index $data_ost_idx)"
	stop $data_facet
	wait_osc_import_state client $data_facet "\(DISCONN\|IDLE\)"

	start $data_facet $(ostdevname $((data_ost_idx + 1))) $OST_MOUNT_OPTS
	wait_recovery_complete $data_facet

	# Data should still be readable and correct
	drop_client_cache
	local cksum_after=$(md5sum $tf | awk '{print $1}')
	[[ "$cksum_before" == "$cksum_after" ]] ||
		error "data corrupted after OST cycle: $cksum_before != $cksum_after"

	# Write new data and resync - everything should still work
	dd if=/dev/urandom of=$tf bs=1M count=2 conv=notrunc ||
		error "write after OST recovery failed"
	$LFS mirror resync $tf || error "resync after OST recovery failed"
	verify_flr_state $tf "ro"
}
run_test 30c "data survives OST restart cycle, resync works after recovery"

test_30d() {
	# test that reading from ec mirror reads the full set of parities
	(( OSTCOUNT >= 4 )) || skip "needs >= 4 OSTs"

	enable_ec

	local tf=$DIR/$tfile

	# Create a simple EC file with data mirror + parity mirror
	$LFS setstripe -E -1 -S 64k -c 4 --ec 2+2 $tf ||
		error "setstripe --ec 2+2 failed"

	# Write some data to the file at block 40
	tr "\000" "\002" < /dev/zero | dd bs=64k count=1 seek=40  \
		iflag=fullblock of=$tf 2>/dev/null

	rm -f $TMP/$tfile.parity
	stack_trap "rm -f $TMP/$tfile.parity"

	# stripe size 64k, 4 data stripes, ec 2+2
	# With EC_MIN_SPLIT_SIZE=4, 4 data stripes split into 2 raid
	# sets of 2, giving 4 parity stripes per row.
	# seek=40: data reaches row 10, so 11 rows of parity.
	# parity mirror size = 11 * 4 * 64k = 2883584
	$LFS mirror read --mirror-id 2 -o $TMP/$tfile.parity $tf
	stat $TMP/$tfile.parity | grep "Size: 2883584" ||
	    error "Wrong size of parity mirror"
}
run_test 30d "test that size of parity mirror is 11*4*64k"

test_31a() {
	# Inject OBD_FAIL_OST_BRW_WRITE_BULK on a parity OST during
	# resync. The data mirror must remain intact regardless of
	# whether the resync succeeds or fails.
	(( OSTCOUNT >= 4 )) || skip "need >= 4 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf" EXIT

	$LFS setstripe -E -1 -S 1M -c 2 --ec 2+1 $tf ||
		error "setstripe failed"

	dd if=/dev/urandom of=$tf bs=1M count=4 || error "write failed"
	local cksum_before=$(md5sum $tf | awk '{print $1}')

	# Parity is stale. Now inject write failure on a parity OST.
	local parity_ost_idx=$($LFS getstripe --mirror-id=2 $tf |
		awk '/l_ost_idx:/ {print $5; exit}' | tr -d ',')
	[[ -n "$parity_ost_idx" ]] || error "could not find parity OST"
	local parity_facet=ost$((parity_ost_idx + 1))

	#define OBD_FAIL_OST_BRW_WRITE_BULK  0x20e
	echo "Injecting OBD_FAIL_OST_BRW_WRITE_BULK on $parity_facet"
	do_facet $parity_facet $LCTL set_param fail_loc=0x8000020e

	echo "Attempting resync with write failure injected..."
	$LFS mirror resync $tf 2>/dev/null
	local rc=$?

	# Clear the fail_loc
	do_facet $parity_facet $LCTL set_param fail_loc=0

	# Data mirror must be untouched regardless of resync outcome
	local cksum_after=$(md5sum $tf | awk '{print $1}')
	[[ "$cksum_before" == "$cksum_after" ]] ||
		error "data corrupted by failed resync: $cksum_before != $cksum_after"

	if (( rc != 0 )); then
		echo "Resync correctly failed with write error on parity OST"
	else
		echo "Resync appeared to succeed despite injected write failure"
	fi

	# The parity may now be corrupt (partial write). Write new data
	# to make parity stale again, then resync cleanly.
	dd if=/dev/urandom of=$tf bs=1M count=1 conv=notrunc ||
		error "write to re-stale parity failed"
	$LFS mirror resync $tf ||
		error "resync failed after re-staling parity"
	verify_flr_state $tf "ro"
}
run_test 31a "data mirror intact after write failure on parity OST during resync"

test_31b() {
	# test that reading from ec mirror reads the full set of parities
	(( OSTCOUNT >= 6 )) || skip "needs >= 6 OSTs"

	enable_ec

	local tf=$DIR/$tfile

	# Create a simple EC file with data mirror + parity mirror
	$LFS setstripe -E -1 -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write some data to the file
	echo "Hello" > $tf || error "error writing to file"

	rm -f $TMP/$tfile.parity
	stack_trap "rm -f $TMP/$tfile.parity"

	# stripe size 1M
	# 4 data stripes, ec 4+2
	# 1 raid set with 2 parities
	# parity mirror size should be 1 * 2 * 1M
	$LFS mirror read --mirror-id 2 -o $TMP/$tfile.parity $tf
	stat $TMP/$tfile.parity | grep "Size: 2097152" ||
	    error "Wrong size of parity mirror"
}
run_test 31b "test that size of parity mirror is 1*2*1M"

test_31c() {
	# test that reading from ec mirror reads the full set of parities
	(( OSTCOUNT >= 6 )) || skip "needs >= 6 OSTs"

	enable_ec

	local tf=$DIR/$tfile

	# Create a simple EC file with data mirror + parity mirror
	$LFS setstripe -E -1 -S 64k -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write some data to the file
	echo "Hello" > $tf || error "error writing to file"

	rm -f $TMP/$tfile.parity
	stack_trap "rm -f $TMP/$tfile.parity"

	# stripe size 64k
	# 4 data stripes, ec 4+2
	# 1 raid set with 2 parities
	# parity mirror size should be 1 * 2 * 64k
	$LFS mirror read --mirror-id 2 -o $TMP/$tfile.parity $tf
	stat $TMP/$tfile.parity | grep "Size: 131072" ||
	    error "Wrong size of parity mirror"
}
run_test 31c "test that size of parity mirror is 1*2*64k"

test_31d() {
	# test that reading from ec mirror reads the full set of parities
	(( OSTCOUNT >= 4 )) || skip "needs >= 4 OSTs"

	enable_ec

	local tf=$DIR/$tfile

	# Create a simple EC file with data mirror + parity mirror
	$LFS setstripe -E -1 -S 64k -c 4 --ec 2+2 $tf ||
		error "setstripe --ec 2+2 failed"

	# Write some data to the file
	echo "Hello" > $tf || error "error writing to file"

	rm -f $TMP/$tfile.parity
	stack_trap "rm -f $TMP/$tfile.parity"

	# stripe size 64k
	# 4 data stripes, ec 2+2
	# With EC_MIN_SPLIT_SIZE=4, split into 2 raid sets of 2,
	# each with 2 parities = 4 parity stripes
	# parity mirror size should be 2 * 2 * 64k
	$LFS mirror read --mirror-id 2 -o $TMP/$tfile.parity $tf
	stat $TMP/$tfile.parity | grep "Size: 262144" ||
	    error "Wrong size of parity mirror"
}
run_test 31d "test that size of parity mirror is 2*2*64k"

test_31e() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"

	enable_ec

	local tf=$DIR/$tfile
	local stripe_size=$((128 * 1024))

	rm -f $TMP/$tfile.parity
	stack_trap "rm -f $TMP/$tfile.parity"

	# Data and parity mirrors each have two components:
	# data [0, 1M) and [1M, EOF), both EC(4+2), 4 data stripes, 128k stripes
	$LFS setstripe -E 1M -S $stripe_size -c 4 -E -1 -S $stripe_size \
		-c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 with PFL failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 4

	# Write 1.5M so data spans both components (1M + 512k).
	dd if=/dev/urandom of=$tf bs=512K count=3 2>/dev/null ||
		error "failed to write 1.5M"
	(( $(stat -c %s $tf) == $((3 * 512 * 1024)) )) ||
		error "unexpected file size"

	$LFS mirror resync $tf || error "mirror resync failed"

	# Parity lsme_extent matches data lsme_extent (same file offsets, not
	# packed parity bytes).
	# ec_raidset_size = 2 parities * stripe_size = 262144.
	# Parity comp 1 (ext [1M, EOF), data 512k):
	# comp_eof = 1M + 262144 = 1310720
	local ec_raidset_size=$((2 * stripe_size))
	local expected=$((1024 * 1024 + ec_raidset_size))
	$LFS mirror read --mirror-id 2 -o $TMP/$tfile.parity $tf ||
		error "mirror read from parity failed"
	stat $TMP/$tfile.parity | grep "Size: $expected" ||
		error "Wrong size of parity mirror (expected $expected)"
}
run_test 31e "test parity mirror size with multiple PFL components"

test_31f() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	verify_yaml_available || skip_env "YAML verification not installed"
	enable_ec

	local tf=$DIR/$tfile

	# 7 data stripes, EC 3+2 -> uneven raidsets (k=3,2,2)
	$LFS setstripe -E -1 -c 7 --ec 3+2 $tf || error "setstripe failed"

	local parity_mirror_id=$($LFS getstripe $tf |
		awk '/lcme_mirror_id:/ { id=$2 }
		     /lcme_flags.*parity/ { print id; exit }')
	[[ -n "$parity_mirror_id" ]] || error "could not find parity mirror"

	local parity_comp_id=$($LFS getstripe $tf |
		awk -v mid="$parity_mirror_id" '
		/lcme_id:/ { id=$2 }
		/lcme_mirror_id:/ { if ($2 == mid) { print id; exit } }')

	verify_comp_parity $tf $parity_comp_id

	local data_comp_id=$($LFS getstripe $tf |
		awk '/lcme_id:/ {id=$2}
		     /lcme_flags:/ {
			if ($0 !~ /parity/) { print id; exit }
		     }')
	[[ -n "$data_comp_id" ]] || error "could not find data component"

	# Whole-file --ec-map (no -I): every parity component, with lcme_id
	verify_ec_raidsets $tf "" 3 \
		"lcme_id:.*$parity_comp_id" \
		'lcme_ec:[[:space:]]*3+2' \
		'0: { ec_data_count: 3, data_stripes: "0-2", parity_stripes: "0-1" }' \
		'1: { ec_data_count: 2, data_stripes: "3-4", parity_stripes: "2-3" }' \
		'2: { ec_data_count: 2, data_stripes: "5-6", parity_stripes: "4-5" }'

	# Filtered --ec-map with -I on parity
	verify_ec_raidsets $tf $parity_comp_id 3 \
		"lcme_id:.*$parity_comp_id" \
		'lcme_ec:[[:space:]]*3+2' \
		'0: { ec_data_count: 3, data_stripes: "0-2", parity_stripes: "0-1" }' \
		'1: { ec_data_count: 2, data_stripes: "3-4", parity_stripes: "2-3" }' \
		'2: { ec_data_count: 2, data_stripes: "5-6", parity_stripes: "4-5" }'

	# -I on data: reverse-lookup parity, same raidset map
	verify_ec_raidsets $tf $data_comp_id 3 \
		"lcme_id:.*$data_comp_id" \
		'lcme_ec:[[:space:]]*3+2' \
		'0: { ec_data_count: 3, data_stripes: "0-2", parity_stripes: "0-1" }' \
		'1: { ec_data_count: 2, data_stripes: "3-4", parity_stripes: "2-3" }' \
		'2: { ec_data_count: 2, data_stripes: "5-6", parity_stripes: "4-5" }'
}
run_test 31f "test getstripe EC raidset map"

test_31g() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	verify_yaml_available || skip_env "YAML verification not installed"
	enable_ec

	local tf=$DIR/$tfile
	local id out

	# Later PFL component is a template: k+p known, raidsets empty
	$LFS setstripe -E 1G -c 4 --ec 2+1 -E -1 -c 4 --ec 4+2 $tf ||
		error "setstripe failed"
	id=$($LFS getstripe $tf |
		awk '/lcme_id:/ { id=$2 }
		     /lcme_flags:/ && /parity/ && !/init/ { print id; exit }')
	[[ -n "$id" ]] || error "no uninstantiated parity component"
	verify_ec_raidsets $tf $id 0 \
		'lcme_ec:[[:space:]]*4+2' \
		'lcme_ec_raidsets: \[\]'

	# Non-EC: no stdout, warning on stderr
	$LFS setstripe -c 1 $tf.plain || error "setstripe plain failed"
	out=$($LFS getstripe --ec-map $tf.plain 2>/dev/null)
	[[ -z "$out" ]] || error "--ec-map on non-EC file: $out"
	$LFS getstripe --ec-map $tf.plain 2>&1 >/dev/null |
		grep -q "no parity component found" ||
		error "--ec-map on non-EC file missing warning"
}
run_test 31g "test getstripe --ec-map empty and uninstantiated"

test_32a() {
	# Verify that after an OST goes down and comes back, a full
	# write+resync cycle produces correct parity. This validates
	# the end-to-end recovery path.
	(( OSTCOUNT >= 4 )) || skip "need >= 4 OSTs"
	enable_ec

	local tf=$DIR/$tdir/$tfile

	test_mkdir $DIR/$tdir
	stack_trap "rm -rf $DIR/$tdir" EXIT

	$LFS setstripe -E -1 -S 1M -c 2 --ec 2+1 $tf ||
		error "setstripe failed"

	# Write known pattern and resync to establish good parity
	dd if=/dev/urandom of=$tf bs=1M count=4 || error "write 1 failed"
	$LFS mirror resync $tf || error "resync 1 failed"
	verify_flr_state $tf "ro"

	# Save parity checksum
	local parity_sum_1=$($LFS mirror read -N2 $tf | md5sum)

	# Stop a data OST, restart it
	local data_ost_idx=$($LFS getstripe --mirror-id=1 $tf |
		awk '/l_ost_idx:/ {print $5; exit}' | tr -d ',')
	local data_facet=ost$((data_ost_idx + 1))

	stop $data_facet
	wait_osc_import_state client $data_facet "\(DISCONN\|IDLE\)"
	start $data_facet $(ostdevname $((data_ost_idx + 1))) $OST_MOUNT_OPTS
	wait_recovery_complete $data_facet

	# Write new data and resync
	dd if=/dev/urandom of=$tf bs=1M count=4 conv=notrunc ||
		error "write 2 after recovery failed"
	$LFS mirror resync $tf || error "resync 2 after recovery failed"
	verify_flr_state $tf "ro"

	# Parity must have changed (new data -> new parity)
	local parity_sum_2=$($LFS mirror read -N2 $tf | md5sum)
	[[ "$parity_sum_1" != "$parity_sum_2" ]] ||
		error "parity unchanged after writing new data post-recovery"

	# Verify data is readable and consistent
	local cksum=$(md5sum $tf | awk '{print $1}')
	local mirror_cksum
	mirror_cksum=$($LFS mirror read --mirror-id 1 $tf | md5sum |
		awk '{print $1}')
	[[ "$cksum" == "$mirror_cksum" ]] ||
		error "data mirror inconsistent after recovery cycle"
}
run_test 32a "full write+resync cycle correct after OST recovery"

test_33a() {
	# Multiple writes and resyncs with an intermittent OST failure
	# in between. This exercises the stale tracking and resync logic
	# across multiple failure/recovery cycles.
	(( OSTCOUNT >= 4 )) || skip "need >= 4 OSTs"
	enable_ec

	local tf=$DIR/$tfile
	local i

	stack_trap "rm -f $tf" EXIT

	$LFS setstripe -E -1 -S 1M -c 2 --ec 2+1 $tf ||
		error "setstripe failed"

	for i in 1 2 3; do
		echo "=== Cycle $i ==="

		dd if=/dev/urandom of=$tf bs=1M count=4 conv=notrunc ||
			error "write $i failed"
		verify_flr_state $tf "wp"

		# Resync parity
		$LFS mirror resync $tf || error "resync $i failed"
		verify_flr_state $tf "ro"

		# Cycle a random data OST
		local ost_idx=$($LFS getstripe --mirror-id=1 $tf |
			awk '/l_ost_idx:/ {print $5; exit}' | tr -d ',')
		local facet=ost$((ost_idx + 1))

		stop $facet
		wait_osc_import_state client $facet "\(DISCONN\|IDLE\)"
		start $facet $(ostdevname $((ost_idx + 1))) $OST_MOUNT_OPTS
		wait_recovery_complete $facet
	done

	# Final data integrity check
	drop_client_cache
	md5sum $tf > /dev/null || error "final read failed"
	echo "Survived $i write+resync+OST-cycle iterations"
}
run_test 33a "EC survives repeated write/resync/OST-failure cycles"

test_34a() {
	# test resyncing a stale ec mirror
	(( OSTCOUNT >= 5 )) || skip_env "needs >= 5 OSTs"

	enable_ec

	test_mkdir $DIR/$tdir

	$LFS setstripe -E -1 -S 4M -c 4 --ec 3+2 $DIR/$tdir/$tfile ||
	    error "setstripe --ec 3+2 failed"

	# create a small file
	echo "hello" > $DIR/$tdir/$tfile
	SIZE1=`stat -c "%s" $DIR/$tdir/$tfile`

	# resync the ec mirror:
	$LFS mirror resync $DIR/$tdir/$tfile ||
	    error "failed to resync ec mirror"
	SIZE2=`stat -c "%s" $DIR/$tdir/$tfile`
	(( SIZE1 == SIZE2 )) ||
		error "mirror resync changed eof: ${SIZE1} vs ${SIZE2}"

	# read from the ec mirror:
	$LFS mirror read -N 2 $DIR/$tdir/$tfile >/dev/null ||
	    error "failed to read ec mirror"
	SIZE3=`stat -c "%s" $DIR/$tdir/$tfile`

	(( SIZE1 == SIZE3 )) ||
		error "mirror read changed eof: ${SIZE1} vs ${SIZE3}"
}
run_test 34a "test that lfs mirror read from ec does not change eof"

test_34b() {
	# test resyncing a stale ec mirror
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"

	enable_ec
	test_mkdir $DIR/$tdir

	$LFS setstripe -E -1 -S 4M -c 4 --ec 4+2 $DIR/$tdir/$tfile ||
	    error "setstripe --ec 4+2 failed"

	# create a small file
	echo "hello" > $DIR/$tdir/$tfile
	SIZE1=$(stat -c "%s" $DIR/$tdir/$tfile)
	BLOCKS1=$(stat -c "%b" $DIR/$tdir/$tfile)
	APPARENT1=$(stat -c "%B" $DIR/$tdir/$tfile)
	echo "After write: size=$SIZE1 blocks=$BLOCKS1 apparent_blksize=$APPARENT1"

	# resync the ec mirror:
	$LFS mirror resync $DIR/$tdir/$tfile ||
	    error "failed to resync ec mirror"
	SIZE2=$(stat -c "%s" $DIR/$tdir/$tfile)
	BLOCKS2=$(stat -c "%b" $DIR/$tdir/$tfile)
	APPARENT2=$(stat -c "%B" $DIR/$tdir/$tfile)
	echo "After resync: size=$SIZE2 blocks=$BLOCKS2 apparent_blksize=$APPARENT2"
	(( SIZE1 == SIZE2 )) ||
		error "mirror resync changed eof: ${SIZE1} vs ${SIZE2}"

	# verify the ec mirror:
	$LFS mirror verify $DIR/$tdir/$tfile ||
	    error "failed to verify ec mirror"
	SIZE3=$(stat -c "%s" $DIR/$tdir/$tfile)
	BLOCKS3=$(stat -c "%b" $DIR/$tdir/$tfile)
	APPARENT3=$(stat -c "%B" $DIR/$tdir/$tfile)
	echo "After verify: size=$SIZE3 blocks=$BLOCKS3 apparent_blksize=$APPARENT3"

	(( SIZE1 == SIZE3 )) ||
		error "mirror verify changed eof: ${SIZE1} vs ${SIZE3}"
}
run_test 34b "test that lfs mirror verify for ec does not change eof"

test_34c() {
	# test that reading past parity data returns zeros, not garbage
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"

	enable_ec

	test_mkdir $DIR/$tdir

	# Test with data sizes that span at least one full stripe.
	# Reed-Solomon parity is a linear code over GF(2^8), so parity
	# bytes at byte offset i are 0 whenever every data stripe is 0
	# at offset i.  A sub-stripe file has zero input at every offset
	# past the data tail across all data stripes, so its parity is
	# correctly zero there and "expect parity bytes" cannot succeed.
	# - 4M     (exactly one stripe)
	# - 4.5M   (one stripe + partial)
	# - 8.5M   (two stripes + partial)
	local -a test_sizes=($((4 * 1024 * 1024)) \
			     $((4 * 1024 * 1024 + 512 * 1024)) \
			     $((8 * 1024 * 1024 + 512 * 1024)))
	local size
	local i
	local parity_mirror_id

	for size in "${test_sizes[@]}"; do
		echo "Testing with data size: $size bytes"

		rm -f $DIR/$tdir/$tfile
		$LFS setstripe -E -1 -S 4M -c 8 --ec 3+2 \
			$DIR/$tdir/$tfile ||
			error "setstripe --ec 3+2 failed"

		# Write data
		dd if=/dev/urandom of=$DIR/$tdir/$tfile bs=$size \
			count=1 2>/dev/null ||
			error "failed to write $size bytes"

		# Resync to write parity
		$LFS mirror resync $DIR/$tdir/$tfile ||
			error "failed to resync ec mirror"

		# Get parity mirror ID
		parity_mirror_id=$($LFS getstripe $DIR/$tdir/$tfile | \
			grep -B1 "lcme_flags.*parity" | \
			grep "lcme_mirror_id" | awk '{print $2}')

		echo "Parity mirror ID: $parity_mirror_id"

		# Test reads at various offsets
		# For 3+2 EC with 4M stripes, we have 2 parity stripes
		# Each parity stripe should have parity data up to $size,
		# then zeros

		# Test start of first parity stripe (should have data)
		echo "  Checking offset 0 (start of first parity stripe)..."
		check_parity_read $DIR/$tdir/$tfile $parity_mirror_id \
			0 "no"

		# Parity is computed at block granularity, covering
		# only the data range.  Offsets within a parity stripe
		# but past the data range read as zeros.

		# Only check offset 1M if data extends into that range
		if (( size > 1024 * 1024 )); then
			echo "  Checking offset 1M (within first parity stripe)..."
			check_parity_read $DIR/$tdir/$tfile \
				$parity_mirror_id $((1024 * 1024)) "no"
		fi

		# Test start of second parity stripe at 4M: always has
		# data as long as any data was written (each coding stripe
		# gets parity for the same data range)
		echo "  Checking offset 4M (start of second parity stripe)..."
		check_parity_read $DIR/$tdir/$tfile $parity_mirror_id \
			$((4 * 1024 * 1024)) "no"

		# Test past all parity stripes (should be zeros)
		echo "  Checking offset 8M (past all parity)..."
		check_parity_read $DIR/$tdir/$tfile $parity_mirror_id \
			$((8 * 1024 * 1024)) "yes"
	done
}
run_test 34c "test that reading past parity data returns zeros"

test_40a() {
	(( $OSTCOUNT >= 3 )) || skip_env "needs >= 3 OSTs for EC rebuild"

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"
	enable_ec
	local dstripe=$EC_DSTRIPE
	local cstripe=$EC_CSTRIPE
	# Create a simple EC file with data mirror + parity mirror
	$LFS setstripe -E eof -S 1M -c $dstripe --ec $dstripe+$cstripe $tf ||
		error "setstripe --ec $dstripe+$cstripe failed"

	# Write some data to the file
	dd if=/dev/urandom of=$tf bs=1M count=$dstripe || error "dd failed"

	# Copy data to a temp file
	local tmpfile=$(mktemp)
	stack_trap "rm -f $tmpfile"
	dd if=$tf of=$tmpfile bs=1M count=$dstripe ||
		error "copy to $tmpfile failed"

	# Resync to update parity mirror
	$LFS mirror resync $tf || error "mirror resync failed"

	$LFS find --printf "%Lo\n" $tf

	# collect objects
	local ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' |
		tr '\n' ' '))
	local osts=($($LFS getstripe -I${ids[0]} $tf |
		awk '/l_ost_idx:/ { print $5 }' | tr -d "," ))

	# randomly disable 2 OSTs
	local idx1=$((RANDOM % ${#osts[@]}))
	local idx2=$((RANDOM % ${#osts[@]}))
	while (( $idx2 == $idx1 )); do
		idx2=$((RANDOM % ${#osts[@]}))
	done

	cancel_lru_locks osc
	echo "** Disabling OST ${osts[$idx1]}"
	local osc1=$($LCTL dl |
		awk "/OST.*${osts[$idx1]}-osc-[^M]/ {print \$4}")
	$LCTL --device $osc1 deactivate || error "deactivate $osc1 failed"
	stack_trap "$LCTL --device $osc1 activate || true"

	#Verify read still succeeds
	ls -l $tmpfile
	ls -l $tf
	cmp $tmpfile $tf || {
		diff -y --suppress-common-lines <(od -Ax -tx1z $tmpfile) \
			<(od -Ax -tx1z $tf) | head -n 20
		error "data mismatch after OST failure"
	}
	echo "         passed"

	(( cstripe > 1)) || return 0

	cancel_lru_locks osc
	echo "** Disabling OST ${osts[$idx2]}"
	local osc2=$($LCTL dl |
		awk "/OST.*${osts[$idx2]}-osc-[^M]/ {print \$4}")
	$LCTL --device $osc2 deactivate || error "deactivate $osc2 failed"
	stack_trap "$LCTL --device $osc2 activate || true"

	#Verify read still succeeds
	ls -l $tf
	cmp $tmpfile $tf || {
		diff -y --suppress-common-lines <(od -Ax -tx1z $tmpfile) \
			<(od -Ax -tx1z $tf) | head -n 20
		error "data mismatch after OST failure"
	}
	echo "         passed"
}
run_test 40a "test recovery read"

# OBD_FAIL_OST_BRW_READ_BULK is evaluated in tgt_brw_read() on the OSS,
# so fail_loc has to be set on the OST nodes, not the client.
ec_ost_fail_loc() {
	local loc=$1
	local val=${2:-0}

	do_nodes $(osts_nodes) \
		$LCTL set_param -n fail_loc=$loc fail_val=$val > /dev/null
}

# Drop resend_count to 1 so an injected -EIO reaches the LOV layer
# instead of being resent.  0 means "resend forever", so save and
# restore the original rather than assuming a default.
EC_SAVED_RESEND=""
ec_set_resend_count() {
	[[ -n "$EC_SAVED_RESEND" ]] ||
		EC_SAVED_RESEND=$($LCTL get_param -n osc.*.resend_count |
			head -n1)
	$LCTL set_param -n osc.*.resend_count=$1 > /dev/null
}

ec_restore_resend_count() {
	[[ -n "$EC_SAVED_RESEND" ]] || return 0
	$LCTL set_param -n osc.*.resend_count=$EC_SAVED_RESEND > /dev/null
	EC_SAVED_RESEND=""
}

# Simulate OST loss by failing its BRW reads while the OSC stays active,
# so the read really enters CIT_EC_RD reconstruction.  "lctl deactivate"
# would return -EIO before the recovery path and never exercise it.
# In fail_val, 0x10000 means "low bits are an OST index mask".
EC_FAULT_MASK=0
ec_apply_fault() {
	if (( EC_FAULT_MASK == 0 )); then
		ec_ost_fail_loc 0 0
		ec_restore_resend_count
	else
		ec_set_resend_count 1
		ec_ost_fail_loc 0x20f $(( 0x10000 | EC_FAULT_MASK ))
	fi
	# returns non-zero when no unused locks remain; not an error here
	cancel_lru_locks osc || true
}

# Fail an OST by index, pushing the fault-clear onto stack_trap.
ec_deactivate_ost() {
	local ost=$1

	ec_check_fault_index $ost
	EC_FAULT_MASK=$(( EC_FAULT_MASK | (1 << ost) ))
	ec_apply_fault
	stack_trap "EC_FAULT_MASK=\$(( EC_FAULT_MASK & ~(1 << $ost) )); \
		ec_apply_fault"
}

ec_reactivate_ost() {
	local ost=$1

	EC_FAULT_MASK=$(( EC_FAULT_MASK & ~(1 << ost) ))
	ec_apply_fault
}

# Sets data_osts[], parity_osts[] and safe_osts[] in the caller.
# safe_osts = data OSTs not used as parity anywhere.
ec_classify_osts() {
	local tf=$1
	local ids=($($LFS getstripe $tf | awk '/lcme_id/ { print $2 }'))
	local id flags o

	data_osts=()
	parity_osts=()
	safe_osts=()
	for id in "${ids[@]}"; do
		local osts

		flags=$($LFS getstripe -I$id $tf |
			awk '/lcme_flags:/ { print $2 }')
		osts=($($LFS getstripe -I$id $tf |
			awk '/l_ost_idx:/ { print $5 }'))
		if [[ "$flags" == *parity* ]]; then
			parity_osts+=("${osts[@]%,}")
		else
			data_osts+=("${osts[@]%,}")
		fi
	done

	local safe_flag
	for o in "${data_osts[@]}"; do
		local p

		safe_flag=true
		for p in "${parity_osts[@]}"; do
			[[ $o -eq $p ]] && safe_flag=false && break
		done
		$safe_flag && safe_osts+=($o)
	done
	safe_osts=($(printf '%s\n' "${safe_osts[@]}" | sort -un))
}

#
# Inject BRW read failures for EC recovery testing.  Both helpers use
# OBD_FAIL_OST_BRW_READ_BULK (0x20f) and drop resend_count to 1 so an
# injected -EIO reaches the LOV layer instead of being absorbed by the
# OSC.  Each must be paired with its ec_stop_* counterpart (via
# stack_trap or an explicit call).
#
# ec_start_read_fault fails one data OST for as long as the fault is
# armed, which a 4+2 or 2+1 layout can still recover from, so the read
# has to reconstruct from parity.  A one-shot fault (CFS_FAIL_ONCE) does
# not work here: resend_count=1 still permits one OSC resend, and that
# resend lands after the fault has cleared itself, so the read succeeds
# without ever reaching the recovery path.
#
# ec_start_all_reads_fail fails every OST persistently, so the parity
# reads fail too and recovery cannot succeed -- that is what the
# unrecoverable-error tests want.
#
# Use ec_deactivate_ost() when a test needs to name the OSTs itself.
#

# Map data-stripe positions to the OST indices holding them, so a test
# can say "the first and last data stripe" without assuming the
# allocator put the file on OST 0..n.  Index -1 is the last stripe.
# Fails when a wanted stripe shares an OST with a parity object: taking
# that OST out costs two objects rather than one, which would push the
# read past the recovery limit and test something else entirely.
# Usage: ec_data_stripe_osts <file> <stripe>...  -> sets EC_STRIPE_OSTS
EC_STRIPE_OSTS=()
ec_data_stripe_osts() {
	local tf=$1
	local i p

	shift
	ec_classify_osts $tf
	EC_STRIPE_OSTS=()
	for i in "$@"; do
		(( i < 0 )) && i=$(( ${#data_osts[@]} + i ))
		(( i >= 0 && i < ${#data_osts[@]} )) ||
			error "layout has ${#data_osts[@]} data stripes"
		for p in "${parity_osts[@]}"; do
			(( data_osts[i] == p )) &&
				error "data stripe $i shares a parity OST"
		done
		EC_STRIPE_OSTS+=(${data_osts[i]})
	done
}

# Pick the first of the given data stripes whose OST is not also carrying
# parity, and leave it in EC_PICKED_OST.  Stripe order is what matters: a
# file smaller than one raid set holds data on stripe 0 alone, so choosing
# by lowest OST index instead arms the fault on an object the read never
# reaches.  Stripes sharing an OST with a parity object are passed over,
# because failing one costs two objects at once.
# Usage: ec_pick_data_ost <file> [stripe]...   (default: every data stripe)
# Returns non-zero when no candidate is free of parity duty.
EC_PICKED_OST=""
ec_pick_data_ost() {
	local tf=$1
	local stripes=()
	local i p shared

	shift
	ec_classify_osts $tf
	if (( $# > 0 )); then
		stripes=("$@")
	else
		for ((i = 0; i < ${#data_osts[@]}; i++)); do
			stripes+=($i)
		done
	fi

	EC_PICKED_OST=""
	for i in "${stripes[@]}"; do
		(( i >= 0 && i < ${#data_osts[@]} )) || continue
		shared=false
		for p in "${parity_osts[@]}"; do
			(( data_osts[i] == p )) && shared=true && break
		done
		$shared && continue
		EC_PICKED_OST=${data_osts[i]}
		return 0
	done

	return 1
}

# Collect one parity-free OST from every data mirror, so a read cannot be
# served by simply switching to an intact copy.  With several data mirrors
# each holding the whole file, failing a single OST proves nothing: the
# client just reads the other mirror and no reconstruction runs.
# Usage: ec_mirror_victims <file>   -> sets EC_MIRROR_VICTIMS
EC_MIRROR_VICTIMS=()
ec_mirror_victims() {
	local tf=$1
	local comp osts o p shared

	ec_classify_osts $tf
	EC_MIRROR_VICTIMS=()
	for comp in $($LFS getstripe $tf |
		awk '/lcme_id:/ { id = $2 }
		     /lcme_flags:/ { if ($0 !~ /parity/) print id }'); do
		osts=($($LFS getstripe -I$comp $tf |
			awk '/l_ost_idx:/ { print $5 }' | tr -d ","))
		for o in "${osts[@]}"; do
			shared=false
			for p in "${parity_osts[@]}"; do
				(( o == p )) && shared=true && break
			done
			$shared && continue
			EC_MIRROR_VICTIMS+=($o)
			break
		done
	done

	(( ${#EC_MIRROR_VICTIMS[@]} > 0 ))
}

# cfs_fail_index() decodes only bits 0-15 of fail_val in bitmask mode, so a
# mask bit for an OST index >= 16 selects no OST at all: the fault never
# fires and the read succeeds without recovery, which looks exactly like a
# pass.  Fail rather than report success for a fault that was never armed.
ec_check_fault_index() {
	local ost

	for ost in "$@"; do
		(( ost < 16 )) ||
			error "OST index $ost outside fail_val mask (0-15)"
	done
}

# Usage: ec_start_read_fault <file> [ost_index]...
# Defaults to the OST holding the file's first data stripe.  Note this is
# not safe_osts[0]: that array is sorted numerically, so its first element
# is the lowest OST index rather than the OST carrying stripe 0.  A file
# smaller than one raid set has data only on stripe 0, so failing any other
# OST arms a fault the read never reaches.
EC_READ_FAULT_OSTS=()
ec_start_read_fault() {
	local tf=$1
	local mask=0
	local ost

	shift
	if (( $# > 0 )); then
		EC_READ_FAULT_OSTS=("$@")
	else
		ec_pick_data_ost $tf ||
			error "no data OST free of parity duty"
		EC_READ_FAULT_OSTS=($EC_PICKED_OST)
	fi

	ec_check_fault_index "${EC_READ_FAULT_OSTS[@]}"
	for ost in "${EC_READ_FAULT_OSTS[@]}"; do
		mask=$(( mask | (1 << ost) ))
	done

	ec_set_resend_count 1
	ec_ost_fail_loc 0x20f $(( 0x10000 | mask ))
	# cancel_lru_locks forces pages out of the client cache so
	# the next read actually issues a BRW RPC and fires fail_loc.
	# Plain drop_caches is not sufficient: pages from a buffered
	# write remain bulk-pinned for replay until the OST commits
	# the write, and mapping_evict_folio refuses to evict them.
	cancel_lru_locks osc
}

ec_stop_read_fault() {
	EC_READ_FAULT_OSTS=()
	ec_ost_fail_loc 0 0
	ec_restore_resend_count
}

# ec_start_all_reads_fail injects a persistent (non-ONCE) fault so every
# subsequent OST BRW_READ bulk fails on every OST.  EC recovery cannot
# succeed because parity reads also hit the fault.  Use this for tests
# that verify unrecoverable error paths (e.g., EIO propagation when too
# many OSTs fail for the parity count to cover).
ec_start_all_reads_fail() {
	ec_set_resend_count 1
	# 0x20f = OBD_FAIL_OST_BRW_READ_BULK, no CFS_FAIL_ONCE bit.
	# fail_val=0 targets all OSTs.  Fires on every BRW_READ until
	# cleared.
	ec_ost_fail_loc 0x20f 0
	cancel_lru_locks osc
}
ec_stop_all_reads_fail() {
	ec_ost_fail_loc 0 0
	ec_restore_resend_count
}

test_40b() {
	(( OSTCOUNT >= 3 )) || skip_env "needs >= 3 OSTs for 2+1"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 2 --ec 2+1 $tf ||
		error "setstripe --ec 2+1 failed"

	dd if=/dev/urandom of=$tf bs=1M count=2 || error "dd failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	local sum1=$(md5sum $tf | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	local sum2=$(md5sum $tf | awk '{print $1}')
	[[ "$sum1" == "$sum2" ]] ||
		error "data changed after read fault: $sum1 vs $sum2"
}
run_test 40b "test recovery read with 2+1 EC"

test_40c() {
	(( OSTCOUNT >= 4 )) || skip_env "needs >= 4 OSTs for 2+2"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 2 --ec 2+2 $tf ||
		error "setstripe --ec 2+2 failed"

	dd if=/dev/urandom of=$tf bs=1M count=2 || error "dd failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	local sum1=$(md5sum $tf | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	local sum2=$(md5sum $tf | awk '{print $1}')
	[[ "$sum1" == "$sum2" ]] ||
		error "data changed after read fault: $sum1 vs $sum2"
}
run_test 40c "test recovery read with 2+2 EC"

test_40d() {
	(( OSTCOUNT >= 5 )) || skip_env "needs >= 5 OSTs for 4+1"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+1 $tf ||
		error "setstripe --ec 4+1 failed"

	dd if=/dev/urandom of=$tf bs=1M count=4 || error "dd failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	local sum1=$(md5sum $tf | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	local sum2=$(md5sum $tf | awk '{print $1}')
	[[ "$sum1" == "$sum2" ]] ||
		error "data changed after read fault: $sum1 vs $sum2"
}
run_test 40d "test recovery read with 4+1 EC"

test_41a() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write 8MB of data (2 raid sets)
	dd if=/dev/urandom of=$tf bs=1M count=8 || error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksums of different portions before failure
	local sum_full=$(md5sum $tf | awk '{print $1}')
	local sum_first_1m=$(dd if=$tf bs=1M count=1 2>/dev/null | md5sum |
		awk '{print $1}')
	local sum_middle_2m=$(dd if=$tf bs=1M skip=3 count=2 2>/dev/null |
		md5sum | awk '{print $1}')
	local sum_last_1m=$(dd if=$tf bs=1M skip=7 count=1 2>/dev/null |
		md5sum | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	# Verify partial reads still work
	local sum_full_after=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_full" == "$sum_full_after" ]] ||
		error "full file checksum changed: $sum_full vs $sum_full_after"

	# The full-file read above left all 8M uptodate in the page cache,
	# so without dropping the locks again each partial read is a cache
	# hit: no BRW RPC, no fault, and nothing to reconstruct.
	cancel_lru_locks osc
	local sum_first_1m_after=$(dd if=$tf bs=1M count=1 2>/dev/null |
		md5sum | awk '{print $1}')
	[[ "$sum_first_1m" == "$sum_first_1m_after" ]] ||
		error "first 1M checksum changed: $sum_first_1m vs" \
			"$sum_first_1m_after"

	cancel_lru_locks osc
	local sum_middle_2m_after=$(dd if=$tf bs=1M skip=3 count=2 \
		2>/dev/null | md5sum | awk '{print $1}')
	[[ "$sum_middle_2m" == "$sum_middle_2m_after" ]] ||
		error "middle 2M checksum changed: $sum_middle_2m vs" \
			"$sum_middle_2m_after"

	cancel_lru_locks osc
	local sum_last_1m_after=$(dd if=$tf bs=1M skip=7 count=1 \
		2>/dev/null | md5sum | awk '{print $1}')
	[[ "$sum_last_1m" == "$sum_last_1m_after" ]] ||
		error "last 1M checksum changed: $sum_last_1m vs" \
			"$sum_last_1m_after"

	echo "** All partial read checksums match after OST failures"
}
run_test 41a "test partial reads with recovery"

test_41b() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write 32MB of data (8 raid sets of 4MB each)
	dd if=/dev/urandom of=$tf bs=1M count=32 || error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksums of reads spanning multiple raid sets
	local sum_full=$(md5sum $tf | awk '{print $1}')
	# Read spanning raid sets 1-2 (0-8MB)
	local sum_span_1_2=$(dd if=$tf bs=1M count=8 2>/dev/null |
		md5sum | awk '{print $1}')
	# Read spanning raid sets 3-5 (8MB-20MB)
	local sum_span_3_5=$(dd if=$tf bs=1M skip=8 count=12 2>/dev/null |
		md5sum | awk '{print $1}')
	# Read spanning raid sets 6-8 (20MB-32MB)
	local sum_span_6_8=$(dd if=$tf bs=1M skip=20 count=12 2>/dev/null |
		md5sum | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	# Verify reads spanning multiple raid sets still work
	local sum_full_after=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_full" == "$sum_full_after" ]] ||
		error "full file checksum changed: $sum_full vs $sum_full_after"

	# Drop the locks between reads: the full-file read above cached the
	# whole 32M, and a cached read issues no BRW RPC and so never hits
	# the injected fault.
	cancel_lru_locks osc
	local sum_span_1_2_after=$(dd if=$tf bs=1M count=8 2>/dev/null |
		md5sum | awk '{print $1}')
	[[ "$sum_span_1_2" == "$sum_span_1_2_after" ]] ||
		error "raid sets 1-2 checksum changed: $sum_span_1_2 vs" \
			"$sum_span_1_2_after"

	cancel_lru_locks osc
	local sum_span_3_5_after=$(dd if=$tf bs=1M skip=8 count=12 \
		2>/dev/null | md5sum | awk '{print $1}')
	[[ "$sum_span_3_5" == "$sum_span_3_5_after" ]] ||
		error "raid sets 3-5 checksum changed: $sum_span_3_5 vs" \
			"$sum_span_3_5_after"

	cancel_lru_locks osc
	local sum_span_6_8_after=$(dd if=$tf bs=1M skip=20 count=12 \
		2>/dev/null | md5sum | awk '{print $1}')
	[[ "$sum_span_6_8" == "$sum_span_6_8_after" ]] ||
		error "raid sets 6-8 checksum changed: $sum_span_6_8 vs" \
			"$sum_span_6_8_after"

	echo "** All multi-raid-set read checksums match after OST failures"
}
run_test 41b "test reads spanning multiple raid sets with recovery"

test_41c() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write 8MB of data
	dd if=/dev/urandom of=$tf bs=1M count=8 || error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Baseline checksums at aligned and unaligned offsets, so the
	# post-failure reads below can be compared against them.

	# Aligned to stripe size (1M) - offset 2M, length 2M
	local sum_aligned=$(dd if=$tf bs=1M skip=2 count=2 2>/dev/null |
		md5sum | awk '{print $1}')
	# Unaligned offset (512K) - offset 512K, length 2M
	local sum_unaligned_512k=$(dd if=$tf bs=512K skip=1 count=4 \
		2>/dev/null | md5sum | awk '{print $1}')
	# Unaligned offset (256K) - offset 1.25M, length 2M
	local sum_unaligned_256k=$(dd if=$tf bs=256K skip=5 count=8 \
		2>/dev/null | md5sum | awk '{print $1}')
	# Small unaligned read (64K offset, 128K size)
	local sum_small_unaligned=$(dd if=$tf bs=64K skip=1 count=2 \
		2>/dev/null | md5sum | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	# Drop caches to force re-read from OSTs (not from cache)
	sync; echo 3 > /proc/sys/vm/drop_caches

	# Verify reads at various offsets still work
	local sum_aligned_after=$(dd if=$tf bs=1M skip=2 count=2 \
		2>/dev/null | md5sum | awk '{print $1}')
	[[ "$sum_aligned" == "$sum_aligned_after" ]] ||
		error "aligned read (offset 2M) checksum changed after" \
			"OST failure: $sum_aligned vs $sum_aligned_after"

	local sum_unaligned_512k_after=$(dd if=$tf bs=512K skip=1 count=4 \
		2>/dev/null | md5sum | awk '{print $1}')
	[[ "$sum_unaligned_512k" == "$sum_unaligned_512k_after" ]] ||
		error "512K unaligned read (offset 512K) checksum" \
			"changed after OST failure: $sum_unaligned_512k vs" \
			"$sum_unaligned_512k_after"

	local sum_unaligned_256k_after=$(dd if=$tf bs=256K skip=5 count=8 \
		2>/dev/null | md5sum | awk '{print $1}')
	[[ "$sum_unaligned_256k" == "$sum_unaligned_256k_after" ]] ||
		error "256K unaligned read (offset 1.25M) checksum" \
			"changed after OST failure: $sum_unaligned_256k vs" \
			"$sum_unaligned_256k_after"

	local sum_small_unaligned_after=$(dd if=$tf bs=64K skip=1 count=2 \
		2>/dev/null | md5sum | awk '{print $1}')
	[[ "$sum_small_unaligned" == "$sum_small_unaligned_after" ]] ||
		error "small unaligned read (offset 64K, size 128K)" \
			"checksum changed after OST failure:" \
			"$sum_small_unaligned vs $sum_small_unaligned_after"

	echo "** aligned and unaligned read checksums match after OST failure"
}
run_test 41c "test reads at different offsets with recovery"

test_41d() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"
	local out=$TMP/$tfile.mmap.out
	stack_trap "rm -f $out"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	dd if=/dev/urandom of=$tf bs=1M count=8 || error "dd failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	# $MMAP_CAT does mmap(MAP_PRIVATE|MAP_POPULATE) + write.  This
	# forces the page-fault path (CIT_FAULT), unlike md5sum/cat
	# which use read(2).  Baseline first to confirm mmap returns
	# the same bytes as a plain read before any fault injection.
	$MMAP_CAT $tf > $out || error "mmap_cat baseline failed"
	local sum_mmap=$(md5sum $out | awk '{print $1}')
	local sum_read=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_mmap" == "$sum_read" ]] ||
		error "mmap baseline mismatch: $sum_mmap vs $sum_read"

	# Inject a persistent BRW_READ_BULK failure on the OST holding
	# the first data object so every read of that stripe forces EC
	# recovery via parity.  fail_val = 0x10000 | mask, mask bit i =
	# filesystem OST index i, so the index has to come from the
	# layout -- nothing pins the file's objects to OST 0.
	local ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}'))
	local osts=($($LFS getstripe -I${ids[0]} $tf |
		awk '/l_ost_idx:/ { print $5 }' | tr -d ","))
	local ost=${osts[0]}

	ec_check_fault_index $ost
	ec_set_resend_count 1
	stack_trap "ec_ost_fail_loc 0 0; ec_restore_resend_count"
	#define OBD_FAIL_OST_BRW_READ_BULK 0x20f
	ec_ost_fail_loc 0x20f $(( 0x10000 | (1 << ost) ))
	cancel_lru_locks osc
	sync; echo 3 > /proc/sys/vm/drop_caches

	# CIT_FAULT must route through EC recovery, otherwise the
	# page-fault read returns garbage or kills mmap_cat with
	# SIGBUS (process exits 135).
	$MMAP_CAT $tf > $out
	local rc=$?
	(( rc == 0 )) ||
		error "mmap_cat exited $rc (SIGBUS=135) under OST $ost fault"

	local sum_after=$(md5sum $out | awk '{print $1}')
	[[ "$sum_mmap" == "$sum_after" ]] ||
		error "mmap checksum changed under OST $ost fault:" \
			"$sum_mmap vs $sum_after"

	echo "** mmap read checksum matches with OST $ost persistently failing"
}
run_test 41d "test mmap reads with EC recovery"

test_41e() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write 8MB of data using Direct I/O
	dd if=/dev/urandom of=$tf bs=1M count=8 oflag=direct ||
		error "dd with direct I/O failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# ll_file_io_generic() sets ci_switch_ec_io and restarts a
	# failed DIO read on an EC file as CIT_EC_RD, so O_DIRECT has a
	# recovery path of its own; check it returns the same bytes as
	# the pre-failure read.

	# Get checksum using Direct I/O read
	local sum_before=$(dd if=$tf bs=1M count=8 iflag=direct 2>/dev/null |
		md5sum | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	# Verify Direct I/O read still works
	local sum_after=$(dd if=$tf bs=1M count=8 iflag=direct 2>/dev/null |
		md5sum | awk '{print $1}')
	[[ "$sum_before" == "$sum_after" ]] ||
		error "Direct I/O read checksum changed:" \
			"$sum_before vs $sum_after"

	echo "** Direct I/O read checksum matches after OST failures"
}
run_test 41e "test Direct I/O reads with recovery"

test_41f() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write with buffered I/O, read back with DIO during recovery
	dd if=/dev/urandom of=$tf bs=1M count=4 || error "dd failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	local sum_before=$(md5sum $tf | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	local sum_after=$(dd if=$tf bs=1M count=4 iflag=direct 2>/dev/null |
		md5sum | awk '{print $1}')
	[[ "$sum_before" == "$sum_after" ]] ||
		error "DIO read after buffered write failed: $sum_before" \
			"vs $sum_after"
}
run_test 41f "test DIO read recovery after buffered write"

test_41g() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 2+1 -- smaller stripe count
	$LFS setstripe -E eof -S 1M -c 2 --ec 2+1 $tf ||
		error "setstripe --ec 2+1 failed"

	dd if=/dev/urandom of=$tf bs=1M count=2 oflag=direct ||
		error "dd failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	local sum_before=$(dd if=$tf bs=1M count=2 iflag=direct 2>/dev/null |
		md5sum | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	local sum_after=$(dd if=$tf bs=1M count=2 iflag=direct 2>/dev/null |
		md5sum | awk '{print $1}')
	[[ "$sum_before" == "$sum_after" ]] ||
		error "DIO recovery with 2+1 EC failed: $sum_before vs" \
			"$sum_after"
}
run_test 41g "test DIO recovery with 2+1 EC"

test_41h() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write 16MB with DIO -- spans multiple raid sets
	dd if=/dev/urandom of=$tf bs=1M count=16 oflag=direct ||
		error "dd failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	local sum_before=$(dd if=$tf bs=1M count=16 iflag=direct \
		2>/dev/null | md5sum | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	local sum_after=$(dd if=$tf bs=1M count=16 iflag=direct \
		2>/dev/null | md5sum | awk '{print $1}')
	[[ "$sum_before" == "$sum_after" ]] ||
		error "DIO multi-raidset recovery failed: $sum_before vs" \
			"$sum_after"
}
run_test 41h "test DIO recovery spanning multiple raid sets"

test_41i() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	dd if=/dev/urandom of=$tf bs=1M count=8 || error "dd failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	# Verify buffered recovery works first
	local sum_before=$(md5sum $tf | awk '{print $1}')
	ec_start_read_fault $tf
	local sum_buffered=$(md5sum $tf | awk '{print $1}')
	ec_stop_read_fault
	[[ "$sum_before" == "$sum_buffered" ]] ||
		error "buffered recovery failed: $sum_before vs" \
			"$sum_buffered"

	# Now try the same file with DIO
	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	echo 3 > /proc/sys/vm/drop_caches
	local sum_dio=$(dd if=$tf bs=1M count=8 iflag=direct 2>/dev/null |
		md5sum | awk '{print $1}')
	[[ "$sum_before" == "$sum_dio" ]] ||
		error "buffered recovery works but DIO fails:" \
			"$sum_before vs $sum_dio"
}
run_test 41i "test DIO vs buffered recovery on same file"

test_41j() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec
	which aiocp || skip_env "no aiocp installed"

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"
	local tmp=$DIR/$tfile.aio

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	dd if=/dev/urandom of=$tf bs=1M count=8 oflag=direct ||
		error "dd write failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	# Baseline: AIO read without faults
	touch $tmp
	aiocp -a $PAGE_SIZE -b 1M -s 8M -f O_DIRECT $tf $tmp ||
		error "aiocp baseline failed"
	local sum_before=$(md5sum $tmp | awk '{print $1}')
	rm -f $tmp

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"
	echo 3 > /proc/sys/vm/drop_caches

	# AIO read during recovery
	touch $tmp
	aiocp -a $PAGE_SIZE -b 1M -s 8M -f O_DIRECT $tf $tmp ||
		error "aiocp with fault failed"
	# $tmp is on Lustre as well, so clear the fault before reading it
	# back: otherwise the verification read is itself taken through the
	# faulted OSTs and a mismatch says nothing about $tf.  The
	# stack_trap above still covers the error paths.
	ec_stop_read_fault
	local sum_after=$(md5sum $tmp | awk '{print $1}')
	rm -f $tmp

	[[ "$sum_before" == "$sum_after" ]] ||
		error "AIO read checksum changed: $sum_before vs $sum_after"
}
run_test 41j "test AIO reads with EC recovery"

test_41k() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec
	which aiocp || skip_env "no aiocp installed"

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"
	local tmp=$DIR/$tfile.aio

	# 2+1 EC -- smaller stripe count
	$LFS setstripe -E eof -S 1M -c 2 --ec 2+1 $tf ||
		error "setstripe --ec 2+1 failed"

	dd if=/dev/urandom of=$tf bs=1M count=2 oflag=direct ||
		error "dd write failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	touch $tmp
	aiocp -a $PAGE_SIZE -b 1M -s 2M -f O_DIRECT $tf $tmp ||
		error "aiocp baseline failed"
	local sum_before=$(md5sum $tmp | awk '{print $1}')
	rm -f $tmp

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"
	echo 3 > /proc/sys/vm/drop_caches

	touch $tmp
	aiocp -a $PAGE_SIZE -b 1M -s 2M -f O_DIRECT $tf $tmp ||
		error "aiocp with fault failed"
	# clear the fault before checksumming the copy, which is on Lustre
	ec_stop_read_fault
	local sum_after=$(md5sum $tmp | awk '{print $1}')
	rm -f $tmp

	[[ "$sum_before" == "$sum_after" ]] ||
		error "AIO 2+1 checksum changed: $sum_before vs $sum_after"
}
run_test 41k "test AIO recovery with 2+1 EC"

test_41l() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec
	which aiocp || skip_env "no aiocp installed"

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"
	local tmp=$DIR/$tfile.aio

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# 16MB spans multiple raid sets
	dd if=/dev/urandom of=$tf bs=1M count=16 oflag=direct ||
		error "dd write failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	touch $tmp
	aiocp -a $PAGE_SIZE -b 1M -s 16M -f O_DIRECT $tf $tmp ||
		error "aiocp baseline failed"
	local sum_before=$(md5sum $tmp | awk '{print $1}')
	rm -f $tmp

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"
	echo 3 > /proc/sys/vm/drop_caches

	touch $tmp
	aiocp -a $PAGE_SIZE -b 1M -s 16M -f O_DIRECT $tf $tmp ||
		error "aiocp multi-raidset failed"
	# clear the fault before checksumming the copy, which is on Lustre
	ec_stop_read_fault
	local sum_after=$(md5sum $tmp | awk '{print $1}')
	rm -f $tmp

	[[ "$sum_before" == "$sum_after" ]] ||
		error "AIO multi-raidset checksum changed: $sum_before vs" \
			"$sum_after"
}
run_test 41l "test AIO recovery spanning multiple raid sets"

test_41m() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec
	which aiocp || skip_env "no aiocp installed"

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"
	local tmp=$DIR/$tfile.aio

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	dd if=/dev/urandom of=$tf bs=1M count=8 || error "dd failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	# Large block size -- single AIO covers full file
	touch $tmp
	aiocp -a $PAGE_SIZE -b 8M -s 8M -f O_DIRECT $tf $tmp ||
		error "aiocp baseline failed"
	local sum_before=$(md5sum $tmp | awk '{print $1}')
	rm -f $tmp

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"
	echo 3 > /proc/sys/vm/drop_caches

	touch $tmp
	aiocp -a $PAGE_SIZE -b 8M -s 8M -f O_DIRECT $tf $tmp ||
		error "aiocp large block failed"
	# clear the fault before checksumming the copy, which is on Lustre
	ec_stop_read_fault
	local sum_after=$(md5sum $tmp | awk '{print $1}')
	rm -f $tmp

	[[ "$sum_before" == "$sum_after" ]] ||
		error "AIO large block checksum changed: $sum_before vs" \
			"$sum_after"
}
run_test 41m "test AIO recovery with large block size"

test_41n() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec
	which aiocp || skip_env "no aiocp installed"

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"
	local tmp=$DIR/$tfile.aio

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	dd if=/dev/urandom of=$tf bs=1M count=8 || error "dd failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	# Verify buffered and sync DIO recovery work first
	local sum_before=$(md5sum $tf | awk '{print $1}')

	ec_start_read_fault $tf
	local sum_buffered=$(md5sum $tf | awk '{print $1}')
	ec_stop_read_fault
	[[ "$sum_before" == "$sum_buffered" ]] ||
		error "buffered recovery failed: $sum_before vs" \
			"$sum_buffered"

	# Now try AIO on the same file
	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"
	echo 3 > /proc/sys/vm/drop_caches

	touch $tmp
	aiocp -a $PAGE_SIZE -b 1M -s 8M -f O_DIRECT $tf $tmp ||
		error "aiocp with fault failed"
	# clear the fault before checksumming the copy, which is on Lustre
	ec_stop_read_fault
	local sum_aio=$(md5sum $tmp | awk '{print $1}')
	rm -f $tmp

	[[ "$sum_before" == "$sum_aio" ]] ||
		error "buffered works but AIO fails: $sum_before vs" \
			"$sum_aio"
}
run_test 41n "test AIO vs buffered recovery on same file"

test_42a() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration, 1M stripe size
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write file smaller than one stripe (512K with 1M stripe)
	# This tests if recovery works when file doesn't span all data OSTs
	dd if=/dev/urandom of=$tf bs=512K count=1 || error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksum before failure
	local sum1=$(md5sum $tf | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	# Verify read still succeeds
	local sum2=$(md5sum $tf | awk '{print $1}')
	[[ "$sum1" == "$sum2" ]] ||
		error "data changed after OST failure: $sum1 vs $sum2"
	echo "** File smaller than stripe size: recovery successful"
}
run_test 42a "test recovery with file smaller than stripe size"

test_42b() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration, 1M stripe size
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write file with partial stripes (1.5M = 1 full + 0.5 partial)
	# This tests if recovery handles partial stripe reconstruction
	dd if=/dev/urandom of=$tf bs=512K count=3 || error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksum before failure
	local sum1=$(md5sum $tf | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	# Verify read still succeeds
	local sum2=$(md5sum $tf | awk '{print $1}')
	[[ "$sum1" == "$sum2" ]] ||
		error "data changed after OST failure: $sum1 vs $sum2"
	echo "** File with partial stripes: recovery successful"
}
run_test 42b "test recovery with partial stripes"

test_42c() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration, 1M stripe size
	# With 4+2 EC, a complete raid set is 4MB (4 data stripes * 1M)
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write 3M - doesn't complete a raid set (< 4MB)
	# This tests if recovery works with incomplete raid sets
	dd if=/dev/urandom of=$tf bs=1M count=3 || error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksum before failure
	local sum1=$(md5sum $tf | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	# Verify read still succeeds
	local sum2=$(md5sum $tf | awk '{print $1}')
	[[ "$sum1" == "$sum2" ]] ||
		error "data changed after OST failure: $sum1 vs $sum2"
	echo "** File with incomplete raid set: recovery successful"
}
run_test 42c "test recovery with incomplete raid set"

test_42d() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create PFL file with EC - two components with different extents
	# Component 1: [0, 4M] with 4+2 EC
	# Component 2: [4M, EOF] with 4+2 EC
	$LFS setstripe -E 4M -S 1M -c 4 --ec 4+2 \
		-E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe with PFL failed"

	# Write data that spans the component boundary
	# Write 6M total: 4M in first component, 2M in second component
	dd if=/dev/urandom of=$tf bs=1M count=6 || error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksums before failure
	local sum_full=$(md5sum $tf | awk '{print $1}')
	# Read from first component only (0-4M)
	local sum_comp1=$(dd if=$tf bs=1M count=4 2>/dev/null |
		md5sum | awk '{print $1}')
	# Read from second component only (4M-6M)
	local sum_comp2=$(dd if=$tf bs=1M skip=4 count=2 2>/dev/null |
		md5sum | awk '{print $1}')
	# Read spanning the boundary (2M-6M, crosses at 4M)
	local sum_span=$(dd if=$tf bs=1M skip=2 count=4 2>/dev/null |
		md5sum | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	# Verify all reads still succeed
	local sum_full_after=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_full" == "$sum_full_after" ]] ||
		error "full file checksum changed: $sum_full vs $sum_full_after"

	# Each per-component read needs its own lock cancellation, or it is
	# served from the cache the full-file read just filled and never
	# reaches the faulted OST.
	cancel_lru_locks osc
	local sum_comp1_after=$(dd if=$tf bs=1M count=4 2>/dev/null |
		md5sum | awk '{print $1}')
	[[ "$sum_comp1" == "$sum_comp1_after" ]] ||
		error "component 1 checksum changed: $sum_comp1 vs" \
			"$sum_comp1_after"

	cancel_lru_locks osc
	local sum_comp2_after=$(dd if=$tf bs=1M skip=4 count=2 \
		2>/dev/null | md5sum | awk '{print $1}')
	[[ "$sum_comp2" == "$sum_comp2_after" ]] ||
		error "component 2 checksum changed: $sum_comp2 vs" \
			"$sum_comp2_after"

	cancel_lru_locks osc
	local sum_span_after=$(dd if=$tf bs=1M skip=2 count=4 \
		2>/dev/null | md5sum | awk '{print $1}')
	[[ "$sum_span" == "$sum_span_after" ]] ||
		error "boundary-spanning checksum changed: $sum_span vs" \
			"$sum_span_after"

	echo "** PFL component boundary recovery successful"
}
run_test 42d "test recovery at PFL component boundaries"

test_43a() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write 8MB of data
	dd if=/dev/urandom of=$tf bs=1M count=8 || error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksum before failure
	local sum_before=$(md5sum $tf | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	# Verify read still succeeds with 1 OST failure
	local sum_after=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_before" == "$sum_after" ]] ||
		error "checksum changed after single OST failure: $sum_before" \
			"vs $sum_after"

	echo "** Single OST failure recovery successful"
}
run_test 43a "test recovery with single OST failure (1 of 6 OSTs)"

test_43b() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write 8MB of data
	dd if=/dev/urandom of=$tf bs=1M count=8 || error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksum before failure
	local sum_before=$(md5sum $tf | awk '{print $1}')

	# 4+2 tolerates two lost objects; fail exactly that many.
	ec_data_stripe_osts $tf 0 1
	ec_start_read_fault $tf "${EC_STRIPE_OSTS[@]}"
	stack_trap "ec_stop_read_fault"

	# Verify read still succeeds at the recovery limit
	local sum_after=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_before" == "$sum_after" ]] ||
		error "checksum changed at max failures: $sum_before vs" \
			"$sum_after"

	echo "** Maximum recoverable failure (2 OSTs) recovery successful"
}
run_test 43b "test recovery at maximum (2 OST failures with 4+2 EC)"

test_43c() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	dd if=/dev/urandom of=$tf bs=1M count=8 conv=fsync ||
		error "dd failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	# Fail every OST read persistently: both data and parity
	# reads fail, so EC cannot recover.
	ec_start_all_reads_fail
	stack_trap "ec_stop_all_reads_fail"

	# Verify read fails with -EIO (not corrupt data or crash)
	dd if=$tf of=/dev/null bs=1M 2>&1 | grep -q "Input/output error" ||
		error "Read should fail with EIO when all reads fail"
	echo "** Read correctly failed with I/O error"
}
run_test 43c "test graceful failure with too many OST failures (3+ OSTs)"

test_43d() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	dd if=/dev/urandom of=$tf bs=1M count=8 || error "dd failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	local sum_before=$(md5sum $tf | awk '{print $1}')

	# Round 1: inject faults, read, verify, clear
	ec_start_read_fault $tf
	local sum_after1=$(md5sum $tf | awk '{print $1}')
	ec_stop_read_fault
	[[ "$sum_before" == "$sum_after1" ]] ||
		error "checksum changed: $sum_before vs $sum_after1"
	echo "** Read successful after first fault round"

	# Round 2: fail a second data stripe on top of the first.  4+2
	# tolerates two lost objects, so the read must still reconstruct.
	ec_data_stripe_osts $tf 0 1
	ec_start_read_fault $tf "${EC_STRIPE_OSTS[@]}"
	stack_trap "ec_stop_read_fault"
	local sum_after2=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_before" == "$sum_after2" ]] ||
		error "checksum changed with two OSTs failed:" \
			"$sum_before vs $sum_after2"
	echo "** Read successful with two data stripes failed"
}
run_test 43d "test progressive failures (fail 1, verify, fail 2nd, verify)"

test_44a() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	dd if=/dev/urandom of=$tf bs=1M count=8 conv=fsync ||
		error "dd failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	# Fail every OST read persistently: EC cannot recover.
	ec_start_all_reads_fail
	stack_trap "ec_stop_all_reads_fail"

	# Verify read returns EIO (not corrupt data or crash)
	dd if=$tf of=/dev/null bs=1M 2>&1 | grep -q "Input/output error" ||
		error "Read should return EIO when all reads fail"
	echo "** Read correctly returned -EIO"

	# Clear faults and verify file is accessible again
	ec_stop_all_reads_fail
	cancel_lru_locks osc
	dd if=$tf of=/dev/null bs=1M 2>/dev/null ||
		error "File should be readable after faults cleared"

	echo "** Error handling verified: -EIO returned, file accessible" \
		"after clear"
}
run_test 44a "test error handling with too many OST failures"

test_44b() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write 8MB of data
	dd if=/dev/urandom of=$tf bs=1M count=8 || error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksum before failures
	local sum_before=$(md5sum $tf | awk '{print $1}')

	echo "** Round 1: Inject read faults, verify recovery"
	ec_start_read_fault $tf
	local sum_round1=$(md5sum $tf | awk '{print $1}')
	ec_stop_read_fault
	[[ "$sum_before" == "$sum_round1" ]] ||
		error "checksum changed after round 1: $sum_before vs" \
			"$sum_round1"
	echo "** Round 1 recovery successful"

	echo "** Round 2: Re-inject faults, verify recovery again"
	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"
	local sum_round2=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_before" == "$sum_round2" ]] ||
		error "checksum changed after round 2: $sum_before vs" \
			"$sum_round2"
	echo "** Round 2 recovery successful"
}
run_test 44b "test repeated recovery with read fault injection"

test_44c() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write 8MB of data
	dd if=/dev/urandom of=$tf bs=1M count=8 conv=fsync ||
		error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Fail every OST read persistently: both data and recovery
	# reads fail, so EC cannot recover.
	ec_start_all_reads_fail
	stack_trap "ec_stop_all_reads_fail"

	# Read should fail with EIO
	dd if=$tf of=/dev/null bs=1M 2>&1 | grep -q "Input/output error" ||
		error "Read should return EIO when recovery reads also fail"
	echo "** Read correctly returned -EIO"

	# Clear faults and verify file is accessible again
	ec_stop_all_reads_fail
	cancel_lru_locks osc
	dd if=$tf of=/dev/null bs=1M 2>/dev/null ||
		error "File should be readable after faults cleared"

	echo "** Error handling verified: -EIO returned, file accessible" \
		"after clear"
}
run_test 44c "test error handling with read failures during recovery"

test_45a() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write 8MB of data
	dd if=/dev/urandom of=$tf bs=1M count=8 || error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksum before failure
	local sum_before=$(md5sum $tf | awk '{print $1}')

	ec_data_stripe_osts $tf 0 1
	ec_start_read_fault $tf "${EC_STRIPE_OSTS[@]}"
	stack_trap "ec_stop_read_fault"

	# Verify read succeeds with consecutive OST failures
	local sum_after=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_before" == "$sum_after" ]] ||
		error "Consecutive OST failure recovery failed"

	echo "** Consecutive OST failure recovery successful"
}
run_test 45a "test recovery with consecutive OST failures (OST0 and OST1)"

test_45b() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write 8MB of data
	dd if=/dev/urandom of=$tf bs=1M count=8 || error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksum before failure
	local sum_before=$(md5sum $tf | awk '{print $1}')

	ec_data_stripe_osts $tf 0 3
	ec_start_read_fault $tf "${EC_STRIPE_OSTS[@]}"
	stack_trap "ec_stop_read_fault"

	# Verify read succeeds with non-consecutive OST failures
	local sum_after=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_before" == "$sum_after" ]] ||
		error "Non-consecutive OST failure recovery failed"

	echo "** Non-consecutive OST failure recovery successful"
}
run_test 45b "test recovery with non-consecutive OST failures (OST0 and OST3)"

test_45c() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write 8MB of data
	dd if=/dev/urandom of=$tf bs=1M count=8 || error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksum before failure
	local sum_before=$(md5sum $tf | awk '{print $1}')

	# Fail only the parity objects: the data stripes are all intact,
	# so the read never reconstructs and the failure is invisible.
	ec_classify_osts $tf
	(( ${#parity_osts[@]} >= 1 )) || skip_env "no parity OSTs found"
	ec_start_read_fault $tf "${parity_osts[@]}"
	stack_trap "ec_stop_read_fault"

	# Verify read succeeds - should be transparent since data OSTs are fine
	local sum_after=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_before" == "$sum_after" ]] ||
		error "Parity-only OST failure should be transparent"

	echo "** Parity-only OST failure handled correctly (no reconstruction" \
		"needed)"
}
run_test 45c "test recovery with only parity OSTs failed (transparent)"

test_45d() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write 8MB of data
	dd if=/dev/urandom of=$tf bs=1M count=8 || error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksum before failure
	local sum_before=$(md5sum $tf | awk '{print $1}')

	ec_data_stripe_osts $tf 0 2
	ec_start_read_fault $tf "${EC_STRIPE_OSTS[@]}"
	stack_trap "ec_stop_read_fault"

	# Verify read succeeds with specific data OST failures
	local sum_after=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_before" == "$sum_after" ]] ||
		error "Specific data OST failure recovery failed"

	echo "** Specific data OST (0,2) failure recovery successful"
}
run_test 45d "test recovery with specific data OST failures (OST0 and OST2)"

test_46a() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration and 64K stripe size
	$LFS setstripe -E eof -S 64K -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 -S 64K failed"

	# Write 1MB of data (16 stripes across 4 OSTs with 64K stripe)
	dd if=/dev/urandom of=$tf bs=1M count=1 || error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksum before failure
	local sum_before=$(md5sum $tf | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	# Verify read succeeds with correct data
	local sum_after=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_before" == "$sum_after" ]] ||
		error "64K stripe recovery failed: $sum_before vs $sum_after"

	echo "** 64K stripe size recovery successful"
}
run_test 46a "test EC recovery with 64K stripe size"

test_46b() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration and 256K stripe size
	$LFS setstripe -E eof -S 256K -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 -S 256K failed"

	# Write 4MB of data (16 stripes across 4 OSTs with 256K stripe)
	dd if=/dev/urandom of=$tf bs=1M count=4 || error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksum before failure
	local sum_before=$(md5sum $tf | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	# Verify read succeeds with correct data
	local sum_after=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_before" == "$sum_after" ]] ||
		error "256K stripe recovery failed: $sum_before vs $sum_after"

	echo "** 256K stripe size recovery successful"
}
run_test 46b "test EC recovery with 256K stripe size"

test_46c() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration and 4M stripe size
	$LFS setstripe -E eof -S 4M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 -S 4M failed"

	# Write 16MB of data (4 stripes across 4 OSTs with 4M stripe)
	dd if=/dev/urandom of=$tf bs=1M count=16 || error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksum before failure
	local sum_before=$(md5sum $tf | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	# Verify read succeeds with correct data
	local sum_after=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_before" == "$sum_after" ]] ||
		error "4M stripe recovery failed: $sum_before vs $sum_after"

	echo "** 4M stripe size recovery successful"
}
run_test 46c "test EC recovery with 4M stripe size"

test_46d() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create PFL file with mixed stripe sizes:
	# Component 1: [0, 4M] with 1M stripe
	# Component 2: [4M, EOF] with 4M stripe
	$LFS setstripe -E 4M -S 1M -c 4 --ec 4+2 \
		-E eof -S 4M -c 4 --ec 4+2 $tf ||
		error "setstripe with mixed stripe sizes failed"

	# Write 12MB of data spanning both components
	dd if=/dev/urandom of=$tf bs=1M count=12 || error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksums for different regions
	local sum_full=$(md5sum $tf | awk '{print $1}')
	local sum_comp1=$(dd if=$tf bs=1M count=4 2>/dev/null |
		md5sum | awk '{print $1}')
	local sum_comp2=$(dd if=$tf bs=1M skip=4 count=8 2>/dev/null |
		md5sum | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	# Verify all reads succeed
	local sum_full_after=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_full" == "$sum_full_after" ]] ||
		error "Mixed stripe full recovery failed"

	# Without cancelling locks these re-reads come from the page cache
	# the full-file read filled and never issue a BRW RPC.
	cancel_lru_locks osc
	local sum_comp1_after=$(dd if=$tf bs=1M count=4 2>/dev/null |
		md5sum | awk '{print $1}')
	[[ "$sum_comp1" == "$sum_comp1_after" ]] ||
		error "Mixed stripe comp1 recovery failed"

	cancel_lru_locks osc
	local sum_comp2_after=$(dd if=$tf bs=1M skip=4 count=8 2>/dev/null |
		md5sum | awk '{print $1}')
	[[ "$sum_comp2" == "$sum_comp2_after" ]] ||
		error "Mixed stripe comp2 recovery failed"

	echo "** Mixed stripe sizes recovery successful"
}
run_test 46d "test EC recovery with mixed stripe sizes in PFL layout"

test_47a() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create PFL file with multiple EC components:
	# Component 1: [0, 16M] with 2+1 EC (needs 3 OSTs)
	# Component 2: [16M, EOF] with 4+2 EC (needs 6 OSTs)
	$LFS setstripe -E 16M -S 1M -c 2 --ec 2+1 \
		-E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe with multiple EC components failed"

	# Write 32MB of data spanning both components
	dd if=/dev/urandom of=$tf bs=1M count=32 || error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksum before failure
	local sum_before=$(md5sum $tf | awk '{print $1}')
	local sum_comp1=$(dd if=$tf bs=1M count=16 2>/dev/null |
		md5sum | awk '{print $1}')
	local sum_comp2=$(dd if=$tf bs=1M skip=16 count=16 2>/dev/null |
		md5sum | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	# Verify all reads succeed
	local sum_after=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_before" == "$sum_after" ]] ||
		error "Multiple EC components full recovery failed"

	# Without cancelling locks these re-reads come from the page cache
	# the full-file read filled and never issue a BRW RPC.
	cancel_lru_locks osc
	local sum_comp1_after=$(dd if=$tf bs=1M count=16 2>/dev/null |
		md5sum | awk '{print $1}')
	[[ "$sum_comp1" == "$sum_comp1_after" ]] ||
		error "Multiple EC components comp1 recovery failed"

	cancel_lru_locks osc
	local sum_comp2_after=$(dd if=$tf bs=1M skip=16 count=16 2>/dev/null |
		md5sum | awk '{print $1}')
	[[ "$sum_comp2" == "$sum_comp2_after" ]] ||
		error "Multiple EC components comp2 recovery failed"

	echo "** Multiple EC components recovery successful"
}
run_test 47a "test EC recovery with multiple EC components in PFL"

test_47b() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create PFL file with EC and non-EC components:
	# Component 1: [0, 4M] RAID0 (no EC)
	# Component 2: [4M, EOF] with 4+2 EC
	$LFS setstripe -E 4M -S 1M -c 4 \
		-E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe with EC and non-EC components failed"

	dd if=/dev/urandom of=$tf bs=1M count=16 || error "dd failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	local sum_comp2=$(dd if=$tf bs=1M skip=4 count=12 2>/dev/null |
		md5sum | awk '{print $1}')

	# ec_classify_osts() lumps every non-parity component into
	# data_osts with comp1 first, so data stripe 4 is the EC
	# component's first stripe.  Failing one of comp1's plain RAID0
	# OSTs instead would leave the 4M-16M read below untouched and its
	# comparison true no matter what recovery does.
	ec_data_stripe_osts $tf 4
	ec_start_read_fault $tf "${EC_STRIPE_OSTS[@]}"
	stack_trap "ec_stop_read_fault"

	# EC component should recover via parity
	local sum_comp2_after=$(dd if=$tf bs=1M skip=4 count=12 \
		2>/dev/null | md5sum | awk '{print $1}')
	[[ "$sum_comp2" == "$sum_comp2_after" ]] ||
		error "EC recovery failed: $sum_comp2 vs $sum_comp2_after"
	echo "** EC+non-EC mixed layout recovery successful"
}
run_test 47b "test EC recovery with EC and non-EC components in PFL"

test_47c() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create PFL file with different stripe sizes per EC component:
	# Component 1: [0, 8M] with 1M stripes, 4+2 EC
	# Component 2: [8M, EOF] with 4M stripes, 4+2 EC
	$LFS setstripe -E 8M -S 1M -c 4 --ec 4+2 \
		-E eof -S 4M -c 4 --ec 4+2 $tf ||
		error "setstripe with different stripe sizes failed"

	# Write 24MB of data spanning both components
	dd if=/dev/urandom of=$tf bs=1M count=24 || error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksums before failure
	local sum_full=$(md5sum $tf | awk '{print $1}')
	local sum_comp1=$(dd if=$tf bs=1M count=8 2>/dev/null |
		md5sum | awk '{print $1}')
	local sum_comp2=$(dd if=$tf bs=1M skip=8 count=16 2>/dev/null |
		md5sum | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	# Drop cached locks to force re-read from OSTs via EC recovery
	cancel_lru_locks osc

	# Verify all reads succeed
	local sum_full_after=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_full" == "$sum_full_after" ]] ||
		error "Different stripe sizes full recovery failed"

	local sum_comp1_after=$(dd if=$tf bs=1M count=8 2>/dev/null |
		md5sum | awk '{print $1}')
	[[ "$sum_comp1" == "$sum_comp1_after" ]] ||
		error "Different stripe sizes comp1 (1M) recovery failed"

	local sum_comp2_after=$(dd if=$tf bs=1M skip=8 count=16 2>/dev/null |
		md5sum | awk '{print $1}')
	[[ "$sum_comp2" == "$sum_comp2_after" ]] ||
		error "Different stripe sizes comp2 (4M) recovery failed"

	echo "** Different stripe sizes per component recovery successful"
}
run_test 47c "test EC recovery with different stripe sizes per PFL component"

test_47d() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create PFL file with boundary at 8M:
	# Component 1: [0, 8M] with 4+2 EC
	# Component 2: [8M, EOF] with 4+2 EC
	$LFS setstripe -E 8M -S 1M -c 4 --ec 4+2 \
		-E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe for boundary test failed"

	# Write 16MB of data
	dd if=/dev/urandom of=$tf bs=1M count=16 || error "dd failed"

	# Resync to update parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksum for boundary-spanning region (6M offset, 4M length)
	# This crosses the 8M boundary: reads 6M-8M from comp1,
	# 8M-10M from comp2
	local sum_boundary=$(dd if=$tf bs=1M skip=6 count=4 2>/dev/null |
		md5sum | awk '{print $1}')
	# Also test other boundary-spanning regions
	local sum_boundary2=$(dd if=$tf bs=1M skip=7 count=2 2>/dev/null |
		md5sum | awk '{print $1}')
	local sum_full=$(md5sum $tf | awk '{print $1}')

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	# Verify boundary-spanning reads succeed
	local sum_boundary_after=$(dd if=$tf bs=1M skip=6 count=4 2>/dev/null |
		md5sum | awk '{print $1}')
	[[ "$sum_boundary" == "$sum_boundary_after" ]] ||
		error "Boundary read (6M+4M) failed: $sum_boundary vs" \
			"$sum_boundary_after"

	local sum_boundary2_after=$(dd if=$tf bs=1M skip=7 count=2 2>/dev/null |
		md5sum | awk '{print $1}')
	[[ "$sum_boundary2" == "$sum_boundary2_after" ]] ||
		error "Boundary read (7M+2M) failed: $sum_boundary2 vs" \
			"$sum_boundary2_after"

	local sum_full_after=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_full" == "$sum_full_after" ]] ||
		error "Full file read failed after OST failures"

	echo "** Boundary-spanning reads recovery successful"
}
run_test 47d "test EC recovery with reads spanning PFL component boundaries"

test_48a() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write data
	dd if=/dev/urandom of=$tf bs=1M count=8 || error "dd failed"

	# Get checksum before any failures
	local sum_before=$(md5sum $tf | awk '{print $1}')

	# Intentionally DO NOT resync - parity is stale
	echo "** Skipping resync - parity remains stale"

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	# Parity was never computed, so EC cannot reconstruct the failed
	# stripe.  Either outcome is acceptable -- the read returns the
	# original bytes, or it fails -- but handing back silently wrong
	# data would be a corruption bug, so assert against it.
	local out=$TMP/$tfile.stale
	stack_trap "rm -f $out"

	if dd if=$tf of=$out bs=1M 2>/dev/null; then
		local sum_after=$(md5sum $out | awk '{print $1}')

		[[ "$sum_before" == "$sum_after" ]] ||
			error "stale-parity read returned wrong data:" \
				"$sum_before vs $sum_after"
		echo "** Read with stale parity returned correct data"
	else
		echo "** Read with stale parity failed, as expected"
	fi
}
run_test 48a "test recovery behavior with stale parity"

test_48b() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create PFL file with two EC components to allow partial resync
	# Component 1: [0, 16M] with 4+2 EC
	# Component 2: [16M, EOF] with 4+2 EC
	$LFS setstripe -E 16M -S 1M -c 4 --ec 4+2 \
		-E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe for partial resync test failed"

	# Write 32MB spanning both components
	dd if=/dev/urandom of=$tf bs=1M count=32 || error "dd failed"

	# Get checksums for both halves
	local sum_first=$(dd if=$tf bs=1M count=16 2>/dev/null |
		md5sum | awk '{print $1}')
	local sum_second=$(dd if=$tf bs=1M skip=16 count=16 2>/dev/null |
		md5sum | awk '{print $1}')

	# Resync the whole file.  A component-qualified resync is not
	# available here, so both components are brought up to date.
	# Use mirror resync with component ID
	local ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' |
		tr '\n' ' '))
	echo "** Component IDs: ${ids[*]}"
	echo "** Resyncing the file (component ${ids[0]} included)"

	# Full resync then write to second half to make it stale
	$LFS mirror resync $tf || error "mirror resync failed"

	# Overwrite second half to make its parity stale
	dd if=/dev/urandom of=$tf bs=1M seek=16 count=16 conv=notrunc ||
		error "overwrite second half failed"

	# Update checksum for second half after overwrite
	sum_second=$(dd if=$tf bs=1M skip=16 count=16 2>/dev/null |
		md5sum | awk '{print $1}')

	# Now first half has valid parity, second half has stale parity
	echo "** First half: valid parity, Second half: stale parity"

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	# First half should recover correctly (valid parity)
	local sum_first_after=$(dd if=$tf bs=1M count=16 2>/dev/null |
		md5sum | awk '{print $1}')
	[[ "$sum_first" == "$sum_first_after" ]] ||
		error "First half recovery failed: $sum_first vs" \
			"$sum_first_after"
	echo "** First half (valid parity) recovery successful"

	# The second half's parity is stale, so recovery there may fail;
	# what it must not do is return data that differs from what was
	# written.
	local out=$TMP/$tfile.second
	stack_trap "rm -f $out"

	if dd if=$tf of=$out bs=1M skip=16 count=16 2>/dev/null; then
		local sum_second_after=$(md5sum $out | awk '{print $1}')

		[[ "$sum_second" == "$sum_second_after" ]] ||
			error "second half returned wrong data:" \
				"$sum_second vs $sum_second_after"
		echo "** Second half (stale parity) returned correct data"
	else
		echo "** Second half read failed, as expected with stale parity"
	fi
}
run_test 48b "test recovery with partially stale parity"

test_48c() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write initial data
	dd if=/dev/urandom of=$tf bs=1M count=8 || error "initial dd failed"

	# Resync to have valid parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksum of synced data
	local sum_synced=$(md5sum $tf | awk '{print $1}')
	echo "** Initial data synced, checksum: $sum_synced"

	# Overwrite part of the file WITHOUT resyncing
	# This makes parity stale for the overwritten region
	dd if=/dev/urandom of=$tf bs=1M seek=2 count=4 conv=notrunc ||
		error "overwrite dd failed"

	# Get new checksum after overwrite
	local sum_overwritten=$(md5sum $tf | awk '{print $1}')
	echo "** After overwrite (no resync), checksum: $sum_overwritten"

	# DO NOT resync - parity is now stale for overwritten region
	echo "** Skipping resync after overwrite - parity is stale"

	ec_start_read_fault $tf
	stack_trap "ec_stop_read_fault"

	# Parity still covers the pre-overwrite contents, so recovery of
	# the overwritten range may fail.  Returning the stale, pre-
	# overwrite bytes would be worse than failing: it is a silent
	# rollback of an acknowledged write.
	local out=$TMP/$tfile.overwritten
	local rc=0

	stack_trap "rm -f $out"
	dd if=$tf of=$out bs=1M 2>/dev/null || rc=$?

	if (( rc == 0 )); then
		local sum_after=$(md5sum $out | awk '{print $1}')

		[[ "$sum_synced" != "$sum_after" ]] ||
			error "recovery returned pre-overwrite data"
		[[ "$sum_overwritten" == "$sum_after" ]] ||
			error "recovery returned wrong data:" \
				"$sum_overwritten vs $sum_after"
		echo "** Read after overwrite returned correct data"
	else
		echo "** Read with stale parity failed, as expected"
	fi

	# LCME_FL_STALE is per component, so the overwrite above stales the
	# whole parity mirror and the branch taken there is not guaranteed.
	# Resync and repeat: with parity up to date the degraded read must
	# succeed and return the post-overwrite bytes.  That is the check
	# that can actually fail.
	ec_stop_read_fault
	$LFS mirror resync $tf || error "resync after overwrite failed"

	ec_start_read_fault $tf
	dd if=$tf of=$out bs=1M 2>/dev/null ||
		error "degraded read failed after resync"

	local sum_resynced=$(md5sum $out | awk '{print $1}')

	[[ "$sum_overwritten" == "$sum_resynced" ]] ||
		error "recovery after resync returned wrong data:" \
			"$sum_overwritten vs $sum_resynced"
	echo "** Recovery after resync returned the overwritten data"
}
run_test 48c "test recovery after overwrite without resync"

test_49a() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	dd if=/dev/urandom of=$tf bs=1M count=32 ||
		error "dd failed"

	$LFS mirror resync $tf || error "mirror resync failed"

	local sum_expected=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 2 )) ||
		skip_env "need >= 2 safe data OSTs"

	echo "** Concurrent reads: Disabling OSTs" \
		"${safe_osts[0]} and ${safe_osts[1]}"
	ec_deactivate_ost ${safe_osts[0]}
	ec_deactivate_ost ${safe_osts[1]}

	cancel_lru_locks osc

	# concurrent readers stress EC recovery page-cache serialization
	local pids=()
	local i
	for i in 1 2 3 4; do
		md5sum $tf > $TMP/ec_read_${i}_$tfile 2>&1 &
		pids+=($!)
	done
	stack_trap "rm -f $TMP/ec_read_*_$tfile"

	local failures=0
	for i in 1 2 3 4; do
		if ! wait ${pids[$((i-1))]}; then
			echo "Reader $i: process failed"
			failures=$((failures + 1))
			continue
		fi
		local sum
		sum=$(awk '{print $1}' \
			$TMP/ec_read_${i}_$tfile)
		if [[ "$sum_expected" != "$sum" ]]; then
			echo "Reader $i: $sum != $sum_expected"
			failures=$((failures + 1))
		fi
	done
	(( failures == 0 )) ||
		error "$failures of 4 concurrent readers failed"

	echo "** All 4 concurrent reads succeeded"
}
run_test 49a "test concurrent reads during EC recovery"

test_49b() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"
	local tf_other=$DIR/${tfile}_other

	# Create EC file with 4+2 configuration
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write data
	dd if=/dev/urandom of=$tf bs=1M count=32 ||
		error "dd failed"

	# Resync parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksum
	local sum_expected=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 2 )) ||
		skip_env "need >= 2 safe data OSTs"

	# Pre-allocate other files on a parity OST
	# (which stays active during test)
	local active_ost=${parity_osts[0]}
	local i
	for i in 1 2 3; do
		$LFS setstripe -c 1 -i $active_ost \
			${tf_other}_$i ||
			error "setstripe ${tf_other}_$i"
		dd if=/dev/urandom of=${tf_other}_$i \
			bs=1M count=1 2>/dev/null ||
			error "pre-write ${tf_other}_$i"
	done
	stack_trap "rm -f ${tf_other}_*"

	echo "** Write during recovery: Disabling" \
		"OSTs ${safe_osts[0]} and ${safe_osts[1]}"
	ec_deactivate_ost ${safe_osts[0]}
	ec_deactivate_ost ${safe_osts[1]}

	# Start recovery read in background
	local read_result=$TMP/read_result_$$
	stack_trap "rm -f $read_result"
	cancel_lru_locks osc
	md5sum $tf > $read_result 2>&1 &
	local read_pid=$!
	echo "** Started recovery read (PID $read_pid)"

	# Overwrite the pre-allocated files while
	# EC recovery is in progress
	local write_ok=true
	for i in 1 2 3; do
		dd if=/dev/urandom of=${tf_other}_$i \
			bs=1M count=4 2>/dev/null ||
			write_ok=false
	done

	# Wait for recovery read
	if ! wait $read_pid; then
		error "Recovery read failed"
	fi

	local sum_got=$(awk '{print $1}' $read_result)
	[[ "$sum_expected" == "$sum_got" ]] ||
		error "Recovery read got wrong data:" \
			"$sum_got vs $sum_expected"

	$write_ok ||
		error "Writes to other files failed"

	for i in 1 2 3; do
		local sz=$(stat -c %s ${tf_other}_$i)
		(( sz == 4 * 1048576 )) ||
			error "${tf_other}_$i: $sz != 4M"
	done

	echo "** Recovery read and concurrent writes OK"
}
run_test 49b "test writes to other files during EC recovery"

test_49c() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create EC file with 4+2 configuration
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	dd if=/dev/urandom of=$tf bs=1M count=32 ||
		error "dd failed"
	$LFS mirror resync $tf ||
		error "initial mirror resync failed"

	local sum_expected=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 2 )) ||
		skip_env "need >= 2 safe data OSTs"

	# A resync only does work when a component is stale.  $tf was just
	# resynced, so resyncing it again would fall through to the verify
	# path and the concurrent resync this test is named for would never
	# happen.  Give it a second file whose parity really is stale.
	local tf2=$DIR/$tfile.stale

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf2 ||
		error "setstripe $tf2 failed"
	dd if=/dev/urandom of=$tf2 bs=1M count=8 || error "dd $tf2 failed"
	$LFS mirror resync $tf2 || error "resync $tf2 failed"
	dd if=/dev/urandom of=$tf2 bs=1M seek=2 count=4 conv=notrunc ||
		error "overwrite $tf2 failed"
	stack_trap "rm -f $tf2"

	echo "** Resync during recovery: Disabling" \
		"OSTs ${safe_osts[0]} and ${safe_osts[1]}"
	ec_deactivate_ost ${safe_osts[0]}
	ec_deactivate_ost ${safe_osts[1]}
	cancel_lru_locks osc

	# Start recovery read in background
	local read_result=$TMP/resync_read_result_$$
	stack_trap "rm -f $read_result"
	md5sum $tf > $read_result 2>&1 &
	local read_pid=$!
	echo "** Started recovery read (PID $read_pid)"

	# Simultaneously resync the stale file.  It may fail with OSTs
	# down; what matters is that it runs concurrently with the
	# recovery read and neither wedges the other.
	echo "** Attempting mirror resync during recovery..."
	$LFS mirror resync $tf2 2>/dev/null &&
		echo "** Resync succeeded" ||
		echo "** Resync failed (expected with OSTs down)"

	# Two failed OSTs is within a 4+2 layout's tolerance, so the read
	# has to succeed with the right data whether or not the competing
	# resync got anywhere.
	wait $read_pid || error "recovery read failed during resync"

	local sum_got=$(awk '{print $1}' $read_result)

	[[ "$sum_expected" == "$sum_got" ]] ||
		error "recovery read got wrong data: $sum_got vs $sum_expected"
	echo "** Recovery read succeeded"

	echo "** Resync during recovery: no deadlock"
}
run_test 49c "test mirror resync during EC recovery"

test_49d() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	dd if=/dev/urandom of=$tf bs=1M count=64 ||
		error "dd failed"
	$LFS mirror resync $tf || error "mirror resync failed"

	local sum_expected=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 2 )) ||
		skip_env "need >= 2 safe data OSTs"

	echo "** OST reactivation: Disabling" \
		"OSTs ${safe_osts[0]} and ${safe_osts[1]}"
	ec_deactivate_ost ${safe_osts[0]}
	ec_deactivate_ost ${safe_osts[1]}
	cancel_lru_locks osc

	# Start recovery read in background
	local read_result=$TMP/reactivate_read_result_$$
	stack_trap "rm -f $read_result"
	md5sum $tf > $read_result 2>&1 &
	local read_pid=$!
	echo "** Started recovery read (PID $read_pid)"

	# Brief delay then reactivate OSTs mid-read
	sleep 0.5
	echo "** Reactivating OSTs during read..."
	ec_reactivate_ost ${safe_osts[0]}
	ec_reactivate_ost ${safe_osts[1]}
	echo "** OSTs reactivated"

	# Wait for read to complete
	if ! wait $read_pid; then
		error "Recovery read failed after reactivation"
	fi

	local sum_got=$(awk '{print $1}' $read_result)
	[[ "$sum_expected" == "$sum_got" ]] ||
		error "Read got wrong data:" \
			"$sum_got vs $sum_expected"

	echo "** OST reactivation during recovery OK"
}
run_test 49d "test OST reactivation during EC recovery"

test_50a() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"
	local tf2=$DIR2/$tfile

	# Setup second mount
	# check_and_setup_lustre() already mounts $MOUNT2 when the
	# session sets MOUNT_2; only tear down a mount this test made.
	if ! is_mounted $MOUNT2; then
		mkdir -p $MOUNT2
		mount_client $MOUNT2 || error "mount_client $MOUNT2 failed"
		stack_trap "umount_client $MOUNT2"
	fi

	# Create EC file with 4+2 configuration
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write data
	dd if=/dev/urandom of=$tf bs=1M count=16 || error "dd failed"

	# Resync parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get expected checksum
	local sum_expected=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 2 )) ||
		skip_env "need >= 2 safe data OSTs"
	echo "** Multi-mount test: Disabling OSTs ${safe_osts[0]} and" \
		"${safe_osts[1]}"

	ec_deactivate_ost ${safe_osts[0]}
	ec_deactivate_ost ${safe_osts[1]}
	cancel_lru_locks osc

	# Both mounts read simultaneously
	local result_dir=$TMP/multi_mount_$$
	mkdir -p $result_dir
	stack_trap "rm -rf $result_dir"

	md5sum $tf > $result_dir/mount1 2>&1 &
	local pid1=$!
	md5sum $tf2 > $result_dir/mount2 2>&1 &
	local pid2=$!

	echo "** Started readers on both mounts: PIDs $pid1, $pid2"

	wait $pid1 || error "Mount1 read failed"
	wait $pid2 || error "Mount2 read failed"

	# Verify both got correct data
	local sum1=$(awk '{print $1}' $result_dir/mount1)
	local sum2=$(awk '{print $1}' $result_dir/mount2)

	[[ "$sum_expected" == "$sum1" ]] ||
		error "Mount1 got wrong data: $sum1 vs $sum_expected"
	[[ "$sum_expected" == "$sum2" ]] ||
		error "Mount2 got wrong data: $sum2 vs $sum_expected"
	[[ "$sum1" == "$sum2" ]] ||
		error "Mounts got different data: $sum1 vs $sum2"

	echo "** Both mounts read identical correct data during recovery"
}
run_test 50a "test both mounts read same EC file during recovery"

test_50b() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"
	local tf2=$DIR2/$tfile

	# Setup second mount
	# check_and_setup_lustre() already mounts $MOUNT2 when the
	# session sets MOUNT_2; only tear down a mount this test made.
	if ! is_mounted $MOUNT2; then
		mkdir -p $MOUNT2
		mount_client $MOUNT2 || error "mount_client $MOUNT2 failed"
		stack_trap "umount_client $MOUNT2"
	fi

	# Create EC file with 4+2 configuration
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write data
	dd if=/dev/urandom of=$tf bs=1M count=32 || error "dd failed"

	# Resync parity
	$LFS mirror resync $tf || error "mirror resync failed"

	# Get checksums for different regions
	local sum_first=$(dd if=$tf bs=1M count=8 2>/dev/null |
		md5sum | awk '{print $1}')
	local sum_middle=$(dd if=$tf bs=1M skip=12 count=8 2>/dev/null |
		md5sum | awk '{print $1}')
	local sum_last=$(dd if=$tf bs=1M skip=24 count=8 2>/dev/null |
		md5sum | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 2 )) ||
		skip_env "need >= 2 safe data OSTs"
	echo "** Interleaved reads: Disabling OSTs ${safe_osts[0]} and" \
		"${safe_osts[1]}"

	ec_deactivate_ost ${safe_osts[0]}
	ec_deactivate_ost ${safe_osts[1]}
	cancel_lru_locks osc

	# Interleaved reads from different offsets
	# Mount1 reads first 8M, Mount2 reads middle 8M, then swap
	local result_dir=$TMP/interleaved_$$
	mkdir -p $result_dir
	stack_trap "rm -rf $result_dir"

	# Round 1: Mount1 reads first, Mount2 reads middle
	dd if=$tf bs=1M count=8 2>/dev/null |
		md5sum > $result_dir/m1_first &
	local pid1=$!
	dd if=$tf2 bs=1M skip=12 count=8 2>/dev/null |
		md5sum > $result_dir/m2_middle &
	local pid2=$!

	wait $pid1 || error "Mount1 first region read failed"
	wait $pid2 || error "Mount2 middle region read failed"

	# Round 2: Mount1 reads last, Mount2 reads first
	dd if=$tf bs=1M skip=24 count=8 2>/dev/null |
		md5sum > $result_dir/m1_last &
	pid1=$!
	dd if=$tf2 bs=1M count=8 2>/dev/null |
		md5sum > $result_dir/m2_first &
	pid2=$!

	wait $pid1 || error "Mount1 last region read failed"
	wait $pid2 || error "Mount2 first region read failed"

	# Verify all reads got correct data
	local got
	got=$(awk '{print $1}' $result_dir/m1_first)
	[[ "$sum_first" == "$got" ]] ||
		error "Mount1 first region wrong: $got vs $sum_first"

	got=$(awk '{print $1}' $result_dir/m2_middle)
	[[ "$sum_middle" == "$got" ]] ||
		error "Mount2 middle region wrong: $got vs $sum_middle"

	got=$(awk '{print $1}' $result_dir/m1_last)
	[[ "$sum_last" == "$got" ]] ||
		error "Mount1 last region wrong: $got vs $sum_last"

	got=$(awk '{print $1}' $result_dir/m2_first)
	[[ "$sum_first" == "$got" ]] ||
		error "Mount2 first region wrong: $got vs $sum_first"

	echo "** Interleaved reads from both mounts successful"
}
run_test 50b "test interleaved partial reads from both mounts during recovery"

test_51a() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Single-component 3+1 EC with 6 data stripes.
	# ec_split_stripes(6, 3) → k0=3, n0=2:
	#   2 stripe sets of 3 stripes per RAID set.
	# swidth = 6 * 1M = 6M.
	# RAID set 0: [0, 6M)
	#   SS0: stripes 0,1,2 → [0, 3M)
	#   SS1: stripes 3,4,5 → [3M, 6M)
	# RAID set 1: [6M, 12M)
	#   SS0: stripes 0,1,2 → [6M, 9M)
	#   SS1: stripes 3,4,5 → [9M, 12M)
	#
	# Test EOF at 4 positions:
	#  2M: inside RS0/SS0 (partial first stripe set)
	#  5M: inside RS0/SS1 (partial second stripe set)
	#  8M: inside RS1/SS0 (second RAID set, first SS)
	# 11M: inside RS1/SS1 (second RAID set, second SS)
	local sizes="2 5 8 11"
	local labels=(
		"RS0/SS0"
		"RS0/SS1"
		"RS1/SS0"
		"RS1/SS1"
	)

	local idx=0
	local sz
	for sz in $sizes; do
		echo "** EOF at ${sz}M (${labels[$idx]})"

		rm -f $tf
		$LFS setstripe -E eof -S 1M -c 6 --ec 3+1 \
			$tf ||
			error "setstripe failed for ${sz}M test"

		dd if=/dev/urandom of=$tf bs=1M count=$sz ||
			error "dd ${sz}M failed"

		$LFS mirror resync $tf ||
			error "resync failed for ${sz}M test"

		local sum=$(md5sum $tf | awk '{print $1}')

		# Collect parity and data OSTs to find
		# safe OSTs (data-only, not reused for
		# parity)
		local ids=($($LFS getstripe $tf |
			awk '/lcme_id/{print $2}'))
		local parity_osts=()
		local data_osts=()
		local id flags osts
		for id in "${ids[@]}"; do
			flags=$($LFS getstripe -I$id $tf |
				awk '/lcme_flags:/{print $2}')
			osts=($($LFS getstripe -I$id $tf |
				awk '/l_ost_idx:/{print $5}' |
				tr -d ","))
			if [[ "$flags" == *parity* ]]; then
				parity_osts+=("${osts[@]}")
			elif (( ${#data_osts[@]} == 0 )); then
				data_osts=("${osts[@]}")
			fi
		done

		local safe=()
		local o p safe_flag
		for o in "${data_osts[@]}"; do
			safe_flag=true
			for p in "${parity_osts[@]}"; do
				(( o == p )) &&
					safe_flag=false && break
			done
			$safe_flag && safe+=($o)
		done

		(( ${#safe[@]} >= 1 )) ||
			skip_env "no safe data OSTs for ${sz}M"
		local ost1=${safe[0]}
		echo "** Disabling data OST $ost1"

		ec_deactivate_ost $ost1

		local sum_after=$(md5sum $tf | awk '{print $1}')
		ec_reactivate_ost $ost1

		[[ "$sum" == "$sum_after" ]] ||
			error "EOF ${sz}M ${labels[$idx]}:"\
				" md5 $sum != $sum_after"

		echo "** EOF at ${sz}M (${labels[$idx]}) OK"
		((idx++))
	done
}
run_test 51a "test EC recovery with EOF inside RAID / stripe sets"

test_52a() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# 4+2 EC: pcount=2, so max recoverable = 2 data OSTs
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"
	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum_before=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 2 )) ||
		skip_env "not enough safe data OSTs (${#safe_osts[@]})"

	echo "** Max degradation: disabling 2 data OSTs:" \
		"${safe_osts[0]} and ${safe_osts[1]}"

	ec_deactivate_ost ${safe_osts[0]}
	ec_deactivate_ost ${safe_osts[1]}
	cancel_lru_locks osc

	local sum_after=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_before" == "$sum_after" ]] ||
		error "max degradation recovery failed:" \
			"$sum_before vs $sum_after"

	echo "** Max degradation (2 of 4 data OSTs down) passed"
}
run_test 52a "test EC recovery at max degradation (pcount data OSTs down)"

test_52b() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# 4+2 EC: pcount=2, so 3 data OSTs down = unrecoverable
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"
	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum_before=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 3 )) ||
		skip_env "not enough safe data OSTs (${#safe_osts[@]})"

	echo "** Over-degradation: disabling 3 data OSTs:" \
		"${safe_osts[0]}, ${safe_osts[1]}," \
		"${safe_osts[2]}"

	ec_deactivate_ost ${safe_osts[0]}
	ec_deactivate_ost ${safe_osts[1]}
	ec_deactivate_ost ${safe_osts[2]}
	cancel_lru_locks osc

	# Read must fail: 3 lost data stripes exceed the pcount=2 parity
	# capacity, so there is nothing left to reconstruct from and an
	# error is the only correct answer.  Handing back bytes at all is
	# silent corruption, and handing back the original content means
	# the fault never took effect.  md5sum runs on its own here rather
	# than in a pipeline, so rc is md5sum's status and not awk's.
	local out sum_after rc=0

	out=$(md5sum $tf 2>/dev/null) || rc=$?
	sum_after=$(echo "$out" | awk '{print $1}')

	if (( rc == 0 )); then
		[[ "$sum_before" != "$sum_after" ]] ||
			error "over-degradation returned the original data," \
				"so failing 3 of 4 data OSTs had no effect"
		error "over-degradation returned data ($sum_after) instead" \
			"of an error with 3 of 4 data OSTs down"
	fi
	echo "** Over-degradation correctly returned read error (rc=$rc)"
}
run_test 52b "test EC over-degradation (pcount+1 data OSTs down)"

test_52c() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# 4+2 EC: lose 1 data + 1 parity. Still recoverable
	# since 1 parity remains for the 1 lost data stripe.
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"
	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum_before=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "not enough safe data OSTs"
	(( ${#parity_osts[@]} >= 1 )) ||
		skip_env "no parity OSTs found"

	# Pick one safe data OST and one parity OST
	local data_victim=${safe_osts[0]}
	# Find a parity OST that's not also a data OST
	local par_victim=""
	local p o in_data
	for p in "${parity_osts[@]}"; do
		in_data=false
		for o in "${data_osts[@]}"; do
			(( p == o )) &&
				in_data=true && break
		done
		if ! $in_data; then
			par_victim=$p
			break
		fi
	done
	[[ -n "$par_victim" ]] ||
		skip_env "no parity-only OST found"

	echo "** Mixed failure: disabling data" \
		"OST$data_victim + parity OST$par_victim"

	ec_deactivate_ost $data_victim
	ec_deactivate_ost $par_victim
	cancel_lru_locks osc

	# With 4+2, losing 1 data + 1 parity = 2 failures
	# total, within pcount tolerance. The remaining
	# parity stripe provides enough data to recover
	# the single lost data stripe.
	local sum_after=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_before" == "$sum_after" ]] ||
		error "mixed parity+data failure recovery" \
			"failed: $sum_before vs $sum_after"

	echo "** Mixed parity+data failure recovery passed"
}
run_test 52c "test EC recovery with mixed parity and data OST failure"

test_53a() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Single-component 3+1 EC with 6 data stripes.
	# swidth = 6M. Write 12M (2 full RAID sets).
	# Then read from various non-zero offsets with
	# one data OST down, forcing EC recovery with
	# crw_pos != 0.
	$LFS setstripe -E eof -S 1M -c 6 --ec 3+1 $tf ||
		error "setstripe failed"
	dd if=/dev/urandom of=$tf bs=1M count=12 ||
		error "dd failed"
	$LFS mirror resync $tf || error "resync failed"

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"
	local victim=${safe_osts[0]}

	# Offsets to test (in 1M blocks):
	#  1M: start of stripe 1 in RS0/SS0
	#  3M: start of SS1 in RS0
	#  5M: start of stripe 5 in RS0/SS1
	#  6M: exact RAID set boundary (RS1 start)
	#  7M: start of stripe 1 of the second row, RS1/SS0
	# 10M: start of stripe 4 of the second row, RS1/SS1
	local offsets="1 3 5 6 7 10"

	local off
	for off in $offsets; do
		local remain=$((12 - off))

		# Get reference read from healthy file
		local ref=$(dd if=$tf bs=1M skip=$off \
			count=$remain 2>/dev/null | md5sum |
			awk '{print $1}')

		echo "** offset=${off}M count=${remain}M"

		ec_deactivate_ost $victim
		cancel_lru_locks osc

		local got=$(dd if=$tf bs=1M skip=$off \
			count=$remain 2>/dev/null | md5sum |
			awk '{print $1}')

		ec_reactivate_ost $victim

		[[ "$ref" == "$got" ]] ||
			error "offset ${off}M: $ref != $got"
	done
}
run_test 53a "test EC recovery with non-zero read offsets"

test_55a() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Tiny files: 1 byte and 4K (one page).
	# With 3+1 EC and 6 data stripes, only stripe 0
	# has any data. All other stripes are beyond-EOF.
	# Tests the i_size cap in lov_ecio_add_data_sub
	# that prevents false LSS_READ_ERR for empty stripes.
	local -a sizes=(1 4096)
	local -a labels=("1-byte" "4K-one-page")

	local i
	for ((i = 0; i < ${#sizes[@]}; i++)); do
		local sz=${sizes[$i]}
		echo "** ${labels[$i]} (${sz} bytes)"

		rm -f $tf
		$LFS setstripe -E eof -S 1M -c 6 --ec 3+1 \
			$tf ||
			error "setstripe failed for ${labels[$i]}"
		dd if=/dev/urandom of=$tf bs=1 count=$sz ||
			error "dd ${labels[$i]} failed"
		$LFS mirror resync $tf ||
			error "resync ${labels[$i]} failed"

		local sum=$(md5sum $tf | awk '{print $1}')

		# Only stripe 0 holds data in a file this small, and
		# safe_osts is sorted by OST index, so its first entry is
		# usually an OST this read never touches.
		ec_data_stripe_osts $tf 0
		local victim=${EC_STRIPE_OSTS[0]}

		ec_deactivate_ost $victim
		cancel_lru_locks osc

		local got=$(md5sum $tf | awk '{print $1}')
		ec_reactivate_ost $victim

		[[ "$sum" == "$got" ]] ||
			error "${labels[$i]}: $sum != $got"

		echo "** ${labels[$i]} OK"
	done
}
run_test 55a "test EC recovery with tiny files (1 byte, one page)"

test_58a() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	# Test parity_used[] with every 2-OST combination in
	# a 4+2 layout. With 2 parity OSTs, degrading 2 data
	# OSTs exercises parity selection and coefficient matrix
	# construction in lov_recover_data().
	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe 4+2 failed"
	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd 8M failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	local n=${#safe_osts[@]}
	(( n >= 2 )) || skip_env "need >= 2 safe data OSTs"

	local i j
	for ((i = 0; i < n - 1; i++)); do
		for ((j = i + 1; j < n; j++)); do
			ec_deactivate_ost ${safe_osts[$i]}
			ec_deactivate_ost ${safe_osts[$j]}
			cancel_lru_locks osc

			local got=$(md5sum $tf | awk '{print $1}')
			ec_reactivate_ost ${safe_osts[$j]}
			ec_reactivate_ost ${safe_osts[$i]}

			[[ "$sum" == "$got" ]] ||
				error "2-of-${n} OST${safe_osts[$i]}+" \
					"OST${safe_osts[$j]}:" \
					"$sum != $got"
			echo "  OST${safe_osts[$i]}+" \
				"OST${safe_osts[$j]} OK"
		done
	done
}
run_test 58a "EC parity_used[] with 2-OST combos in 4+2 layout"

test_58b() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	# Combined stress: PFL 4+2 with 2 degraded data stripes
	# and stripe rotation from non-zero e_start. Tests the
	# interaction of parity_eof, err_array, and parity_used[]
	# all together under PFL offset mapping.
	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"
	local sizes="3 5 8 12 17"

	for sz in $sizes; do
		rm -f $tf
		$LFS setstripe \
			-E 4M -S 1M -c 4 --ec 4+2 \
			-E eof -S 1M -c 4 --ec 4+2 $tf ||
			error "setstripe PFL 4+2 failed"
		dd if=/dev/urandom of=$tf bs=1M count=$sz ||
			error "dd ${sz}M failed"
		$LFS mirror resync $tf ||
			error "resync ${sz}M failed"

		local sum=$(md5sum $tf | awk '{print $1}')

		ec_classify_osts $tf
		(( ${#safe_osts[@]} >= 2 )) ||
			skip_env "need >= 2 safe data OSTs (sz=$sz)"
		local v1=${safe_osts[0]}
		local v2=${safe_osts[1]}

		ec_deactivate_ost $v1
		ec_deactivate_ost $v2
		cancel_lru_locks osc

		local got=$(md5sum $tf | awk '{print $1}')
		ec_reactivate_ost $v2
		ec_reactivate_ost $v1

		[[ "$sum" == "$got" ]] ||
			error "PFL 4+2 sz=${sz}M " \
				"OST${v1}+OST${v2}:" \
				"$sum != $got"
		echo "  sz=${sz}M OST${v1}+OST${v2} OK"
	done
}
run_test 58b "EC combined PFL 4+2 with 2 degraded + rotation"

test_59a() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# PFL: [0,4M) + [4M,EOF), both 4+2 (2 parity for 2-down)
	$LFS setstripe \
		-E 4M -S 1M -c 4 --ec 4+2 \
		-E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe PFL failed"

	# Write 2M, skip to 6M, write 4M => spans comp boundary
	dd if=/dev/urandom of=$tf bs=1M count=2 ||
		error "dd first 2M failed"
	dd if=/dev/urandom of=$tf bs=1M count=4 seek=6 ||
		error "dd at offset 6M failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')
	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"

	local ost
	for ost in "${safe_osts[@]}"; do
		ec_deactivate_ost $ost
		cancel_lru_locks osc
		local got=$(md5sum $tf | awk '{print $1}')
		ec_reactivate_ost $ost
		[[ "$sum" == "$got" ]] ||
			error "PFL sparse OST$ost:" \
				"$sum != $got"
		echo "  OST$ost OK"
	done

	# 2-down test (needs pcount >= 2, so 4+2 layout)
	(( ${#safe_osts[@]} >= 2 )) ||
		skip_env "need >= 2 safe data OSTs for 2-down"

	local v1=${safe_osts[0]}
	local v2=${safe_osts[1]}
	ec_deactivate_ost $v1
	ec_deactivate_ost $v2
	cancel_lru_locks osc
	local got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $v2
	ec_reactivate_ost $v1
	[[ "$sum" == "$got" ]] ||
		error "PFL sparse 2-down: $sum != $got"
	echo "** PFL sparse with 2 OSTs down OK"
}
run_test 59a "EC recovery with sparse PFL file spanning components"

test_60a() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# 4+2 layout, 1M stripes, swidth=4M
	$LFS setstripe -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	# Write 8M (2 full stripe sets), resync parity
	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd write failed"
	$LFS mirror resync $tf || error "resync failed"

	# Truncate mid-stripe to 2.5M while healthy
	$TRUNCATE $tf $((2 * 1024 * 1024 + 512 * 1024)) ||
		error "truncate to 2.5M failed"
	# Resync so parity reflects truncated state
	$LFS mirror resync $tf || error "resync after trunc failed"

	# Capture reference checksum
	local sum=$(md5sum $tf | awk '{print $1}')

	# Now degrade and verify EC recovery
	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "need >= 1 safe data OST"
	local victim=${safe_osts[0]}
	echo "** Deactivating data OST $victim"

	ec_deactivate_ost $victim
	cancel_lru_locks osc

	local sz=$(stat -c %s $tf)
	(( sz == 2 * 1024 * 1024 + 512 * 1024 )) ||
		error "size mismatch: $sz != 2621440"

	local got=$(md5sum $tf | awk '{print $1}')
	[[ "$sum" == "$got" ]] ||
		error "60a: mid-stripe truncate recovery failed:" \
			"$sum != $got"

	echo "** EC recovery after mid-stripe truncate OK"
}
run_test 60a "EC recovery after mid-stripe truncate"

test_60b() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	# Write 12M (3 stripe sets), resync
	dd if=/dev/urandom of=$tf bs=1M count=12 ||
		error "dd write failed"
	$LFS mirror resync $tf || error "resync failed"

	# Save checksum of first 4M (one swidth)
	local sum_4m=$(dd if=$tf bs=1M count=4 2>/dev/null |
		md5sum | awk '{print $1}')

	# Truncate to swidth boundary while healthy
	$TRUNCATE $tf $((4 * 1024 * 1024)) ||
		error "truncate to 4M failed"
	$LFS mirror resync $tf ||
		error "resync after trunc failed"

	local sum=$(md5sum $tf | awk '{print $1}')
	# First 4M should be unchanged
	[[ "$sum_4m" == "$sum" ]] ||
		error "data changed by truncate: $sum_4m != $sum"

	# Degrade and verify recovery
	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "need >= 1 safe data OST"
	local victim=${safe_osts[0]}
	echo "** Deactivating data OST $victim"

	ec_deactivate_ost $victim
	cancel_lru_locks osc

	local got=$(md5sum $tf | awk '{print $1}')
	[[ "$sum" == "$got" ]] ||
		error "60b: stripe-boundary truncate recovery" \
			"failed: $sum != $got"

	local sz=$(stat -c %s $tf)
	(( sz == 4 * 1024 * 1024 )) ||
		error "size mismatch: $sz != 4194304"

	echo "** EC recovery after stripe-boundary truncate OK"
}
run_test 60b "EC recovery after stripe-boundary truncate"

test_60c() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	# Write 8M, resync, then truncate to zero
	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd write failed"
	$LFS mirror resync $tf || error "resync failed"
	$TRUNCATE $tf 0 || error "truncate to 0 failed"

	# Degrade and verify file reads as empty
	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "need >= 1 safe data OST"
	local victim=${safe_osts[0]}
	echo "** Deactivating data OST $victim"

	ec_deactivate_ost $victim
	cancel_lru_locks osc

	local sz=$(stat -c %s $tf)
	(( sz == 0 )) || error "size not 0 after truncate: $sz"

	# read through the client rather than asking fstat: wc -c on a
	# regular file takes the stat shortcut and issues no read at all
	local bytes=$(dd if=$tf bs=1M 2>/dev/null | wc -c)
	(( bytes == 0 )) ||
		error "read returned $bytes bytes from truncated file"

	# Re-write while still degraded should fail or succeed
	# depending on whether victim stripe is used; just verify
	# recovery works after reactivate+write+resync
	ec_reactivate_ost $victim
	dd if=/dev/urandom of=$tf bs=1M count=4 ||
		error "dd re-write failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')
	ec_deactivate_ost $victim
	cancel_lru_locks osc

	local got=$(md5sum $tf | awk '{print $1}')
	[[ "$sum" == "$got" ]] ||
		error "60c: re-write after truncate recovery" \
			"failed: $sum != $got"

	echo "** EC recovery after truncate-to-zero OK"
}
run_test 60c "EC recovery after truncate to zero and re-write"

test_60d() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# PFL: comp1 [0,16M] 2+1, comp2 [16M,EOF] 4+2
	$LFS setstripe -E 16M -S 1M -c 2 --ec 2+1 \
		-E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe PFL failed"

	# Write 32M spanning both components, resync
	dd if=/dev/urandom of=$tf bs=1M count=32 ||
		error "dd write failed"
	$LFS mirror resync $tf || error "resync failed"

	# Save comp1 checksum before truncate
	local sum_comp1=$(dd if=$tf bs=1M count=16 \
		2>/dev/null | md5sum | awk '{print $1}')

	# Truncate at component boundary (16M) — removes comp2
	$TRUNCATE $tf $((16 * 1024 * 1024)) ||
		error "truncate to 16M failed"
	$LFS mirror resync $tf ||
		error "resync after trunc failed"

	local sum=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_comp1" == "$sum" ]] ||
		error "comp1 changed by truncate: $sum_comp1 != $sum"

	# Degrade and verify comp1 recovers.  The truncate leaves comp2 in
	# the layout, so its OSTs stay in the classification even though
	# nothing reads them now; restrict the choice to comp1's own two
	# data stripes, both of which still hold 8M of the file.  This
	# layout needs 9 objects and rarely gets 9 distinct OSTs, so one
	# of the two usually doubles as parity.
	ec_pick_data_ost $tf 0 1 ||
		skip_env "no parity-free data OST in comp1"
	local victim=$EC_PICKED_OST
	echo "** Deactivating data OST $victim"

	ec_deactivate_ost $victim
	cancel_lru_locks osc

	local got=$(md5sum $tf | awk '{print $1}')
	[[ "$sum" == "$got" ]] ||
		error "60d: comp-boundary truncate recovery" \
			"failed: $sum != $got"

	local sz=$(stat -c %s $tf)
	(( sz == 16 * 1024 * 1024 )) ||
		error "size mismatch: $sz != 16777216"

	# Verify no data beyond comp boundary
	local tail=$(dd if=$tf bs=1M skip=16 count=1 \
		2>/dev/null | wc -c)
	(( tail == 0 )) ||
		error "got $tail bytes beyond comp boundary"

	echo "** EC recovery after PFL comp-boundary truncate OK"
}
run_test 60d "EC recovery after PFL component-boundary truncate"

test_61a() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# 4+2 layout, 1M stripes: test various sub-stripe sizes
	local -a sizes=(4096 32768 65536 524288 $((1048576 - 1)))
	local -a labels=(
		"4K" "32K" "64K" "512K" "1M-1"
	)

	local i
	for ((i = 0; i < ${#sizes[@]}; i++)); do
		rm -f $tf
		$LFS setstripe -S 1M -c 4 --ec 4+2 $tf ||
			error "setstripe failed"
		dd if=/dev/urandom of=$tf \
			bs=${sizes[$i]} count=1 ||
			error "dd ${labels[$i]} failed"
		$LFS mirror resync $tf ||
			error "resync ${labels[$i]} failed"
		local sum=$(md5sum $tf | awk '{print $1}')

		# Every size here is under one 1M stripe, so the data lives
		# on stripe 0 alone; safe_osts[0] is the lowest OST index
		# and usually holds none of it.
		ec_data_stripe_osts $tf 0
		local victim=${EC_STRIPE_OSTS[0]}

		ec_deactivate_ost $victim
		cancel_lru_locks osc
		local got=$(md5sum $tf | awk '{print $1}')
		ec_reactivate_ost $victim
		[[ "$sum" == "$got" ]] ||
			error "${labels[$i]} OST$victim:" \
				"$sum != $got"
		echo "  ${labels[$i]} OK"
	done
}
run_test 61a "EC recovery with various sub-stripe file sizes"

test_61b() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# 64K stripe: sub-stripe means < 64K
	local -a sizes=(1 4096 $((65536 - 1)))
	local -a labels=("1-byte" "4K" "64K-1")

	local i
	for ((i = 0; i < ${#sizes[@]}; i++)); do
		rm -f $tf
		$LFS setstripe -S 64K -c 4 --ec 4+2 $tf ||
			error "setstripe 64K failed"
		dd if=/dev/urandom of=$tf \
			bs=${sizes[$i]} count=1 ||
			error "dd ${labels[$i]} failed"
		$LFS mirror resync $tf ||
			error "resync ${labels[$i]} failed"
		local sum=$(md5sum $tf | awk '{print $1}')

		ec_classify_osts $tf
		(( ${#safe_osts[@]} >= 1 )) ||
			skip_env "no safe data OSTs"

		local ost
		for ost in "${safe_osts[@]}"; do
			ec_deactivate_ost $ost
			cancel_lru_locks osc
			local got=$(md5sum $tf | awk '{print $1}')
			ec_reactivate_ost $ost
			[[ "$sum" == "$got" ]] ||
				error "${labels[$i]} " \
					"OST$ost:" \
					"$sum != $got"
		done
		echo "  ${labels[$i]} OK (all safe OSTs)"
	done
}
run_test 61b "EC recovery with sub-stripe files and 64K stripe"

test_61c() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# PFL: comp1 [0,4M) 4+2 64K stripes (swidth=256K)
	# comp2 [4M,EOF) 4+2 1M stripes
	# File stays within comp1 at sub-stripe size
	$LFS setstripe \
		-E 4M -S 64K -c 4 --ec 4+2 \
		-E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe PFL failed"

	# Write less than one 64K stripe (32K)
	dd if=/dev/urandom of=$tf bs=32K count=1 ||
		error "dd 32K failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')
	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"

	local ost
	for ost in "${safe_osts[@]}"; do
		ec_deactivate_ost $ost
		cancel_lru_locks osc
		local got=$(md5sum $tf | awk '{print $1}')
		ec_reactivate_ost $ost
		[[ "$sum" == "$got" ]] ||
			error "PFL sub-stripe OST$ost:" \
				"$sum != $got"
		echo "  OST$ost OK"
	done
}
run_test 61c "EC recovery sub-stripe file in PFL with 64K stripes"

test_61d() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# 4+2, 1M stripe: sub-stripe file with 2 OSTs down
	$LFS setstripe -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	dd if=/dev/urandom of=$tf bs=100K count=1 ||
		error "dd 100K failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')

	# A 100K file occupies stripe 0 only.  Fail that stripe's OST plus
	# one more, so the 2-down case really loses the stripe being read
	# rather than two OSTs the read never reaches.
	ec_data_stripe_osts $tf 0 1

	local v1=${EC_STRIPE_OSTS[0]}
	local v2=${EC_STRIPE_OSTS[1]}

	ec_deactivate_ost $v1
	ec_deactivate_ost $v2
	cancel_lru_locks osc
	local got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $v2
	ec_reactivate_ost $v1
	[[ "$sum" == "$got" ]] ||
		error "sub-stripe 2-down: $sum != $got"
	echo "** sub-stripe 100K with 2 OSTs down OK"
}
run_test 61d "EC recovery sub-stripe file with 2 OST failures"

test_62a() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# 4+2 layout, 1M stripes
	$LFS setstripe -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	# Append in multiple stages, resync after each
	local stage
	for stage in 1 2 3; do
		dd if=/dev/urandom of=$tf bs=1M count=2 \
			oflag=append conv=notrunc ||
			error "append stage $stage failed"
		$LFS mirror resync $tf ||
			error "resync stage $stage failed"
	done

	# File should be 6M total
	local sz=$(stat -c %s $tf)
	(( sz == 6 * 1048576 )) ||
		error "size mismatch: $sz != 6291456"

	local sum=$(md5sum $tf | awk '{print $1}')
	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"

	local ost
	for ost in "${safe_osts[@]}"; do
		ec_deactivate_ost $ost
		cancel_lru_locks osc
		local got=$(md5sum $tf | awk '{print $1}')
		ec_reactivate_ost $ost
		[[ "$sum" == "$got" ]] ||
			error "append OST$ost: $sum != $got"
		echo "  OST$ost OK"
	done
}
run_test 62a "EC recovery after multiple append writes"

test_62b() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# 4+2 layout, 1M stripes: append non-aligned amounts
	# with a single resync after the last one
	$LFS setstripe -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	# Append 3M, 1M, 512K, 3M = 7.5M total (unaligned)

	dd if=/dev/urandom of=$tf bs=1M count=3 ||
		error "append 3M failed"
	dd if=/dev/urandom of=$tf bs=1M count=1 \
		oflag=append conv=notrunc ||
		error "append 1M failed"
	dd if=/dev/urandom of=$tf bs=512K count=1 \
		oflag=append conv=notrunc ||
		error "append 512K failed"
	dd if=/dev/urandom of=$tf bs=1M count=3 \
		oflag=append conv=notrunc ||
		error "append last 3M failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')
	local sz=$(stat -c %s $tf)
	echo "  file size: $sz"

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 2 )) ||
		skip_env "need >= 2 safe data OSTs"

	# 1-down
	local victim=${safe_osts[0]}
	ec_deactivate_ost $victim
	cancel_lru_locks osc
	local got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $victim
	[[ "$sum" == "$got" ]] ||
		error "unaligned append 1-down:" \
			"$sum != $got"
	echo "  1-down OK"

	# 2-down
	local v1=${safe_osts[0]}
	local v2=${safe_osts[1]}
	ec_deactivate_ost $v1
	ec_deactivate_ost $v2
	cancel_lru_locks osc
	got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $v2
	ec_reactivate_ost $v1
	[[ "$sum" == "$got" ]] ||
		error "unaligned append 2-down:" \
			"$sum != $got"
	echo "** unaligned append with 2-down OK"
}
run_test 62b "EC recovery after unaligned append writes"

test_62c() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# PFL: [0,4M) + [4M,EOF), both 4+2
	$LFS setstripe \
		-E 4M -S 1M -c 4 --ec 4+2 \
		-E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe PFL failed"

	# Write 2M in comp1, resync
	dd if=/dev/urandom of=$tf bs=1M count=2 ||
		error "dd 2M failed"
	$LFS mirror resync $tf || error "resync 1 failed"

	# Append to cross into comp2
	dd if=/dev/urandom of=$tf bs=1M count=4 \
		oflag=append conv=notrunc ||
		error "append 4M failed"
	$LFS mirror resync $tf || error "resync 2 failed"

	local sum=$(md5sum $tf | awk '{print $1}')
	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"

	local ost
	for ost in "${safe_osts[@]}"; do
		ec_deactivate_ost $ost
		cancel_lru_locks osc
		local got=$(md5sum $tf | awk '{print $1}')
		ec_reactivate_ost $ost
		[[ "$sum" == "$got" ]] ||
			error "PFL append OST$ost:" \
				"$sum != $got"
		echo "  OST$ost OK"
	done
}
run_test 62c "EC recovery after append crossing PFL boundary"

test_62d() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# 4+2 layout, 1M stripes
	$LFS setstripe -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	# Append sub-stripe amounts repeatedly
	local i
	for ((i = 0; i < 10; i++)); do
		dd if=/dev/urandom of=$tf bs=100K count=1 \
			oflag=append conv=notrunc ||
			error "append $i failed"
	done
	# Total: 1000K, which is still inside the first 1M stripe
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')

	# All 1000K sit on stripe 0, so both victims are chosen from the
	# stripe map rather than from the numerically sorted safe_osts,
	# whose first entries usually hold none of this file's data.
	ec_data_stripe_osts $tf 0 1

	# Single degradation
	local victim=${EC_STRIPE_OSTS[0]}
	ec_deactivate_ost $victim
	cancel_lru_locks osc
	local got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $victim
	[[ "$sum" == "$got" ]] ||
		error "sub-stripe appends 1-down:" \
			"$sum != $got"
	echo "  1-down OK"

	# Double degradation
	local v1=${EC_STRIPE_OSTS[0]}
	local v2=${EC_STRIPE_OSTS[1]}
	ec_deactivate_ost $v1
	ec_deactivate_ost $v2
	cancel_lru_locks osc
	got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $v2
	ec_reactivate_ost $v1
	[[ "$sum" == "$got" ]] ||
		error "sub-stripe appends 2-down:" \
			"$sum != $got"
	echo "** sub-stripe appends with 2-down OK"
}
run_test 62d "EC recovery after many sub-stripe appends"

test_63a() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# 4+2 layout, 1M stripes
	$LFS setstripe -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"
	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd 8M failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')
	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 3 )) ||
		skip_env "need >= 3 safe data OSTs"

	# Cycle through each safe OST one at a time
	local ost
	for ost in "${safe_osts[@]}"; do
		ec_deactivate_ost $ost
		cancel_lru_locks osc
		local got=$(md5sum $tf | awk '{print $1}')
		ec_reactivate_ost $ost
		[[ "$sum" == "$got" ]] ||
			error "cycle OST$ost: $sum != $got"
		echo "  OST$ost OK"
	done
	echo "** single-OST cycling OK"
}
run_test 63a "EC recovery cycling through each data OST"

test_63b() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# 4+2 layout, 1M stripes
	$LFS setstripe -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"
	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd 8M failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')
	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 3 )) ||
		skip_env "need >= 3 safe data OSTs"

	# Cycle through all 2-OST combinations
	local i j
	for ((i = 0; i < ${#safe_osts[@]} - 1; i++)); do
		for ((j = i + 1; j < ${#safe_osts[@]}; j++)); do
			local v1=${safe_osts[$i]}
			local v2=${safe_osts[$j]}
			ec_deactivate_ost $v1
			ec_deactivate_ost $v2
			cancel_lru_locks osc
			local got=$(md5sum $tf |
				awk '{print $1}')
			ec_reactivate_ost $v2
			ec_reactivate_ost $v1
			[[ "$sum" == "$got" ]] ||
				error "pair OST${v1}+" \
					"OST${v2}:" \
					"$sum != $got"
			echo "  OST${v1}+OST${v2} OK"
		done
	done
}
run_test 63b "EC recovery cycling all 2-OST failure pairs"

test_63c() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# 4+2 layout, 1M stripes
	$LFS setstripe -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"
	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd 8M failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')
	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 2 )) ||
		skip_env "need >= 2 safe data OSTs"

	# Deactivate first, read, deactivate second while
	# first is still down, read again, then recover
	local v1=${safe_osts[0]}
	local v2=${safe_osts[1]}

	ec_deactivate_ost $v1
	cancel_lru_locks osc
	local got1=$(md5sum $tf | awk '{print $1}')
	[[ "$sum" == "$got1" ]] ||
		error "1-down OST$v1: $sum != $got1"
	echo "  1-down OST$v1 OK"

	# Add second failure while first still down
	ec_deactivate_ost $v2
	cancel_lru_locks osc
	local got2=$(md5sum $tf | awk '{print $1}')
	[[ "$sum" == "$got2" ]] ||
		error "2-down OST${v1}+OST${v2}:" \
			"$sum != $got2"
	echo "  2-down OST${v1}+OST${v2} OK"

	# Recover first, read with only second down
	ec_reactivate_ost $v1
	cancel_lru_locks osc
	local got3=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $v2
	[[ "$sum" == "$got3" ]] ||
		error "swap to OST$v2-only:" \
			"$sum != $got3"
	echo "** progressive fail/recover cycle OK"
}
run_test 63c "EC recovery with progressive failure and partial recovery"

test_63d() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# PFL: [0,4M) 4+2, [4M,EOF) 4+2
	$LFS setstripe \
		-E 4M -S 1M -c 4 --ec 4+2 \
		-E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe PFL failed"
	dd if=/dev/urandom of=$tf bs=1M count=12 ||
		error "dd 12M failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')
	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 3 )) ||
		skip_env "need >= 3 safe data OSTs"

	# Cycle: fail OST A, verify, reactivate A,
	# fail OST B, verify, reactivate B, ...
	local prev=""
	local ost
	for ost in "${safe_osts[@]}"; do
		[[ -n "$prev" ]] && ec_reactivate_ost $prev
		ec_deactivate_ost $ost
		cancel_lru_locks osc
		local got=$(md5sum $tf | awk '{print $1}')
		[[ "$sum" == "$got" ]] ||
			error "PFL cycle OST$ost:" \
				"$sum != $got"
		echo "  OST$ost OK"
		prev=$ost
	done
	[[ -n "$prev" ]] && ec_reactivate_ost $prev
	echo "** PFL OST cycling OK"
}
run_test 63d "EC recovery cycling OSTs with PFL layout"

test_64a() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"
	local tf2=$DIR2/$tfile

	# check_and_setup_lustre() already mounts $MOUNT2 when the
	# session sets MOUNT_2; only tear down a mount this test made.
	if ! is_mounted $MOUNT2; then
		mkdir -p $MOUNT2
		mount_client $MOUNT2 || error "mount_client $MOUNT2 failed"
		stack_trap "umount_client $MOUNT2"
	fi
	enable_ec

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"
	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd 8M failed"
	$LFS mirror resync $tf || error "resync 1 failed"

	local sum1=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"
	local victim=${safe_osts[0]}

	ec_deactivate_ost $victim
	cancel_lru_locks osc

	local got2=$(md5sum $tf2 | awk '{print $1}')
	ec_reactivate_ost $victim

	[[ "$sum1" == "$got2" ]] ||
		error "mount2 after write1: $sum1 != $got2"

	echo "** mount2 reads mount1 data after resync OK"

	cancel_lru_locks osc
	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd overwrite failed"
	$LFS mirror resync $tf || error "resync 2 failed"

	local sum2=$(md5sum $tf | awk '{print $1}')
	[[ "$sum1" != "$sum2" ]] ||
		error "overwrite produced same checksum"

	ec_deactivate_ost $victim
	cancel_lru_locks osc

	got2=$(md5sum $tf2 | awk '{print $1}')
	ec_reactivate_ost $victim

	[[ "$sum2" == "$got2" ]] ||
		error "mount2 after write2: $sum2 != $got2"

	echo "** mount2 reads updated data after re-resync OK"
}
run_test 64a "mount2 EC recovery after mount1 write+resync cycles"

test_64b() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"
	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd initial failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum_synced=$(md5sum $tf | awk '{print $1}')

	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd overwrite failed"

	local sum_dirty=$(md5sum $tf | awk '{print $1}')
	[[ "$sum_synced" != "$sum_dirty" ]] ||
		error "overwrite produced same checksum"

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"
	local victim=${safe_osts[0]}

	ec_deactivate_ost $victim
	cancel_lru_locks osc

	# Parity is stale after the un-resynced overwrite, so EC cannot
	# reconstruct the failed stripe.  Either outcome is acceptable --
	# the read returns the current bytes, or it fails -- but silently
	# handing back different data is a corruption bug, so assert
	# against it (same invariant as 48a).
	local out=$TMP/$tfile.stale64b
	local rc=0

	stack_trap "rm -f $out"
	dd if=$tf of=$out bs=1M 2>/dev/null || rc=$?
	ec_reactivate_ost $victim

	if (( rc == 0 )); then
		local got=$(md5sum $out | awk '{print $1}')

		[[ "$sum_dirty" == "$got" ]] ||
			error "stale-parity read returned wrong data:" \
				"$sum_dirty vs $got"
		echo "** stale-parity read returned the current data"
	else
		echo "** stale-parity read failed, as expected"
	fi

	# The overwrite stales the whole parity component, so which branch
	# above runs is not guaranteed.  Resync and repeat: with parity up
	# to date the degraded read must succeed and return the current
	# bytes.  That is the assertion that can actually fail.
	$LFS mirror resync $tf || error "resync after overwrite failed"

	ec_deactivate_ost $victim
	cancel_lru_locks osc
	dd if=$tf of=$out bs=1M 2>/dev/null ||
		error "degraded read failed after resync"
	ec_reactivate_ost $victim

	local sum_resynced=$(md5sum $out | awk '{print $1}')

	[[ "$sum_dirty" == "$sum_resynced" ]] ||
		error "recovery after resync returned wrong data:" \
			"$sum_dirty vs $sum_resynced"
	echo "** Recovery after resync returned the current data"
}
run_test 64b "EC stale-parity read returns current data or fails"

test_64c() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"
	local tf2=$DIR2/$tfile

	# check_and_setup_lustre() already mounts $MOUNT2 when the
	# session sets MOUNT_2; only tear down a mount this test made.
	if ! is_mounted $MOUNT2; then
		mkdir -p $MOUNT2
		mount_client $MOUNT2 || error "mount_client $MOUNT2 failed"
		stack_trap "umount_client $MOUNT2"
	fi
	enable_ec

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd initial failed"
	$LFS mirror resync $tf || error "resync 0 failed"

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"
	local victim=${safe_osts[0]}

	local iter
	for ((iter = 1; iter <= 3; iter++)); do
		echo "** iteration $iter"

		cancel_lru_locks osc
		dd if=/dev/urandom of=$tf bs=1M count=8 ||
			error "dd iter $iter failed"
		$LFS mirror resync $tf ||
			error "resync iter $iter failed"

		local sum=$(md5sum $tf | awk '{print $1}')

		ec_deactivate_ost $victim
		cancel_lru_locks osc

		local got=$(md5sum $tf2 | awk '{print $1}')
		ec_reactivate_ost $victim

		[[ "$sum" == "$got" ]] ||
			error "iter $iter: $sum != $got"

		echo "** iteration $iter OK"
	done
}
run_test 64c "EC recovery stability across write+resync iterations"

test_64d() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"
	local tf2=$DIR2/$tfile

	# check_and_setup_lustre() already mounts $MOUNT2 when the
	# session sets MOUNT_2; only tear down a mount this test made.
	if ! is_mounted $MOUNT2; then
		mkdir -p $MOUNT2
		mount_client $MOUNT2 || error "mount_client $MOUNT2 failed"
		stack_trap "umount_client $MOUNT2"
	fi
	enable_ec

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	dd if=/dev/urandom of=$tf bs=1M count=4 ||
		error "dd mount1 failed"

	dd if=/dev/urandom of=$tf2 bs=1M count=4 \
		oflag=append conv=notrunc ||
		error "dd mount2 append failed"

	local fsize=$(stat -c '%s' $tf)
	(( fsize == 8388608 )) ||
		error "file size $fsize != 8388608"

	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"
	local victim=${safe_osts[0]}

	ec_deactivate_ost $victim
	cancel_lru_locks osc

	local got1=$(md5sum $tf | awk '{print $1}')
	local got2=$(md5sum $tf2 | awk '{print $1}')

	ec_reactivate_ost $victim

	[[ "$sum" == "$got1" ]] ||
		error "mount1 recovery: $sum != $got1"
	[[ "$sum" == "$got2" ]] ||
		error "mount2 recovery: $sum != $got2"

	echo "** multi-mount append + recovery OK"
}
run_test 64d "EC recovery after multi-mount append"

test_65a() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# 3 PFL components: [0,4M) 4+2, [4M,16M) 2+1,
	# [16M,EOF) 4+2
	$LFS setstripe \
		-E 4M -S 1M -c 4 --ec 4+2 \
		-E 16M -S 1M -c 2 --ec 2+1 \
		-E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe 3-comp PFL failed"

	# Write 24M spanning all three components
	dd if=/dev/urandom of=$tf bs=1M count=24 ||
		error "dd 24M failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')
	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"

	local ost
	for ost in "${safe_osts[@]}"; do
		ec_deactivate_ost $ost
		cancel_lru_locks osc
		local got=$(md5sum $tf | awk '{print $1}')
		ec_reactivate_ost $ost
		[[ "$sum" == "$got" ]] ||
			error "3-comp OST$ost: $sum != $got"
		echo "  OST$ost OK"
	done
}
run_test 65a "EC recovery with 3-component PFL layout"

test_65b() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# 4 PFL components with different EC configs
	$LFS setstripe \
		-E 2M -S 64K -c 4 --ec 4+2 \
		-E 8M -S 256K -c 2 --ec 2+1 \
		-E 32M -S 1M -c 4 --ec 4+2 \
		-E eof -S 1M -c 2 --ec 2+1 $tf ||
		error "setstripe 4-comp PFL failed"

	# Write 48M spanning all four components
	dd if=/dev/urandom of=$tf bs=1M count=48 ||
		error "dd 48M failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')
	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"

	local ost
	for ost in "${safe_osts[@]}"; do
		ec_deactivate_ost $ost
		cancel_lru_locks osc
		local got=$(md5sum $tf | awk '{print $1}')
		ec_reactivate_ost $ost
		[[ "$sum" == "$got" ]] ||
			error "4-comp OST$ost: $sum != $got"
		echo "  OST$ost OK"
	done
}
run_test 65b "EC recovery with 4-component PFL layout"

test_65c() {
	# The layout below is sparse from 2M to 20M, so resync has to find
	# the holes to know which stripe sets to skip.  ZFS lseek does not
	# report holes reliably for dirty data, as test 12b describes.
	[[ "$ost1_FSTYPE" != "zfs" ]] ||
		skip "LU-14217: lseek holes unreliable on ZFS"

	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# 3 PFL components, data only in comp1 and comp3
	$LFS setstripe \
		-E 4M -S 1M -c 4 --ec 4+2 \
		-E 16M -S 1M -c 2 --ec 2+1 \
		-E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe 3-comp PFL failed"

	# Write 2M in comp1, skip comp2, write 4M in comp3
	dd if=/dev/urandom of=$tf bs=1M count=2 ||
		error "dd comp1 2M failed"
	dd if=/dev/urandom of=$tf bs=1M count=4 seek=20 ||
		error "dd comp3 at 20M failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')
	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"

	local ost
	for ost in "${safe_osts[@]}"; do
		ec_deactivate_ost $ost
		cancel_lru_locks osc
		local got=$(md5sum $tf | awk '{print $1}')
		ec_reactivate_ost $ost
		[[ "$sum" == "$got" ]] ||
			error "sparse 3-comp OST$ost:" \
				"$sum != $got"
		echo "  OST$ost OK"
	done
}
run_test 65c "EC recovery with sparse 3-component PFL layout"

test_65d() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# 3 PFL components, all 4+2 for 2-down testing
	$LFS setstripe \
		-E 4M -S 1M -c 4 --ec 4+2 \
		-E 16M -S 1M -c 4 --ec 4+2 \
		-E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe 3-comp PFL failed"

	dd if=/dev/urandom of=$tf bs=1M count=24 ||
		error "dd 24M failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')
	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 2 )) ||
		skip_env "need >= 2 safe data OSTs for 2-down"

	local v1=${safe_osts[0]}
	local v2=${safe_osts[1]}

	ec_deactivate_ost $v1
	ec_deactivate_ost $v2
	cancel_lru_locks osc
	local got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $v2
	ec_reactivate_ost $v1
	[[ "$sum" == "$got" ]] ||
		error "3-comp 2-down: $sum != $got"
	echo "** 3-component PFL with 2 OSTs down OK"
}
run_test 65d "EC recovery with 3-comp PFL and 2 OST failures"

test_66a() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Two data mirrors, both with EC (2+1)
	$LFS setstripe -N -E eof -S 1M -c 2 --ec 2+1 \
		-N -E eof -S 1M -c 2 --ec 2+1 \
		$tf || error "setstripe 2-EC-mirror failed"

	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd 8M failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')

	# Degrade every data mirror at once.  Failing one OST would leave
	# the other mirror intact and the read would be served from it
	# without any reconstruction.
	ec_mirror_victims $tf ||
		skip_env "no parity-free data OST per mirror"

	local ost
	for ost in "${EC_MIRROR_VICTIMS[@]}"; do
		ec_deactivate_ost $ost
	done
	cancel_lru_locks osc

	local got=$(md5sum $tf | awk '{print $1}')

	for ost in "${EC_MIRROR_VICTIMS[@]}"; do
		ec_reactivate_ost $ost
	done

	[[ "$sum" == "$got" ]] ||
		error "2-EC-mirror OSTs ${EC_MIRROR_VICTIMS[*]}:" \
			"$sum != $got"
	echo "  OSTs ${EC_MIRROR_VICTIMS[*]} OK"
}
run_test 66a "EC recovery with two EC data mirrors"

test_66b() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Mixed: one regular data mirror + one EC data mirror
	$LFS setstripe -N -E eof -S 1M -c 2 \
		-N -E eof -S 1M -c 2 --ec 2+1 \
		$tf || error "setstripe mixed failed"

	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd 8M failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')

	# Degrade every data mirror at once.  Failing one OST would leave
	# the other mirror intact and the read would be served from it
	# without any reconstruction.
	ec_mirror_victims $tf ||
		skip_env "no parity-free data OST per mirror"

	local ost
	for ost in "${EC_MIRROR_VICTIMS[@]}"; do
		ec_deactivate_ost $ost
	done
	cancel_lru_locks osc

	local got=$(md5sum $tf | awk '{print $1}')

	for ost in "${EC_MIRROR_VICTIMS[@]}"; do
		ec_reactivate_ost $ost
	done

	[[ "$sum" == "$got" ]] ||
		error "mixed mirror OSTs ${EC_MIRROR_VICTIMS[*]}:" \
			"$sum != $got"
	echo "  OSTs ${EC_MIRROR_VICTIMS[*]} OK"
}
run_test 66b "EC recovery with mixed regular and EC mirrors"

test_66c() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Two EC mirrors with different configs: 2+2 and 2+1
	$LFS setstripe -N -E eof -S 1M -c 2 --ec 2+2 \
		-N -E eof -S 1M -c 2 --ec 2+1 \
		$tf || error "setstripe diff-EC failed"

	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd 8M failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')

	# Degrade every data mirror at once.  Failing one OST would leave
	# the other mirror intact and the read would be served from it
	# without any reconstruction.
	ec_mirror_victims $tf ||
		skip_env "no parity-free data OST per mirror"

	local ost
	for ost in "${EC_MIRROR_VICTIMS[@]}"; do
		ec_deactivate_ost $ost
	done
	cancel_lru_locks osc

	local got=$(md5sum $tf | awk '{print $1}')

	for ost in "${EC_MIRROR_VICTIMS[@]}"; do
		ec_reactivate_ost $ost
	done

	[[ "$sum" == "$got" ]] ||
		error "diff-EC OSTs ${EC_MIRROR_VICTIMS[*]}:" \
			"$sum != $got"
	echo "  OSTs ${EC_MIRROR_VICTIMS[*]} OK"
}
run_test 66c "EC recovery with two different EC configs"

test_66d() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Two EC mirrors (2+2) with 2 OST failures
	$LFS setstripe -N -E eof -S 1M -c 2 --ec 2+2 \
		-N -E eof -S 1M -c 2 --ec 2+2 \
		$tf || error "setstripe 2-EC failed"

	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd 8M failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')

	# One victim per data mirror, so both mirrors are degraded at once.
	# Two victims picked by OST index could land in the same mirror and
	# leave the other one able to answer the read on its own.
	ec_mirror_victims $tf ||
		skip_env "no parity-free data OST per mirror"
	(( ${#EC_MIRROR_VICTIMS[@]} >= 2 )) ||
		skip_env "need a victim in each of the 2 mirrors"

	local ost
	for ost in "${EC_MIRROR_VICTIMS[@]}"; do
		ec_deactivate_ost $ost
	done
	cancel_lru_locks osc

	local got=$(md5sum $tf | awk '{print $1}')

	for ost in "${EC_MIRROR_VICTIMS[@]}"; do
		ec_reactivate_ost $ost
	done

	[[ "$sum" == "$got" ]] ||
		error "2-EC 2-down OSTs ${EC_MIRROR_VICTIMS[*]}:" \
			"$sum != $got"
	echo "** two EC mirrors with 2 OSTs down OK"
}
run_test 66d "EC recovery with two EC mirrors and 2 OST failures"

test_67a() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	# Write initial data and resync parity
	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd initial failed"
	$LFS mirror resync $tf || error "resync initial failed"

	# Find which stripe index maps to which OST
	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"
	local victim=${safe_osts[0]}

	# Find the stripe index for the victim OST so we
	# can write to other stripes while it's down
	local ids=($($LFS getstripe $tf |
		awk '/lcme_id/{print $2}'))
	local stripe_osts=($($LFS getstripe -I${ids[0]} \
		$tf | awk '/l_ost_idx:/ { print $5 }' |
		tr -d ","))
	local victim_idx=-1 i
	for ((i = 0; i < ${#stripe_osts[@]}; i++)); do
		[[ ${stripe_osts[$i]} -eq $victim ]] &&
			victim_idx=$i && break
	done
	(( victim_idx >= 0 )) ||
		error "victim OST$victim not in stripe map"

	# Pick a safe stripe to write to (not the victim)
	local write_idx=$(( (victim_idx + 1) % 4 ))

	ec_deactivate_ost $victim
	cancel_lru_locks osc

	# Write 1M to a stripe NOT on the degraded OST.  Note the injected
	# fault is OBD_FAIL_OST_BRW_READ_BULK, which fails reads only, so
	# the write itself is not degraded; what this checks is that a
	# write issued while one data object is unreadable still resyncs
	# and reconstructs correctly afterwards.
	dd if=/dev/urandom of=$tf bs=1M count=1 \
		seek=$write_idx conv=notrunc ||
		error "dd to stripe $write_idx failed"

	ec_reactivate_ost $victim
	$LFS mirror resync $tf ||
		error "resync after degraded write failed"

	local sum=$(md5sum $tf | awk '{print $1}')

	# Verify recovery returns correct data
	ec_deactivate_ost $victim
	cancel_lru_locks osc
	local got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $victim

	[[ "$sum" == "$got" ]] ||
		error "degraded write recovery: $sum != $got"
	echo "** write to non-degraded stripe + recovery OK"
}
run_test 67a "EC write to available stripes with one OST unreadable"

test_67b() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	# Multiple rewrite + resync cycles, then verify recovery uses
	# the final parity.  Each dd below opens with O_TRUNC (no
	# conv=notrunc, no seek), so a pass replaces the file rather
	# than overwriting it in place.
	local sum
	local iter
	for ((iter = 1; iter <= 3; iter++)); do
		dd if=/dev/urandom of=$tf bs=1M count=8 ||
			error "dd iteration $iter failed"
		$LFS mirror resync $tf ||
			error "resync iteration $iter failed"
	done

	sum=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"

	local ost
	for ost in "${safe_osts[@]}"; do
		ec_deactivate_ost $ost
		cancel_lru_locks osc
		local got=$(md5sum $tf | awk '{print $1}')
		ec_reactivate_ost $ost
		[[ "$sum" == "$got" ]] ||
			error "3-cycle OST$ost: $sum != $got"
		echo "  OST$ost OK"
	done
}
run_test 67b "EC recovery after multiple rewrite+resync cycles"

test_67c() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# PFL layout
	$LFS setstripe -E 4M -S 1M -c 4 --ec 4+2 \
		-E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe PFL failed"

	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd initial failed"
	$LFS mirror resync $tf || error "resync initial failed"

	# Overwrite just comp1 (first 4M), resync, verify
	dd if=/dev/urandom of=$tf bs=1M count=4 \
		conv=notrunc || error "dd overwrite comp1 failed"
	$LFS mirror resync $tf ||
		error "resync after comp1 overwrite failed"

	local sum=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"
	local victim=${safe_osts[0]}

	ec_deactivate_ost $victim
	cancel_lru_locks osc
	local got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $victim

	[[ "$sum" == "$got" ]] ||
		error "PFL partial overwrite recovery:" \
			"$sum != $got"
	echo "** PFL partial overwrite + recovery OK"
}
run_test 67c "EC recovery after partial overwrite of PFL component"

test_67d() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd initial failed"
	$LFS mirror resync $tf || error "resync initial failed"

	# Overwrite first 2M (partial RAID set), resync
	dd if=/dev/urandom of=$tf bs=1M count=2 \
		conv=notrunc || error "dd overwrite 2M failed"
	$LFS mirror resync $tf ||
		error "resync after partial overwrite failed"

	local sum=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 2 )) ||
		skip_env "need >= 2 safe data OSTs"
	local v1=${safe_osts[0]}
	local v2=${safe_osts[1]}

	# Single OST down
	ec_deactivate_ost $v1
	cancel_lru_locks osc
	local got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $v1
	[[ "$sum" == "$got" ]] ||
		error "partial overwrite 1-down: $sum != $got"
	echo "** 1-OST down after partial overwrite OK"

	# Two OSTs down
	ec_deactivate_ost $v1
	ec_deactivate_ost $v2
	cancel_lru_locks osc
	got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $v2
	ec_reactivate_ost $v1
	[[ "$sum" == "$got" ]] ||
		error "partial overwrite 2-down: $sum != $got"
	echo "** 2-OSTs down after partial overwrite OK"
}
run_test 67d "EC recovery after partial overwrite with 1 and 2 OST failures"

test_68a() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# 2+1: 2 data stripes, 1 parity, max 1 failure
	$LFS setstripe -E eof -S 1M -c 2 --ec 2+1 $tf ||
		error "setstripe 2+1 failed"

	# 6M = 3 full RAID sets with k=2
	dd if=/dev/urandom of=$tf bs=1M count=6 ||
		error "dd 6M failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')
	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs for 2+1"

	local ost
	for ost in "${safe_osts[@]}"; do
		ec_deactivate_ost $ost
		cancel_lru_locks osc
		local got=$(md5sum $tf | awk '{print $1}')
		ec_reactivate_ost $ost
		[[ "$sum" == "$got" ]] ||
			error "2+1 OST$ost: $sum != $got"
		echo "  2+1 OST$ost OK"
	done
}
run_test 68a "EC 2+1 recovery cycling all safe data OSTs"

test_68b() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# 2+2: 2 data stripes, 2 parity, max 2 failures
	$LFS setstripe -E eof -S 1M -c 2 --ec 2+2 $tf ||
		error "setstripe 2+2 failed"

	dd if=/dev/urandom of=$tf bs=1M count=6 ||
		error "dd 6M failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')
	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 2 )) ||
		skip_env "need >= 2 safe data OSTs for 2+2"

	# Test all 2-OST failure combinations
	local i j
	for ((i = 0; i < ${#safe_osts[@]}; i++)); do
		for ((j = i + 1; j < ${#safe_osts[@]}; j++)); do
			local v1=${safe_osts[$i]}
			local v2=${safe_osts[$j]}
			ec_deactivate_ost $v1
			ec_deactivate_ost $v2
			cancel_lru_locks osc
			local got=$(md5sum $tf | awk '{print $1}')
			ec_reactivate_ost $v2
			ec_reactivate_ost $v1
			[[ "$sum" == "$got" ]] ||
				error "2+2 OST$v1+$v2:" \
					"$sum != $got"
			echo "  2+2 OST$v1+OST$v2 OK"
		done
	done
}
run_test 68b "EC 2+2 recovery with all 2-OST failure pairs"

test_68c() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# 4+1: 4 data stripes, 1 parity, max 1 failure
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+1 $tf ||
		error "setstripe 4+1 failed"

	# 16M = 4 full RAID sets with k=4
	dd if=/dev/urandom of=$tf bs=1M count=16 ||
		error "dd 16M failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')
	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs for 4+1"

	local ost
	for ost in "${safe_osts[@]}"; do
		ec_deactivate_ost $ost
		cancel_lru_locks osc
		local got=$(md5sum $tf | awk '{print $1}')
		ec_reactivate_ost $ost
		[[ "$sum" == "$got" ]] ||
			error "4+1 OST$ost: $sum != $got"
		echo "  4+1 OST$ost OK"
	done
}
run_test 68c "EC 4+1 recovery cycling all safe data OSTs"

test_68d() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# PFL with different EC geometry per component
	# comp1: 2+1 (3 OSTs), comp2: 4+2 (6 OSTs)
	$LFS setstripe -E 4M -S 1M -c 2 --ec 2+1 \
		-E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe mixed PFL failed"

	# Write spanning both components
	dd if=/dev/urandom of=$tf bs=1M count=12 ||
		error "dd 12M failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')
	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs for mixed PFL"

	local ost
	for ost in "${safe_osts[@]}"; do
		ec_deactivate_ost $ost
		cancel_lru_locks osc
		local got=$(md5sum $tf | awk '{print $1}')
		ec_reactivate_ost $ost
		[[ "$sum" == "$got" ]] ||
			error "mixed PFL OST$ost:" \
				"$sum != $got"
		echo "  mixed PFL OST$ost OK"
	done
}
run_test 68d "EC recovery with mixed 2+1 and 4+2 PFL components"

test_69a() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	# Write with O_DIRECT
	dd if=/dev/urandom of=$tf bs=1M count=8 oflag=direct ||
		error "dd DIO write failed"
	$LFS mirror resync $tf || error "resync failed"

	# Read back with buffered I/O for baseline
	local sum=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"

	local ost
	for ost in "${safe_osts[@]}"; do
		ec_deactivate_ost $ost
		cancel_lru_locks osc
		local got=$(md5sum $tf | awk '{print $1}')
		ec_reactivate_ost $ost
		[[ "$sum" == "$got" ]] ||
			error "DIO-write OST$ost: $sum != $got"
		echo "  DIO-write OST$ost OK"
	done
}
run_test 69a "EC recovery after O_DIRECT writes"

test_69b() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	# DIO write with 2-OST failure tolerance
	dd if=/dev/urandom of=$tf bs=1M count=8 oflag=direct ||
		error "dd DIO write failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 2 )) ||
		skip_env "need >= 2 safe data OSTs"
	local v1=${safe_osts[0]}
	local v2=${safe_osts[1]}

	ec_deactivate_ost $v1
	ec_deactivate_ost $v2
	cancel_lru_locks osc
	local got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $v2
	ec_reactivate_ost $v1

	[[ "$sum" == "$got" ]] ||
		error "DIO-write 2-down: $sum != $got"
	echo "** DIO write with 2 OSTs down OK"
}
run_test 69b "EC recovery after O_DIRECT write with 2 OST failures"

test_69c() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	# Initial buffered write + resync
	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd initial failed"
	$LFS mirror resync $tf || error "resync 1 failed"

	# DIO overwrite + resync
	dd if=/dev/urandom of=$tf bs=1M count=8 \
		oflag=direct conv=notrunc ||
		error "dd DIO overwrite failed"
	$LFS mirror resync $tf || error "resync 2 failed"

	local sum=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"
	local victim=${safe_osts[0]}

	ec_deactivate_ost $victim
	cancel_lru_locks osc
	local got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $victim

	[[ "$sum" == "$got" ]] ||
		error "DIO-overwrite recovery: $sum != $got"
	echo "** buffered write then DIO overwrite + recovery OK"
}
run_test 69c "EC recovery after buffered write then O_DIRECT overwrite"

test_69d() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# PFL with DIO writes
	$LFS setstripe -E 4M -S 1M -c 4 --ec 4+2 \
		-E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe PFL failed"

	dd if=/dev/urandom of=$tf bs=1M count=12 \
		oflag=direct || error "dd DIO PFL failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 2 )) ||
		skip_env "need >= 2 safe data OSTs"
	local v1=${safe_osts[0]}
	local v2=${safe_osts[1]}

	# 1-down
	ec_deactivate_ost $v1
	cancel_lru_locks osc
	local got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $v1
	[[ "$sum" == "$got" ]] ||
		error "DIO PFL 1-down: $sum != $got"
	echo "** DIO PFL 1-OST down OK"

	# 2-down
	ec_deactivate_ost $v1
	ec_deactivate_ost $v2
	cancel_lru_locks osc
	got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $v2
	ec_reactivate_ost $v1
	[[ "$sum" == "$got" ]] ||
		error "DIO PFL 2-down: $sum != $got"
	echo "** DIO PFL 2-OSTs down OK"
}
run_test 69d "EC recovery after O_DIRECT write to PFL layout"

test_70a() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	# Write 8M, resync, then overwrite middle 2M
	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd initial failed"
	$LFS mirror resync $tf || error "resync 1 failed"

	dd if=/dev/urandom of=$tf bs=1M count=2 seek=3 \
		conv=notrunc || error "dd mid-overwrite failed"
	$LFS mirror resync $tf || error "resync 2 failed"

	local sum=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"

	local ost
	for ost in "${safe_osts[@]}"; do
		ec_deactivate_ost $ost
		cancel_lru_locks osc
		local got=$(md5sum $tf | awk '{print $1}')
		ec_reactivate_ost $ost
		[[ "$sum" == "$got" ]] ||
			error "mid-overwrite OST$ost:" \
				"$sum != $got"
		echo "  mid-overwrite OST$ost OK"
	done
}
run_test 70a "EC recovery after mid-file overwrite"

test_70b() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	# Write 8M, resync, overwrite with non-aligned size
	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd initial failed"
	$LFS mirror resync $tf || error "resync 1 failed"

	# Overwrite 512K at offset 1.5M, inside stripe 1, ending
	# exactly on the 2M stripe boundary
	dd if=/dev/urandom of=$tf bs=512K count=1 \
		seek=3 conv=notrunc ||
		error "dd unaligned overwrite failed"
	$LFS mirror resync $tf || error "resync 2 failed"

	local sum=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"
	local victim=${safe_osts[0]}

	ec_deactivate_ost $victim
	cancel_lru_locks osc
	local got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $victim

	[[ "$sum" == "$got" ]] ||
		error "unaligned overwrite: $sum != $got"
	echo "** non-aligned overwrite + recovery OK"
}
run_test 70b "EC recovery after non-stripe-aligned overwrite"

test_70c() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	# Write 4M (1 RAID set), resync, extend to 12M,
	# resync, then overwrite first 4M again
	dd if=/dev/urandom of=$tf bs=1M count=4 ||
		error "dd 4M failed"
	$LFS mirror resync $tf || error "resync 1 failed"

	dd if=/dev/urandom of=$tf bs=1M count=8 seek=4 ||
		error "dd extend failed"
	$LFS mirror resync $tf || error "resync 2 failed"

	dd if=/dev/urandom of=$tf bs=1M count=4 \
		conv=notrunc ||
		error "dd re-overwrite failed"
	$LFS mirror resync $tf || error "resync 3 failed"

	local sum=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 2 )) ||
		skip_env "need >= 2 safe data OSTs"
	local v1=${safe_osts[0]}
	local v2=${safe_osts[1]}

	# 1-down
	ec_deactivate_ost $v1
	cancel_lru_locks osc
	local got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $v1
	[[ "$sum" == "$got" ]] ||
		error "extend+re-overwrite 1-down:" \
			"$sum != $got"
	echo "** 1-down after extend + re-overwrite OK"

	# 2-down
	ec_deactivate_ost $v1
	ec_deactivate_ost $v2
	cancel_lru_locks osc
	got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $v2
	ec_reactivate_ost $v1
	[[ "$sum" == "$got" ]] ||
		error "extend+re-overwrite 2-down:" \
			"$sum != $got"
	echo "** 2-down after extend + re-overwrite OK"
}
run_test 70c "EC recovery after extend then re-overwrite original data"

test_70d() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# PFL: overwrite only comp2, leave comp1 untouched
	$LFS setstripe -E 4M -S 1M -c 4 --ec 4+2 \
		-E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe PFL failed"

	dd if=/dev/urandom of=$tf bs=1M count=12 ||
		error "dd 12M failed"
	$LFS mirror resync $tf || error "resync 1 failed"

	# Overwrite only in comp2 (offsets 4M-8M)
	dd if=/dev/urandom of=$tf bs=1M count=4 seek=4 \
		conv=notrunc ||
		error "dd overwrite comp2 failed"
	$LFS mirror resync $tf || error "resync 2 failed"

	local sum=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"

	local ost
	for ost in "${safe_osts[@]}"; do
		ec_deactivate_ost $ost
		cancel_lru_locks osc
		local got=$(md5sum $tf | awk '{print $1}')
		ec_reactivate_ost $ost
		[[ "$sum" == "$got" ]] ||
			error "PFL comp2-overwrite OST$ost:" \
				"$sum != $got"
		echo "  comp2-overwrite OST$ost OK"
	done
}
run_test 70d "EC recovery after overwriting only PFL comp2"

test_71a() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	stack_trap "rm -f $DIR/$tfile.*"

	# Create 8 EC files with different sizes
	local files=()
	local sums=()
	local i
	for ((i = 0; i < 8; i++)); do
		local f=$DIR/${tfile}.${i}
		$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $f ||
			error "setstripe file $i failed"
		local sz=$(( (i + 1) * 2 ))
		dd if=/dev/urandom of=$f bs=1M count=$sz ||
			error "dd file $i (${sz}M) failed"
		$LFS mirror resync $f ||
			error "resync file $i failed"
		files+=("$f")
		sums+=($(md5sum $f | awk '{print $1}'))
	done

	# Degrade one OST, verify ALL files
	ec_classify_osts ${files[0]}
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"
	local victim=${safe_osts[0]}

	ec_deactivate_ost $victim
	cancel_lru_locks osc

	for ((i = 0; i < 8; i++)); do
		local got=$(md5sum ${files[$i]} | awk '{print $1}')
		[[ "${sums[$i]}" == "$got" ]] ||
			error "file $i OST$victim:" \
				"${sums[$i]} != $got"
		echo "  file $i OK"
	done
	ec_reactivate_ost $victim

	echo "** 8 files all recovered with 1 OST down"
}
run_test 71a "EC batch recovery: 8 files with 1 OST failure"

test_71b() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	stack_trap "rm -f $DIR/$tfile.*"

	# Mix of EC geometries in different files
	local f1=$DIR/${tfile}.2p1
	local f2=$DIR/${tfile}.4p2
	local f3=$DIR/${tfile}.2p2

	$LFS setstripe -E eof -S 1M -c 2 --ec 2+1 $f1 ||
		error "setstripe 2+1 failed"
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $f2 ||
		error "setstripe 4+2 failed"
	$LFS setstripe -E eof -S 1M -c 2 --ec 2+2 $f3 ||
		error "setstripe 2+2 failed"

	dd if=/dev/urandom of=$f1 bs=1M count=6 ||
		error "dd f1 failed"
	dd if=/dev/urandom of=$f2 bs=1M count=8 ||
		error "dd f2 failed"
	dd if=/dev/urandom of=$f3 bs=1M count=6 ||
		error "dd f3 failed"

	$LFS mirror resync $f1 || error "resync f1 failed"
	$LFS mirror resync $f2 || error "resync f2 failed"
	$LFS mirror resync $f3 || error "resync f3 failed"

	local s1=$(md5sum $f1 | awk '{print $1}')
	local s2=$(md5sum $f2 | awk '{print $1}')
	local s3=$(md5sum $f3 | awk '{print $1}')

	# Find an OST that is a safe data OST for all files
	ec_classify_osts $f2
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"
	local victim=${safe_osts[0]}

	ec_deactivate_ost $victim
	cancel_lru_locks osc

	local g1=$(md5sum $f1 | awk '{print $1}')
	local g2=$(md5sum $f2 | awk '{print $1}')
	local g3=$(md5sum $f3 | awk '{print $1}')
	ec_reactivate_ost $victim

	[[ "$s1" == "$g1" ]] ||
		error "2+1 file: $s1 != $g1"
	[[ "$s2" == "$g2" ]] ||
		error "4+2 file: $s2 != $g2"
	[[ "$s3" == "$g3" ]] ||
		error "2+2 file: $s3 != $g3"
	echo "** mixed geometry batch recovery OK"
}
run_test 71b "EC batch recovery: mixed geometries with 1 OST failure"

test_71c() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	stack_trap "rm -f $DIR/$tfile.*"

	# 5 files with different sizes, 2-OST failure
	local files=()
	local sums=()
	local sizes=(1 3 5 8 12)
	local i
	for ((i = 0; i < 5; i++)); do
		local f=$DIR/${tfile}.${i}
		$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $f ||
			error "setstripe file $i failed"
		dd if=/dev/urandom of=$f \
			bs=1M count=${sizes[$i]} ||
			error "dd file $i failed"
		$LFS mirror resync $f ||
			error "resync file $i failed"
		files+=("$f")
		sums+=($(md5sum $f | awk '{print $1}'))
	done

	ec_classify_osts ${files[0]}
	(( ${#safe_osts[@]} >= 2 )) ||
		skip_env "need >= 2 safe data OSTs"
	local v1=${safe_osts[0]}
	local v2=${safe_osts[1]}

	ec_deactivate_ost $v1
	ec_deactivate_ost $v2
	cancel_lru_locks osc

	for ((i = 0; i < 5; i++)); do
		local got=$(md5sum ${files[$i]} | awk '{print $1}')
		[[ "${sums[$i]}" == "$got" ]] ||
			error "file $i 2-down:" \
				"${sums[$i]} != $got"
		echo "  file $i (${sizes[$i]}M) OK"
	done
	ec_reactivate_ost $v2
	ec_reactivate_ost $v1

	echo "** 5 files with 2 OSTs down OK"
}
run_test 71c "EC batch recovery: 5 varied files with 2 OST failures"

test_71d() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	stack_trap "rm -f $DIR/$tfile.*"

	# Mix of plain and PFL files
	local f1=$DIR/${tfile}.plain
	local f2=$DIR/${tfile}.pfl

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $f1 ||
		error "setstripe plain failed"
	$LFS setstripe -E 4M -S 1M -c 4 --ec 4+2 \
		-E eof -S 1M -c 4 --ec 4+2 $f2 ||
		error "setstripe PFL failed"

	dd if=/dev/urandom of=$f1 bs=1M count=8 ||
		error "dd plain failed"
	dd if=/dev/urandom of=$f2 bs=1M count=12 ||
		error "dd PFL failed"

	$LFS mirror resync $f1 || error "resync plain failed"
	$LFS mirror resync $f2 || error "resync PFL failed"

	local s1=$(md5sum $f1 | awk '{print $1}')
	local s2=$(md5sum $f2 | awk '{print $1}')

	ec_classify_osts $f1
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"

	local ost
	for ost in "${safe_osts[@]}"; do
		ec_deactivate_ost $ost
		cancel_lru_locks osc
		local g1=$(md5sum $f1 | awk '{print $1}')
		local g2=$(md5sum $f2 | awk '{print $1}')
		ec_reactivate_ost $ost
		[[ "$s1" == "$g1" ]] ||
			error "plain OST$ost: $s1 != $g1"
		[[ "$s2" == "$g2" ]] ||
			error "PFL OST$ost: $s2 != $g2"
		echo "  OST$ost: plain+PFL OK"
	done
}
run_test 71d "EC batch recovery: plain and PFL files cycling OSTs"

test_73a() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"
	local sz=16

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"
	dd if=/dev/urandom of=$tf bs=1M count=$sz ||
		error "dd failed"
	$LFS mirror resync $tf || error "resync failed"

	# Compute md5 of whole file and individual 1M blocks
	local sum_full=$(md5sum $tf | awk '{print $1}')
	local block_sums=()
	local i
	for ((i = 0; i < sz; i++)); do
		block_sums+=($(dd if=$tf bs=1M skip=$i count=1 \
			2>/dev/null | md5sum | awk '{print $1}'))
	done

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"

	# Read blocks in random (non-sequential) order while
	# degraded to exercise EC recovery with seeks
	local victim=${safe_osts[0]}
	ec_deactivate_ost $victim
	cancel_lru_locks osc

	# Full sequential read first
	local got_full=$(md5sum $tf | awk '{print $1}')
	# NOTE: if this fails, it may indicate a bug in EC
	# recovery for sequential reads after degradation.
	[[ "$sum_full" == "$got_full" ]] ||
		error "full read OST$victim:" \
			"$sum_full != $got_full"

	cancel_lru_locks osc

	# Random-order single-block reads
	local order=($(shuf -i 0-$((sz - 1))))
	local failures=0
	for i in "${order[@]}"; do
		local got=$(dd if=$tf bs=1M skip=$i count=1 \
			2>/dev/null | md5sum | awk '{print $1}')
		if [[ "${block_sums[$i]}" != "$got" ]]; then
			echo "block $i: ${block_sums[$i]} != $got"
			failures=$((failures + 1))
		fi
	done
	ec_reactivate_ost $victim

	# NOTE: failures here may indicate a bug in EC
	# recovery when reading non-sequential offsets
	# (e.g. parity offset calculation per-stripe).
	(( failures == 0 )) ||
		error "$failures/$sz blocks failed random read"

	echo "** random-order block reads: all $sz OK"
}
run_test 73a "EC random/non-sequential reads during recovery"

test_73b() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec
	# need allocate-mode fallocate: osd-zfs only implements punch
	check_fallocate_or_skip ost1 alloc
	check_set_fallocate_or_skip

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	# Fallocate 16M, then write 8M into the middle
	fallocate -l 16M $tf ||
		error "fallocate 16M failed"
	dd if=/dev/urandom of=$tf bs=1M count=8 seek=4 \
		conv=notrunc ||
		error "dd into fallocated region failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs"

	# 1-down recovery
	local victim=${safe_osts[0]}
	ec_deactivate_ost $victim
	cancel_lru_locks osc
	local got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $victim
	# NOTE: failure may indicate a bug in EC recovery
	# for sparse/fallocated regions (zero-fill vs
	# actual parity mismatch).
	[[ "$sum" == "$got" ]] ||
		error "fallocate 1-down OST$victim:" \
			"$sum != $got"
	echo "  fallocate 1-down OK"

	# Also test pure fallocate (no dd overwrites)
	local tf2=$DIR/${tfile}.pure
	stack_trap "rm -f $tf2"
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf2 ||
		error "setstripe tf2 failed"
	fallocate -l 8M $tf2 ||
		error "fallocate tf2 failed"
	$LFS mirror resync $tf2 ||
		error "resync tf2 failed"

	local sum2=$(md5sum $tf2 | awk '{print $1}')
	ec_classify_osts $tf2
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "no safe data OSTs for tf2"
	victim=${safe_osts[0]}

	ec_deactivate_ost $victim
	cancel_lru_locks osc
	local got2=$(md5sum $tf2 | awk '{print $1}')
	ec_reactivate_ost $victim
	# NOTE: pure fallocate with no user data tests
	# whether EC recovery handles all-zero stripes.
	[[ "$sum2" == "$got2" ]] ||
		error "pure fallocate 1-down: $sum2 != $got2"

	echo "** fallocate EC recovery OK"
}
run_test 73b "EC recovery after fallocate"

test_73c() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	# Write 8M, resync
	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd 8M failed"
	$LFS mirror resync $tf || error "resync 1 failed"

	# Truncate to 2M.  $TRUNCATE is $LUSTRE/tests/truncate, which takes
	# "PATH LENGTH" rather than the coreutils --size option.
	$TRUNCATE $tf 2097152 ||
		error "truncate to 2M failed"
	$LFS mirror resync $tf || error "resync 2 failed"

	# Extend back to 12M with new data
	dd if=/dev/urandom of=$tf bs=1M count=10 seek=2 ||
		error "dd extend to 12M failed"
	$LFS mirror resync $tf || error "resync 3 failed"

	local sum=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 2 )) ||
		skip_env "need >= 2 safe data OSTs"

	# 1-down
	local v1=${safe_osts[0]}
	ec_deactivate_ost $v1
	cancel_lru_locks osc
	local got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $v1
	# NOTE: failure may indicate a bug in EC recovery
	# when file size changes between parity syncs
	# (truncate invalidates old parity, extend adds
	# new stripes that need fresh parity).
	[[ "$sum" == "$got" ]] ||
		error "truncate-extend 1-down: $sum != $got"
	echo "  1-down after truncate+extend OK"

	# 2-down
	ec_deactivate_ost ${safe_osts[0]}
	ec_deactivate_ost ${safe_osts[1]}
	cancel_lru_locks osc
	got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost ${safe_osts[1]}
	ec_reactivate_ost ${safe_osts[0]}
	[[ "$sum" == "$got" ]] ||
		error "truncate-extend 2-down: $sum != $got"
	echo "  2-down after truncate+extend OK"

	# Additional: truncate to zero then extend
	local tf2=$DIR/${tfile}.zero
	stack_trap "rm -f $tf2"
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf2 ||
		error "setstripe tf2 failed"
	dd if=/dev/urandom of=$tf2 bs=1M count=4 ||
		error "dd tf2 failed"
	$LFS mirror resync $tf2 || error "resync tf2 1 failed"
	$TRUNCATE $tf2 0 ||
		error "truncate to 0 failed"
	dd if=/dev/urandom of=$tf2 bs=1M count=6 ||
		error "dd tf2 re-extend failed"
	$LFS mirror resync $tf2 ||
		error "resync tf2 2 failed"

	local sum2=$(md5sum $tf2 | awk '{print $1}')

	# safe_osts still describes $tf; $tf2 has its own object placement,
	# so classify it before picking a victim or the OST failed here may
	# hold none of $tf2's stripes.
	ec_data_stripe_osts $tf2 0
	ec_deactivate_ost ${EC_STRIPE_OSTS[0]}
	cancel_lru_locks osc
	local got2=$(md5sum $tf2 | awk '{print $1}')
	ec_reactivate_ost ${EC_STRIPE_OSTS[0]}
	# NOTE: truncate-to-zero then extend is a special
	# case — all parity from the first write is gone.
	[[ "$sum2" == "$got2" ]] ||
		error "truncate-zero-extend: $sum2 != $got2"

	echo "** truncate-then-extend recovery OK"
}
run_test 73c "EC truncate-then-extend recovery"

test_73d() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"

	# Seed the file with initial data, resync parity
	dd if=/dev/urandom of=$tf bs=1M count=4 ||
		error "dd seed failed"
	$LFS mirror resync $tf || error "resync 1 failed"

	# Append 8M using O_APPEND via dd
	dd if=/dev/urandom of=$tf bs=1M count=8 \
		oflag=append conv=notrunc ||
		error "dd O_APPEND failed"
	$LFS mirror resync $tf || error "resync 2 failed"

	local sum=$(md5sum $tf | awk '{print $1}')
	local fsize=$(stat -c '%s' $tf)
	(( fsize == 12 * 1048576 )) ||
		error "expected 12M, got $fsize bytes"

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 2 )) ||
		skip_env "need >= 2 safe data OSTs"

	# 1-down degraded read
	local v1=${safe_osts[0]}
	ec_deactivate_ost $v1
	cancel_lru_locks osc
	local got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $v1
	# NOTE: failure may indicate a bug in EC recovery
	# for appended regions where parity was computed
	# over the extended file range.
	[[ "$sum" == "$got" ]] ||
		error "O_APPEND 1-down: $sum != $got"
	echo "  O_APPEND 1-down OK"

	# 2-down degraded read
	ec_deactivate_ost ${safe_osts[0]}
	ec_deactivate_ost ${safe_osts[1]}
	cancel_lru_locks osc
	got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost ${safe_osts[1]}
	ec_reactivate_ost ${safe_osts[0]}
	[[ "$sum" == "$got" ]] ||
		error "O_APPEND 2-down: $sum != $got"
	echo "  O_APPEND 2-down OK"

	# Append in degraded mode. The BRW_READ_BULK fault
	# leaves the OSC import active and fails only reads,
	# so (unlike an inactive import) the append itself
	# succeeds; the new data lands in the data mirror
	# with parity left stale until the next resync.
	ec_deactivate_ost ${safe_osts[0]}
	dd if=/dev/urandom of=$tf bs=1M count=4 \
		oflag=append conv=notrunc ||
		error "degraded O_APPEND write failed"
	ec_reactivate_ost ${safe_osts[0]}

	fsize=$(stat -c '%s' $tf)
	(( fsize == 16 * 1048576 )) ||
		error "expected 16M after degraded append, " \
			"got $fsize bytes"

	# Restore parity over the extended range, then confirm
	# the whole file still reads back through parity
	# reconstruction with a data OST down.
	$LFS mirror resync $tf || error "resync 3 failed"
	sum=$(md5sum $tf | awk '{print $1}')

	ec_deactivate_ost ${safe_osts[0]}
	cancel_lru_locks osc
	local got3=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost ${safe_osts[0]}
	[[ "$sum" == "$got3" ]] ||
		error "degraded-append recovery mismatch:" \
			"$sum != $got3"
	echo "  degraded O_APPEND succeeded and recovers"

	echo "** O_APPEND degraded mode: all OK"
}
run_test 73d "EC O_APPEND during degraded mode"

test_73e() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile
	local sz=128

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"
	stack_trap "rm -f $tf"

	# Write 128M
	dd if=/dev/urandom of=$tf bs=1M count=$sz ||
		error "dd ${sz}M failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')
	local fsize=$(stat -c '%s' $tf)
	(( fsize == sz * 1048576 )) ||
		error "size mismatch: expected ${sz}M, " \
			"got $fsize"

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 2 )) ||
		skip_env "need >= 2 safe data OSTs"

	# 1-down: single data OST failure
	local v1=${safe_osts[0]}
	ec_deactivate_ost $v1
	cancel_lru_locks osc
	local got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost $v1
	# NOTE: large file recovery exercises many RAID
	# sets (128M / 4M swidth = 32 sets). Failure may
	# indicate offset calculation bugs that only
	# manifest at higher offsets.
	[[ "$sum" == "$got" ]] ||
		error "large ${sz}M 1-down: $sum != $got"
	echo "  ${sz}M 1-down OK"

	# 2-down: two data OST failures
	ec_deactivate_ost ${safe_osts[0]}
	ec_deactivate_ost ${safe_osts[1]}
	cancel_lru_locks osc
	got=$(md5sum $tf | awk '{print $1}')
	ec_reactivate_ost ${safe_osts[1]}
	ec_reactivate_ost ${safe_osts[0]}
	[[ "$sum" == "$got" ]] ||
		error "large ${sz}M 2-down: $sum != $got"
	echo "  ${sz}M 2-down OK"

	# Spot-check: read a few individual blocks at
	# high offsets to verify per-stripe recovery
	local offsets=(0 31 64 96 127)
	local block_sums=()
	local i
	for i in "${offsets[@]}"; do
		block_sums+=($(dd if=$tf bs=1M skip=$i \
			count=1 2>/dev/null |
			md5sum | awk '{print $1}'))
	done

	ec_deactivate_ost ${safe_osts[0]}
	cancel_lru_locks osc

	local failures=0
	local j=0
	for i in "${offsets[@]}"; do
		local got_blk=$(dd if=$tf bs=1M skip=$i \
			count=1 2>/dev/null |
			md5sum | awk '{print $1}')
		if [[ "${block_sums[$j]}" != "$got_blk" ]]; then
			echo "block $i: ${block_sums[$j]}" \
				"!= $got_blk"
			failures=$((failures + 1))
		fi
		j=$((j + 1))
	done
	ec_reactivate_ost ${safe_osts[0]}

	(( failures == 0 )) ||
		error "$failures/${#offsets[@]} blocks " \
			"failed at high offsets"

	echo "** large file (${sz}M) recovery: all OK"
}
run_test 73e "EC large file recovery (128M)"

test_74a() {
	[[ $OSTCOUNT -ge 8 ]] || skip_env "needs >= 8 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"
	local sz=64
	local rounds=20

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe failed"
	dd if=/dev/urandom of=$tf bs=1M count=$sz ||
		error "dd failed"
	$LFS mirror resync $tf || error "resync failed"

	local sum=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 2 )) ||
		skip_env "need >= 2 safe data OSTs"

	# Race deactivation against active reads so the
	# failure lands mid-I/O.
	local failures=0
	local reads_done=0
	local i

	for ((i = 1; i <= rounds; i++)); do
		local pids=()
		local j
		for ((j = 0; j < 4; j++)); do
			md5sum $tf \
				> $TMP/ec_race_${j}_$tfile \
				2>&1 &
			pids+=($!)
		done

		# deactivate while readers are likely in flight
		sleep 0.$((RANDOM % 3))
		local victim=${safe_osts[$((i % 2))]}
		ec_deactivate_ost $victim

		for ((j = 0; j < 4; j++)); do
			if ! wait ${pids[$j]}; then
				echo "round $i reader $j:" \
					"process failed"
				failures=$((failures + 1))
				continue
			fi
			local got
			got=$(awk '{print $1}' \
				$TMP/ec_race_${j}_$tfile)
			if [[ "$sum" != "$got" ]]; then
				echo "round $i reader $j:" \
					"$sum != $got"
				failures=$((failures + 1))
			fi
			reads_done=$((reads_done + 1))
		done

		ec_reactivate_ost $victim
		cancel_lru_locks osc
	done
	stack_trap "rm -f $TMP/ec_race_*_$tfile"

	echo "** $reads_done reads across $rounds rounds," \
		"$failures failures"
	(( failures == 0 )) ||
		error "$failures reads failed racing with" \
			"OST deactivation"
}
run_test 74a "EC reads racing with OST deactivation"

test_75a() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"
	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd failed"
	$LFS mirror resync $tf || error "resync failed"

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "need >= 1 safe data OST"

	# Baseline for the degraded reads below.  Without it the reads
	# only prove that md5sum exited 0, so a reconstruction returning
	# correct-length but wrong bytes would pass.
	local sum=$(md5sum $tf | awk '{print $1}')

	# stat/getattr on healthy file.  These are served from the MDS and
	# the inode LVB, so the injected BRW read fault does not affect
	# them; they assert that degrading an OST does not disturb the
	# size, not that stat itself goes through recovery.
	local sz
	sz=$(stat -c %s $tf)
	(( sz == 8 * 1024 * 1024 )) ||
		error "size $sz != 8M before degrade"

	# degrade 1 data OST
	ec_deactivate_ost ${safe_osts[0]}
	cancel_lru_locks osc

	# lfs getstripe must always work (MDS-only)
	$LFS getstripe $tf > /dev/null ||
		error "getstripe failed with OST down"

	# Data reads via EC recovery must work and return the same bytes
	local got
	got=$(md5sum $tf | awk '{print $1}') ||
		error "md5sum failed with OST down"
	[[ "$sum" == "$got" ]] ||
		error "degraded read returned wrong data: $sum vs $got"

	echo "** data read during degraded mode: OK"

	# Degrade a parity OST instead
	ec_reactivate_ost ${safe_osts[0]}
	(( ${#parity_osts[@]} >= 1 )) ||
		skip_env "need >= 1 parity OST"

	ec_deactivate_ost ${parity_osts[0]}
	cancel_lru_locks osc

	# Stat should succeed when only parity is down
	sz=$(stat -c %s $tf)
	(( sz == 8 * 1024 * 1024 )) ||
		error "size $sz != 8M after parity degrade"

	$LFS getstripe $tf > /dev/null ||
		error "getstripe failed with parity down"

	# With only parity unreadable the data stripes are all intact, so
	# the read must succeed without reconstructing anything.
	got=$(md5sum $tf | awk '{print $1}') ||
		error "md5sum failed with parity down"
	[[ "$sum" == "$got" ]] ||
		error "read with parity down returned wrong data:" \
			"$sum vs $got"

	echo "** stat/getattr during degraded mode: OK"
}
run_test 75a "EC stat/getattr during degraded mode"

test_75b() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"
	local iterations=50
	local fail_count=0

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "need >= 1 safe data OST"

	local i sum got
	for ((i = 0; i < iterations; i++)); do
		dd if=/dev/urandom of=$tf bs=1M count=4 \
			conv=notrunc 2>/dev/null ||
			error "dd failed iter $i"
		$LFS mirror resync $tf 2>/dev/null ||
			error "mirror resync failed"

		sum=$(md5sum $tf | awk '{print $1}')

		ec_deactivate_ost ${safe_osts[0]}
		cancel_lru_locks osc

		got=$(md5sum $tf | awk '{print $1}')
		ec_reactivate_ost ${safe_osts[0]}

		if [[ "$sum" != "$got" ]]; then
			((fail_count++))
			echo "FAIL iteration $i: $sum != $got"
		fi
	done

	(( fail_count == 0 )) ||
		error "$fail_count/$iterations iterations " \
			"had checksum mismatch"
	echo "** $iterations stress iterations passed"
}
run_test 75b "EC stress/repeatability degraded read loop"

test_75c() {
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"
	enable_ec

	local tdir=$DIR/$tdir
	test_mkdir $tdir
	stack_trap "rm -rf $tdir"

	# Create a PFL file with 2 EC components that
	# use overlapping OSTs via stripe rotation
	local tf=$tdir/$tfile
	$LFS setstripe \
		-E 4M -S 1M -c 4 --ec 4+2 \
		-E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "PFL setstripe failed"

	dd if=/dev/urandom of=$tf bs=1M count=12 ||
		error "dd failed"
	$LFS mirror resync $tf 2>/dev/null ||
		error "mirror resync failed"

	# Verify both components are present
	local ncomp
	ncomp=$($LFS getstripe --component-count $tf)
	(( ncomp >= 4 )) ||
		error "expected >= 4 components, got $ncomp"

	# Degrade: pick an OST in the first component
	ec_classify_osts $tf
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "need >= 1 safe data OST"

	local sum
	sum=$(md5sum $tf | awk '{print $1}')

	ec_deactivate_ost ${safe_osts[0]}
	cancel_lru_locks osc

	local got
	got=$(md5sum $tf | awk '{print $1}')
	[[ "$sum" == "$got" ]] ||
		error "PFL rotation collision: $sum != $got"

	echo "** PFL stripe rotation collision: data OK"
}
run_test 75c "EC stripe rotation collision in PFL"

test_75d() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"
	dd if=/dev/urandom of=$tf bs=1M count=8 ||
		error "dd failed"
	$LFS mirror resync $tf ||
		error "mirror resync failed"

	# mirror verify must succeed on a healthy file
	$LFS mirror verify $tf ||
		error "mirror verify failed on healthy file"

	local sum=$(md5sum $tf | awk '{print $1}')

	ec_classify_osts $tf
	(( ${#parity_osts[@]} >= 1 )) ||
		skip_env "need >= 1 parity OST"
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "need >= 1 safe data OST"

	# Test 1: SEEK_DATA/SEEK_HOLE with a data OST down.  This asserts
	# that LSEEK still returns the right answers while a stripe is
	# unreadable; it does not by itself prove the lov_lock_enqueue
	# degraded-stripe path ran, since a fully allocated file can be
	# answered without consulting every stripe.  A sparse file is used
	# so the offsets below have to come from the OSTs, and the seek
	# starts past stripe 0 so it crosses the degraded stripe.
	#
	# ZFS lseek does not report holes reliably for dirty data, as test
	# 12b describes, so neither the resync nor the offsets below can be
	# asserted there and only the mirror verify below runs (LU-14217).
	if [[ "$ost1_FSTYPE" != "zfs" ]]; then
		local tfs=$DIR/$tfile.sparse

		$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tfs ||
			error "setstripe sparse failed"
		stack_trap "rm -f $tfs"
		dd if=/dev/urandom of=$tfs bs=1M count=1 seek=5 \
			conv=notrunc || error "sparse dd failed"
		$LFS mirror resync $tfs || error "resync sparse failed"

		echo "** Test SEEK_DATA with data OST down"
		ec_deactivate_ost ${safe_osts[0]}
		cancel_lru_locks osc

		local data_off hole_off

		data_off=$($LUSTRE/tests/lseek_test -d 1048576 $tfs) ||
			error "SEEK_DATA failed with data OST down"
		(( data_off == 5 * 1024 * 1024 )) ||
			error "SEEK_DATA returned $data_off, expected 5M"

		hole_off=$($LUSTRE/tests/lseek_test -l 0 $tfs) ||
			error "SEEK_HOLE failed with data OST down"
		(( hole_off == 0 )) ||
			error "SEEK_HOLE returned $hole_off, expected 0"

		ec_reactivate_ost ${safe_osts[0]}
	fi

	# Test 2: parity OST down — verify should
	# detect unreadable parity but not crash/hang
	echo "** Test mirror verify with parity OST down"
	ec_deactivate_ost ${parity_osts[0]}
	cancel_lru_locks osc

	# Verify cannot read the parity objects, so it is allowed to fail;
	# rc is reported rather than asserted on.  What must hold is that it
	# returns instead of hanging, and leaves the file itself intact --
	# that is what the checksum below actually checks.
	local out rc
	out=$($LFS mirror verify $tf 2>&1)
	rc=$?
	echo "mirror verify (parity down): rc=$rc"
	echo "$out" | head -5

	ec_reactivate_ost ${parity_osts[0]}
	cancel_lru_locks osc

	local sum_after=$(md5sum $tf | awk '{print $1}')
	[[ "$sum" == "$sum_after" ]] ||
		error "mirror verify with parity down changed the data:" \
			"$sum vs $sum_after"

	# Note: mirror verify with data OST down is
	# currently blocked by an O_DIRECT bug
	# (LBUGs in osc_req_attr_set for uncovered
	# pages). When that is fixed, add a test here.
	echo "** mirror verify degraded tests: done"
}
run_test 75d "EC lfs mirror verify in degraded mode"

test_75e() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tdir=$DIR/$tdir
	test_mkdir $tdir
	stack_trap "rm -rf $tdir"

	# Set EC default on directory
	$LFS setstripe -E eof -S 1M -c 4 --ec 4+2 $tdir ||
		error "setstripe on dir failed"

	# Create files that inherit directory layout
	local i tf sum got
	for ((i = 0; i < 5; i++)); do
		tf=$tdir/file.$i
		dd if=/dev/urandom of=$tf bs=1M count=4 \
			2>/dev/null ||
			error "dd failed for file.$i"
	done

	# Verify files inherited EC layout
	for ((i = 0; i < 5; i++)); do
		tf=$tdir/file.$i
		local cstripe
		cstripe=$($LFS getstripe $tf |
			awk '/lcme_cstripe_count:/ {print $2}')
		(( cstripe == 2 )) ||
			error "file.$i: cstripe $cstripe != 2"
	done

	# Resync all
	for ((i = 0; i < 5; i++)); do
		$LFS mirror resync $tdir/file.$i 2>/dev/null ||
			error "mirror resync failed"
	done

	# Degrade and verify all files still readable
	ec_classify_osts $tdir/file.0
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "need >= 1 safe data OST"

	ec_deactivate_ost ${safe_osts[0]}
	cancel_lru_locks osc

	for ((i = 0; i < 5; i++)); do
		tf=$tdir/file.$i
		md5sum $tf > /dev/null 2>&1 ||
			error "read failed on file.$i " \
				"with OST down"
	done

	echo "** dir-inherited EC recovery: all OK"
}
run_test 75e "EC directory-inherited layout recovery"

test_75f() {
	(( OSTCOUNT >= 6 )) || skip_env "needs >= 6 OSTs"
	enable_ec

	local tdir=$DIR/$tdir
	test_mkdir $tdir
	stack_trap "rm -rf $tdir"

	# Create multiple EC files — stripe rotation
	# means each file starts on a different OST
	local nfiles=8
	local i tf
	for ((i = 0; i < nfiles; i++)); do
		tf=$tdir/file.$i
		$LFS setstripe -E eof -S 1M -c 4 \
			--ec 4+2 $tf ||
			error "setstripe file.$i failed"
		dd if=/dev/urandom of=$tf bs=1M count=4 \
			2>/dev/null ||
			error "dd file.$i failed"
		$LFS mirror resync $tf 2>/dev/null ||
			error "mirror resync failed"
	done

	# Collect md5sums before degrade
	local -A sums
	for ((i = 0; i < nfiles; i++)); do
		sums[$i]=$(md5sum $tdir/file.$i |
			awk '{print $1}')
	done

	# Degrade an OST
	ec_classify_osts $tdir/file.0
	(( ${#safe_osts[@]} >= 1 )) ||
		skip_env "need >= 1 safe data OST"

	ec_deactivate_ost ${safe_osts[0]}
	cancel_lru_locks osc

	# All files should be readable via EC recovery
	local fail=0
	for ((i = 0; i < nfiles; i++)); do
		local got
		got=$(md5sum $tdir/file.$i 2>&1 |
			awk '{print $1}')
		if [[ "${sums[$i]}" != "$got" ]]; then
			echo "FAIL file.$i: expected " \
				"${sums[$i]} got $got"
			((fail++))
		fi
	done

	(( fail == 0 )) ||
		error "$fail/$nfiles files had " \
			"checksum mismatch"
	echo "** stripe rotation across $nfiles files: OK"
}
run_test 75f "EC stripe rotation across files"

complete_test $SECONDS
check_and_cleanup_lustre
exit_status

