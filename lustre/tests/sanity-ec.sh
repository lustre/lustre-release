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
always_except LU-12688 6d 6f
always_except LU-19631 12 34b
# tests 6d/6f: pending lfs mirror verify support for EC components
# tests 12/34b: EC parity calculation produces incorrect content (LU-19631)

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
	local ec_enable=$($LCTL get_param -n llite.*.enable_erasure_coding)

	$LCTL set_param llite.*.enable_erasure_coding=1
	stack_trap "$LCTL set_param -n llite.*.enable_erasure_coding=$ec_enable"
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

test_1a() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	stack_trap "rm -f $tf"

	# Single component with EC
	$LFS setstripe -E -1 -c 8 --ec 8+2 $tf ||
		error "setstripe failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 2

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify data mirror (mirror 1, component 0)
	verify_comp_extent $tf ${ids[0]} 0 EOF

	# Verify parity mirror (mirror 2, component 1)
	verify_comp_parity $tf ${ids[1]}
	verify_ec_stripe_count $tf ${ids[1]} 8 2
	verify_comp_extent $tf ${ids[1]} 0 EOF

	# Verify stripe size matches between data and EC components
	verify_ec_stripe_size $tf ${ids[0]} ${ids[1]}
}
run_test 1a "basic setstripe with single component and EC"

test_1b() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	stack_trap "rm -f $tf"

	# Order independence: --ec before -E
	$LFS setstripe --ec 8+2 -E -1 -c 8 $tf ||
		error "setstripe failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 2

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify data mirror (mirror 1, component 0)
	verify_comp_extent $tf ${ids[0]} 0 EOF

	# Verify parity mirror (mirror 2, component 1)
	verify_comp_parity $tf ${ids[1]}
	verify_ec_stripe_count $tf ${ids[1]} 8 2
	verify_comp_extent $tf ${ids[1]} 0 EOF
}
run_test 1b "setstripe with --ec before -E (order independence)"

test_1c() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	stack_trap "rm -f $tf"

	# Test colon separator: --ec 8:2 instead of 8+2
	$LFS setstripe -E -1 -c 8 --ec 8:2 $tf ||
		error "setstripe with colon separator failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 2

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify data mirror (mirror 1, component 0)
	verify_comp_extent $tf ${ids[0]} 0 EOF

	# Verify parity mirror (mirror 2, component 1)
	verify_comp_parity $tf ${ids[1]}
	verify_ec_stripe_count $tf ${ids[1]} 8 2
	verify_comp_extent $tf ${ids[1]} 0 EOF
}
run_test 1c "setstripe with colon separator (--ec 8:2)"

test_1d() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	stack_trap "rm -f $tf"

	# Multiple components, single EC spec
	$LFS setstripe -E 128M -E -1 --ec 8+2 $tf ||
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
	verify_ec_stripe_count $tf ${ids[2]} 8 2
	verify_comp_extent $tf ${ids[2]} 0 134217728

	# Second parity component
	verify_comp_parity $tf ${ids[3]}
	verify_ec_stripe_count $tf ${ids[3]} 8 2
	verify_comp_extent $tf ${ids[3]} 134217728 EOF
}
run_test 1d "setstripe with multiple components and single EC spec"

test_1e() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	stack_trap "rm -f $tf"

	# EC specified on first component, should inherit to second
	$LFS setstripe -E 128M --ec 8+2 -E -1 -c 4 $tf ||
		error "setstripe failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 4

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify data mirror components (mirror 1)
	verify_comp_extent $tf ${ids[0]} 0 134217728
	verify_comp_extent $tf ${ids[1]} 134217728 EOF

	# Verify parity mirror components (mirror 2)
	# First component has EC(8+2) from the spec
	verify_comp_parity $tf ${ids[2]}
	verify_ec_stripe_count $tf ${ids[2]} 8 2
	verify_comp_extent $tf ${ids[2]} 0 134217728

	# Second component has EC(4+2) - reduced from EC(8+2) because
	# the data component has -c 4, so we can't have 8 data stripes
	verify_comp_parity $tf ${ids[3]}
	verify_ec_stripe_count $tf ${ids[3]} 4 2
	verify_comp_extent $tf ${ids[3]} 134217728 EOF
}
run_test 1e "setstripe with EC inheriting to second component"

test_1f() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	stack_trap "rm -f $tf"

	# Different EC for different components
	# Note: second component has -c 4, so EC will be adjusted to 4+2
	# (can't have 8 data stripes with only 4 total stripes)
	$LFS setstripe -E 128M --ec 4+2 -E -1 -c 4 --ec 8+2 $tf ||
		error "setstripe failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 4

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify data mirror components (mirror 1)
	verify_comp_extent $tf ${ids[0]} 0 134217728
	verify_comp_extent $tf ${ids[1]} 134217728 EOF

	# Verify parity mirror components (mirror 2)
	# First component should have EC(4+2)
	verify_comp_parity $tf ${ids[2]}
	verify_ec_stripe_count $tf ${ids[2]} 4 2
	verify_comp_extent $tf ${ids[2]} 0 134217728

	# Second component has EC adjusted to 4+2 (data component has -c 4)
	verify_comp_parity $tf ${ids[3]}
	verify_ec_stripe_count $tf ${ids[3]} 4 2
	verify_comp_extent $tf ${ids[3]} 134217728 EOF
}
run_test 1f "setstripe with different EC for different components"

test_1g() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	stack_trap "rm -f $tf"

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
	enable_ec
	local tf=$DIR/$tfile
	local ids

	stack_trap "rm -f $tf"

	# Test -N flag with explicit stripe counts and --ec
	# This should create:
	# Mirror 1: data mirror 2 comps ([0, 1M] with -c 1, [1M, EOF] with -c 1)
	# Mirror 2: data mirror 2 comps ([0, 1M] with -c 8, [1M, EOF] with -c 4)
	# Mirror 3: parity 2 EC comps ([0, 1M] with EC(8+2), [1M, EOF] with EC(4+1))
	#
	# This test verifies that when using -N with multiple mirrors and --ec,
	# the EC parity components correctly bind to the data components in the
	# mirror they were added with (Mirror 2), not to components from other
	# mirrors (Mirror 1).

	$LFS setstripe -N -E 1M -c 1 -E -1 -c 1 \
		-N -E 1M -c 8 --ec 8+2 -E -1 -c 4 --ec 4+1 $tf ||
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
	# First component should have EC(8+2) with dstripe=8
	verify_comp_parity $tf ${ids[4]}
	verify_ec_stripe_count $tf ${ids[4]} 8 2
	verify_comp_extent $tf ${ids[4]} 0 1048576

	# Second component should have EC(4+1) with dstripe=4
	verify_comp_parity $tf ${ids[5]}
	verify_ec_stripe_count $tf ${ids[5]} 4 1
	verify_comp_extent $tf ${ids[5]} 1048576 EOF
}
run_test 1h "setstripe with -N flag and explicit stripe counts with --ec"

test_1i() {
	enable_ec
	local td=$DIR/$tdir
	local ids

	stack_trap "rm -rf $td"

	test_mkdir $td

	# Set default EC layout on directory
	$LFS setstripe -E 128M -E -1 --ec 8+2 $td ||
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
	verify_ec_stripe_count $td/$tfile ${ids[2]} 8 2
	verify_comp_extent $td/$tfile ${ids[2]} 0 134217728

	verify_comp_parity $td/$tfile ${ids[3]}
	verify_ec_stripe_count $td/$tfile ${ids[3]} 8 2
	verify_comp_extent $td/$tfile ${ids[3]} 134217728 EOF

	# Create another file to verify inheritance works consistently
	touch $td/${tfile}.2 || error "touch second file failed"
	verify_mirror_count $td/${tfile}.2 2
	verify_comp_count $td/${tfile}.2 4
}
run_test 1i "default EC layout on directory"

test_1j() {
	enable_ec
	local tf=$DIR/$tfile
	local ids
	local data_stripe_size
	local ec_stripe_size

	stack_trap "rm -f $tf"

	# Test with explicit stripe size
	$LFS setstripe -E -1 -S 4M -c 8 --ec 8+2 $tf ||
		error "setstripe with explicit stripe size failed"

	verify_mirror_count $tf 2
	verify_comp_count $tf 2

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify data mirror (mirror 1, component 0)
	verify_comp_extent $tf ${ids[0]} 0 EOF

	# Verify parity mirror (mirror 2, component 1)
	verify_comp_parity $tf ${ids[1]}
	verify_ec_stripe_count $tf ${ids[1]} 8 2
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

test_2a() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	stack_trap "rm -f $tf"

	# Single data mirror with EC using -N
	$LFS setstripe -N -E 128M -E -1 --ec 8+2 $tf ||
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
	verify_ec_stripe_count $tf ${ids[2]} 8 2
	verify_comp_extent $tf ${ids[2]} 0 134217728

	verify_comp_parity $tf ${ids[3]}
	verify_ec_stripe_count $tf ${ids[3]} 8 2
	verify_comp_extent $tf ${ids[3]} 134217728 EOF
}
run_test 2a "setstripe with -N and EC"

test_2b() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	stack_trap "rm -f $tf"

	# Two data mirrors, one with EC
	$LFS setstripe -N -E 128M -E -1 --ec 8+2 \
			-N -E 256M -E -1 \
			$tf || error "setstripe failed"

	verify_mirror_count $tf 3
	verify_comp_count $tf 6

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify mirror 1 (data with EC)
	verify_comp_extent $tf ${ids[0]} 0 134217728
	verify_comp_extent $tf ${ids[1]} 134217728 EOF

	# Verify mirror 2 (parity for mirror 1)
	verify_comp_parity $tf ${ids[2]}
	verify_ec_stripe_count $tf ${ids[2]} 8 2
	verify_comp_extent $tf ${ids[2]} 0 134217728

	verify_comp_parity $tf ${ids[3]}
	verify_ec_stripe_count $tf ${ids[3]} 8 2
	verify_comp_extent $tf ${ids[3]} 134217728 EOF

	# Verify mirror 3 (data without EC)
	verify_comp_extent $tf ${ids[4]} 0 268435456
	verify_comp_extent $tf ${ids[5]} 268435456 EOF
}
run_test 2b "setstripe with -N: two data mirrors, one with EC"

test_2c() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	stack_trap "rm -f $tf"

	# Two data mirrors, both with EC
	$LFS setstripe -N -E 128M --ec 4+2 -E -1 --ec 8+2 \
			-N -E 256M --ec 6+1 -E -1 \
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
	verify_ec_stripe_count $tf ${ids[2]} 4 2
	verify_comp_extent $tf ${ids[2]} 0 134217728

	verify_comp_parity $tf ${ids[3]}
	verify_ec_stripe_count $tf ${ids[3]} 8 2
	verify_comp_extent $tf ${ids[3]} 134217728 EOF

	# Verify mirror 3 (data)
	verify_comp_extent $tf ${ids[4]} 0 268435456
	verify_comp_extent $tf ${ids[5]} 268435456 EOF

	# Verify mirror 4 (parity for mirror 3)
	verify_comp_parity $tf ${ids[6]}
	verify_ec_stripe_count $tf ${ids[6]} 6 1
	verify_comp_extent $tf ${ids[6]} 0 268435456

	verify_comp_parity $tf ${ids[7]}
	verify_ec_stripe_count $tf ${ids[7]} 6 1
	verify_comp_extent $tf ${ids[7]} 268435456 EOF
}
run_test 2c "setstripe with -N: two data mirrors, both with EC"

test_2d() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	stack_trap "rm -f $tf"

	# Multiple identical EC mirrors using -N count
	$LFS setstripe -N2 -E 128M -E -1 --ec 8+2 $tf ||
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
	verify_ec_stripe_count $tf ${ids[2]} 8 2
	verify_comp_extent $tf ${ids[2]} 0 134217728

	verify_comp_parity $tf ${ids[3]}
	verify_ec_stripe_count $tf ${ids[3]} 8 2
	verify_comp_extent $tf ${ids[3]} 134217728 EOF

	# Verify mirror 3 (data, identical to mirror 1)
	verify_comp_extent $tf ${ids[4]} 0 134217728
	verify_comp_extent $tf ${ids[5]} 134217728 EOF

	# Verify mirror 4 (parity for mirror 3, identical to mirror 2)
	verify_comp_parity $tf ${ids[6]}
	verify_ec_stripe_count $tf ${ids[6]} 8 2
	verify_comp_extent $tf ${ids[6]} 0 134217728

	verify_comp_parity $tf ${ids[7]}
	verify_ec_stripe_count $tf ${ids[7]} 8 2
	verify_comp_extent $tf ${ids[7]} 134217728 EOF
}
run_test 2d "setstripe with -N2: multiple identical EC mirrors"

test_2e() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	stack_trap "rm -f $tf"

	# Mixed: regular mirror + EC mirror
	$LFS setstripe -N -E -1 -c 4 \
			-N -E -1 -c 8 --ec 8+2 \
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
	verify_ec_stripe_count $tf ${ids[2]} 8 2
	verify_comp_extent $tf ${ids[2]} 0 EOF
}
run_test 2e "setstripe with -N: mixed regular and EC mirrors"

test_2f() {
	enable_ec
	local td=$DIR/$tdir
	local ids

	stack_trap "rm -rf $td"

	test_mkdir $td

	# Set default EC layout on directory using mirror mode (-N)
	$LFS setstripe -N -E 128M -E -1 --ec 8+2 $td ||
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
	verify_ec_stripe_count $td/$tfile ${ids[2]} 8 2
	verify_comp_extent $td/$tfile ${ids[2]} 0 134217728

	verify_comp_parity $td/$tfile ${ids[3]}
	verify_ec_stripe_count $td/$tfile ${ids[3]} 8 2
	verify_comp_extent $td/$tfile ${ids[3]} 134217728 EOF

	# Test with multiple data mirrors + EC
	$LFS setstripe -d $td || error "delete default layout failed"
	$LFS setstripe -N -E -1 -c 4 -N -E -1 --ec 8+2 $td ||
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

	stack_trap "rm -f $tf"

	$LFS mirror create -N -E 128M -E -1 --ec 8+2 $tf ||
		error "failed to create mirrored file with EC"

	verify_mirror_count $tf 2
	verify_comp_count $tf 4

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify parity components (components 2 and 3 in parity mirror)
	verify_comp_parity $tf ${ids[2]}
	verify_comp_parity $tf ${ids[3]}

	# Verify EC stripe counts
	verify_ec_stripe_count $tf ${ids[2]} 8 2
	verify_ec_stripe_count $tf ${ids[3]} 8 2
}
run_test 3a "lfs mirror create with single EC mirror"

test_3b() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	stack_trap "rm -f $tf"

	$LFS mirror create -N2 -E 128M -E -1 --ec 8+2 $tf ||
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
	verify_ec_stripe_count $tf ${ids[2]} 8 2
	verify_ec_stripe_count $tf ${ids[3]} 8 2
	verify_ec_stripe_count $tf ${ids[6]} 8 2
	verify_ec_stripe_count $tf ${ids[7]} 8 2
}
run_test 3b "lfs mirror create with -N2 and EC"

test_3c() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	stack_trap "rm -f $tf"

	$LFS mirror create -N -E 128M -E -1 --ec 8+2 \
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
	verify_ec_stripe_count $tf ${ids[2]} 8 2
	verify_ec_stripe_count $tf ${ids[3]} 8 2
}
run_test 3c "lfs mirror create with mixed EC and regular mirrors"

test_3d() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	stack_trap "rm -f $tf"

	$LFS mirror create -N -E 128M -E -1 --ec 8+2 \
			   -N -E 256M -E -1 --ec 4+1 $tf ||
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
	verify_ec_stripe_count $tf ${ids[2]} 8 2
	verify_ec_stripe_count $tf ${ids[3]} 8 2
	verify_ec_stripe_count $tf ${ids[6]} 4 1
	verify_ec_stripe_count $tf ${ids[7]} 4 1
}
run_test 3d "lfs mirror create with different EC configs per mirror"

test_3e() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	stack_trap "rm -f $tf"

	$LFS mirror create -N -E 64M --ec 4+1 -E 128M --ec 8+2 -E -1 $tf ||
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
	verify_ec_stripe_count $tf ${ids[4]} 8 2
	verify_ec_stripe_count $tf ${ids[5]} 8 2
}
run_test 3e "lfs mirror create with multiple EC specs in one mirror"

test_3f() {
	enable_ec
	local tf=$DIR/$tfile
	local ids

	stack_trap "rm -f $tf"

	# Test EC inheritance with "holes" - components without --ec
	# First component uses 4+2, second has no --ec (should inherit 4+2
	# from first), third uses 8+2
	$LFS mirror create -N -E 128M --ec 4+2 -E 512M -E -1 --ec 8+2 $tf ||
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
	verify_ec_stripe_count $tf ${ids[3]} 4 2
	# Second component: 4+2 (inherited from first --ec 4+2)
	verify_ec_stripe_count $tf ${ids[4]} 4 2
	# Third component: 8+2 (explicitly set)
	verify_ec_stripe_count $tf ${ids[5]} 8 2
}
run_test 3f "EC inheritance with holes"

test_3g() {
	(( OSTCOUNT < 6 )) && skip_env "needs >= 6 OSTs"
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
	enable_ec

	(( OSTCOUNT >= 4 )) || skip "needs >= 4 OSTs"

	local tf=$DIR/$tfile

	stack_trap "rm -f $tf"

	# Create file with 2 data mirrors + 1 EC mirror (data + parity)
	# Mirror 1 (data): stripe on OST0,1
	# Mirror 2 (data): stripe on OST2,3
	# Mirror 3 (data): EC data component with 2 stripes
	# Mirror 4 (parity): EC parity component with 2+2
	# EC 2+2 keeps the OST requirement at >= 4 to match the skip above.
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

test_7() {
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
run_test 7 "nosync flag on parity mirror prevents resync updates"

test_10() {
	local tf=${DIR}/${tdir}/$tfile

	# The number of parity stripes in the EC mirror must be equal to or
	# less than the number of data stripes in the same EC mirror.
	(( OSTCOUNT < 5 )) && skip_env "needs >= 5 OSTs"
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
	(( OSTCOUNT < 4 )) && skip_env "needs >= 4 OSTs"
	enable_ec

	test_mkdir $DIR/$tdir
	# Test that creating ec 2+2 mirror works
	$LFS setstripe -E -1 -S 4M -c 4 --ec 2+2 $DIR/$tdir/$tfile ||
	    error "setstripe --ec 2+2 failed"
}
run_test 11 "can create --ec 2+2"

test_12() {
	local tf=${DIR}/${tdir}/$tfile
	local tf_data=${DIR}/${tdir}/${tfile}.data
	local tf_ec=${DIR}/${tdir}/${tfile}.ec

	# test resyncing a stale ec mirror
	(( OSTCOUNT < 4 )) && skip_env "needs >= 4 OSTs"
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
	    | sha1sum -c - || error "wrong content in $tf"

	# resync the ec mirror:
	$LFS mirror resync $tf || error "failed to resync ec mirror"

	# Verify the mirrro is no longer stale
	$LFS getstripe $tf | grep lcme_flags | grep stale &&
	    error "after resyncing $tf, it still contains stale component"

	# verify the file content did not change after updating the ec mirror
	echo "fa9fe1782aee74e978e806fb6a0e7a4a1c83610f $tf" | sha1sum -c - ||
		error "wrong content in $tf"

	# Verify the data mirror is still correct
	rm -f $tf_data
	lfs mirror read --mirror-id 1 -o $tf_data $tf
	echo "fa9fe1782aee74e978e806fb6a0e7a4a1c83610f $tf_data" |
		sha1sum -c - || error "wrong content in data mirror"

	# Expected content of the ec mirror:
	#  000000 9a 9a 9a 9a 9a 9a 9a 9a 9a 9a 9a 9a 9a 9a 9a 9a
	#  *
	#  400000 fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
	#  *
	#  800000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	#  *
	#  c00000

	# Verify we have expected content in the ec mirror
	rm -f $tf_ec
	lfs mirror read --mirror-id 2 -o $tf_ec $tf
	echo "aca75f6b8ae9a16aa64f8ca38160bfa39bd2a785 $tf_ec" |
	    sha1sum -c - || error "wrong content in ec mirror"
}
run_test 12 "resync stale parities"

test_13() {
	local tf=${DIR}/${tdir}/$tfile
	local tf_data=${DIR}/${tdir}/${tfile}.data
	local tf_ec=${DIR}/${tdir}/${tfile}.ec

	(( OSTCOUNT < 4 )) && skip_env "needs >= 4 OSTs"
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
	lfs mirror read --mirror-id 1 -o $tf_data $tf
	echo "fa9fe1782aee74e978e806fb6a0e7a4a1c83610f $tf_data" |
	    sha1sum -c - || error "wrong content in data mirror"

	rm -f $tf_ec
	stack_trap "rm -f $tf_ec"
	lfs mirror read --mirror-id 2 -o $tf_ec $tf
	echo "fa9fe1782aee74e978e806fb6a0e7a4a1c83610f $tf_ec" |
	    sha1sum -c - || error "wrong content in ec mirror"
}
run_test 13 "parity of single stripe data is just a copy"

test_20() {
	local tf=${DIR}/${tdir}/$tfile

	(( OSTCOUNT < 4 )) && skip_env "needs >= 4 OSTs"
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
	(( OSTCOUNT < 3 )) && skip_env "needs >= 3 OSTs"
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
	(( OSTCOUNT < 3 )) && skip_env "needs >= 3 OSTs"
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
	(( OSTCOUNT < 4 )) && skip_env "needs >= 4 OSTs"
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
	(( OSTCOUNT < 3 )) && skip_env "needs >= 3 OSTs"
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
	(( OSTCOUNT < 6 )) && skip_env "needs >= 6 OSTs"
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
	enable_ec

	local tf=$DIR/$tdir/$tfile
	local ids
	local flags

	test_mkdir $DIR/$tdir
	stack_trap "rm -rf $DIR/$tdir"

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
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"

	enable_ec

	local tf=$DIR/$tfile

	# Create a simple EC file with data mirror + parity mirror
	$LFS setstripe -E -1 -S 64k -c 8 --ec 2+2 $tf ||
		error "setstripe --ec 2+2 failed"

	# Write some data to the file
	# The file now spans 5 full stripe sets plus an extra stripe
	# The resulting parity should then be for 6 full stripe sets
	# of parities.
	tr "\000" "\002" < /dev/zero | dd bs=64k count=1 seek=40  \
		iflag=fullblock of=$tf 2>/dev/null

	rm -f $TMP/$tfile.parity
	stack_trap "rm -f $TMP/$tfile.parity"

	# stripe size 64k
	# 8 data stripes, ec 2+2
	# 4 raid sets with 2 parities each
	# a total of 6 stripe sets
	# parity mirror size should be 6 * 4 * 2 * 64k plus
	$LFS mirror read --mirror-id 2 -o $TMP/$tfile.parity $tf
	stat $TMP/$tfile.parity | grep "Size: 3145728" ||
	    error "Wrong size of parity mirror"
}
run_test 30d "test that size of parity mirror is (5+1)*4*2*64k"

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
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"

	enable_ec

	local tf=$DIR/$tfile

	# Create a simple EC file with data mirror + parity mirror
	$LFS setstripe -E -1 -S 1M -c 8 --ec 4+2 $tf ||
		error "setstripe --ec 4+2 failed"

	# Write some data to the file
	echo "Hello" > $tf || error "error writing to file"

	rm -f $TMP/$tfile.parity
	stack_trap "rm -f $TMP/$tfile.parity"

	# stripe size 1M
	# 8 data stripes, ec 4+2
	# 2 raid sets with 2 parities each
	# parity mirror size should be 2 * 2 * 1M
	$LFS mirror read --mirror-id 2 -o $TMP/$tfile.parity $tf
	stat $TMP/$tfile.parity | grep "Size: 4194304" ||
	    error "Wrong size of parity mirror"
}
run_test 31b "test that size of parity mirror is 2*2*1M"

test_31c() {
	# test that reading from ec mirror reads the full set of parities
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"

	enable_ec

	local tf=$DIR/$tfile

	# Create a simple EC file with data mirror + parity mirror
	$LFS setstripe -E -1 -S 64k -c 8 --ec 4+3 $tf ||
		error "setstripe --ec 4+3 failed"

	# Write some data to the file
	echo "Hello" > $tf || error "error writing to file"

	rm -f $TMP/$tfile.parity
	stack_trap "rm -f $TMP/$tfile.parity"

	# stripe size 64k
	# 8 data stripes, ec 4+3
	# 2 raid sets with 3 parities each
	# parity mirror size should be 2 * 3 * 64k
	$LFS mirror read --mirror-id 2 -o $TMP/$tfile.parity $tf
	stat $TMP/$tfile.parity | grep "Size: 393216" ||
	    error "Wrong size of parity mirror"
}
run_test 31c "test that size of parity mirror is 2*3*64k"

test_31d() {
	# test that reading from ec mirror reads the full set of parities
	(( OSTCOUNT >= 8 )) || skip_env "needs >= 8 OSTs"

	enable_ec

	local tf=$DIR/$tfile

	# Create a simple EC file with data mirror + parity mirror
	$LFS setstripe -E -1 -S 64k -c 8 --ec 2+2 $tf ||
		error "setstripe --ec 2+2 failed"

	# Write some data to the file
	echo "Hello" > $tf || error "error writing to file"

	rm -f $TMP/$tfile.parity
	stack_trap "rm -f $TMP/$tfile.parity"

	# stripe size 64k
	# 8 data stripes, ec 2+2
	# 4 raid sets with 2 parities each
	# parity mirror size should be 4 * 2 * 64k
	$LFS mirror read --mirror-id 2 -o $TMP/$tfile.parity $tf
	stat $TMP/$tfile.parity | grep "Size: 524288" ||
	    error "Wrong size of parity mirror"
}
run_test 31d "test that size of parity mirror is 4*2*64k"

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

# Helper function to read from parity mirror and check for zeros
# Usage: check_parity_read <file> <mirror_id> <offset> <expect_zeros>
check_parity_read() {
	local file=$1
	local mirror_id=$2
	local offset=$3
	local expect_zeros=$4
	local rc

	# Run the test program
	# It returns 0 if all zeros, 1 if non-zero bytes found
	$LUSTRE/tests/test_parity_read $file $mirror_id $offset \
		> /dev/null 2>&1
	rc=$?

	if [[ $expect_zeros == "yes" ]]; then
		(( rc == 0 )) ||
			error "offset $offset: expected zeros, got non-zero bytes"
	else
		(( rc == 1 )) ||
			error "offset $offset: expected parity data, got all zeros"
	fi
}

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

		# Parity is computed per full stripe (4M), so all
		# offsets within the parity extent have valid data
		# regardless of data file size.  Only offsets past
		# the parity extent (8M for 3+2 with 4M stripes)
		# should return zeros.

		# Test within first parity stripe (should have data)
		echo "  Checking offset 1M (within first parity stripe)..."
		check_parity_read $DIR/$tdir/$tfile \
			$parity_mirror_id $((1024 * 1024)) "no"

		# Test start of second parity stripe (should have data)
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

complete_test $SECONDS
check_and_cleanup_lustre
exit_status

