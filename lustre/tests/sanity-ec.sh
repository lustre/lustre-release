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
	enable_ec
	(( $OSTCOUNT >= 2 )) || skip "need >= 2 OSTs" && return

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

	stack_trap "rm -f $tf $TMP/$tfile.mirror"

	# Create EC file with data mirror + parity mirror
	$LFS setstripe -N -E 1M -c 1 -E -1 -c 1 \
		-N -E 1M -c 8 --ec 8+2 -E -1 -c 4 --ec 4+1 $tf ||
		error "create EC file failed"

	# Get component IDs
	ids=($($LFS getstripe $tf | awk '/lcme_id/{print $2}' | tr '\n' ' '))

	# Verify EC parameters on parity components (mirror 3, N3)
	verify_comp_parity $tf ${ids[4]}
	verify_ec_stripe_count $tf ${ids[4]} 8 2
	verify_comp_parity $tf ${ids[5]}
	verify_ec_stripe_count $tf ${ids[5]} 4 1

	# Test mirror write to parity mirror (N3)
	$LFS mirror write -N3 -i /etc/passwd $tf ||
		error "mirror write to parity mirror failed"

	# Verify round-trip: read back what we wrote
	$LFS mirror read -N3 -o $TMP/$tfile.mirror $tf ||
		error "mirror read after write failed"
	cmp $TMP/$tfile.mirror /etc/passwd ||
		error "mirror write/read round-trip failed"
}
run_test 5a "EC mirror read/write commands"

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

complete_test $SECONDS
check_and_cleanup_lustre
exit_status

