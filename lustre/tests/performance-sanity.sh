#!/bin/bash

set -e

TESTNAME=$(basename $0 .sh)
LOG=${LOG:-"$TMP/${TESTNAME}.log"}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env "$@"
init_logging

ALWAYS_EXCEPT="$PERFORMANCE_SANITY_EXCEPT "
build_test_filter

[[ -x "$MPIRUN" ]] || skip_env "no mpirun program found"
[[ -x "$MDTEST" ]] || skip_env "no mdtest program found"

check_and_setup_lustre

get_mpiuser_id $MPI_USER
MPI_RUNAS=${MPI_RUNAS:-"runas -u $MPI_USER_UID -g $MPI_USER_GID"}
$GSS_KRB5 && refresh_krb5_tgt $MPI_USER_UID $MPI_USER_GID $MPI_RUNAS

test_1() {
	echo "Small files creation performance test"
	# LU-2600/LU-4108 - Decrease load on zfs
	if [[ "$SLOW" == no && "$mds1_FSTYPE" == zfs ]]; then
		NUM_FILES=10000
	fi
	run_mdtest create-small
}
run_test 1 "small files create/open/delete"

test_2() {
	echo "Large files creation performance test"
	run_mdtest create-large
}
run_test 2 "large files create/open/delete"

test_3() {
	NUM_DIRS=1
	NUM_FILES=200000
	echo "Single directory lookup rate for $NUM_FILES files"
	run_mdtest lookup-single
}
run_test 3 "lookup rate 200k files in single directory"

test_4() {
	NUM_DIRS=100
	NUM_FILES=200000
	echo "Directory lookup rate $NUM_DIRS directories, $((NUM_FILES/NUM_DIRS)) files each"
	run_mdtest lookup-multi
}
run_test 4 "lookup rate 200k files in 100 directories"

complete_test $SECONDS
check_and_cleanup_lustre
exit_status
