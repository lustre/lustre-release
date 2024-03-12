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

check_and_setup_lustre

env_verify()
{
	[[ -x "$MPIRUN" ]] || skip_env "no mpirun program found"
	[[ -x "$MDTEST" ]] || skip_env "no mdtest program found"
	get_mpiuser_id $MPI_USER
	MPI_RUNAS=${MPI_RUNAS:-"runas -u $MPI_USER_UID -g $MPI_USER_GID"}
	$GSS_KRB5 && refresh_krb5_tgt $MPI_USER_UID $MPI_USER_GID $MPI_RUNAS
}

test_1() {
	env_verify
	echo "Small files creation performance test"
	# LU-2600/LU-4108 - Decrease load on zfs
	if [[ "$SLOW" == no && "$mds1_FSTYPE" == zfs ]]; then
		NUM_FILES=10000
	fi
	run_mdtest create-small
}
run_test 1 "small files create/open/delete"

test_2() {
	env_verify
	echo "Large files creation performance test"
	run_mdtest create-large
}
run_test 2 "large files create/open/delete"

test_3() {
	env_verify
	NUM_DIRS=1
	NUM_FILES=200000
	echo "Single directory lookup rate for $NUM_FILES files"
	run_mdtest lookup-single
}
run_test 3 "lookup rate 200k files in single directory"

test_4() {
	env_verify
	NUM_DIRS=100
	NUM_FILES=200000
	echo "Directory lookup rate $NUM_DIRS directories, $((NUM_FILES/NUM_DIRS)) files each"
	run_mdtest lookup-multi
}
run_test 4 "lookup rate 200k files in 100 directories"

test_5a() {
	touch $DIR/$tfile
	for((i=0; i < 20001; i++)) {
		echo "W$((i * 10)), 5"
		[ $i -eq 20000 ] && echo "T5" && continue
	} | flocks_test 6 $DIR/$tfile
	rm -r $DIR/$tfile
}
run_test 5a "enqueue 20k no overlap flocks on same file"

test_5b() {
	touch $DIR/$tfile
	for((i=0; i < 20001; i++)) {
		[ $i -eq 0 ] && echo "W0,99999999" && continue
		echo "R$((i * 10)), 5"
		[ $i -eq 20000 ] && echo "T5" && continue
	} | flocks_test 6 $DIR/$tfile
	rm -r $DIR/$tfile
}
run_test 5b "split a flock 20k times"

test_5c() {
	touch $DIR/$tfile
	for((i=0; i < 20001; i++)) {
		echo "R$((i * 10)), 5"
		[ $i -eq 20000 ] && echo "W0,99999999" && echo "T0" && continue
	} | flocks_test 6 $DIR/$tfile
	rm -r $DIR/$tfile
}
run_test 5c "merge 20k flocks"

test_5d() {
	local v=0

	touch $DIR/$tfile
	for((i=0; i < 20001; i++)) {
		echo "F$i"
		echo "R400, $((100 + v))"
		[ $i -eq 0 -a $v -eq 0 ] && echo "S20100"
		[ $i -eq 20000 ] && {
			echo "T5"
			[ $v -eq 1 ] && break
			v=$((v + 1))
			i=0
		}
	} | flocks_test 6 $DIR/$tfile
	rm -r $DIR/$tfile
}
run_test 5d "Enqueue 20k same range flocks, then expand them"

complete_test $SECONDS
check_and_cleanup_lustre
exit_status
