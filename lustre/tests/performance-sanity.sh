#!/bin/bash
set -e

TESTNAME=$(basename $0 .sh)
LOG=${LOG:-"$TMP/${TESTNAME}.log"}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
init_logging

ALWAYS_EXCEPT="$PERFORMANCE_SANITY_EXCEPT "
build_test_filter

[ -x "$MDSRATE" ] || FAIL_ON_ERROR=true error "No mdsrate program. Aborting."
which mpirun > /dev/null 2>&1 ||
	FAIL_ON_ERROR=true error "No mpirun program. Aborting."

get_mpiuser_id $MPI_USER
MPI_RUNAS=${MPI_RUNAS:-"runas -u $MPI_USER_UID -g $MPI_USER_GID"}
$GSS_KRB5 && refresh_krb5_tgt $MPI_USER_UID $MPI_USER_GID $MPI_RUNAS

# mdsrate-create-small
test_3() {
    echo "File creation performance tests for file objects"
    bash mdsrate-create-small.sh
}
run_test 3 "small file create/open/delete ======"

# mdsrate-create-large
test_4() {
	# LU-2600/LU-4108 - Decrease load on zfs
	[ "$SLOW" = no -a "$mds1_FSTYPE" = zfs ] &&
		NUM_FILES=10000
	echo "Large file creation performance"
	bash mdsrate-create-large.sh
}
run_test 4 "large file create/open/delete"

# mdsrate-lookup-1dir
test_5() {
    echo "Single directory lookup retrieval rate"
    bash mdsrate-lookup-1dir.sh
}
run_test 5 "lookup rate 10M file dir ======"

# mdsrate-lookup-10dir
test_6() {
    echo "Directory lookup retrieval rate 10 directories, 1 million files each"
    bash mdsrate-lookup-10dirs.sh
}
run_test 6 "lookup rate 10M file 10 dir ======"

# mdsrate-stat-small
test_7() {
    echo "File attribute retrieval rate for small file creation"
    bash mdsrate-stat-small.sh
}
run_test 7 "getattr small file ======"

# mdsrate-stat-large
test_8() {
    echo "File attribute retrieval rate for large file creation"
    bash mdsrate-stat-large.sh
}
run_test 8 "getattr large files ======"

complete $SECONDS
check_and_cleanup_lustre
[ -f "$LOG" ] && cat $LOG || true
exit_status
