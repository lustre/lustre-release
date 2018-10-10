#!/bin/bash
#
#set -vx

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

# bug number for skipped test:  LU-9429
     ALWAYS_EXCEPT="            parallel_grouplock  $PARALLEL_SCALE_EXCEPT "

if [ $(facet_fstype $SINGLEMDS) = zfs -o $(facet_fstype "ost1") = zfs ]; then
	ZFSSLOW=$SLOW
	SLOW=no

	cbench_IDIRS=${cbench_IDIRS:-1}
	cbench_RUNS=${cbench_RUNS:-1}

	mdtest_nFiles=${mdtest_nFiles:-"10000"}
	statahead_NUMFILES=${statahead_NUMFILES:-100000}
fi

# common setup
MACHINEFILE=${MACHINEFILE:-$TMP/$(basename $0 .sh).machines}
clients=${CLIENTS:-$HOSTNAME}
generate_machine_file $clients $MACHINEFILE ||
    error "Failed to generate machine file"
num_clients=$(get_node_count ${clients//,/ })

# compilbench
if [ "$SLOW" = "no" ]; then
	cbench_IDIRS=${cbench_IDIRS:-2}
	cbench_RUNS=${cbench_RUNS:-2}
fi

# metabench
[ "$SLOW" = "no" ] && mbench_NFILES=${mbench_NFILES:-10000}

# simul
[ "$SLOW" = "no" ] && simul_REP=${simul_REP:-2}

# connectathon
[ "$SLOW" = "no" ] && cnt_NRUN=${cnt_NRUN:-2}

# cascading rw
[ "$SLOW" = "no" ] && casc_REP=${casc_REP:-10}

# IOR
[ "$SLOW" = "no" ] && ior_DURATION=${ior_DURATION:-5}

# write_append_truncate
[ "$SLOW" = "no" ] && write_REP=${write_REP:-100}

# write_disjoint
[ "$SLOW" = "no" ] && wdisjoint_REP=${wdisjoint_REP:-100}

# fs_test
if [ "$SLOW" = "no" ]; then
	fs_test_ndirs=${fs_test_ndirs:-10000}
	fs_test_nobj=${fs_test_nobj:-2}
fi

# xdd
[ "$SLOW" = "no" ] && xdd_passes=${xdd_passes:-15}

. $LUSTRE/tests/functions.sh

build_test_filter
check_and_setup_lustre

get_mpiuser_id $MPI_USER
MPI_RUNAS=${MPI_RUNAS:-"runas -u $MPI_USER_UID -g $MPI_USER_GID"}
$GSS_KRB5 && refresh_krb5_tgt $MPI_USER_UID $MPI_USER_GID $MPI_RUNAS

test_compilebench() {
    run_compilebench
}
run_test compilebench "compilebench"

test_metabench() {
    run_metabench
}
run_test metabench "metabench"

test_simul() {
    run_simul
}
run_test simul "simul"

test_mdtestssf() {
    run_mdtest "ssf"
}
run_test mdtestssf "mdtestssf"

test_mdtestfpp() {
    run_mdtest "fpp"
}
run_test mdtestfpp "mdtestfpp"

test_connectathon() {
    run_connectathon
}
run_test connectathon "connectathon"

test_iorssf() {
    run_ior "ssf"
}
run_test iorssf "iorssf"

test_iorfpp() {
    run_ior "fpp"
}
run_test iorfpp "iorfpp"

test_ior_mdtest_parallel_ssf() {
	ior_mdtest_parallel "ssf"
}
run_test ior_mdtest_parallel_ssf "iormdtestssf"

test_ior_mdtest_parallel_fpp() {
	ior_mdtest_parallel "fpp"
}
run_test ior_mdtest_parallel_fpp "iormdtestfpp"

test_mib() {
    run_mib
}
run_test mib "mib"

test_cascading_rw() {
    run_cascading_rw
}
run_test cascading_rw "cascading_rw"

test_write_append_truncate() {
    run_write_append_truncate
}
run_test write_append_truncate "write_append_truncate"

# Argument is chunk size limit, the upper bound on write size
test_write_disjoint() {
    run_write_disjoint 123456
}
run_test write_disjoint "write_disjoint"

# Make sure to exercise the tiny write code
test_write_disjoint_tiny() {
	run_write_disjoint 16384
}
run_test write_disjoint_tiny "write_disjoint_tiny"

test_parallel_grouplock() {
    run_parallel_grouplock
}
run_test parallel_grouplock "parallel_grouplock"

test_statahead () {
    run_statahead
}
run_test statahead "statahead test, multiple clients"

test_rr_alloc () {
	run_rr_alloc
}
run_test rr_alloc "Checking even file distribution over OSTs in RR policy"

test_fs_test () {
	run_fs_test
}
run_test fs_test "fs_test"

test_fio () {
	run_fio
}
run_test fio "fio"

test_xdd () {
	run_xdd
}
run_test xdd "xdd"

[ $(facet_fstype $SINGLEMDS) = zfs -o $(facet_fstype "ost1") = zfs ] &&
	SLOW=$ZFSSLOW

complete $SECONDS
check_and_cleanup_lustre
exit_status
