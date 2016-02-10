#!/bin/bash
#
#set -vx

NFSVERSION=${1:-"3"}
LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
# only call init_test_env if this script is called directly
if [[ -z "$TESTSUITE" || "$TESTSUITE" = "$(basename $0 .sh)" ]]; then
    init_test_env $@
fi
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

racer=$LUSTRE/tests/racer/racer.sh
. $LUSTRE/tests/setup-nfs.sh

check_and_setup_lustre

# first unmount all the lustre client
cleanup_mount $MOUNT
# mount lustre on mds
lustre_client=$(facet_active_host $SINGLEMDS)
[ "$NFSVERSION" = "4" ] && cl_mnt_opt="${MOUNT_OPTS:+$MOUNT_OPTS,}32bitapi" ||
    cl_mnt_opt=""
zconf_mount_clients $lustre_client $MOUNT "$cl_mnt_opt" || \
    error "mount lustre on $lustre_client failed"

# setup the nfs
if ! setup_nfs "$NFSVERSION" "$MOUNT" "$lustre_client" "$CLIENTS"; then
    error_noexit false "setup nfs failed!"
    cleanup_nfs "$MOUNT" "$lustre_client" "$CLIENTS" || \
        error_noexit false "failed to cleanup nfs"
    if ! zconf_umount_clients $lustre_client $MOUNT force; then
        error_noexit false "failed to umount lustre on $lustre_client"
    elif ! zconf_mount_clients $CLIENTS $MOUNT; then
        error_noexit false "failed to mount lustre"
    fi
    check_and_cleanup_lustre
    exit
fi

NFSCLIENT=true
FAIL_ON_ERROR=false

# common setup
MACHINEFILE=${MACHINEFILE:-$TMP/$(basename $0 .sh).machines}
clients=${CLIENTS:-$HOSTNAME}
generate_machine_file $clients $MACHINEFILE || \
    error "Failed to generate machine file"
num_clients=$(get_node_count ${clients//,/ })

# compilbench
# Run short iteration in nfs mode
cbench_IDIRS=${cbench_IDIRS:-2}
cbench_RUNS=${cbench_RUNS:-2}

# metabench
# Run quick in nfs mode
mbench_NFILES=${mbench_NFILES:-10000}

# connectathon
[ "$SLOW" = "no" ] && cnt_NRUN=2

# IOR
ior_DURATION=${ior_DURATION:-30}

# source the common file after all parameters are set to take affect
. $LUSTRE/tests/functions.sh

build_test_filter

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

test_racer_on_nfs() {
	$racer $CLIENTS
}
run_test racer_on_nfs "racer on NFS client"

# cleanup nfs
cleanup_nfs "$MOUNT" "$lustre_client" "$CLIENTS" || \
    error_noexit false "cleanup_nfs failed"
if ! zconf_umount_clients $lustre_client $MOUNT force; then
    error_noexit false "failed to umount lustre on $lustre_client"
elif ! zconf_mount_clients $CLIENTS $MOUNT; then
    error_noexit false "failed to mount lustre after nfs test"
fi

complete $SECONDS
check_and_cleanup_lustre
exit_status
