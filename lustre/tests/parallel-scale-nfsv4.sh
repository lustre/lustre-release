#!/bin/bash
#
#set -vx

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

. $LUSTRE/tests/setup-nfs.sh

# first unmount all the lustre client
cleanup_mount $MOUNT
# mount lustre on mds
lustre_client=$(facet_active_host $SINGLEMDS)
zconf_mount_clients $lustre_client $MOUNT \
    "-o user_xattr,acl,flock,32bitapi" || \
    error "mount lustre on $lustre_client failed"

# setup the nfs
if ! setup_nfs "4" "$MOUNT" "$lustre_client" "$CLIENTS"; then
    error_noexit false "setup nfs failed!"
    cleanup_nfs "$MOUNT" "$lustre_client" "$CLIENTS" || \
        error_noexit false "failed to cleanup nfs"
    if ! zconf_umount_clients $lustre_client $MOUNT force; then
        error_noexit false "failed to umount lustre on $lustre_client"
    elif ! zconf_mount_clients $CLIENTS $MOUNT; then
        error_noexit false "failed to mount lustre after nfs test"
    fi
    check_and_cleanup_lustre
    exit
fi

NFSCLIENT=yes
FAIL_ON_ERROR=false

# common setup
#
MACHINEFILE=${MACHINEFILE:-$TMP/$(basename $0 .sh).machines}
clients=${CLIENTS:-$HOSTNAME}
generate_machine_file $clients $MACHINEFILE || \
    error "Failed to generate machine file"
num_clients=$(get_node_count ${clients//,/ })

# compilbench
#
cbench_DIR=${cbench_DIR:-"/usr/bin"}
cbench_IDIRS=${cbench_IDIRS:-4}
# FIXME: wiki page requirements is 30, do we really need 30 ?
cbench_RUNS=${cbench_RUNS:-4}

if [ "$SLOW" = "no" ]; then
    cbench_IDIRS=2
    cbench_RUNS=2
fi

#
# metabench
#
METABENCH=${METABENCH:-$(which metabench 2> /dev/null || true)}
mbench_NFILES=${mbench_NFILES:-30400}
[ "$SLOW" = "no" ] && mbench_NFILES=10000
# threads per client
mbench_THREADS=${mbench_THREADS:-4}

#
# connectathon
#
cnt_DIR=${cnt_DIR:-""}
cnt_NRUN=${cnt_NRUN:-10}
[ "$SLOW" = "no" ] && cnt_NRUN=2

#
# IOR
#
IOR=${IOR:-$(which IOR 2> /dev/null || true)}
# threads per client
ior_THREADS=${ior_THREADS:-2}
ior_iteration=${ior_iteration:-1}
ior_blockSize=${ior_blockSize:-6} # Gb
ior_xferSize=${ior_xferSize:-2m}
ior_type=${ior_type:-POSIX}
ior_DURATION=${ior_DURATION:-60} # minutes
[ "$SLOW" = "no" ] && ior_DURATION=30

# source the common file after all parameters are set to take affect
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

# cleanup nfs
cleanup_nfs "$MOUNT" "$lustre_client" "$CLIENTS" || \
    error_noexit false "cleanup_nfs failed"
if ! zconf_umount_clients $lustre_client $MOUNT force; then
    error_noexit false "failed to umount lustre on $lustre_client"
elif ! zconf_mount_clients $CLIENTS $MOUNT; then
    error_noexit false "failed to mount lustre after nfs test"
fi

complete $(basename $0) $SECONDS
check_and_cleanup_lustre
exit_status
