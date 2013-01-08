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

. $LUSTRE/tests/setup-nfs.sh

check_and_setup_lustre

# first unmount all the lustre client
cleanup_mount $MOUNT
# mount lustre on mds
lustre_client=$(facet_active_host mds)
[ "$NFSVERSION" = "4" ] && cl_mnt_opt="$MOUNTOPT,32bitapi" || cl_mnt_opt=""
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

test_nfsread_orphan_file() {
    run_nfsread_orphan_file
}
run_test nfsread_orphan_file

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
