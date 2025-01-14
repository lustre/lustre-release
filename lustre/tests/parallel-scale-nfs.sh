#!/bin/bash

NFSVERSION=${1:-"3"}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
# only call init_test_env if this script is called directly
if [[ -z "$TESTSUITE" || "$TESTSUITE" = "$(basename $0 .sh)" ]]; then
	init_test_env "$@"
else
	. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

fi

init_logging

racer=$LUSTRE/tests/racer/racer.sh
. $LUSTRE/tests/setup-nfs.sh

# lustre client used as nfs server (default is mds node)
LUSTRE_CLIENT_NFSSRV=${LUSTRE_CLIENT_NFSSRV:-$(facet_active_host $SINGLEMDS)}
NFS_SRVMNTPT=${NFS_SRVMNTPT:-$MOUNT}
NFS_CLIENTS=${NFS_CLIENTS:-$CLIENTS}
NFS_CLIENTS=$(exclude_items_from_list $NFS_CLIENTS $LUSTRE_CLIENT_NFSSRV)
NFS_CLIMNTPT=${NFS_CLIMNTPT:-$MOUNT}

[ -z "$NFS_CLIENTS" ] &&
	skip_env "need at least two nodes: nfs server and nfs client"

[ "$NFSVERSION" = "4" ] && cl_mnt_opt="${MOUNT_OPTS:+$MOUNT_OPTS,}32bitapi" ||
	cl_mnt_opt=""

check_and_setup_lustre
$LFS df
TESTDIR=$NFS_CLIMNTPT/d0.$(basename $0 .sh)
mkdir -p $TESTDIR
$LFS setstripe -c -1 $TESTDIR

# first unmount all the lustre clients
cleanup_mount $MOUNT

cleanup_exit () {
	trap 0
	cleanup
	check_and_cleanup_lustre
	exit
}

cleanup () {
	cleanup_nfs "$LUSTRE_CLIENT_NFSSRV" "$NFS_SRVMNTPT" \
			"$NFS_CLIENTS" "$NFS_CLIMNTPT" || \
		error_noexit false "failed to cleanup nfs"
	zconf_umount $LUSTRE_CLIENT_NFSSRV $NFS_SRVMNTPT force ||
		error_noexit false "failed to umount lustre on"\
			"$LUSTRE_CLIENT_NFSSRV"
	# restore lustre mount
	restore_mount $MOUNT ||
		error_noexit false "failed to mount lustre"
}

trap cleanup_exit EXIT SIGHUP SIGINT

zconf_mount $LUSTRE_CLIENT_NFSSRV $NFS_SRVMNTPT "$cl_mnt_opt" ||
	error "mount lustre on $LUSTRE_CLIENT_NFSSRV failed"

# setup the nfs
setup_nfs "$LUSTRE_CLIENT_NFSSRV" "$NFS_SRVMNTPT" "$NFS_CLIENTS" \
		"$NFS_CLIMNTPT" "$NFSVERSION" || \
	error false "setup nfs failed!"

NFSCLIENT=true
FAIL_ON_ERROR=false

# common setup
clients=${NFS_CLIENTS:-$HOSTNAME}
generate_machine_file $clients $MACHINEFILE ||
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

test_1() {
	local src_file=/tmp/testfile.txt
	local dst_file=$TESTDIR/$tfile
	local native_file=$MOUNT/${dst_file#$NFS_CLIMNTPT}
	local mode=644
	local got
	local ver

	ver=$(version_code $(lustre_build_version_node $LUSTRE_CLIENT_NFSSRV))
	(( $ver >= $(version_code v2_15_90-11-g75f55f99a3) )) ||
		skip "Need lustre client version of nfs server (MDS1 by default) >= 2.15.91 for NFS ACL handling fix"

	touch $src_file
	chmod $mode $src_file

	cp -p $src_file $dst_file || error "copy  $src_file->$dst_file failed"

	stat $dst_file
	got="$(stat -c %a $dst_file)"
	[[ "$got" == "$mode" ]] || error "permissions mismatch on '$dst_file'"

	local xattr=system.posix_acl_access
	local lustre_xattrs=$(do_node $LUSTRE_CLIENT_NFSSRV \
		"getfattr -d -m - -e hex $native_file")

	echo $lustre_xattrs
	# If this fails then the mountpoint is non-Lustre or does
	# not exist because we failed to find a native mountpoint
	[[ "$lustre_xattrs" =~ "trusted.link" ]] ||
		error "no trusted.link xattr in '$native_file'"

	[[ "$lustre_xattrs" =~ "$xattr" ]] &&
		error "found unexpected $xattr in '$native_file'"

	do_node $LUSTRE_CLIENT_NFSSRV "stat $native_file"
	got=$(do_node $LUSTRE_CLIENT_NFSSRV "stat -c %a $native_file")
	[[ "$got" == "$mode" ]] || error "permission mismatch on '$native_file'"

	rm -f $src_file $dst_file
}
run_test 1 "test copy with attributes"

mod_strings()
{
	local node=$1
	local mod=$2

	local args=($(do_node $node "cat /sys/module/$mod/sections/__ksymtab /sys/module/$mod/coresize"))

	[[ $((args[1])) > 0 ]] || return

	local min=$((0x7fffffffffffffff))
	while read line; do
		local as=($line)

		val=$((${args[0]}-${as[2]}))
		(($val > 0 && $min > $val)) && ofs=${as[1]} && min=$val
	done <<< $(do_node $node "readelf -l /proc/kcore" | grep LOAD)

	do_node $node "od --strings -A none -j $((ofs+min)) -N ${args[1]} /proc/kcore"
}

test_2() {
	local mp1file=$TESTDIR/file1
	local tmpdir=$(mktemp -d /tmp/nfs-XXXXXX)
	local mp2file=$tmpdir/${mp1file#$NFS_CLIMNTPT}

	# Skip without fixing patch
	mod_strings $LUSTRE_CLIENT_NFSSRV lustre |
		grep 'Invoke locks_copy_lock for NFSv3' ||
		skip "NFSv3 server missing locks_copy_lock()"

	mount -v -t nfs -o nfsvers=$NFSVERSION,async \
		$LUSTRE_CLIENT_NFSSRV:$NFS_SRVMNTPT $tmpdir ||\
		error "Nfs 2nd mount($tmpdir) error"

	local owc=$(do_node $LUSTRE_CLIENT_NFSSRV \
		"dmesg | grep -v 'DEBUG MARKER:' | grep -c 'refcount_t: underflow; use-after-free'")
	(( $owc > 0 )) && do_node $LUSTRE_CLIENT_NFSSRV \
		'echo 1 > /sys/kernel/debug/clear_warn_once'

	touch $mp1file
	local i=0
	for ((i=1; i<=10; i++)) do
		[ $i -eq 10 ] && echo "P100"
		echo "R$((i * 2)),10"
		echo "W$((i * 100)),100"
		sleep 1
	done | flocks_test 6 $mp1file &
	local pid=$!
	for ((i = 0; i < 5; )); do
		echo "T0" | flocks_test 6 $mp2file |\
			grep 'R2,26;W100,900.' && i=$((i + 1))
		local nwc=$(do_node $LUSTRE_CLIENT_NFSSRV \
			"dmesg | grep -v 'DEBUG MARKER:' | grep -c 'refcount_t: underflow; use-after-free'")
		(( $owc >= $nwc )) || {
			do_node $LUSTRE_CLIENT_NFSSRV \
				"dmesg | grep -1 'refcount_t: underflow; use-after-free'"
			error "Failed (owc:$owc < nwc:$nwc)"
		}
		sleep 1
	done
	kill -9 $pid
	wait

	umount $tmpdir
	rm -rf $tmpdir || true
}
run_test 2 "fcntl getlk on nfs shouldn't cause refcount underflow"

test_compilebench() {
	if [[ "$TESTSUITE" =~ "parallel-scale-nfs" ]]; then
		skip "LU-12957 and LU-13068: compilebench for $TESTSUITE"
	fi

	run_compilebench $TESTDIR
}
run_test compilebench "compilebench"

test_metabench() {
	run_metabench $TESTDIR $NFS_CLIMNTPT
}
run_test metabench "metabench"

test_connectathon() {
	run_connectathon $TESTDIR
}
run_test connectathon "connectathon"

test_iorssf() {
	run_ior "ssf" $TESTDIR $NFS_SRVMNTPT
}
run_test iorssf "iorssf"

test_iorfpp() {
	run_ior "fpp" $TESTDIR $NFS_SRVMNTPT
}
run_test iorfpp "iorfpp"

test_racer_on_nfs() {
	local racer_params="MDSCOUNT=$MDSCOUNT OSTCOUNT=$OSTCOUNT LFS=$LFS"

	do_nodes $CLIENTS "$racer_params $racer $TESTDIR"
}
run_test racer_on_nfs "racer on NFS client"

complete_test $SECONDS
exit_status
