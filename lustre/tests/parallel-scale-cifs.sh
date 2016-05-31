#!/bin/bash

# Requires the pre-configured samba machine
# RPMS required are :
# server:
#      samba
#      samba-common
#      cifs-utils
# clients:
#      samba-client
#      samba-common
#      cifs-utils

#set -vx

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging
. $LUSTRE/tests/setup-cifs.sh

check_and_setup_lustre

# first unmount all the lustre clients
cleanup_mount $MOUNT
# lustre client used as samba server (default is mds node)
LUSTRE_CLIENT_SMBSRV=${LUSTRE_CLIENT_SMBSRV:-$(facet_active_host $SINGLEMDS)}
SMBSHARE=${SMBSHARE:-lustretest}
SMBUSER=${SMBUSER:-root}
SMBPASSWD=${SMBPASSWD:-lustre}
SMBSRVMNTPT=${SMBSRVMNTPT:-$MOUNT}
SMBCLIMNTPT=${SMBCLIMNTPT:-$MOUNT}
SMBCLIENTS=${SMBCLIENTS:-$CLIENTS}
SMBCLIENTS=$(exclude_items_from_list $SMBCLIENTS $LUSTRE_CLIENT_SMBSRV)

[ -z "$SMBCLIENTS" ] &&
	skip_env "need at least two nodes: samba server and samba client" &&
	exit 0

# set CONFIGURE_SMB=false to skip smb config
CONFIGURE_SMB=${CONFIGURE_SMB:-true}

# store smb status to restart smb service if it was running initially
SMBSTATUS=0
smb_status $LUSTRE_CLIENT_SMBSRV || SMBSTATUS=$?
SMBCONFTMP=$(do_node $LUSTRE_CLIENT_SMBSRV "mktemp -t smb.conf.XXX")

cleanup_exit() {
	trap 0
	cleanup
	check_and_cleanup_lustre
	exit
}

cleanup() {
	cleanup_cifs $LUSTRE_CLIENT_SMBSRV $SMBCLIMNTPT $SMBCLIENTS ||
		error_noexit false "failed to cleanup cifs"
	zconf_umount $LUSTRE_CLIENT_SMBSRV $SMBSRVMNTPT force ||
		error_noexit false "failed to umount lustre on $LUSTRE_CLIENT_SMBSRV"
	# restore lustre mount
	restore_mount $MOUNT ||
		error_noexit false "failed to mount lustre"

	$CONFIGURE_SMB && restore_config_smb $LUSTRE_CLIENT_SMBSRV $SMBCONFTMP
	[[ $SMBSTATUS -eq 0 ]] &&
		do_node $LUSTRE_CLIENT_SMBSRV "service smb start"
	unset CIFSCLIENT
}

$CONFIGURE_SMB && configure_smb $LUSTRE_CLIENT_SMBSRV $SMBSHARE $SMBUSER \
		$SMBPASSWD $SMBSRVMNTPT $SMBCONFTMP ||
	echo -e "\nSkipping smb config ..."

trap cleanup_exit EXIT SIGHUP SIGINT

# mount lustre client on smb server
zconf_mount $LUSTRE_CLIENT_SMBSRV $SMBSRVMNTPT ||
	error "mount lustre on $LUSTRE_CLIENT_SMBSRV failed"

# setup the cifs
setup_cifs $LUSTRE_CLIENT_SMBSRV $SMBSHARE $SMBCLIMNTPT $SMBUSER \
		$SMBPASSWD $SMBCLIENTS ||
	error false "setup cifs failed"

CIFSCLIENT=yes
FAIL_ON_ERROR=false

# compilbench
# Run short iteration in cifs mode
cbench_IDIRS=${cbench_IDIRS:-2}
cbench_RUNS=${cbench_RUNS:-2}

# source the common file after all parameters are set to take effect
. $LUSTRE/tests/functions.sh

build_test_filter

check_prog_output() {
	local clients=$1
	local file=$2
	local str=$3

	do_nodes $clients grep -q \\\"$str\\\" $file 2>/dev/null
}

wait_prog_output() {
	local clients=$1
	local file=$2
	local str=$3
	local time=$4
	local start_ts=$(date +%s)
	local elapsed

	while ! check_prog_output $clients $file "$str"; do
		elapsed=$(($(date +%s) - start_ts))
		if [ $elapsed -gt $time ]; then
			return 1
		fi
		sleep 1
	done
}

test_compilebench() {
	run_compilebench $SMBCLIMNTPT
}
run_test compilebench "compilebench on cifs clients"

test_dbench() {
	local clients=$SMBCLIENTS
	local duration=${DBENCH_DURATION:-300}
	local nproc=${DBENCH_NPROC:-1}
	local delay=${dbench_STARTDELAY:-120}
	local log=$TMP/dbench.log
	local pid=""

	local cmd="rundbench $nproc -t $duration"

	echo "Using: $cmd"

	do_nodesv $clients "set -x; MISSING_DBENCH_OK=$MISSING_DBENCH_OK \
		PATH=\$PATH DBENCH_LIB=$DBENCH_LIB \
		TESTSUITE=$TESTSUITE TESTNAME=$TESTNAME \
		DIR=$SMBCLIMNTPT/$tdir/\\\$(hostname) \
		LCTL=$LCTL $cmd 2>&1 | tee $log; \
		exit \\\${PIPESTATUS[0]}" &
	pid=$!

	# check that dbench is started on all clients after
	# $dbench_STARTDELAY: the dbench log on each client
	# is to be started for this moment and contain "dbench PID";
	if ! wait_prog_output $clients $log "dbench PID" $delay; then
		kill -s TERM $pid
		killall_process $clients dbench
		error "dbench failed to start on $clients!"
	fi

	log "Started rundbench load pid=$pid ..."
	wait $pid || error "rundbench load on $clients failed!"
}
run_test dbench "dbench on cifs clients"

test_fsx() {
	local clients=$SMBCLIENTS
	local seed=${fsx_SEED:-$RANDOM}
	local size=${fsx_SIZE:-1024}
	local numop=${fsx_NUMOP:-100000}
	local delay=${fsx_STARTDELAY:-120}
	local log=$TMP/fsx.log
	local pid=""

	local nclients=$(get_node_count ${clients//,/ })
	local space=$(df -P $SMBCLIMNTPT | tail -n 1 | awk '{ print $4 }')
	[ $space -lt $((size * nclients)) ] && size=$((space * 3 / 4 / nclients))

	local cmd="$FSX -c 50 -p 500 -S $seed -P $TMP -l $size -N $numop "

	echo "Using: $cmd"

	do_nodesv $clients "set -x; \
		PATH=\$PATH \
		$cmd $SMBCLIMNTPT/f0.fsx_\\\$(hostname) 2>&1 | tee $log; \
		exit \\\${PIPESTATUS[0]}" &
	pid=$!

	# check that fsx is started on all clients after
	# $fsx_STARTDELAY: the fsx log on each client
	# is to be started for this moment and contain "Seed set";
	if ! wait_prog_output $clients $log "Seed set" $delay; then
		kill -s TERM $pid
		killall_process $clients fsx
		error "fsx failed to start on $clients!"
	fi

	log "Started fsx load pid=$pid ..."
	wait $pid || error "fsx load on $clients failed!"
}
run_test fsx "fsx on cifs clients"

test_iozone() {
	local clients=$SMBCLIENTS
	local size=${iozone_SIZE:-262144} # 256m
	local delay=${iozone_STARTDELAY:-120}
	local log=$TMP/iozone.log
	local pid=""

	local nclients=$(get_node_count ${clients//,/ })

	local space=$(df -P $SMBCLIMNTPT | tail -n 1 | awk '{ print $4 }')

	[[ $((size * nclients)) -gt $((space * 3 / 4)) ]] &&
		size=$((space * 3 / 4 / nclients))

	do_node $LUSTRE_CLIENT_SMBSRV "mkdir $SMBSRVMNTPT/$tdir
		lfs setstripe -c -1 $SMBSRVMNTPT/$tdir"

	log "free space: $space Kb, using $size size, $nclients number of clients"

	local cmd="iozone -a -e -+d -s $size "

	echo "Using: $cmd"

	do_nodesv $clients "set -x; \
		PATH=\$PATH \
		$cmd -f $SMBCLIMNTPT/$tdir/f0.iozone_\\\$(hostname) \
		2>&1 | tee $log; exit \\\${PIPESTATUS[0]}" &
	pid=$!

	# check that iozone is started on all clients after
	# $iozone_STARTDELAY: the iozone log on each client
	# is to be started for this moment and contain "Command line used";
	if ! wait_prog_output $clients $log "Command line used" $delay; then
		kill -s TERM $pid
		killall_process $clients iozone
		error "iozone failed to start on $clients!"
	fi

	log "Started iozone load pid=$pid ..."
	wait $pid
	rc=$?
	log "Processing iozone log"
	do_nodesv $clients "tail -1 $log | grep -q complete" || rc=2
	do_node $LUSTRE_CLIENT_SMBSRV "rm -rf $SMBSRVMNTPT/$tdir"
	[ $rc -eq 0 ] || error "iozone load on $clients failed! rc=$rc"
}
run_test iozone "iozone on cifs clients"

complete $SECONDS
exit_status
