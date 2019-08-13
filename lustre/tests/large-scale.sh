#!/bin/bash

set -e

PTLDEBUG=${PTLDEBUG:--1}
SETUP=${SETUP:-""}
CLEANUP=${CLEANUP:-""}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
init_logging

ALWAYS_EXCEPT="$LARGE_SCALE_EXCEPT "

build_test_filter

remote_mds_nodsh && skip "remote MDS with nodsh"

[ -z "$CLIENTS" ] && skip_env "$TESTSUITE: Need two or more clients"
[ $CLIENTCOUNT -lt 2 ] &&
	skip_env "$TESTSUITE: Need 2+ clients, have only $CLIENTCOUNT"

MOUNT_2=""

check_and_setup_lustre
rm -rf $DIR/[df][0-9]*

get_mpiuser_id $MPI_USER
MPI_RUNAS=${MPI_RUNAS:-"runas -u $MPI_USER_UID -g $MPI_USER_GID"}
$GSS_KRB5 && refresh_krb5_tgt $MPI_USER_UID $MPI_USER_GID $MPI_RUNAS

[ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE

test_3a() {
	assert_env CLIENTS MDSRATE MPIRUN

	local -a nodes=(${CLIENTS//,/ })
	# INCREMENT is a number of clients a half of clients by default
	local increment=${INCREMENT:-$(( CLIENTCOUNT / 2 ))}
	local num=$increment
	local LOG=$TMP/${TESTSUITE}_$tfile
	local var=${SINGLEMDS}_svc
	local procfile="*.${!var}.recovery_status"
	local iters=${ITERS:-3}
	local nfiles=${NFILES:-50000}
	local nthreads=${THREADS_PER_CLIENT:-3}
	local IFree=$(inodes_available)
	local pid
	local list
	local -a res
	local dir=$DIR/d0.$TESTNAME

	[ $IFree -gt $nfiles ] || nfiles=$IFree

	mkdir -p $dir
	chmod 0777 $dir

	while [ $num -le $CLIENTCOUNT ]; do
		list=$(comma_list ${nodes[@]:0:$num})

		generate_machine_file $list $MACHINEFILE ||
			error "can not generate machinefile"

		for i in $(seq $iters); do
			mdsrate_cleanup $num $MACHINEFILE $nfiles $dir 'f%%d' \
				--ignore

			COMMAND="${MDSRATE} --create --nfiles $nfiles --dir
				 $dir --filefmt 'f%%d'"
			mpi_run ${MACHINEFILE_OPTION} $MACHINEFILE \
				-np $((num * nthreads)) ${COMMAND} | tee ${LOG}&

			pid=$!
			echo "pid=$pid"

			# 2 threads 100000 creates 117 secs
			sleep 20

			log "$i : Starting failover on $SINGLEMDS"
			facet_failover $SINGLEMDS
			if ! wait_recovery_complete $SINGLEMDS \
			     $((TIMEOUT * 10)); then
				echo "$SINGLEMDS recovery is not completed!"
				kill -9 $pid
				exit 7
			fi

			duration=$(do_facet $SINGLEMDS lctl get_param -n \
				$procfile | grep recovery_duration)

			res=( "${res[@]}" "$num" )
			res=( "${res[@]}" "$duration" )
			echo "RECOVERY TIME: NFILES=$nfiles number of clients: $num $duration"
			wait $pid
		done
		num=$((num + increment))
	done

	mdsrate_cleanup $num $MACHINEFILE $nfiles $dir 'f%%d' --ignore

	i=0
	while [ $i -lt ${#res[@]} ]; do
		echo "RECOVERY TIME: NFILES=$nfiles number of clients: ${res[i]}  ${res[i+1]}"
		i=$((i+2))
	done
}

run_test 3a "recovery time, $CLIENTCOUNT clients"

complete $SECONDS
check_and_cleanup_lustre
exit_status
