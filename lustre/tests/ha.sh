#!/bin/bash
# -*- mode: Bash; tab-width: 4; indent-tabs-mode: t; -*-
# vim:shiftwidth=4:softtabstop=4:tabstop=4:
#
# NAME
#
#   ha.sh - test Lustre HA (aka failover) configurations
#
# SYNOPSIS
#
#   ha.sh [OPTIONS]
#
# DESCRIPTION
#
#   ha.sh tests Lustre HA (aka failover) configurations with a CRM.
#
# OPTIONS
#
#   -h
#       Help.
#
#   -c HOST[,...]
#       Specify client nodes.
#
#   -s HOST[,...]
#       Specify server nodes.
#
#   -v HOST[,...]
#       Specify victim nodes to be rebooted.
#
#   -d DIRECTORY
#       Choose a parent of the test directory.  "/mnt/lustre" if not specified.
#
#   -u SECONDS
#       Define a duration for the test. 86400 seconds if not specified.
#
#   -p SECONDS
#       Define a max failover period. 10 minutes if not set.
#
#   -w
#       Only run the workloads; no failure will be introduced.
#       -v, -s are ignored in this case.
#   -r
#       Workloads dry run for several seconds; no failures will be introduced.
#       This option is useful to verify the loads.
#       -u is ignored in this case
#
#
# ASSUMPTIONS
#
#   A Lustre file system is up and mounted on all client nodes.  This script
#   does not mount or unmount any Lustre targets or clients, let alone format
#   anything.
#
#   Each target has a failnode, so that workloads can continue after a power
#   failure.
#
#   CRM could be configured by 2 ways:
#   1.
#   Targets are automatically failed back when their primary node is back.  This
#   assumption avoids calling CRM-specific commands to trigger failbacks, making
#   this script more CRM-neural.
#   2.
#   Targets are not automatically failed back when their primary node is back.
#   CRM-specific command is executed to trigger failbacks.
#
#   A crash dump mechanism is configured to catch LBUGs, panics, etc.
#
# WORKLOADS
#
#   Each client runs set of MPI and non-MPI workloads. These
#   applications are run in short loops so that their exit status can be waited
#   for and checked within reasonable time by ha_wait_loads.
#   The set of MPI and non-MPI workloads are configurable by parameters:
#	ha_mpi_loads
#		default set: dd, tar, iozone
#	ha_nonmpi_loads
#		default set: ior, simul.
#
#   The number of clients run MPI loads is configured by parameter
#   ha_mpi_instances. Only one client runs MPI workloads by default.
#
# PROCESS STRUCTURE AND IPC
#
#   On the node where this script is run, the processes look like this:
#
#       ~ ha.sh (ha_killer)
#
#           ~ ha.sh (ha_repeat_mpi_load ior)
#               ~ mpirun IOR
#           ~ ha.sh (ha_repeat_mpi_load simul)
#               ~ mpirun simul
#           ~ ... (one for each MPI load)
#
#           ~ ha.sh (ha_repeat_nonmpi_load client2 dbench)
#               ~ pdsh client2 dbench
#           ~ ha.sh (ha_repeat_nonmpi_load client2 iozone)
#               ~ pdsh client2 iozone
#           ~ ha.sh (ha_repeat_nonmpi_load client5 iozone)
#               ~ pdsh client5 iozone
#           ~ ... (one for each non-MPI load on each client)
#
#   Each tilde represents a process.  Indentations imply parent-children
#   relation.
#
#   IPC is done by files in the temporary directory.
#

#set -x

SIMUL=${SIMUL:-$(which simul 2> /dev/null || true)}
IOR=${IOR:-$(which IOR 2> /dev/null || true)}

ior_blockSize=${ior_blockSize:-6g}
mpi_threads_per_client=${mpi_threads_per_client:-2}

iozone_SIZE=${iozone_SIZE:-262144} # 256m

mpirun=${MPIRUN:-$(which mpirun)}
LFS=${LFS:-$(which lfs)}

ha_check_env()
{
	for ((load = 0; load < ${#ha_mpi_load_tags[@]}; load++)); do
		local tag=${ha_mpi_load_tags[$load]}
		local bin=$(echo $tag | tr '[:lower:]' '[:upper:]')
		if [ x${!bin} = x ]; then
			ha_error ha_mpi_loads: ${ha_mpi_loads}, $bin is not set
			exit 1
		fi
	done
}

ha_info()
{
	echo "$0: $(date +%H:%M:%S' '%s):" "$@"
}

ha_log()
{
	local nodes=${1// /,}
	shift
	ha_on $nodes "lctl mark $*"
}

ha_error()
{
    ha_info "$@" >&2
}

ha_trap_err()
{
    local i

    ha_error "Trap ERR triggered by:"
    ha_error "    $BASH_COMMAND"
    ha_error "Call trace:"
    for ((i = 0; i < ${#FUNCNAME[@]}; i++)); do
        ha_error "    ${FUNCNAME[$i]} [${BASH_SOURCE[$i]}:${BASH_LINENO[$i]}]"
    done
}

trap ha_trap_err ERR
set -eE

declare     ha_tmp_dir=/tmp/$(basename $0)-$$
declare     ha_stop_file=$ha_tmp_dir/stop
declare     ha_fail_file=$ha_tmp_dir/fail
declare     ha_status_file_prefix=$ha_tmp_dir/status
declare -a  ha_status_files
declare     ha_machine_file=$ha_tmp_dir/machine_file
declare     ha_power_down_cmd=${POWER_DOWN:-"pm -0"}
declare     ha_power_up_cmd=${POWER_UP:-"pm -1"}
declare     ha_failback_delay=${DELAY:-5}
declare     ha_failback_cmd=${FAILBACK:-""}
declare     ha_stripe_params=${STRIPEPARAMS:-"-c 0"}
declare -a  ha_clients
declare -a  ha_servers
declare -a  ha_victims
declare     ha_test_dir=/mnt/lustre/$(basename $0)-$$
declare     ha_start_time=$(date +%s)
declare     ha_expected_duration=$((60 * 60 * 24))
declare     ha_max_failover_period=10
declare     ha_nr_loops=0
declare     ha_stop_signals="SIGINT SIGTERM SIGHUP"
declare     ha_load_timeout=$((60 * 10))
declare     ha_workloads_only=false
declare     ha_workloads_dry_run=false

declare     ha_mpi_instances=${ha_mpi_instances:-1}

declare     ha_mpi_loads=${ha_mpi_loads="ior simul"}
declare -a  ha_mpi_load_tags=($ha_mpi_loads)

declare     ha_ior_params=${IORP:-'" -b $ior_blockSize -t 2m -w -W -T 1"'}
declare     ha_simul_params=${SIMULP:-'" -n 10"'}
declare     ha_mpirun_options=${MPIRUN_OPTIONS:-""}

eval ha_params_ior=($ha_ior_params)
eval ha_params_simul=($ha_simul_params)

declare ha_nparams_ior=${#ha_params_ior[@]}
declare ha_nparams_simul=${#ha_params_simul[@]}

declare -A  ha_mpi_load_cmds=(
    [ior]="$IOR -o {}/f.ior {params}"
    [simul]="$SIMUL {params} -d {}"
)

declare     ha_nonmpi_loads=${ha_nonmpi_loads="dd tar iozone"}
declare -a  ha_nonmpi_load_tags=($ha_nonmpi_loads)
declare -a  ha_nonmpi_load_cmds=(
	"dd if=/dev/zero of={}/f.dd bs=1M count=256"
	"tar cf - /etc | tar xf - -C {}"
	"iozone -a -e -+d -s $iozone_SIZE {}/f.iozone"
)

ha_usage()
{
    ha_info "Usage: $0 -c HOST[,...] -s HOST[,...]"                         \
            "-v HOST[,...] [-d DIRECTORY] [-u SECONDS]"
}

ha_process_arguments()
{
    local opt

    while getopts hc:s:v:d:p:u:wr opt; do
        case $opt in
        h)
            ha_usage
            exit 0
            ;;
        c)
            ha_clients=(${OPTARG//,/ })
            ;;
        s)
            ha_servers=(${OPTARG//,/ })
            ;;
        v)
            ha_victims=(${OPTARG//,/ })
            ;;
        d)
            ha_test_dir=$OPTARG/$(basename $0)-$$
            ;;
        u)
            ha_expected_duration=$OPTARG
            ;;
	p)
		ha_max_failover_period=$OPTARG
		;;
        w)
		ha_workloads_only=true
		;;
	r)
		ha_workloads_dry_run=true
		;;
        \?)
            ha_usage
            exit 1
            ;;
        esac
    done

	if [ -z "${ha_clients[*]}" ]; then
		ha_error "-c is mandatory"
		ha_usage
		exit 1
	fi
	if ! ($ha_workloads_dry_run ||
			$ha_workloads_only) &&
			([ -z "${ha_servers[*]}" ] ||
			[ -z "${ha_victims[*]}" ]); then
		ha_error "-s, and -v are all mandatory"
		ha_usage
		exit 1
	fi
}

ha_on()
{
	local nodes=$1
	local rc=0

	shift

	#
	# -S is to be used here to track the
	# remote command return values
	#
	pdsh -S -w $nodes PATH=/usr/local/sbin:/usr/local/bin:/sbin:\
/bin:/usr/sbin:/usr/bin "$@" ||
		rc=$?
	return $rc
}

ha_trap_exit()
{
	touch "$ha_stop_file"
	trap 0
	if [ -e "$ha_fail_file" ]; then
		ha_info "Test directory $ha_test_dir not removed"
		ha_info "Temporary directory $ha_tmp_dir not removed"
	else
		ha_on ${ha_clients[0]} rm -rf "$ha_test_dir"
		ha_info "Please find the results in the directory $ha_tmp_dir"
	fi
}

ha_trap_stop_signals()
{
    ha_info "${ha_stop_signals// /,} received"
    touch "$ha_stop_file"
}

ha_sleep()
{
    local n=$1

    ha_info "Sleeping for ${n}s"
    #
    # sleep(1) could interrupted.
    #
    sleep $n || true
}

ha_lock()
{
    local lock=$1

    until mkdir "$lock" >/dev/null 2>&1; do
        ha_sleep 1 >/dev/null
    done
}

ha_unlock()
{
    local lock=$1

    rm -r "$lock"
}

ha_dump_logs()
{
    local nodes=${1// /,}
    local file=/tmp/$(basename $0)-$$-$(date +%s).dk
    local lock=$ha_tmp_dir/lock-dump-logs

    ha_lock "$lock"
    ha_info "Dumping lctl log to $file"

	#
	# some nodes could crash, so
	# do not exit with error if not all logs are dumped
	#
	ha_on $nodes "lctl dk >$file" ||
		ha_error "not all logs are dumped! Some nodes are unreachable."
	ha_unlock "$lock"
}

ha_repeat_mpi_load()
{
	local client=$1
	local load=$2
	local status=$3
	local parameter=$4
	local tag=${ha_mpi_load_tags[$load]}
	local cmd=${ha_mpi_load_cmds[$tag]}
	local dir=$ha_test_dir/$client-$tag
	local log=$ha_tmp_dir/$client-$tag
	local rc=0
	local nr_loops=0
	local start_time=$(date +%s)

	cmd=${cmd//"{}"/$dir}
	cmd=${cmd//"{params}"/$parameter}

	ha_info "Starting $tag"

	local machines="-machinefile $ha_machine_file"
	while [ ! -e "$ha_stop_file" ] && ((rc == 0)); do
		{
		ha_on $client mkdir -p "$dir" &&
		ha_on $client chmod a+xwr $dir &&
		ha_on $client "su mpiuser sh -c \" $mpirun $ha_mpirun_options \
			-np $((${#ha_clients[@]} * mpi_threads_per_client )) \
			$machines $cmd \" " &&
			ha_on $client rm -rf "$dir";
		} >>"$log" 2>&1 || rc=$?

		ha_info rc=$rc

		if ((rc != 0)); then
			touch "$ha_fail_file"
			touch "$ha_stop_file"
			ha_dump_logs "${ha_clients[*]} ${ha_servers[*]}"
		fi
		echo $rc >"$status"

		nr_loops=$((nr_loops + 1))
	done

	avg_loop_time=$((($(date +%s) - start_time) / nr_loops))

	ha_info "$tag stopped: rc $rc avg loop time $avg_loop_time"
}

ha_start_mpi_loads()
{
	local client
	local load
	local tag
	local status
	local n
	local nparam

	for client in ${ha_clients[@]}; do
		ha_info ha_machine_file=$ha_machine_file
		echo $client >> $ha_machine_file
	done
	local dirname=$(dirname $ha_machine_file)
	for client in ${ha_clients[@]}; do
		ha_on $client mkdir -p $dirname
		scp $ha_machine_file $client:$ha_machine_file
	done

	# ha_mpi_instances defines the number of
	# clients start mpi loads; should be <= ${#ha_clients[@]}
	local inst=$ha_mpi_instances
	(( inst <= ${#ha_clients[@]} )) || inst=${#ha_clients[@]}

	for ((n = 0; n < $inst; n++)); do
		client=${ha_clients[n]}
		for ((load = 0; load < ${#ha_mpi_load_tags[@]}; load++)); do
			tag=${ha_mpi_load_tags[$load]}
			status=$ha_status_file_prefix-$tag-$client
			# ha_nparams_ior
			# ha_nparams_simul
			local num=ha_nparams_$tag
			nparam=$((n % num))
			local aref=ha_params_$tag[nparam]
			local parameter=${!aref}
			ha_repeat_mpi_load $client $load $status "$parameter" &
				ha_status_files+=("$status")
		done
	done
}

ha_repeat_nonmpi_load()
{
    local client=$1
    local load=$2
    local status=$3
    local tag=${ha_nonmpi_load_tags[$load]}
    local cmd=${ha_nonmpi_load_cmds[$load]}
    local dir=$ha_test_dir/$client-$tag
    local log=$ha_tmp_dir/$client-$tag
    local rc=0
    local nr_loops=0
    local start_time=$(date +%s)

    cmd=${cmd//"{}"/$dir}

    ha_info "Starting $tag on $client"

	while [ ! -e "$ha_stop_file" ] && ((rc == 0)); do
		ha_on $client "mkdir -p $dir &&                              \
			$cmd &&                                              \
			rm -rf $dir" >>"$log" 2>&1 || rc=$?

		if ((rc != 0)); then
			ha_dump_logs "${ha_clients[*]} ${ha_servers[*]}"
			touch "$ha_fail_file"
			touch "$ha_stop_file"
		fi
		echo $rc >"$status"

		nr_loops=$((nr_loops + 1))
	done

    avg_loop_time=$((($(date +%s) - start_time) / nr_loops))

    ha_info "$tag on $client stopped: rc $rc avg loop time ${avg_loop_time}s"
}

ha_start_nonmpi_loads()
{
    local client
    local load
    local tag
    local status

    for client in ${ha_clients[@]}; do
        for ((load = 0; load < ${#ha_nonmpi_load_tags[@]}; load++)); do
            tag=${ha_nonmpi_load_tags[$load]}
            status=$ha_status_file_prefix-$tag-$client
            ha_repeat_nonmpi_load $client $load $status &
            ha_status_files+=("$status")
        done
    done
}

ha_start_loads()
{
    trap ha_trap_stop_signals $ha_stop_signals
    ha_start_nonmpi_loads
    ha_start_mpi_loads
}

ha_stop_loads()
{
    touch $ha_stop_file
    trap - $ha_stop_signals
    ha_info "Waiting for workloads to stop"
    wait
}

ha_wait_loads()
{
    local file
    local end=$(($(date +%s) + ha_load_timeout))

    ha_info "Waiting for workload status"
    rm -f "${ha_status_files[@]}"

	#
	# return immediately if ha_stop_file exists,
	# all status_files not needed to be checked
	#
	for file in "${ha_status_files[@]}"; do
		if [ -e "$ha_stop_file" ]; then
			ha_info "$ha_stop_file found! Stop."
			break
		fi
		#
		# Wait status file created during ha_load_timeout.
		# Existing file guarantees that some application
		# is completed. If no status file was created
		# this function guarantees that we allow
		# applications to continue after/before
		# failover/failback during ha_load_timeout time.
		#
		until [ -e "$file" ] || (($(date +%s) >= end)); do
			#
			# check ha_stop_file again, it could appear
			# during ha_load_timeout
			#
			if [ -e "$ha_stop_file" ]; then
				ha_info "$ha_stop_file found! Stop."
				break
			fi
			ha_sleep 1 >/dev/null
		done
	done
}

ha_power_down()
{
    local node=$1

    ha_info "Powering down $node"
    $ha_power_down_cmd $node
}

ha_power_up()
{
    local node=$1

    ha_info "Powering up $node"
    $ha_power_up_cmd $node
}

#
# rand MAX
#
# Print a random integer within [0, MAX).
#
ha_rand()
{
    local max=$1

    #
    # See "5.2 Bash Variables" from "info bash".
    #
    echo -n $((RANDOM * max / 32768))
}

ha_aim()
{
    local i=$(ha_rand ${#ha_victims[@]})

    echo -n ${ha_victims[$i]}
}

ha_wait_node()
{
	local node=$1
	local end=$(($(date +%s) + 10 * 60))

	ha_info "Waiting for $node to boot up"
	until ha_on $node hostname >/dev/null 2>&1 ||
		[ -e "$ha_stop_file" ] ||
			(($(date +%s) >= end)); do
		ha_sleep 1 >/dev/null
	done
}

ha_failback()
{
	local node=$1
	ha_info "Failback resources on $node in $ha_failback_delay sec"

	ha_sleep $ha_failback_delay
	[ "$ha_failback_cmd" ] ||
	{
		ha_info "No failback command set, skiping"
		return 0
	}

	$ha_failback_cmd $node
}

ha_summarize()
{
    ha_info "---------------8<---------------"
    ha_info "Summary:"
    ha_info "    Duration: $(($(date +%s) - $ha_start_time))s"
    ha_info "    Loops: $ha_nr_loops"
}

ha_killer()
{
	local node

	while (($(date +%s) < ha_start_time + ha_expected_duration)) &&
			[ ! -e "$ha_stop_file" ]; do
		ha_info "---------------8<---------------"

		$ha_workloads_only || node=$(ha_aim)

		ha_info "Failing $node"
		$ha_workloads_only && ha_info "    is skipped: workload only..."

		ha_sleep $(ha_rand $ha_max_failover_period)
		$ha_workloads_only || ha_power_down $node
		ha_sleep 10
		ha_wait_loads || return

		if [ -e $ha_stop_file ]; then
			$ha_workloads_only || ha_power_up $node
			break
		fi

		ha_info "Bringing $node back"
		ha_sleep $(ha_rand 10)
		$ha_workloads_only ||
		{
			ha_power_up $node
			ha_wait_node $node
			ha_failback $node
		}

		#
		# Wait for the failback to start.
		#
		ha_sleep 60
		ha_wait_loads || return

		ha_sleep $(ha_rand 20)

		ha_nr_loops=$((ha_nr_loops + 1))
		ha_info "Loop $ha_nr_loops done"
	done
	ha_summarize
}

ha_main()
{
	ha_process_arguments "$@"
	ha_check_env

	ha_log "${ha_clients[*]} ${ha_servers[*]}" \
		"START: $0: $(date +%H:%M:%S' '%s)"
	trap ha_trap_exit EXIT
	mkdir "$ha_tmp_dir"
	ha_on ${ha_clients[0]} mkdir "$ha_test_dir"
	ha_on ${ha_clients[0]} " \
		$LFS setstripe $ha_stripe_params $ha_test_dir"

	ha_start_loads
	ha_wait_loads

	if $ha_workloads_dry_run; then
		ha_sleep 5
	else
		ha_killer
		ha_dump_logs "${ha_clients[*]} ${ha_servers[*]}"
	fi

	ha_stop_loads

	if [ -e "$ha_fail_file" ]; then
		exit 1
	else
		ha_log "${ha_clients[*]} ${ha_servers[*]}" \
			"END: $0: $(date +%H:%M:%S' '%s)"
		exit 0
	fi
}

ha_main "$@"
