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
#   -w
#       Only run the workloads; no failure will be introduced.
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
#   Targets are automatically failed back when their primary node is back.  This
#   assumption avoids calling CRM-specific commands to trigger failbacks, making
#   this script more CRM-neural.
#
#   A crash dump mechanism is configured to catch LBUGs, panics, etc.
#
# WORKLOADS
#
#   Each client runs the same set of MPI and non-MPI workloads.  These
#   applications are run in short loops so that their exit status can be waited
#   for and checked within reasonable time by ha_wait_loads.
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

ha_info()
{
    echo "$0: $(date +%s):" "$@"
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
declare     ha_power_down_cmd=${POWER_DOWN:-pm -0}
declare     ha_power_up_cmd=${POWER_UP:-pm -1}
declare -a  ha_clients
declare -a  ha_servers
declare -a  ha_victims
declare     ha_test_dir=/mnt/lustre/$(basename $0)-$$
declare     ha_start_time=$(date +%s)
declare     ha_expected_duration=$((60 * 60 * 24))
declare     ha_nr_loops=0
declare     ha_stop_signals="SIGINT SIGTERM SIGHUP"
declare     ha_load_timeout=$((60 * 10))
declare     ha_workloads_only=false
declare -a  ha_mpi_load_tags=(
    ior
    simul
)
declare -a  ha_mpi_load_cmds=(
    "/testsuite/tests/x86_64/rhel5/IOR/src/C/IOR -b 256m -o {}/f.ior -t 2m
                                                 -w -W -T 1"
    "/testsuite/tests/x86_64/rhel5/simul/simul -d {}"
)
declare -a  ha_nonmpi_load_tags=(
    dd
    tar
)
declare -a  ha_nonmpi_load_cmds=(
    "dd if=/dev/zero of={}/f.dd bs=1M count=256"
    "tar cf - /etc/fonts | tar xf - -C {}"
)

ha_usage()
{
    ha_info "Usage: $0 -c HOST[,...] -s HOST[,...]"                         \
            "-v HOST[,...] [-d DIRECTORY] [-u SECONDS]"
}

ha_process_arguments()
{
    local opt

    while getopts hc:s:v:d:u:w opt; do
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
        w)
            ha_workloads_only=true
            ;;
        \?)
            ha_usage
            exit 1
            ;;
        esac
    done

    if [ -z "${ha_clients[*]}" ] ||                                         \
       [ -z "${ha_servers[*]}" ] ||                                         \
       [ -z "${ha_victims[*]}" ]; then
        ha_error "-c, -s, and -v are all mandatory"
        ha_usage
        exit 1
    fi
}

ha_on()
{
    local nodes=$1
    local rc=0

    shift
    pdsh -w $nodes PATH=/usr/kerberos/sbin:/usr/kerberos/bin:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin "$@" || rc=$?
    return $rc
}

ha_trap_exit()
{
    if [ -e "$ha_fail_file" ]; then
        ha_info "Test directory $ha_test_dir not removed"
        ha_info "Temporary directory $ha_tmp_dir not removed"
    else
        ha_on ${ha_clients[0]} rm -rf "$ha_test_dir"
        rm -rf "$ha_tmp_dir"
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
    ha_on $nodes "lctl dk >$file" || true
    ha_unlock "$lock"
}

ha_repeat_mpi_load()
{
    local load=$1
    local status=$2
    local tag=${ha_mpi_load_tags[$load]}
    local cmd=${ha_mpi_load_cmds[$load]}
    local dir=$ha_test_dir/$tag
    local log=$ha_tmp_dir/$tag
    local rc=0
    local nr_loops=0
    local start_time=$(date +%s)

    cmd=${cmd//"{}"/$dir}

    ha_info "Starting $tag"

	while [ ! -e "$ha_stop_file" ] && ((rc == 0)); do
		{
			ha_on ${ha_clients[0]} mkdir -p "$dir" &&	   \
			mpirun ${MACHINEFILE_OPTION} "$ha_machine_file"    \
				-np ${#ha_clients[@]} $cmd &&	           \
			ha_on ${ha_clients[0]} rm -rf "$dir"
		} >>"$log" 2>&1 || rc=$?

		if ((rc != 0)); then
			ha_dump_logs "${ha_clients[*]} ${ha_servers[*]}"
			touch "$ha_fail_file"
			touch "$ha_stop_file"
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

    for client in ${ha_clients[@]}; do
        echo $client >>"$ha_machine_file"
    done

    for ((load = 0; load < ${#ha_mpi_load_tags[@]}; load++)); do
        tag=${ha_mpi_load_tags[$load]}
        status=$ha_status_file_prefix-$tag
        ha_repeat_mpi_load $load $status &
        ha_status_files+=("$status")
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
        ha_on $client "mkdir -p $dir &&                                     \
                       $cmd &&                                              \
                       rm -rf $dir" >>"$log" 2>&1 || rc=$?

        if ((rc != 0)); then
            ha_dump_logs "$client ${ha_servers[*]}"
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
    for file in "${ha_status_files[@]}"; do
        until [ -e "$ha_stop_file" ] ||
              [ -e "$file" ]; do
            if (($(date +%s) >= end)); then
                ha_info "Timed out while waiting for load status file $file"
                touch "$ha_fail_file"
                return 1
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
    local end=$(($(date +%s) + 5 * 60))

    ha_info "Waiting for $node to boot up"
    until pdsh -w $node -S hostname >/dev/null 2>&1 ||
          [ -e "$ha_stop_file" ] ||
          (($(date +%s) >= end)); do
        ha_sleep 1 >/dev/null
    done
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

        node=$(ha_aim)

        ha_info "Failing $node"
        ha_sleep $(ha_rand 10)
        ha_power_down $node
        ha_sleep 10
        ha_wait_loads || break

        if [ -e $ha_stop_file ]; then
            ha_power_up $node
            break
        fi

        ha_info "Bringing $node back"
        ha_sleep $(ha_rand 10)
        ha_power_up $node
        ha_wait_node $node
        #
        # Wait for the failback to start.
        #
        ha_sleep 60
        ha_wait_loads || break

        ha_sleep $(ha_rand 20)

        ha_nr_loops=$((ha_nr_loops + 1))
        ha_info "Loop $ha_nr_loops done"
    done
    ha_summarize
}

ha_main()
{
    ha_process_arguments "$@"

    trap ha_trap_exit EXIT
    mkdir "$ha_tmp_dir"
    ha_on ${ha_clients[0]} mkdir "$ha_test_dir"

    ha_start_loads
    if ha_wait_loads; then
        if $ha_workloads_only; then
            ha_sleep $((60 * 60))
        else
            ha_killer
        fi
    fi
    ha_dump_logs "${ha_clients[*]} ${ha_servers[*]}"
    ha_stop_loads

    if [ -e "$ha_fail_file" ]; then
        exit 1
    else
        exit 0
    fi
}

ha_main "$@"
