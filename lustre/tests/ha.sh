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
#   -m
#       Reboot victim nodes simultaneously.
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
#	ha_nonmpi_loads
#		default set: dd, tar, iozone
#	ha_mpi_loads
#		default set: ior, simul, mdtest
#
#   The number of clients run MPI loads is configured by parameter
#   ha_mpi_instances. Only one client runs MPI workloads by default.
#
#   MPI workloads can be run from several users. The list of users to use is
#   configured by parameter ha_mpi_users, default is "mpiuser".
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
#           ~ ha.sh (ha_repeat_mpi_load mdtest)
#               ~ mpirun mdtest
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
MDTEST=${MDTEST:-$(which mdtest 2> /dev/null || true)}

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
declare     ha_pm_states=$ha_tmp_dir/ha_pm_states
declare     ha_status_file_prefix=$ha_tmp_dir/status
declare -a  ha_status_files
declare     ha_machine_file=$ha_tmp_dir/machine_file
declare     ha_lfsck_log=$ha_tmp_dir/lfsck.log
declare     ha_lfsck_lock=$ha_tmp_dir/lfsck.lock
declare     ha_lfsck_stop=$ha_tmp_dir/lfsck.stop
declare     ha_lfsck_bg=${LFSCK_BG:-false}
declare     ha_lfsck_after=${LFSCK_AFTER:-false}
declare     ha_lfsck_node=${LFSCK_NODE:-""}
declare     ha_lfsck_device=${LFSCK_DEV:-""}
declare     ha_lfsck_types=${LFSCK_TYPES:-"namespace layout"}
declare     ha_lfsck_custom_params=${LFSCK_CUSTOM_PARAMS:-""}
declare     ha_lfsck_wait=${LFSCK_WAIT:-1200}
declare     ha_lfsck_fail_on_repaired=${LFSCK_FAIL_ON_REPAIRED:-false}
declare     ha_power_down_cmd=${POWER_DOWN:-"pm -0"}
declare     ha_power_up_cmd=${POWER_UP:-"pm -1"}
declare     ha_power_delay=${POWER_DELAY:-60}
declare     ha_node_up_delay=${NODE_UP_DELAY:-10}
declare     ha_pm_host=${PM_HOST:-$(hostname)}
declare     ha_failback_delay=${DELAY:-5}
declare     ha_failback_cmd=${FAILBACK:-""}
declare     ha_stripe_params=${STRIPEPARAMS:-"-c 0"}
declare     ha_test_dir_stripe_count=${TDSTRIPECOUNT:-"1"}
declare     ha_test_dir_mdt_index=${TDMDTINDEX:-"0"}
declare     ha_test_dir_mdt_index_random=${TDMDTINDEXRAND:-false}
declare     ha_dir_stripe_count=${DSTRIPECOUNT:-"1"}
declare     ha_mdt_index=${MDTINDEX:-"0"}
declare     ha_mdt_index_random=${MDTINDEXRAND:-false}
declare -a  ha_clients
declare -a  ha_servers
declare -a  ha_victims
declare -a  ha_victims_pair
declare     ha_test_dir=/mnt/lustre/$(basename $0)-$$
declare     ha_start_time=$(date +%s)
declare     ha_expected_duration=$((60 * 60 * 24))
declare     ha_max_failover_period=10
declare     ha_nr_loops=0
declare     ha_stop_signals="SIGINT SIGTERM SIGHUP"
declare     ha_load_timeout=${LOAD_TIMEOUT:-$((60 * 10))}
declare     ha_workloads_only=false
declare     ha_workloads_dry_run=false
declare     ha_simultaneous=false

declare     ha_mpi_instances=${ha_mpi_instances:-1}

declare     ha_mpi_loads=${ha_mpi_loads="ior simul mdtest"}
declare -a  ha_mpi_load_tags=($ha_mpi_loads)
declare -a  ha_mpiusers=(${ha_mpi_users="mpiuser"})
declare -a  ha_users
declare -A  ha_mpiopts

for ((i=0; i<${#ha_mpiusers[@]}; i++)); do
	u=${ha_mpiusers[i]%%:*}
	o=""
	# user gets empty option if ha_mpi_users does not specify it explicitly
	[[ ${ha_mpiusers[i]} =~ : ]] && o=${ha_mpiusers[i]##*:}
	ha_users[i]=$u
	ha_mpiopts[$u]+=" $o"
done
ha_users=(${!ha_mpiopts[@]})

declare     ha_ior_params=${IORP:-'" -b $ior_blockSize -t 2m -w -W -T 1"'}
declare     ha_simul_params=${SIMULP:-'" -n 10"'}
declare     ha_mdtest_params=${MDTESTP:-'" -i 1 -n 1000"'}
declare     ha_mpirun_options=${MPIRUN_OPTIONS:-""}
declare     ha_clients_stripe=${CLIENTSSTRIPE:-'"$STRIPEPARAMS"'}
declare     ha_nclientsset=${NCLIENTSSET:-1}
declare     ha_ninstmustfail=${NINSTMUSTFAIL:-0}

declare     ha_racer_params=${RACERP:-"MDSCOUNT=1"}

eval ha_params_ior=($ha_ior_params)
eval ha_params_simul=($ha_simul_params)
eval ha_params_mdtest=($ha_mdtest_params)
eval ha_stripe_clients=($ha_clients_stripe)

declare ha_nparams_ior=${#ha_params_ior[@]}
declare ha_nparams_simul=${#ha_params_simul[@]}
declare ha_nparams_mdtest=${#ha_params_mdtest[@]}
declare ha_nstripe_clients=${#ha_stripe_clients[@]}

declare -A  ha_mpi_load_cmds=(
	[ior]="$IOR -o {}/f.ior {params}"
	[simul]="$SIMUL {params} -d {}"
	[mdtest]="$MDTEST {params} -d {}"
)

declare racer=${RACER:-"$(dirname $0)/racer/racer.sh"}

declare     ha_nonmpi_loads=${ha_nonmpi_loads="dd tar iozone"}
declare -a  ha_nonmpi_load_tags=($ha_nonmpi_loads)
declare -A  ha_nonmpi_load_cmds=(
	[dd]="dd if=/dev/zero of={}/f.dd bs=1M count=256"
	[tar]="tar cf - /etc | tar xf - -C {}"
	[iozone]="iozone -a -e -+d -s $iozone_SIZE {}/f.iozone"
	[racer]="$ha_racer_params $racer {}"
)

ha_usage()
{
	ha_info "Usage: $0 -c HOST[,...] -s HOST[,...]" \
		"-v HOST[,...] -f HOST[,...] [-d DIRECTORY] [-u SECONDS]"
}

ha_process_arguments()
{
    local opt

	while getopts hc:s:v:d:p:u:wrmf: opt; do
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
	m)
		ha_simultaneous=true
		;;
	f)
		ha_victims_pair=(${OPTARG//,/ })
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
	pdsh -S -w $nodes "PATH=/usr/local/sbin:/usr/local/bin:/sbin:\
/bin:/usr/sbin:/usr/bin; $@" ||
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

ha_wait_unlock()
{
	local lock=$1

	while [ -e $lock ]; do
		sleep 1
	done
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
	local rc=0

	ha_lock "$lock"
	ha_info "Dumping lctl log to $file"

	#
	# some nodes could crash, so
	# do not exit with error if not all logs are dumped
	#
	ha_on $nodes "lctl dk >>$file" || rc=$?

	[ $rc -eq 0 ] ||
		ha_error "not all logs are dumped! Some nodes are unreachable."
	ha_unlock "$lock"
}

ha_repeat_mpi_load()
{
	local client=$1
	local load=$2
	local status=$3
	local parameter=$4
	local machines=$5
	local stripeparams=$6
	local mpiuser=$7
	local mustpass=$8
	local mpirunoptions=$9
	local tag=${ha_mpi_load_tags[$load]}
	local cmd=${ha_mpi_load_cmds[$tag]}
	local dir=$ha_test_dir/$client-$tag
	local log=$ha_tmp_dir/$client-$tag
	local rc=0
	local nr_loops=0
	local avg_loop_time=0
	local start_time=$(date +%s)

	cmd=${cmd//"{}"/$dir}
	cmd=${cmd//"{params}"/$parameter}

	[[ -n "$ha_postcmd" ]] && ha_postcmd=${ha_postcmd//"{}"/$dir}
	[[ -n "$ha_precmd" ]] && ha_precmd=${ha_precmd//"{}"/$dir}
	ha_info "Starting $tag"

	machines="-machinefile $machines"
	while [ ! -e "$ha_stop_file" ] && ((rc == 0)); do
		ha_info "$client Starts: $mpiuser: $cmd" 2>&1 |  tee -a $log
		{
		local mdt_index
		if $ha_mdt_index_random && [ $ha_mdt_index -ne 0 ]; then
			mdt_index=$(ha_rand $ha_mdt_index)
		else
			mdt_index=$ha_mdt_index
		fi
		[[ -n "$ha_precmd" ]] && ha_info "$ha_precmd" &&
			ha_on $client "$ha_precmd" >>"$log" 2>&1
		ha_on $client $LFS mkdir -i$mdt_index -c$ha_dir_stripe_count "$dir" &&
		ha_on $client $LFS getdirstripe "$dir" &&
		ha_on $client $LFS setstripe $stripeparams $dir &&
		ha_on $client $LFS getstripe $dir &&
		ha_on $client chmod a+xwr $dir &&
		ha_on $client "su $mpiuser sh -c \" $mpirun $mpirunoptions \
			-np $((${#ha_clients[@]} * mpi_threads_per_client )) \
			$machines $cmd \" " || rc=$?
		[[ -n "$ha_postcmd" ]] && ha_info "$ha_postcmd" &&
			ha_on $client "$ha_postcmd" >>"$log" 2>&1
		(( ((rc == 0)) && (( mustpass != 0 )) )) ||
		(( ((rc != 0)) && (( mustpass == 0 )) )) &&
			ha_on $client rm -rf "$dir";
		} >>"$log" 2>&1 || rc=$?

		ha_info $client: rc=$rc mustpass=$mustpass

		# mustpass=0 means that failure is expected
		if (( rc !=0 )); then
			if (( mustpass != 0 )); then
				touch "$ha_fail_file"
				touch "$ha_stop_file"
				ha_dump_logs "${ha_clients[*]} ${ha_servers[*]}"
			else
				# Ok to fail
				rc=0
			fi
		elif (( mustpass == 0 )); then
			touch "$ha_fail_file"
			touch "$ha_stop_file"
			ha_dump_logs "${ha_clients[*]} ${ha_servers[*]}"
		fi
		echo rc=$rc mustpass=$mustpass >"$status"

		nr_loops=$((nr_loops + 1))
	done

	[ $nr_loops -ne 0 ] &&
		avg_loop_time=$((($(date +%s) - start_time) / nr_loops))

	ha_info "$tag stopped: rc=$rc mustpass=$mustpass \
		avg loop time $avg_loop_time"
}

ha_start_mpi_loads()
{
	local client
	local load
	local tag
	local status
	local n
	local nparam
	local machines
	local m
	local -a mach
	local mpiuser
	local nmpi

	# ha_mpi_instances defines the number of
	# clients start mpi loads; should be <= ${#ha_clients[@]}
	# do nothing if
	#    ha_mpi_instances = 0
	# or
	#    ${#ha_mpi_load_tags[@]} =0
	local inst=$ha_mpi_instances
	(( inst == 0 )) || (( ${#ha_mpi_load_tags[@]} == 0 )) &&
		ha_info "no mpi load to start" &&
		return 0

	(( inst <= ${#ha_clients[@]} )) || inst=${#ha_clients[@]}

	# Define names for machinefiles for each client set
	for (( n=0; n < $ha_nclientsset; n++ )); do
		mach[$n]=$ha_machine_file$n
	done

	for ((n = 0; n < ${#ha_clients[@]}; n++)); do
		m=$(( n % ha_nclientsset))
		machines=${mach[m]}
		ha_info machine_file=$machines
		echo ${ha_clients[n]} >> $machines
	done
	local dirname=$(dirname $ha_machine_file)
	for client in ${ha_clients[@]}; do
		ha_on $client mkdir -p $dirname
		scp $ha_machine_file* $client:$dirname
	done

	for ((n = 0; n < $inst; n++)); do
		client=${ha_clients[n]}
		nmpi=$((n % ${#ha_users[@]}))
		mpiuser=${ha_users[nmpi]}
		for ((load = 0; load < ${#ha_mpi_load_tags[@]}; load++)); do
			tag=${ha_mpi_load_tags[$load]}
			status=$ha_status_file_prefix-$tag-$client
			# ha_nparams_ior
			# ha_nparams_simul
			local num=ha_nparams_$tag
			nparam=$((n % num))
			local aref=ha_params_$tag[nparam]
			local parameter=${!aref}
			local nstripe=$((n % ha_nstripe_clients))
			aref=ha_stripe_clients[nstripe]
			local stripe=${!aref}
			local m=$(( n % ha_nclientsset))
			machines=${mach[m]}
			local mustpass=1
			[[ $ha_ninstmustfail == 0 ]] ||
				mustpass=$(( n % ha_ninstmustfail ))
			ha_repeat_mpi_load $client $load $status "$parameter" \
				$machines "$stripe" "$mpiuser" "$mustpass" \
				"${ha_mpiopts[$mpiuser]} $ha_mpirun_options" &
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
	local cmd=${ha_nonmpi_load_cmds[$tag]}
	local dir=$ha_test_dir/$client-$tag
	local log=$ha_tmp_dir/$client-$tag
	local rc=0
	local nr_loops=0
	local avg_loop_time=0
	local start_time=$(date +%s)

	cmd=${cmd//"{}"/$dir}

	ha_info "Starting $tag on $client"

	while [ ! -e "$ha_stop_file" ] && ((rc == 0)); do
		ha_info "$client Starts: $cmd" 2>&1 |  tee -a $log
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

	[ $nr_loops -ne 0 ] &&
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

ha_lfsck_bg () {
	rm -f $ha_lfsck_log
	rm -f $ha_lfsck_stop

	ha_info "LFSCK BG"
	while [ true ]; do
		[ -f $ha_lfsck_stop ] && ha_info "LFSCK stopped" && break
		[ -f $ha_stop_file ] &&
			ha_info "$ha_stop_file found! LFSCK not started" &&
			break
		ha_start_lfsck 2>&1 | tee -a $ha_lfsck_log
		sleep 1
	done &
	LFSCK_BG_PID=$!
	ha_info LFSCK BG PID: $LFSCK_BG_PID
}

ha_wait_lfsck_completed () {
	local -a status
	local -a types=($ha_lfsck_types)
	local type
	local s

	local nodes="${ha_servers[@]}"
	nodes=${nodes// /,}

	# -A start LFSCK on all nodes
	# -t default all
	[ ${#types[@]} -eq 0 ] && types=(namespace layout)
	ha_info "Waiting LFSCK completed in $ha_lfsck_wait sec: types ${types[@]}"
	for type in ${types[@]}; do
		eval var_$type=0
		for (( i=0; i<=ha_lfsck_wait; i++)); do
			status=($(ha_on $nodes lctl get_param -n *.*.lfsck_$type 2>/dev/null | \
				awk '/status/ { print $3 }'))
			for (( s=0; s<${#status[@]}; s++ )); do
				# "partial" is expected after HARD failover
				[[ "${status[s]}" = "completed" ]] ||
				[[ "${status[s]}" = "partial" ]] ||  break
			done
			[[ $s -eq ${#status[@]} ]] && eval var_$type=1 && break
			sleep 1
		done
		ha_info "LFSCK $type status in $i sec:"
		ha_on $nodes lctl get_param -n *.*.lfsck_$type 2>/dev/null | grep status

	done

	for type in ${types[@]}; do
		local var=var_$type
		ha_on $nodes lctl get_param -n *.*.lfsck_$type 2>/dev/null
		[[ ${!var} -eq 1 ]] ||
			{ ha_info "lfsck not completed in $ha_lfsck_wait sec";
			return 1; }
	done
	return 0
}

ha_start_lfsck()
{
	local -a types=($ha_lfsck_types)
	local rc=0

	# -A: start LFSCK on all nodes via the specified MDT device
	# (see "-M" option) by single LFSCK command
	local params=" -A -r $ha_lfsck_custom_params"

	# use specified device if set
	[ -n "$ha_lfsck_device" ] && params="-M $ha_lfsck_device $params"

	# -t: check type(s) to be performed (default all)
	# check only specified types if set
	if [ ${#types[@]} -ne 0 ]; then
		local type="${types[@]}"
		params="$params -t ${type// /,}"
	fi

	ha_info "LFSCK start $params"
	ha_on $ha_lfsck_node "lctl lfsck_start $params" || rc=1
	if [ $rc -ne 0 ]; then
		if [ -e $ha_lfsck_lock ]; then
			rc=0
			ha_wait_unlock $ha_lfsck_lock
			ha_sleep 120
			ha_on $ha_lfsck_node "lctl lfsck_start $params" || rc=1
		fi
	fi

	[ $rc -eq 0 ] ||
		{ touch "$ha_fail_file"; touch "$ha_stop_file";
		touch $ha_lfsck_stop; return 1; }

	ha_wait_lfsck_completed ||
		{ touch "$ha_fail_file"; touch "$ha_stop_file";
		touch $ha_lfsck_stop; return 1; }

	return 0
}

ha_lfsck_repaired()
{
	local n=0

	n=$(cat $ha_lfsck_log | awk '/repaired/ {print $3}' |\
		awk '{sum += $1} END { print sum }')
	[ $n -eq 0] ||
		{ ha_info "Total repaired: $n";
		touch "$ha_fail_file"; return 1; }
	return 0
}

ha_start_loads()
{
	$ha_lfsck_bg && ha_lfsck_bg
	trap ha_trap_stop_signals $ha_stop_signals
	ha_start_nonmpi_loads
	ha_start_mpi_loads
}

ha_stop_loads()
{
	touch $ha_stop_file
	# true because of lfsck_bg could be stopped already
	$ha_lfsck_bg && wait $LFSCK_BG_PID || true
	trap - $ha_stop_signals
	ha_info "Waiting for workloads to stop"
	wait
}

ha_wait_loads()
{
    local file
    local end=$(($(date +%s) + ha_load_timeout))

    ha_info "Waiting $ha_load_timeout sec for workload status..."
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

ha_powermanage()
{
	local nodes=$1
	local expected_state=$2
	local state
	local -a states
	local i
	local rc=0

	# store pm -x -q $nodes results in a file to have
	# more information about nodes statuses
	ha_on $ha_pm_host pm -x -q $nodes | awk '{print $2 $3}' > $ha_pm_states
	rc=${PIPESTATUS[0]}
	echo pmrc=$rc

	while IFS=": " read node state; do
		[[ "$state" = "$expected_state" ]] && {
			nodes=${nodes/$node/}
			nodes=${nodes//,,/,}
			nodes=${nodes/#,}
			nodes=${nodes/%,}
		}
	done < $ha_pm_states

	if [ -n "$nodes" ]; then
		cat $ha_pm_states
		return 1
	fi
	return 0
}

ha_power_down_cmd_fn()
{
	local nodes=$1
	local cmd

	case $ha_power_down_cmd in
	# format is: POWER_DOWN=sysrqcrash
	sysrqcrash) cmd="pdsh -S -w $nodes 'echo c > /proc/sysrq-trigger' &" ;;
	*) cmd="$ha_power_down_cmd $nodes" ;;
	esac

	eval $cmd
}

ha_power_down()
{
	local nodes=$1
	local rc=1
	local i
	local state

	case $ha_power_down_cmd in
		*pm*) state=off ;;
		sysrqcrash) state=off ;;
		*) state=on;;
	esac

	if $ha_lfsck_bg && [[ ${nodes//,/ /} =~ $ha_lfsck_node ]]; then
		ha_info "$ha_lfsck_node down, delay start LFSCK"
		ha_lock $ha_lfsck_lock
	fi

	ha_info "Powering down $nodes : cmd: $ha_power_down_cmd"
	for (( i=0; i<10; i++ )) {
		ha_info "attempt: $i"
		ha_power_down_cmd_fn $nodes &&
			ha_powermanage $nodes $state && rc=0 && break
		sleep $ha_power_delay
	}

	[ $rc -eq 0 ] || {
		ha_info "Failed Powering down in $i attempts:" \
			"$ha_power_down_cmd"
		cat $ha_pm_states
		exit 1
	}
}

ha_get_pair()
{
	local node=$1
	local i

	for ((i=0; i<${#ha_victims[@]}; i++)) {
		[[ ${ha_victims[i]} == $node ]] && echo ${ha_victims_pair[i]} &&
			return
	}
	[[ $i -ne ${#ha_victims[@]} ]] ||
		ha_error "No pair found!"
}

ha_power_up_delay()
{
	local nodes=$1
	local end=$(($(date +%s) + ha_node_up_delay))
	local rc

	if [[ ${#ha_victims_pair[@]} -eq 0 ]]; then
		ha_sleep $ha_node_up_delay
		return 0
	fi

	# Check CRM status on failover pair
	while (($(date +%s) <= end)); do
		rc=0
		for n in ${nodes//,/ }; do
			local pair=$(ha_get_pair $n)
			local status=$(ha_on $pair crm_mon -1rQ | \
				grep -w $n | head -1)

			ha_info "$n pair: $pair status: $status"
			[[ "$status" == *OFFLINE* ]] ||
				rc=$((rc + $?))
			ha_info "rc: $rc"
		done

		if [[ $rc -eq 0 ]];  then
			ha_info "CRM: Got all victims status OFFLINE"
			return 0
		fi
		sleep 60
	done

	ha_info "$nodes CRM status not OFFLINE"
	for n in ${nodes//,/ }; do
		local pair=$(ha_get_pair $n)

		ha_info "CRM --- $n"
		ha_on $pair crm_mon -1rQ
	done
	ha_error "CRM: some of $nodes are not OFFLINE in $ha_node_up_delay sec"
	exit 1
}

ha_power_up()
{
	local nodes=$1
	local rc=1
	local i

	ha_power_up_delay $nodes
	ha_info "Powering up $nodes : cmd: $ha_power_up_cmd"
	for (( i=0; i<10; i++ )) {
		ha_info "attempt: $i"
		$ha_power_up_cmd $nodes &&
			ha_powermanage $nodes on && rc=0 && break
		sleep $ha_power_delay
	}

	[ $rc -eq 0 ] || {
		ha_info "Failed Powering up in $i attempts: $ha_power_up_cmd"
		cat $ha_pm_states
		exit 1
	}
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
	local i
	local nodes

	if $ha_simultaneous ; then
		nodes=$(echo ${ha_victims[@]})
		nodes=${nodes// /,}
	else
		i=$(ha_rand ${#ha_victims[@]})
		nodes=${ha_victims[$i]}
	fi

	echo -n $nodes
}

ha_wait_nodes()
{
	local nodes=$1
	local end=$(($(date +%s) + 10 * 60))

	ha_info "Waiting for $nodes to boot up"
	until ha_on $nodes hostname >/dev/null 2>&1 ||
		[ -e "$ha_stop_file" ] ||
			(($(date +%s) >= end)); do
		ha_sleep 1 >/dev/null
	done
}

ha_failback()
{
	local nodes=$1
	ha_info "Failback resources on $nodes in $ha_failback_delay sec"

	ha_sleep $ha_failback_delay
	[ "$ha_failback_cmd" ] ||
	{
		ha_info "No failback command set, skiping"
		return 0
	}

	$ha_failback_cmd $nodes
	[ -e $ha_lfsck_lock ] && ha_unlock $ha_lfsck_lock || true
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
	local nodes

	while (($(date +%s) < ha_start_time + ha_expected_duration)) &&
			[ ! -e "$ha_stop_file" ]; do
		ha_info "---------------8<---------------"

		$ha_workloads_only || nodes=$(ha_aim)

		ha_info "Failing $nodes"
		$ha_workloads_only && ha_info "    is skipped: workload only..."

		ha_sleep $(ha_rand $ha_max_failover_period)
		$ha_workloads_only || ha_power_down $nodes
		ha_sleep 10
		ha_wait_loads || return

		if [ -e $ha_stop_file ]; then
			$ha_workloads_only || ha_power_up $nodes
			break
		fi

		ha_info "Bringing $nodes back"
		ha_sleep $(ha_rand 10)
		$ha_workloads_only ||
		{
			ha_power_up $nodes
			ha_wait_nodes $nodes
			ha_failback $nodes
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

	local mdt_index
	if $ha_test_dir_mdt_index_random &&
		[ $ha_test_dir_mdt_index -ne 0 ]; then
		mdt_index=$(ha_rand $ha_test_dir_mdt_index)
	else
		mdt_index=$ha_test_dir_mdt_index
	fi
	ha_on ${ha_clients[0]} "$LFS mkdir -i$mdt_index \
		-c$ha_test_dir_stripe_count $ha_test_dir"
	ha_on ${ha_clients[0]} $LFS getdirstripe $ha_test_dir
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

	$ha_lfsck_after && ha_start_lfsck | tee -a $ha_lfsck_log

	$ha_lfsck_fail_on_repaired && ha_lfsck_repaired

	if [ -e "$ha_fail_file" ]; then
		exit 1
	else
		ha_log "${ha_clients[*]} ${ha_servers[*]}" \
			"END: $0: $(date +%H:%M:%S' '%s)"
		exit 0
	fi
}

ha_main "$@"
