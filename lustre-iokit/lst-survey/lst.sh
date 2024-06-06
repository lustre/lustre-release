#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

print_help() {
	cat <<EOF
Usage:
${0##*/} -f "nid1[ nid2...]" -t "nidA[ nidB...]" -m read|write|rw|ping [options]
or
${0##*/} -H -f "host1[ host2...]" -t "hostA[ hostB...]" -m read|write|rw|ping [options]

Options:
	-b batch_name
	   Creates a batch test called <batch_name> rather than using the
	   default.
	-c concurrency
	   The number of requests that are active at one time.
	-C simple|full
	   A data validation check (checksum of data). The default is that no
	   check is done.
	-d <source_count:sink_count>
	   Determines the ratio of client nodes to server nodes for the
	   specified test. This allows you to specify a wide range of
	   topologies, including one-to-one and all-to-all. Distribution divides
	   the source group into subsets, which are paired with equivalent
	   subsets from the target group so only nodes in matching subsets
	   communicate.
	-D delay
	   The interval of the statistics (in seconds). Default is 15.
	-e
	   Lists the number of failed RPCs on test nodes in the current session.
	-h
	   Display this help.
	-H
	   Run in "host mode". Host mode indicates that the arguments to '-t'
	   and '-f' flags are hostnames rather than LNet nids. This script will
	   attempt to ssh to each node to ensure the lnet-selftest module is
	   loaded, and to determine the appropriate LNet NIDs to give to LST.
	-f "nid1[ nid2...]"
	   Space-separated list of LNet NIDs to place in the "clients" group.
	   When '-H' flag is specified, the '-f' argument is a space-separated
	   list of hostnames.
	   PDSH-style expressions are supported for NID arguments, but not for
	   host mode ('-H').
	-g servers|clients
	   Report stats only from the specified group. Either 'clients' or
	   'servers'.
	-l loops
	   The number of test loops. Default is -1 (infinite).
	-L
	   Load lnet-selftest module on local and remote hosts. The module will
	   be unloaded at the end of the test execution. Requires running in
	   host mode ('-H').
	-m read|write|rw|ping
	   Type of test to run. 'rw' specifies to run simultaneous read and
	   write test.
	-M
	   Report bandwidth stats in MiB/s (default is MB/s).
	-n count
	   The number of stat RPCs to issue. Default is 1.
	-o <offset>
	   Add off=<offset> to brw tests.
	-s iosize
	   I/O size in bytes, kilobytes, or Megabytes (i.e., -s 1024, -s 4K,
	   -s 1M). The default is 1 Megabyte.
	-S <rate|bw|"rate  bw">
	   By default, only bandwidth stats are displayed for read and write
	   and only RPC rate stats are shown for ping tests. The '-S' flag can
	   be used to override the stat output.
	   Examples:
	     Show only RPC rate stats:
		# lst.sh -S rate ...
	     Show only bandwidth stats:
		# lst.sh -S bw ...
	     Show both bandwidth and RPC rate stats:
		# lst.sh -S "rate bw" ...
		or
		# lst.sh -S "bw rate" ...
	-t "nid1[ nid2...]"
	   Space-separated list of LNet NIDs to place in the "servers" group.
	   When '-H' flag is specified, the '-t' argument is a space-separated
	   list of hostnames.
	   PDSH-style expressions are supported for NID arguments, but not for
	   host mode ('-H').
EOF
	exit
}

stop_lst() {
	local rc=0

	if ${LST_BATCH_STARTED}; then
		$LCTL mark "lst stop ${BATCH_NAME}"

		[[ -n ${ALL_HOSTS} ]] &&
			$PDSH "${ALL_HOSTS}" "$LCTL mark 'lst stop ${BATCH_NAME}'"

		lst stop "${BATCH_NAME}" || rc=$?
		LST_BATCH_STARTED=false
	fi

	if ${LST_SESSION_CREATED}; then
		$LCTL mark "Stop LST $MODE"
		echo "Stop LST $MODE - $(date)"

		[[ -n ${ALL_HOSTS} ]] &&
			$PDSH "${ALL_HOSTS}" "$LCTL mark 'Stop LST $MODE'"

		lst end_session || rc=$((rc + $?))
		LST_SESSION_CREATED=false
	fi

	return $rc
}

exit_handler() {
	local rc=${1:-0}

	trap "" EXIT

	stop_lst || rc=$((rc + $?))

	if ${LOAD_MODULES}; then
		echo "Attempting to 'modprobe -r lnet-selftest' on all hosts (30 second timeout)..."
		$PDSH "${ALL_HOSTS}" -u 30 \
			"if lsmod | grep -q lnet_selftest; then
				 modprobe -r lnet-selftest
			 else
				 :
			 fi" | dshbak -c
		rc=$((rc + PIPESTATUS[0]))
		if lsmod | grep -q lnet_selftest; then
			timeout 30 modprobe -r lnet-selftest
			rc=$((rc + $?))
		fi
	fi

	return $rc
}

LST_SESSION_CREATED=false # Whether 'lst new_session' was executed
LST_BATCH_STARTED=false # Whether 'lst run <batch>' was executed

PDSH="pdsh -S -Rssh -w"
BATCH_NAME=""
CONCURRENCY=16
CHECK=
DISTRIBUTION="1:1"
CLIENTS=""
LOOPS=""
MODE=""
IOSIZE="1m"
SERVERS=""
COUNT="1"
DELAY="15"
STAT_GROUP=""
SHOW_ERRORS=false
STAT_OPTS=""
STAT_OPT_RATE=false
STAT_OPT_BW=false
BW_UNITS="--mbs"
HOST_MODE=false
LOAD_MODULES=false
BRW_OFFSET=""
while getopts "b:C:c:d:D:ef:g:hHl:Lm:Mn:o:s:S:t:" flag ; do
	case $flag in
		b) BATCH_NAME="$OPTARG";;
		c) CONCURRENCY="$OPTARG";;
		C) CHECK="$OPTARG";;
		d) DISTRIBUTION="$OPTARG";;
		D) DELAY="$OPTARG";;
		e) SHOW_ERRORS=true;;
		h) print_help;;
		H) HOST_MODE=true;;
		f) CLIENTS="$OPTARG";;
		g) STAT_GROUP="$OPTARG";;
		l) LOOPS="$OPTARG";;
		L) LOAD_MODULES=true;;
		m) MODE="$OPTARG";;
		M) BW_UNITS="";;
		n) COUNT="$OPTARG";;
		o) BRW_OFFSET="$OPTARG";;
		s) IOSIZE="$OPTARG";;
		S) STAT_OPTS="$OPTARG";;
		t) SERVERS="$OPTARG";;
		*) echo "Unrecognized option '-$flag'"
		   exit 1;;
	esac
done

# find where 'lctl' binary is installed on this system
if [[ -x "$LCTL" ]]; then	# full pathname specified
	: # echo "LCTL=$LCTL"
elif [[ -n "$LUSTRE" && -x "$LUSTRE/utils/lctl" ]]; then
	LCTL=$LUSTRE/utils/lctl
else				# hope that it is in the PATH
	LCTL=${LCTL:-lctl}
fi
#echo "using LCTL='$LCTL' lustre_root='$lustre_root' LUSTRE='$LUSTRE'"
[[ -n "$(which $LCTL)" ]] || { echo "error: lctl not found"; exit 99; }

if [[ -z $CLIENTS ]]; then
	echo "Must specify \"clients\" group (-f)"
	exit 1
elif [[ -z $SERVERS ]]; then
	echo "Must specify \"servers\" group (-t)"
	exit 1
elif [[ -z $MODE ]]; then
	echo "Must specify a mode (-m <read|write|rw|ping>)"
	exit 1
elif ! [[ $MODE =~ read|write|rw|ping ]]; then
	echo "Invalid mode - \"$MODE\". (-m <read|write|rw|ping>)"
	exit 1
elif [[ -z $(which lst 2>/dev/null) ]]; then
	echo "Cannot find lst executable in PATH."
	exit 1
elif ${LOAD_MODULES} && ! ${HOST_MODE}; then
	echo "Module loading ('-L') is only available in host mode ('-H')"
	exit 1
fi

for stat_opt in ${STAT_OPTS}; do
	if [[ $stat_opt == rate ]]; then
		STAT_OPT_RATE=true
	elif [[ $stat_opt == bw ]]; then
		STAT_OPT_BW=true
	else
		echo "Invalid stat option \"-S $stat_opt\""
		print_help
	fi
done

if [[ -z $STAT_GROUP ]]; then
	STAT_GROUP="clients servers"
elif ! [[ $STAT_GROUP =~ clients|servers ]]; then
	echo "Stat group must be either \"clients\" or \"servers\". Found \"$STAT_GROUP\""
	exit 1
fi

if [[ -n ${LOOPS} && ${LOOPS} -eq 0 ]]; then
	echo "Loops must be -1 or > 0. Found \"${LOOPS}\""
	exit 1
fi

if ! ${LOAD_MODULES} && ! lsmod | grep -q lnet_selftest; then
	echo "lnet-selftest module is not loaded on local host."
	echo "Please ensure lnet-selftest module is loaded on the local host and all test nodes."
	exit 1
fi

ALL_HOSTS=""
if ${HOST_MODE}; then
	which pdsh &>/dev/null || { echo "Need pdsh for host mode"; exit; }
	which ssh &>/dev/null || { echo "Need ssh for host mode"; exit; }

	ALL_HOSTS="${SERVERS} ${CLIENTS}"
	ALL_HOSTS=${ALL_HOSTS## }
	ALL_HOSTS=${ALL_HOSTS%% }
	ALL_HOSTS="${ALL_HOSTS// /,}"

	if ${LOAD_MODULES}; then
		echo "Loading lnet-selftest on test nodes"
		$PDSH "${ALL_HOSTS}" \
			"if ! lsmod | grep -q lnet_selftest; then
				 modprobe lnet-selftest 2>&1
			 else
				 true
			 fi" | dshbak -c
		rc=${PIPESTATUS[0]}
		if [[ $rc -ne 0 ]]; then
			echo "Failed to load lnet-selftest module on test nodes"
			exit "$rc"
		fi

		if ! lsmod | grep -q lnet_selftest; then
			modprobe lnet-selftest
			rc=$?
			if [[ $rc -ne 0 ]]; then
				echo "Failed to load lnet-selftest on local host"
				exit $rc
			fi
		fi
	fi

	idx=0
	opts=( -o NumberOfPasswordPrompts=0 -o ConnectTimeout=5 )
	for host in ${SERVERS//,/ }; do
		s_nids[idx]=$(ssh "${opts[@]}" "$host" "$LCTL list_nids | head -n 1")
		if [[ -z ${s_nids[idx]} ]]; then
			echo "Failed to determine primary NID of $host"
			exit 1
		fi
		idx=$((idx + 1))
	done

	idx=0
	for host in ${CLIENTS//,/ }; do
		c_nids[idx]=$(ssh "${opts[@]}" "${host}" "$LCTL list_nids | head -n 1")
		if [[ -z ${c_nids[idx]} ]]; then
			echo "Failed to determine primary NID of $host"
			exit 1
		fi
		idx=$((idx + 1))
	done

	SERVER_NIDS=( "${s_nids[@]}" )
	CLIENT_NIDS=( "${c_nids[@]}" )
else
	IFS=" " read -r -a SERVER_NIDS <<< "${SERVERS}"
	IFS=" " read -r -a CLIENT_NIDS <<< "${CLIENTS}"
fi

if ! grep -q '\[' <<<"${SERVER_NIDS[@]}" && which lnetctl &>/dev/null; then
	echo "Discover server NIDs"
	lnetctl discover "${SERVER_NIDS[@]}" 1>/dev/null
	rc=$?
	if [[ $rc -ne 0 ]]; then
		echo "Failed to discover all server NIDs"
		exit $rc
	fi
fi

if ! grep -q '\[' <<<"${CLIENT_NIDS[@]}" && which lnetctl &>/dev/null; then
	echo "Discover client NIDs"
	lnetctl discover "${CLIENT_NIDS[@]}" 1>/dev/null
	rc=$?
	if [[ $rc -ne 0 ]]; then
		echo "Failed to discover all client NIDs"
		exit $rc
	fi
fi

[[ -n $ALL_HOSTS ]] &&
	$PDSH "$ALL_HOSTS" "$LCTL mark 'Start LST $MODE'"

$LCTL mark "Start LST $MODE"
echo "Start LST $MODE - $(date)"

trap 'exit_handler' EXIT

export LST_SESSION=$$
echo "LST_SESSION=$LST_SESSION"
lst new_session lnet_session || { echo "new_session failed $?"; exit; }
LST_SESSION_CREATED=true

echo "Adding clients: ${CLIENT_NIDS[*]}"
lst add_group clients "${CLIENT_NIDS[@]}" || exit
echo "Adding servers: ${SERVER_NIDS[*]}"
lst add_group servers "${SERVER_NIDS[@]}" || exit

if [[ -z ${BATCH_NAME} ]]; then
	BATCH_NAME="brw_${MODE}"
fi
lst add_batch "${BATCH_NAME}" || exit

test_opts+=( --batch "${BATCH_NAME}" --concurrency "${CONCURRENCY}" )
test_opts+=( --from clients --to servers --distribute "${DISTRIBUTION}" )
[[ -n ${LOOPS} ]] &&
	test_opts+=( --loop "${LOOPS}" )

if [[ $MODE == ping ]]; then
	test_opts+=( ping )
elif [[ $MODE == rw ]]; then
	read_opts=( "${test_opts[@]}" brw read size="$IOSIZE" )
	write_opts=( "${test_opts[@]}" brw write size="$IOSIZE" )
	if [[ -n $CHECK ]];  then
		read_opts+=( check="$CHECK" )
		write_opts+=( check="$CHECK" )
	fi
	if [[ -n $BRW_OFFSET ]]; then
		read_opts+=( off="$BRW_OFFSET" )
		write_opts+=( off="$BRW_OFFSET" )
	fi
else
	test_opts+=( brw "${MODE}" )
	[[ -n $BRW_OFFSET ]] &&
		test_opts+=( off="$BRW_OFFSET" )
	[[ -n $CHECK ]] &&
		test_opts+=( check="$CHECK" )
	test_opts+=( size="$IOSIZE" )
fi

stat_opts=( --count "${COUNT}" --delay "${DELAY}" )
if [[ -n $STAT_OPTS ]]; then
	if ${STAT_OPT_RATE}; then
		stat_opts+=( --rate )
	fi
	if ${STAT_OPT_BW}; then
		stat_opts+=( --bw )
	fi
elif [[ $MODE == ping ]]; then
	stat_opts+=( --rate )
else
	stat_opts+=( --bw "${BW_UNITS}" )
fi

for g in ${STAT_GROUP}; do
	stat_opts+=( "${g}" )
done

if [[ $MODE == rw ]]; then
	echo "Test: ${read_opts[*]}"
	echo "Test: ${write_opts[*]}"
	echo "Stat: ${stat_opts[*]}"
	lst add_test "${read_opts[@]}" || exit
	lst add_test "${write_opts[@]}" || exit
else
	echo "Test: ${test_opts[*]}"
	echo "Stat: ${stat_opts[*]}"
	lst add_test "${test_opts[@]}" || exit
fi

lst run "${BATCH_NAME}" || exit

LST_BATCH_STARTED=true

lst stat "${stat_opts[@]}"

if ${SHOW_ERRORS}; then
	lst show_error --session servers clients
fi

exit
