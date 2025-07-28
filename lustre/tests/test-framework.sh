#!/bin/bash

trap 'print_summary && print_stack_trace | tee $TF_FAIL && \
    echo "$TESTSUITE: FAIL: test-framework exiting on error"' ERR
set -e

export LANG=en_US
export REFORMAT=${REFORMAT:-""}
export WRITECONF=${WRITECONF:-""}
export VERBOSE=${VERBOSE:-false}
export GSS=${GSS:-false}
export GSS_SK=${GSS_SK:-false}
export GSS_KRB5=false
export SHARED_KEY=${SHARED_KEY:-false}
export SK_PATH=${SK_PATH:-/tmp/test-framework-keys}
export SK_OM_PATH=$SK_PATH'/tmp-request-mount'
export SK_MOUNTED=${SK_MOUNTED:-false}
export SK_FLAVOR=${SK_FLAVOR:-ski}
export SK_NO_KEY=${SK_NO_KEY:-true}
export SK_UNIQUE_NM=${SK_UNIQUE_NM:-false}
export SK_S2S=${SK_S2S:-false}
export SK_S2SNM=${SK_S2SNM:-TestFrameNM}
export SK_S2SNMCLI=${SK_S2SNMCLI:-TestFrameNMCli}
export SK_SKIPFIRST=${SK_SKIPFIRST:-true}
# whether identity upcall is enabled (true), disabled (false), or default
export IDENTITY_UPCALL=${IDENTITY_UPCALL:-default}
export QUOTA_AUTO=1
export FLAKEY=${FLAKEY:-true}
# specify environment variable containing batch job name for server statistics
export JOBID_VAR=${JOBID_VAR:-"procname_uid"}  # or "existing" or "disable"

#export PDSH="pdsh -S -Rssh -w"
export MOUNT_CMD=${MOUNT_CMD:-"mount -t lustre"}
export UMOUNT=${UMOUNT:-"umount -d"}

# A switch to enable kptr less restrictively
export KPTR_ON_MOUNT=${KPTR_ON_MOUNT:-true}

export LSNAPSHOT_CONF="/etc/ldev.conf"
export LSNAPSHOT_LOG="/var/log/lsnapshot.log"

export DATA_SEQ_MAX_WIDTH=0x1ffffff

# sles12 umount has a issue with -d option
[ -e /etc/SuSE-release ] && grep -w VERSION /etc/SuSE-release | grep -wq 12 && {
	export UMOUNT="umount"
}

# function used by scripts run on remote nodes
LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/functions.sh
. $LUSTRE/tests/yaml.sh

export LD_LIBRARY_PATH=${LUSTRE}/utils/.libs:${LUSTRE}/utils:${LD_LIBRARY_PATH}

LUSTRE_TESTS_CFG_DIR=${LUSTRE_TESTS_CFG_DIR:-${LUSTRE}/tests/cfg}

EXCEPT_LIST_FILE=${EXCEPT_LIST_FILE:-${LUSTRE_TESTS_CFG_DIR}/tests-to-skip.sh}

if [ -f "$EXCEPT_LIST_FILE" ]; then
	echo "Reading test skip list from $EXCEPT_LIST_FILE"
	cat $EXCEPT_LIST_FILE
	. $EXCEPT_LIST_FILE
fi

# check config files for options in decreasing order of preference
[ -z "$MODPROBECONF" -a -f /etc/modprobe.d/lustre.conf ] &&
    MODPROBECONF=/etc/modprobe.d/lustre.conf
[ -z "$MODPROBECONF" -a -f /etc/modprobe.d/Lustre ] &&
    MODPROBECONF=/etc/modprobe.d/Lustre
[ -z "$MODPROBECONF" -a -f /etc/modprobe.conf ] &&
    MODPROBECONF=/etc/modprobe.conf

sanitize_parameters() {
	for i in DIR DIR1 DIR2 MOUNT MOUNT1 MOUNT2
	do
		local path=${!i}

		if [ -d "$path" ]; then
			eval export $i=$(echo $path | sed -r 's/\/+$//g')
		fi
	done
}
assert_DIR () {
	local failed=""
	[[ $DIR/ = $MOUNT/* ]] ||
		{ failed=1 && echo "DIR=$DIR not in $MOUNT. Aborting."; }
	[[ $DIR1/ = $MOUNT1/* ]] ||
		{ failed=1 && echo "DIR1=$DIR1 not in $MOUNT1. Aborting."; }
	[[ $DIR2/ = $MOUNT2/* ]] ||
		{ failed=1 && echo "DIR2=$DIR2 not in $MOUNT2. Aborting"; }

	[ -n "$failed" ] && exit 99 || true
}

usage() {
	echo "usage: $0 [-r] [-f cfgfile]"
	echo "       -r: reformat"

	exit
}

print_summary () {
	trap 0
	[ -z "$DEFAULT_SUITES" ] && return 0
	[ -n "$ONLY" ] && echo "WARNING: ONLY is set to $(echo $ONLY)"
	local details
	local form="%-13s %-17s %-9s %s %s\n"

	printf "$form" "status" "script" "Total(sec)" "E(xcluded) S(low)"
	echo "---------------------------------------------------------------"
	for O in $DEFAULT_SUITES; do
		O=$(echo $O  | tr "-" "_" | tr "[:lower:]" "[:upper:]")
		[ "${!O}" = "no" ] && continue || true
		local o=$(echo $O  | tr "[:upper:]_" "[:lower:]-")
		local log=${TMP}/${o}.log

		if is_sanity_benchmark $o; then
		    log=${TMP}/sanity-benchmark.log
		fi
		local slow=
		local skipped=
		local total=
		local status=Unfinished

		if [ -f $log ]; then
			skipped=$(grep excluded $log |
				awk '{ printf " %s", $3 }' | sed 's/test_//g')
			slow=$(egrep "^PASS|^FAIL" $log |
				tr -d "("| sed s/s\)$//g | sort -nr -k 3 |
				head -n5 |  awk '{ print $2":"$3"s" }')
			total=$(grep duration $log | awk '{ print $2 }')
			if [ "${!O}" = "done" ]; then
				status=Done
			fi
			if $DDETAILS; then
				local durations=$(egrep "^PASS|^FAIL" $log |
					tr -d "("| sed s/s\)$//g |
					awk '{ print $2":"$3"|" }')
				details=$(printf "%s\n%s %s %s\n" "$details" \
					"DDETAILS" "$O" "$(echo $durations)")
			fi
		fi
		printf "$form" $status "$O" "${total}" "E=$skipped"
		printf "$form" "-" "-" "-" "S=$(echo $slow)"
	done

	for O in $DEFAULT_SUITES; do
		O=$(echo $O  | tr "-" "_" | tr "[:lower:]" "[:upper:]")
			if [ "${!O}" = "no" ]; then
				printf "$form" "Skipped" "$O" ""
			fi
	done

	# print the detailed tests durations if DDETAILS=true
	if $DDETAILS; then
		echo "$details"
	fi
}

reset_lustre() {
	if $do_reset; then
		stopall
		setupall
	fi
}

setup_if_needed() {
	! ${do_setup} && return
	nfs_client_mode && return
	AUSTER_CLEANUP=false

	local MOUNTED=$(mounted_lustre_filesystems)

	if $(echo $MOUNTED' ' | grep -w -q $MOUNT' '); then
		check_config_clients $MOUNT
		# init_facets_vars
		# init_param_vars
		return
	fi

	echo "Lustre is not mounted, trying to do setup ... "
	$reformat && CLEANUP_DM_DEV=true formatall
	setupall

	MOUNTED=$(mounted_lustre_filesystems)
	if ! $(echo $MOUNTED' ' | grep -w -q $MOUNT' '); then
		echo "Lustre is not mounted after setup! "
		exit 1
	fi
	AUSTER_CLEANUP=true
}

cleanup_if_needed() {
	if $AUSTER_CLEANUP; then
		cleanupall
	fi
}

find_script_in_path() {
	target=$1
	path=$2
	for dir in $(tr : " " <<< $path); do
		if [ -f $dir/$target ]; then
			echo $dir/$target
			return 0
		fi
		if [ -f $dir/$target.sh ]; then
			echo $dir/$target.sh
			return 0
		fi
	done
	return 1
}

title() {
	log "-----============= acceptance-small: "$*" ============----- `date`"
}

doit() {
	if $dry_run; then
		printf "Would have run: %s\n" "$*"
		return 0
	fi
	if $verbose; then
		printf "Running: %s\n" "$*"
	fi
	"$@"
}


run_suite() {
	local suite_name=$1
	local suite_script=$2

	title $suite_name
	log_test $suite_name

	rm -f $TF_FAIL
	touch $TF_SKIP

	local start_ts=$(date +%s)

	doit $script_lang $suite_script

	local rc=$?
	local duration=$(($(date +%s) - $start_ts))
	local status="PASS"

	if [[ $rc -ne 0 || -f $TF_FAIL ]]; then
		status="FAIL"
	elif [[ -f $TF_SKIP ]]; then
		status="SKIP"
	fi
	log_test_status $duration $status
	[[ ! -f $TF_SKIP ]] || rm -f $TF_SKIP

	# got STOP_NOW_RC, return immediately before reset
	[[ $rc -eq $STOP_NOW_RC ]] &&
		echo "stop testing on rc $STOP_NOW_RC" &&
		return $STOP_NOW_RC

	reset_lustre

	return $rc
}

run_suite_logged() {
	local suite_name=${1%.sh}
	local suite=$(echo ${suite_name} | tr "[:lower:]-" "[:upper:]_")

	suite_script=$(find_script_in_path $suite_name $LUSTRE/tests)

	if [[ -z $suite_script ]]; then
		echo "Can't find test script for $suite_name"
		return 1
	fi

	echo "run_suite $suite_name $suite_script"

	local log_name=${suite_name}.suite_log.$(hostname -s).log

	if $verbose; then
		run_suite $suite_name $suite_script 2>&1 |tee  $LOGDIR/$log_name
	else
		run_suite $suite_name $suite_script > $LOGDIR/$log_name 2>&1
	fi

	return ${PIPESTATUS[0]}
}

reset_logging() {
	export LOGDIR=$1

	unset YAML_LOG
	init_logging
}

split_commas() {
	echo "${*//,/ }"
}

run_suites() {
	local n=0
	local argv=("$@")

	while ((n < repeat_count)); do
		local RC=0
		local logdir=${test_logs_dir}
		local first_suite=$FIRST_SUITE

		((repeat_count > 1)) && logdir="$logdir/$n"
		reset_logging $logdir
		set -- "${argv[@]}"
		while [[ -n $1 ]]; do
			unset ONLY EXCEPT START_AT STOP_AT
			local opts=""
			local time_limit=""

			suite=$1
			shift;
			while [[ -n $1 ]]; do
			case "$1" in
				--only)
					shift;
					export ONLY=$(split_commas $1)

					opts+="ONLY=$ONLY ";;
				--suite)
					shift;
					export SUITE=$(split_commas $1)

					opts+="SUITE=$SUITE ";;
				--pattern)
					shift;
					export PATTERN=$(split_commas $1)

					opts+="PATTERN=$PATTERN ";;
				--except)
					shift;
					export EXCEPT=$(split_commas $1)

					opts+="EXCEPT=$EXCEPT ";;
				--start-at)
					shift;
					export START_AT=$1

					opts+="START_AT=$START_AT ";;
				--stop-at)
					shift;
					export STOP_AT=$1

					opts+="STOP_AT=$STOP_AT ";;
				--stop-on-error)
					shift;
					export STOP_ON_ERROR=$(split_commas $1)

					opts+="STOP_ON_ERROR=$STOP_ON_ERROR ";;
				--time-limit)
					shift;
					time_limit=$1;;
				*)
					break;;
			esac
			shift
			done

		# If first_suite not set or this is the first suite
		if [ "x"$first_suite == "x" ] || [ $first_suite == $suite ]; then
			echo "running: $suite $opts"
			run_suite_logged $suite || RC=$?
			unset first_suite
			echo $suite returned $RC

			# stop testing immediately if rc is STOP_NOW_RC
			[[ $RC -eq $STOP_NOW_RC ]] && exit $STOP_NOW_RC
		fi
		done
	if $upload_logs; then
		$upload_script $LOGDIR
	fi
	n=$((n + 1))
	done
}

# Get information about the Lustre environment. The information collected
# will be used in Lustre tests.
# usage: get_lustre_env
# input: No required or optional arguments
# output: No return values, environment variables are exported

get_lustre_env() {
	if ! $RPC_MODE; then
		export mds1_FSTYPE=${mds1_FSTYPE:-$(facet_fstype mds1)}
		export ost1_FSTYPE=${ost1_FSTYPE:-$(facet_fstype ost1)}

		export MGS_VERSION=$(lustre_version_code mgs)
		export MDS1_VERSION=$(lustre_version_code mds1)
		export OST1_VERSION=$(lustre_version_code ost1)
		export CLIENT_VERSION=$(lustre_version_code client)

		# import server-side version information into local variables
		# so they can be used in tests instead of checked separately
		# MGS_OS_VERSION_ID, MGS_OS_ID, MGS_OS_ID_LIKE,
		# MDS1_OS_VERSION_ID, MDS1_OS_ID, MDS1_OS_ID_LIKE,
		# OST1_OS_VERSION_ID, OST1_OS_ID, OST1_OS_ID_LIKE,
		# CLIENT_OS_VERSION_ID, CLIENT_OS_ID, CLIENT_OS_ID_LIKE
		lustre_os_release mgs
		lustre_os_release mds1
		lustre_os_release ost1
		lustre_os_release client
	fi

	# Prefer using "mds1" directly instead of SINGLEMDS.
	# Keep this for compat until it is removed from scripts.
	export SINGLEMDS=${SINGLEMDS:-mds1}
}

init_test_env() {
	export LUSTRE=$(absolute_path $LUSTRE)
	export TESTSUITE=$(basename $0 .sh)
	export TEST_FAILED=false
	export FAIL_ON_SKIP_ENV=${FAIL_ON_SKIP_ENV:-false}
	export RPC_MODE=${RPC_MODE:-false}
	export DO_CLEANUP=${DO_CLEANUP:-true}
	export KEEP_ZPOOL=${KEEP_ZPOOL:-false}
	export CLEANUP_DM_DEV=false
	export PAGE_SIZE=$(get_page_size client)
	export NAME=${NAME:-local}

	. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

	export MKE2FS=$MKE2FS
	if [ -z "$MKE2FS" ]; then
		if which mkfs.ldiskfs >/dev/null 2>&1; then
			export MKE2FS=mkfs.ldiskfs
		else
			export MKE2FS=mke2fs
		fi
	fi

	export DEBUGFS=$DEBUGFS
	if [ -z "$DEBUGFS" ]; then
		if which debugfs.ldiskfs >/dev/null 2>&1; then
			export DEBUGFS=debugfs.ldiskfs
		else
			export DEBUGFS=debugfs
		fi
	fi

	export TUNE2FS=$TUNE2FS
	if [ -z "$TUNE2FS" ]; then
		if which tunefs.ldiskfs >/dev/null 2>&1; then
			export TUNE2FS=tunefs.ldiskfs
		else
			export TUNE2FS=tune2fs
		fi
	fi

	export E2LABEL=$E2LABEL
	if [ -z "$E2LABEL" ]; then
		if which label.ldiskfs >/dev/null 2>&1; then
			export E2LABEL=label.ldiskfs
		else
			export E2LABEL=e2label
		fi
	fi

	export DUMPE2FS=$DUMPE2FS
	if [ -z "$DUMPE2FS" ]; then
		if which dumpfs.ldiskfs >/dev/null 2>&1; then
			export DUMPE2FS=dumpfs.ldiskfs
		else
			export DUMPE2FS=dumpe2fs
		fi
	fi

	export E2FSCK=$E2FSCK
	if [ -z "$E2FSCK" ]; then
		if which fsck.ldiskfs >/dev/null 2>&1; then
			export E2FSCK=fsck.ldiskfs
		else
			 export E2FSCK=e2fsck
		fi
	fi

	export RESIZE2FS=$RESIZE2FS
	if [ -z "$RESIZE2FS" ]; then
		if which resizefs.ldiskfs >/dev/null 2>&1; then
			export RESIZE2FS=resizefs.ldiskfs
		else
			export RESIZE2FS=resize2fs
		fi
	fi

	export LFSCK_ALWAYS=${LFSCK_ALWAYS:-"no"} # check fs after test suite
	export FSCK_MAX_ERR=4   # File system errors left uncorrected

	export ZFS=${ZFS:-zfs}
	export ZPOOL=${ZPOOL:-zpool}
	export ZDB=${ZDB:-zdb}
	export PARTPROBE=${PARTPROBE:-partprobe}

	#[ -d /r ] && export ROOT=${ROOT:-/r}
	export TMP=${TMP:-$ROOT/tmp}
	export TESTSUITELOG=${TMP}/${TESTSUITE}.log
	export LOGDIR=${LOGDIR:-${TMP}/test_logs/$(date +%s)}
	export TESTLOG_PREFIX=$LOGDIR/$TESTSUITE

	export HOSTNAME=${HOSTNAME:-$(hostname -s)}
	if ! echo $PATH | grep -q $LUSTRE/utils; then
		export PATH=$LUSTRE/utils:$PATH
	fi
	if ! echo $PATH | grep -q $LUSTRE/utils/gss; then
		export PATH=$LUSTRE/utils/gss:$PATH
	fi
	if ! echo $PATH | grep -q $LUSTRE/tests; then
		export PATH=$LUSTRE/tests:$PATH
	fi
	if ! echo $PATH | grep -q $LUSTRE/../lustre-iokit/sgpdd-survey; then
		export PATH=$LUSTRE/../lustre-iokit/sgpdd-survey:$PATH
	fi
	export LST=${LST:-"$LUSTRE/../lnet/utils/lst"}
	[ ! -f "$LST" ] && export LST=$(which lst)
	export LSTSH=${LSTSH:-"$LUSTRE/../lustre-iokit/lst-survey/lst.sh"}
	[ ! -f "$LSTSH" ] && export LSTSH=$(which lst.sh)
	export SGPDDSURVEY=${SGPDDSURVEY:-"$LUSTRE/../lustre-iokit/sgpdd-survey/sgpdd-survey")}
	[ ! -f "$SGPDDSURVEY" ] && export SGPDDSURVEY=$(which sgpdd-survey)
	export MCREATE=${MCREATE:-mcreate}
	export MULTIOP=${MULTIOP:-multiop}
	export MMAP_CAT=${MMAP_CAT:-mmap_cat}
	export STATX=${STATX:-statx}
	# Ubuntu, at least, has a truncate command in /usr/bin
	# so fully path our truncate command.
	export TRUNCATE=${TRUNCATE:-$LUSTRE/tests/truncate}
	export FSX=${FSX:-$LUSTRE/tests/fsx}
	export MDSRATE=${MDSRATE:-"$LUSTRE/tests/mpi/mdsrate"}
	[ ! -f "$MDSRATE" ] && export MDSRATE=$(which mdsrate 2> /dev/null)
	if ! echo $PATH | grep -q $LUSTRE/tests/racer; then
		export PATH=$LUSTRE/tests/racer:$PATH:
	fi
	if ! echo $PATH | grep -q $LUSTRE/tests/mpi; then
		export PATH=$LUSTRE/tests/mpi:$PATH
	fi

	export LNETCTL=${LNETCTL:-"$LUSTRE/../lnet/utils/lnetctl"}
	[ ! -f "$LNETCTL" ] && export LNETCTL=$(which lnetctl 2> /dev/null)
	export LCTL=${LCTL:-"$LUSTRE/utils/lctl"}
	[ ! -f "$LCTL" ] && export LCTL=$(which lctl)
	export LFS=${LFS:-"$LUSTRE/utils/lfs"}
	[ ! -f "$LFS" ] && export LFS=$(which lfs)
	export KSOCKLND_CONFIG=${KSOCKLND_CONFIG:-"$LUSTRE/scripts/ksocklnd-config"}
	[ ! -f "$KSOCKLND_CONFIG" ] &&
		export KSOCKLND_CONFIG=$(which ksocklnd-config 2> /dev/null)
	export LNET_SYSCTL_CONFIG=${LNET_SYSCTL_CONFIG:-"$LUSTRE/scripts/lnet-sysctl-config"}
	[ ! -f "$LNET_SYSCTL_CONFIG" ] &&
		export LNET_SYSCTL_CONFIG=$(which lnet-sysctl-config 2> /dev/null)

	export PERM_CMD=$(echo ${PERM_CMD:-"$LCTL conf_param"})

	export L_GETIDENTITY=${L_GETIDENTITY:-"$LUSTRE/utils/l_getidentity"}
	if [ ! -f "$L_GETIDENTITY" ]; then
		if $(which l_getidentity > /dev/null 2>&1); then
			export L_GETIDENTITY=$(which l_getidentity)
		else
			export L_GETIDENTITY=NONE
		fi
	fi
	export LL_DECODE_FILTER_FID=${LL_DECODE_FILTER_FID:-"$LUSTRE/utils/ll_decode_filter_fid"}
	[ ! -f "$LL_DECODE_FILTER_FID" ] &&
		export LL_DECODE_FILTER_FID="ll_decode_filter_fid"
	export LL_DECODE_LINKEA=${LL_DECODE_LINKEA:-"$LUSTRE/utils/ll_decode_linkea"}
	[ ! -f "$LL_DECODE_LINKEA" ] &&
		export LL_DECODE_LINKEA="ll_decode_linkea"
	export MKFS=${MKFS:-"$LUSTRE/utils/mkfs.lustre"}
	[ ! -f "$MKFS" ] && export MKFS="mkfs.lustre"
	export TUNEFS=${TUNEFS:-"$LUSTRE/utils/tunefs.lustre"}
	[ ! -f "$TUNEFS" ] && export TUNEFS="tunefs.lustre"
	export CHECKSTAT="${CHECKSTAT:-"checkstat -v"} "
	export LUSTRE_RMMOD=${LUSTRE_RMMOD:-$LUSTRE/scripts/lustre_rmmod}
	[ ! -f "$LUSTRE_RMMOD" ] &&
		export LUSTRE_RMMOD=$(which lustre_rmmod 2> /dev/null)
	export LUSTRE_ROUTES_CONVERSION=${LUSTRE_ROUTES_CONVERSION:-$LUSTRE/scripts/lustre_routes_conversion}
	[ ! -f "$LUSTRE_ROUTES_CONVERSION" ] &&
		export LUSTRE_ROUTES_CONVERSION=$(which lustre_routes_conversion 2> /dev/null)
	export LFS_MIGRATE=${LFS_MIGRATE:-$LUSTRE/scripts/lfs_migrate}
	[ ! -f "$LFS_MIGRATE" ] &&
		export LFS_MIGRATE=$(which lfs_migrate 2> /dev/null)
	export LR_READER=${LR_READER:-"$LUSTRE/utils/lr_reader"}
	[ ! -f "$LR_READER" ] &&
		export LR_READER=$(which lr_reader 2> /dev/null)
	[ -z "$LR_READER" ] && export LR_READER="/usr/sbin/lr_reader"
	export LSOM_SYNC=${LSOM_SYNC:-"$LUSTRE/utils/llsom_sync"}
	[ ! -f "$LSOM_SYNC" ] &&
		export LSOM_SYNC=$(which llsom_sync 2> /dev/null)
	[ -z "$LSOM_SYNC" ] && export LSOM_SYNC="/usr/sbin/llsom_sync"
	export L_GETAUTH=${L_GETAUTH:-"$LUSTRE/utils/gss/l_getauth"}
	[ ! -f "$L_GETAUTH" ] && export L_GETAUTH=$(which l_getauth 2> /dev/null)
	export LSVCGSSD=${LSVCGSSD:-"$LUSTRE/utils/gss/lsvcgssd"}
	[ ! -f "$LSVCGSSD" ] && export LSVCGSSD=$(which lsvcgssd 2> /dev/null)
	export KRB5DIR=${KRB5DIR:-"/usr/kerberos"}
	export DIR2
	export SAVE_PWD=${SAVE_PWD:-$LUSTRE/tests}
	export AT_MAX_PATH
	export LDEV=${LDEV:-"$LUSTRE/scripts/ldev"}
	[ ! -f "$LDEV" ] && export LDEV=$(which ldev 2> /dev/null)

	export DMSETUP=${DMSETUP:-dmsetup}
	export DM_DEV_PATH=${DM_DEV_PATH:-/dev/mapper}
	export LOSETUP=${LOSETUP:-losetup}

	if [ "$ACCEPTOR_PORT" ]; then
		export PORT_OPT="--port $ACCEPTOR_PORT"
	fi

	if $SHARED_KEY; then
		$RPC_MODE || echo "Using GSS shared-key feature"
		[ -n "$LGSS_SK" ] ||
			export LGSS_SK=$(which lgss_sk 2> /dev/null)
		[ -n "$LGSS_SK" ] ||
			export LGSS_SK="$LUSTRE/utils/gss/lgss_sk"
		[ -n "$LGSS_SK" ] ||
			error_exit "built with lgss_sk disabled! SEC=$SEC"
		GSS=true
		GSS_SK=true
		SEC=$SK_FLAVOR
	fi

	case "x$SEC" in
		xkrb5*)
		$RPC_MODE || echo "Using GSS/krb5 ptlrpc security flavor"
		which lgss_keyring > /dev/null 2>&1 ||
			error_exit "built with gss disabled! SEC=$SEC"
		GSS=true
		GSS_KRB5=true
		;;
	esac

	export LOAD_MODULES_REMOTE=${LOAD_MODULES_REMOTE:-false}

	# Paths on remote nodes, if different
	export RLUSTRE=${RLUSTRE:-$LUSTRE}
	export RPWD=${RPWD:-$PWD}
	export I_MOUNTED=${I_MOUNTED:-"no"}
	export AUSTER_CLEANUP=${AUSTER_CLEANUP:-false}
	if [ ! -f /lib/modules/$(uname -r)/kernel/fs/lustre/mdt.ko -a \
	     ! -f /lib/modules/$(uname -r)/updates/kernel/fs/lustre/mdt.ko -a \
	     ! -f /lib/modules/$(uname -r)/extra/kernel/fs/lustre/mdt.ko -a \
	     ! -f $LUSTRE/mdt/mdt.ko ]; then
	    export CLIENTMODSONLY=yes
	fi

	export SHUTDOWN_ATTEMPTS=${SHUTDOWN_ATTEMPTS:-3}
	export OSD_TRACK_DECLARES_LBUG=${OSD_TRACK_DECLARES_LBUG:-"yes"}

	# command line

	while getopts "rvwf:" opt $*; do
		case $opt in
			f) CONFIG=$OPTARG;;
			r) REFORMAT=yes;;
			v) VERBOSE=true;;
			w) WRITECONF=writeconf;;
			\?) usage;;
		esac
	done

	shift $((OPTIND - 1))
	ONLY=${ONLY:-$*}

	# print the durations of each test if "true"
	DDETAILS=${DDETAILS:-false}
	[ "$TESTSUITELOG" ] && rm -f $TESTSUITELOG || true
	if ! $RPC_MODE; then
		rm -f $TMP/*active
	fi

	export TF_FAIL=${TF_FAIL:-$TMP/tf.fail}

	# Constants used in more than one test script
	export LOV_MAX_STRIPE_COUNT=2000
	export LMV_MAX_STRIPES_PER_MDT=5
	export DELETE_OLD_POOLS=${DELETE_OLD_POOLS:-false}
	export KEEP_POOLS=${KEEP_POOLS:-false}
	export PARALLEL=${PARALLEL:-"no"}

	export BLCKSIZE=${BLCKSIZE:-4096}
	export MACHINEFILE=${MACHINEFILE:-$TMP/$(basename $0 .sh).machines}
	get_lustre_env

	# use localrecov to enable recovery for local clients, LU-12722
	[[ $MDS1_VERSION -lt $(version_code 2.13.52) ]] || {
		export MDS_MOUNT_OPTS=${MDS_MOUNT_OPTS:-"-o localrecov"}
		export MGS_MOUNT_OPTS=${MGS_MOUNT_OPTS:-"-o localrecov"}
	}

	[[ $OST1_VERSION -lt $(version_code 2.13.52) ]] ||
		export OST_MOUNT_OPTS=${OST_MOUNT_OPTS:-"-o localrecov"}

	# Force large nid testing, if unset or false then large NIDs will only
	# be used if they are the only addresses assigned to the LNet
	# interfaces
	export FORCE_LARGE_NID=${FORCE_LARGE_NID:-false}
	if ${FORCE_LARGE_NID}; then
		export LNET_CONFIG_INIT_OPT="--all --large"
		export LNET_CONFIG_OPT="-l"
	else
		export LNET_CONFIG_INIT_OPT="--all"
		export LNET_CONFIG_OPT=""
	fi
}

check_cpt_number() {
	local facet=$1
	local ncpts

	ncpts=$(do_facet $facet "lctl get_param -n " \
		"cpu_partition_table 2>/dev/null| wc -l" || echo 1)

	if [ $ncpts -eq 0 ]; then
		echo "1"
	else
		echo $ncpts
	fi
}

# Return a numeric version code based on a version string.  The version
# code is useful for comparison two version strings to see which is newer.
version_code() {
	# split arguments like "1.8.6-wc3" into "1", "8", "6", "3"
	eval set -- $(tr "[:punct:][a-zA-Z]" " " <<< $*)

	echo -n $(((${1:-0}<<24) | (${2:-0}<<16) | (${3:-0}<<8) | (${4:-0})))
}

export LINUX_VERSION=$(uname -r | sed -e "s/\([0-9]*\.[0-9]*\.[0-9]*\).*/\1/")
export LINUX_VERSION_CODE=$(version_code ${LINUX_VERSION//\./ })

# Report the Lustre build version string (e.g. 1.8.7.3 or 2.4.1).
#
# usage: lustre_build_version_node
#
# All Lustre versions support "lctl get_param" to report the version of the
# code running in the kernel (what our tests are interested in), but it
# doesn't work without modules loaded.  After 2.9.53 and in upstream kernels
# the "version" parameter doesn't include "lustre: " at the beginning.
# If that fails, call "lctl lustre_build_version" which prints either (or both)
# the userspace and kernel build versions, but until 2.8.55 required root
# access to get the Lustre kernel version.  If that also fails, fall back to
# using "lctl --version", which is easy to parse and works without the kernel
# modules, but was only added in 2.6.50 and only prints the lctl tool version,
# not the module version, though they are usually the same.
#
# Various commands and their output format for different Lustre versions:
# lctl get_param version:	2.9.55
# lctl get_param version:	lustre: 2.8.53
# lctl get_param version:	lustre: 2.6.52
#				kernel: patchless_client
#				build: v2_6_92_0-2.6.32-431.el6_lustre.x86_64
# lctl lustre_build_version:	Lustre version: 2.8.53_27_gae67fc01
# lctl lustre_build_version:	error: lustre_build_version: Permission denied
#	(as non-root user)	lctl   version: v2_6_92_0-2.6.32-431.el6.x86_64
# lctl lustre_build_version:	Lustre version: 2.5.3-2.6.32.26-175.fc12.x86_64
#				lctl   version: 2.5.3-2.6.32..26-175fc12.x86_64
# lctl --version:		lctl 2.6.50
#
# output: prints version string to stdout in (up to 4) dotted-decimal values
lustre_build_version_node() {
	local node=$1
	local ver
	local lver

	# this is the currently-running version of the kernel modules
	ver=$(do_node $node "$LCTL get_param -n version 2>/dev/null")
	# we mostly test 2.10+ systems, only try others if the above fails
	if [ -z "$ver" ]; then
		ver=$(do_node $node "$LCTL lustre_build_version 2>/dev/null")
	fi
	if [ -z "$ver" ]; then
		ver=$(do_node $node "$LCTL --version 2>/dev/null" |
		      cut -d' ' -f2)
	fi
	local lver=$(egrep -i "lustre: |version: " <<<"$ver" | head -n 1)
	[ -n "$lver" ] && ver="$lver"

	lver=$(sed -e 's/[^:]*: //' -e 's/^v//' -e 's/[ -].*//' <<<$ver |
	       tr _ . | cut -d. -f1-4)

	echo $lver
}

lustre_build_version() {
	local facet=${1:-client}
	local node=$(facet_active_host $facet)
	local facet_version=${facet}_VERSION
	local lver

	# if the global variable is already set, then use that
	[ -n "${!facet_version}" ] && echo ${!facet_version} && return

	lver=$(lustre_build_version_node $node)
	# save in global variable for the future
	export $facet_version=$lver

	echo $lver
}

# Report the Lustre numeric build version code for the supplied facet.
lustre_version_code() {
	version_code $(lustre_build_version $1)
}

# Extract the server-side /etc/os-release information into local variables
# usage: lustre_os_release <facet>
# generates $facet_OS_ID, $facet_OS_ID_LIKE, $facet_VERSION_ID
# and also $facet_OS_VERSION_CODE=$(version_code $facet_VERSION_ID)
lustre_os_release() {
	local facet=$1
	local facet_os=$(tr "[:lower:]" "[:upper:]" <<<$facet)_OS_
	local facet_version=${facet_os}VERSION_
	local line

	echo "$facet: $(do_facet $facet "cat /etc/system-release")"
	do_facet $facet "test -r /etc/os-release" || {
		echo "$facet: has no /etc/os-release"
		do_facet $facet "uname -a; ls -s /etc/*release"
		return 0
	}

	while read line; do
		# more variables in os-release could be exported, but these
		# are the ones that looked enough for our needs here
		case $line in
		VERSION_ID=*|ID=*|ID_LIKE=*) eval export ${facet_os}$line ;;
		esac
	done < <(do_facet $facet "cat /etc/os-release")

	eval export ${facet_version}CODE=\$\(version_code \$${facet_version}ID\)
	# add in the "self" ID to ID_LIKE so only one needs to be checked
	eval export ${facet_os}ID_LIKE+=\" \$${facet_os}ID\"
	env | grep "${facet_os}"
}

module_loaded () {
	/sbin/lsmod | grep -q "^\<$1\>"
}

check_lfs_df_ret_val() {
	# Ignore only EOPNOTSUPP (which is 95; Operation not supported) error
	# returned by 'lfs df' for valid dentry but not a lustrefs.
	#
	# 'lfs df' historically always returned success(0) instead of
	# EOPNOTSUPP. This function for compatibility reason, ignores and
	# masquerades EOPNOTSUPP as success.
	[[ $1 -eq 95 ]] && return 0
	return $1
}

PRLFS=false
lustre_insmod() {
	local module=$1
	shift
	local args="$@"
	local msg
	local rc=0

	if ! $PRLFS; then
		msg="$(insmod $module $args 2>&1)" && return 0 || rc=$?
	fi

	# parallels can't load modules directly from prlfs, use /tmp instead
	if $PRLFS || [[ "$(stat -f -c%t $module)" == "7c7c6673" ]]; then
		local target="$(mktemp)"

		cp "$module" "$target"
		insmod $target $args
		rc=$?
		[[ $rc == 0 ]] && PRLFS=true
		rm -f $target
	else
		echo "$msg"
	fi
	return $rc
}

# Load a module on the system where this is running.
#
# usage: load_module module_name [module arguments for insmod/modprobe]
#
# If module arguments are not given but MODOPTS_<MODULE> is set, then its value
# will be used as the arguments.  Otherwise arguments will be obtained from
# /etc/modprobe.conf, from /etc/modprobe.d/Lustre, or else none will be used.
#
load_module() {
	local module=$1 # '../libcfs/libcfs/libcfs', 'obdclass/obdclass', ...
	shift
	local ext=".ko"
	local base=$(basename $module $ext)
	local path
	local -A module_is_loaded_aa
	local optvar
	local mod

	for mod in $(lsmod | awk '{ print $1; }'); do
		module_is_loaded_aa[${mod//-/_}]=true
	done

	module_is_loaded() {
		${module_is_loaded_aa[${1//-/_}]:-false}
	}

	if module_is_loaded $base; then
		return
	fi

	if [[ -f $LUSTRE/$module$ext ]]; then
		path=$LUSTRE/$module$ext
	elif [[ "$base" == lnet_selftest ]] &&
	     [[ -f $LUSTRE/../lnet/selftest/$base$ext ]]; then
		path=$LUSTRE/../lnet/selftest/$base$ext
	else
		path=''
	fi

	if [[ -n "$path" ]]; then
		# Try to load any non-Lustre modules that $module depends on.
		for mod in $(modinfo --field=depends $path | tr ',' ' '); do
			if ! module_is_loaded $mod; then
				modprobe $mod
			fi
		done
	fi

	# If no module arguments were passed then get them from
	# $MODOPTS_<MODULE>, otherwise from modprobe.conf.
	if [ $# -eq 0 ]; then
		# $MODOPTS_<MODULE>; we could use associative arrays, but that's
		# not in Bash until 4.x, so we resort to eval.
		optvar="MODOPTS_$(basename $module | tr a-z A-Z)"
		eval set -- \$$optvar
		if [ $# -eq 0 -a -n "$MODPROBECONF" ]; then
			# Nothing in $MODOPTS_<MODULE>; try modprobe.conf
			local opt
			opt=$(awk -v var="^options $base" '$0 ~ var \
			      {gsub("'"options $base"'",""); print}' \
				$MODPROBECONF)
			set -- $(echo -n $opt)

			# Ensure we have accept=all for lnet
			if [[ "$base" == lnet ]]; then
				# OK, this is a bit wordy...
				local arg accept_all_present=false

				for arg in "$@"; do
					[[ "$arg" == accept=all ]] &&
						accept_all_present=true
				done

				$accept_all_present || set -- "$@" accept=all
			fi

			export $optvar="$*"
		fi
	fi

	[ $# -gt 0 ] && echo "${module} options: '$*'"

	# Note that insmod will ignore anything in modprobe.conf, which is why
	# we're passing options on the command-line. If $path does not exist
	# then we must be testing a "make install" or"rpm" installation. Also
	# note that failing to load ptlrpc_gss is not considered fatal.
	if [[ -n "$path" ]]; then
		lustre_insmod $path "$@"
	elif [[ "$base" == ptlrpc_gss ]]; then
		if ! modprobe $base "$@" 2>/dev/null; then
			echo "gss/krb5 is not supported"
		fi
	else
		modprobe $base "$@"
	fi
}

do_lnetctl() {
	$LCTL mark "$LNETCTL $*"
	echo "$LNETCTL $*"
	$LNETCTL "$@"
}

load_lnet() {
	# For kmemleak-enabled kernels we need clear all past state
	# that obviously has nothing to do with this Lustre run
	# Disable automatic memory scanning to avoid perf hit.
	if [ -f /sys/kernel/debug/kmemleak ] ; then
		echo scan=off > /sys/kernel/debug/kmemleak || true
		echo scan > /sys/kernel/debug/kmemleak || true
		echo clear > /sys/kernel/debug/kmemleak || true
	fi

	echo Loading modules from $LUSTRE

	local ncpus

	if [ -f /sys/devices/system/cpu/online ]; then
		ncpus=$(($(cut -d "-" -f 2 /sys/devices/system/cpu/online) + 1))
		echo "detected $ncpus online CPUs by sysfs"
	else
		ncpus=$(getconf _NPROCESSORS_CONF 2>/dev/null)
		local rc=$?

		if [ $rc -eq 0 ]; then
			echo "detected $ncpus online CPUs by getconf"
		else
			echo "Can't detect number of CPUs"
			ncpus=1
		fi
	fi

	# if there is only one CPU core, libcfs can only create one partition
	# if there is more than 4 CPU cores, libcfs should create multiple CPU
	# partitions. So we just force libcfs to create 2 partitions for
	# system with 2 or 4 cores
	local saved_opts="$MODOPTS_LIBCFS"

	if [ $ncpus -le 4 ] && [ $ncpus -gt 1 ]; then
		# force to enable multiple CPU partitions
		echo "Force libcfs to create 2 CPU partitions"
		MODOPTS_LIBCFS="cpu_npartitions=2 $MODOPTS_LIBCFS"
	else
		echo "libcfs will create CPU partition based on online CPUs"
	fi

	load_module ../libcfs/libcfs/libcfs
	# Prevent local MODOPTS_LIBCFS being passed as part of environment
	# variable to remote nodes
	unset MODOPTS_LIBCFS

	set_default_debug "neterror net nettrace malloc"
	if [[ $1 == config_on_load=1 ]]; then
		load_module ../lnet/lnet/lnet
	else
		load_module ../lnet/lnet/lnet "$@"
	fi

	LNDPATH=${LNDPATH:-"../lnet/klnds"}
	if [ -z "$LNETLND" ]; then
		case $NETTYPE in
		o2ib*)	LNETLND="o2iblnd/ko2iblnd" ;;
		tcp*)	LNETLND="socklnd/ksocklnd" ;;
		kfi*)	LNETLND="kfilnd/kkfilnd" ;;
		gni*)	LNETLND="gnilnd/kgnilnd" ;;
		*)	local lnd="${NETTYPE%%[0-9]}lnd"
			[ -f "$LNDPATH/$lnd/k$lnd.ko" ] &&
				LNETLND="$lnd/k$lnd" ||
				LNETLND="socklnd/ksocklnd"
		esac
	fi
	load_module ../lnet/klnds/$LNETLND

	if [[ $1 == config_on_load=1 ]]; then
		if $FORCE_LARGE_NID; then
			do_lnetctl lnet configure -a -l ||
				return $?
		else
			do_lnetctl lnet configure -a ||
				return $?
		fi
	fi
}

load_modules_local() {
	if [ -n "$MODPROBE" ]; then
		# use modprobe
		echo "Using modprobe to load modules"
		return 0
	fi

	# Create special udev test rules on every node
	if [ -f $LUSTRE/lustre/conf/99-lustre.rules ]; then {
		sed -e 's|/usr/sbin/lctl|$LCTL|g' $LUSTRE/lustre/conf/99-lustre.rules > /etc/udev/rules.d/99-lustre-test.rules
	} else {
		echo "SUBSYSTEM==\"lustre\", ACTION==\"change\", ENV{PARAM}==\"?*\", RUN+=\"$LCTL set_param '\$env{PARAM}=\$env{SETTING}'\"" > /etc/udev/rules.d/99-lustre-test.rules
	} fi
	udevadm control --reload-rules
	udevadm trigger

	if $FORCE_LARGE_NID; then
		load_lnet config_on_load=1
	else
		load_lnet
	fi

	load_module obdclass/obdclass
	if ! client_only; then
		MODOPTS_PTLRPC=${MODOPTS_PTLRPC:-"lbug_on_grant_miscount=1"}
	fi
	load_module ptlrpc/ptlrpc
	load_module ptlrpc/gss/ptlrpc_gss
	load_module fld/fld
	load_module fid/fid
	load_module lmv/lmv
	load_module osc/osc
	load_module lov/lov
	load_module mdc/mdc
	load_module mgc/mgc
	load_module obdecho/obdecho
	if ! client_only; then
		load_module lfsck/lfsck
		[ "$LQUOTA" != "no" ] &&
			load_module quota/lquota $LQUOTAOPTS
		if [[ $(node_fstypes $HOSTNAME) == *zfs* ]]; then
			load_module osd-zfs/osd_zfs
		elif [[ $(node_fstypes $HOSTNAME) == *ldiskfs* ]]; then
			load_module ../ldiskfs/ldiskfs
			load_module osd-ldiskfs/osd_ldiskfs
		fi
		load_module mgs/mgs
		load_module mdd/mdd
		load_module mdt/mdt
		# don't fail if ost module doesn't exist
		load_module ost/ost 2>/dev/null || true;
		load_module lod/lod
		load_module ofd/ofd
		load_module osp/osp
	fi

	load_module llite/lustre
	[ -d /r ] && OGDB=${OGDB:-"/r/tmp"}
	OGDB=${OGDB:-$TMP}
	rm -f $OGDB/ogdb-$HOSTNAME
	$LCTL modules > $OGDB/ogdb-$HOSTNAME

	# 'mount' doesn't look in $PATH, just sbin
	local mount_lustre=$LUSTRE/utils/mount.lustre
	if [ -f $mount_lustre ]; then
		local sbin_mount=$(readlink -f /sbin)/mount.lustre
		if grep -qw "$sbin_mount" /proc/mounts; then
			cmp -s $mount_lustre $sbin_mount || umount $sbin_mount
		fi
		if ! grep -qw "$sbin_mount" /proc/mounts; then
			[ ! -f "$sbin_mount" ] && touch "$sbin_mount"
			if [ ! -s "$sbin_mount" -a -w "$sbin_mount" ]; then
				cat <<- EOF > "$sbin_mount"
				#!/bin/bash
				#STUB MARK
				echo "This $sbin_mount just a mountpoint." 1>&2
				echo "It is never supposed to be run." 1>&2
				logger -p emerg -- "using stub $sbin_mount $@"
				exit 1
				EOF
				chmod a+x $sbin_mount
			fi
			mount --bind $mount_lustre $sbin_mount ||
				error "can't bind $mount_lustre to $sbin_mount"
		fi
	fi
}

load_modules () {
	local facets
	local facet
	local failover
	load_modules_local
	# bug 19124
	# load modules on remote nodes optionally
	# lustre-tests have to be installed on these nodes
	if $LOAD_MODULES_REMOTE; then
		local list=$(comma_list $(remote_nodes_list))

		# include failover nodes in case they are not in the list yet
		facets=$(get_facets)
		for facet in ${facets//,/ }; do
			failover=$(facet_failover_host $facet)
			[ -n "$list" ] && [[ ! "$list" =~ "$failover" ]] &&
				list="$list,$failover"
		done

		if [ -n "$list" ]; then
			echo "loading modules on: '$list'"
			do_rpc_nodes "$list" load_modules_local
		fi
	fi
}

check_mem_leak () {
	LEAK_LUSTRE=$(dmesg | tail -n 30 | grep "obd_memory.*leaked" || true)
	LEAK_PORTALS=$(dmesg | tail -n 20 | egrep -i "libcfs.*memory leaked" ||
		true)
	if [ "$LEAK_LUSTRE" -o "$LEAK_PORTALS" ]; then
		echo "$LEAK_LUSTRE" 1>&2
		echo "$LEAK_PORTALS" 1>&2
		mv $TMP/debug $TMP/debug-leak.`date +%s` || true
		echo "Memory leaks detected"
		[ -n "$IGNORE_LEAK" ] &&
			{ echo "ignoring leaks" && return 0; } || true
		return 1
	fi
}

unload_modules_local() {
	$LUSTRE_RMMOD ldiskfs || return 2

	[ -f /etc/udev/rules.d/99-lustre-test.rules ] &&
		rm /etc/udev/rules.d/99-lustre-test.rules
	udevadm control --reload-rules
	udevadm trigger

	check_mem_leak || return 254

	return 0
}

unload_modules() {
	local rc=0

	wait_exit_ST client # bug 12845

	unload_modules_local || rc=$?

	if $LOAD_MODULES_REMOTE; then
		local list=$(comma_list $(remote_nodes_list))

		if (( MDS1_VERSION >= $(version_code 2.15.51) )); then
			# unload_module_local is only available after 2.15.51
			if [ -n "$list" ]; then
				echo "unloading modules via unload_modules_local on: '$list'"
				do_rpc_nodes "$list" unload_modules_local
			fi
		else
			if [ -n "$list" ]; then
				echo "unloading modules on: '$list'"
				do_rpc_nodes "$list" $LUSTRE_RMMOD ldiskfs
				do_rpc_nodes "$list" check_mem_leak
				do_rpc_nodes "$list" "rm -f /etc/udev/rules.d/99-lustre-test.rules"
				do_rpc_nodes "$list" "udevadm control --reload-rules"
				do_rpc_nodes "$list" "udevadm trigger"
			fi
		fi
	fi

	local sbin_mount=$(readlink -f /sbin)/mount.lustre
	if grep -qe "$sbin_mount " /proc/mounts; then
		umount $sbin_mount || true
		[ -s $sbin_mount ] && ! grep -q "STUB MARK" $sbin_mount ||
			rm -f $sbin_mount
	fi

	[[ $rc -eq 0 ]] && echo "modules unloaded."

	return $rc
}

fs_log_size() {
	local facet=${1:-ost1}
	local size=0
	local mult=$OSTCOUNT

	case $(facet_fstype $facet) in
		ldiskfs) size=32;; # largest seen is 64 with multiple OSTs
		# grant_block_size is in bytes, allow at least 2x max blocksize
		zfs)     size=$(lctl get_param osc.$FSNAME*.import |
				awk '/grant_block_size:/ {print $2/512; exit;}')
			  ;;
	esac

	[[ $facet =~ mds ]] && mult=$MDTCOUNT
	echo -n $((size * mult))
}

fs_inode_ksize() {
	local facet=${1:-$SINGLEMDS}
	local fstype=$(facet_fstype $facet)
	local size=0
	case $fstype in
		ldiskfs) size=4;;  # ~4KB per inode
		zfs)     size=11;; # 10 to 11KB per inode
	esac

	echo -n $size
}

runas_su() {
	local user=$1
	local cmd=$2
	shift 2
	local opts="$*"

	if $VERBOSE; then
		echo Running as $user: $cmd $opts
	fi
	cmd=$(which $cmd)
	su - $user -c "$cmd $opts"
}

check_gss_daemon_nodes() {
	local list=$1
	local dname=$(basename "$2" | awk '{print $1}')
	local loopmax=10
	local loop
	local node
	local ret

	do_nodesv $list "num=0;
for proc in \\\$(pgrep $dname); do
[ \\\$(ps -o ppid= -p \\\$proc) -ne 1 ] || ((num++))
done;
if [ \\\"\\\$num\\\" -ne 1 ]; then
    echo \\\$num instance of $dname;
    exit 1;
fi; "
	ret=$?
	(( $ret == 0 )) || return $ret

	for node in ${list//,/ }; do
		loop=0
		while (( $loop < $loopmax )); do
			do_nodesv $node "$L_GETAUTH -d"
			ret=$?
			(( $ret == 0 )) && break
			loop=$((loop + 1))
			sleep 5
		done
		(( $loop < $loopmax )) || return 1
	done
	return 0
}

check_gss_daemon_facet() {
	local facet=$1
	local dname=$(basename "$2" | awk '{print $1}')
	local num=$(do_facet $facet ps -o cmd -C $dname | grep -c $dname)

	if (( $num != 1 )); then
		echo "$num instance of $dname on $facet"
		return 1
	fi
	return 0
}

send_sigint() {
	local list=$1

	shift
	echo "Stopping "$@" on $list"
	do_nodes $list "killall -2 $* 2>/dev/null || true"
}

# start gss daemons on all nodes, or "daemon" on "nodes" if set
start_gss_daemons() {
	local nodes=$1
	local daemon=$2
	local options=$3

	if [ "$nodes" ] && [ "$daemon" ] ; then
		echo "Starting gss daemon on nodes: $nodes"
		do_nodes $nodes "$daemon" "$options" || return 8
		check_gss_daemon_nodes $nodes "$daemon" || return 9
		return 0
	fi

	nodes=$(comma_list $(mdts_nodes))
	echo "Starting gss daemon on mds: $nodes"
	if $GSS_SK; then
		# Start all versions, in case of switching
		do_nodes $nodes "$LSVCGSSD -vvv -s -m -o -z $options" ||
			return 1
	else
		do_nodes $nodes "$LSVCGSSD -vvv $options" || return 1
	fi

	nodes=$(comma_list $(osts_nodes))
	echo "Starting gss daemon on ost: $nodes"
	if $GSS_SK; then
		# Start all versions, in case of switching
		do_nodes $nodes "$LSVCGSSD -vvv -s -m -o -z $options" ||
			return 3
	else
		do_nodes $nodes "$LSVCGSSD -vvv $options" || return 3
	fi
	# starting on clients

	local clients=${CLIENTS:-$HOSTNAME}

	#
	# check daemons are running
	#
	nodes=$(comma_list $(mdts_nodes) $(osts_nodes))
	check_gss_daemon_nodes $nodes "$LSVCGSSD" || return 5
}

stop_gss_daemons() {
	local nodes=$(comma_list $(mdts_nodes))

	send_sigint $nodes lsvcgssd lgssd

	nodes=$(comma_list $(osts_nodes))
	send_sigint $nodes lsvcgssd

	nodes=${CLIENTS:-$HOSTNAME}
	send_sigint $nodes lgssd
}

add_sk_mntflag() {
	# Add mount flags for shared key
	local mt_opts=$@

	if grep -q skpath <<< "$mt_opts" ; then
		mt_opts=$(echo $mt_opts |
			sed -e "s#skpath=[^ ,]*#skpath=$SK_PATH#")
	else
		if [ -z "$mt_opts" ]; then
			mt_opts="-o skpath=$SK_PATH"
		else
			mt_opts="$mt_opts,skpath=$SK_PATH"
		fi
	fi
	echo -n $mt_opts
}

from_build_tree() {
	local from_tree

	case $LUSTRE in
	/usr/lib/lustre/* | /usr/lib64/lustre/* | /usr/lib/lustre | \
	/usr/lib64/lustre )
		from_tree=false
		;;
	*)
		from_tree=true
		;;
	esac

	[ $from_tree = true ]
}

init_gss() {
	if $SHARED_KEY; then
		GSS=true
		GSS_SK=true
	fi

	if ! $GSS; then
		return
	fi

	if ! module_loaded ptlrpc_gss; then
		load_module ptlrpc/gss/ptlrpc_gss
		module_loaded ptlrpc_gss ||
			error_exit "init_gss: GSS=$GSS, but gss/krb5 missing"
	fi

	if $GSS_KRB5 || $GSS_SK; then
		start_gss_daemons || error_exit "start gss daemon failed! rc=$?"
	fi

	if $GSS_SK && ! $SK_NO_KEY; then
		echo "Loading basic SSK keys on all servers"
		do_nodes $(comma_list $(all_server_nodes)) \
			"$LGSS_SK -t server -l $SK_PATH/$FSNAME.key || true"
		do_nodes $(comma_list $(all_server_nodes)) \
				"keyctl show | grep lustre | cut -c1-11 |
				sed -e 's/ //g;' |
				xargs -IX keyctl setperm X 0x3f3f3f3f"
	fi

	if $GSS_SK && $SK_NO_KEY; then
		local numclients=${1:-$CLIENTCOUNT}
		local clients=${CLIENTS:-$HOSTNAME}

		# security ctx config for keyring
		SK_NO_KEY=false
		local lgssc_conf_file="/etc/request-key.d/lgssc.conf"

		if from_build_tree; then
			mkdir -p $SK_OM_PATH
			if grep -q request-key /proc/mounts > /dev/null; then
				echo "SSK: Request key already mounted."
			else
				mount -o bind $SK_OM_PATH /etc/request-key.d/
			fi
			local lgssc_conf_line='create lgssc * * '
			lgssc_conf_line+=$(which lgss_keyring)
			lgssc_conf_line+=' %o %k %t %d %c %u %g %T %P %S'
			echo "$lgssc_conf_line" > $lgssc_conf_file
		fi

		[ -e $lgssc_conf_file ] ||
			error_exit "Could not find key options in $lgssc_conf_file"
		echo "$lgssc_conf_file content is:"
		cat $lgssc_conf_file

		if ! local_mode; then
			if from_build_tree; then
				do_nodes $(comma_list $(all_nodes)) "mkdir -p \
					$SK_OM_PATH"
				do_nodes $(comma_list $(all_nodes)) "mount \
					-o bind $SK_OM_PATH \
					/etc/request-key.d/"
				do_nodes $(comma_list $(all_nodes)) "rsync \
					-aqv $HOSTNAME:$lgssc_conf_file \
					$lgssc_conf_file >/dev/null 2>&1"
			else
				do_nodes $(comma_list $(all_nodes)) \
					"echo $lgssc_conf_file: ; \
					cat $lgssc_conf_file"
			fi
		fi

		# create shared key on all nodes
		mkdir -p $SK_PATH/nodemap
		rm -f $SK_PATH/$FSNAME.key $SK_PATH/nodemap/c*.key \
			$SK_PATH/$FSNAME-*.key
		# for nodemap testing each client may need own key,
		# and S2S now requires keys as well, both for "client"
		# and for "server"
		if $SK_S2S; then
			$LGSS_SK -t server -f$FSNAME -n $SK_S2SNMCLI \
				-w $SK_PATH/$FSNAME-nmclient.key \
				-d /dev/urandom >/dev/null 2>&1
			$LGSS_SK -t mgs,server -f$FSNAME -n $SK_S2SNM \
				-w $SK_PATH/$FSNAME-s2s-server.key \
				-d /dev/urandom >/dev/null 2>&1
		fi
		# basic key create
		$LGSS_SK -t server -f$FSNAME -w $SK_PATH/$FSNAME.key \
			-d /dev/urandom >/dev/null 2>&1
		# per-nodemap keys
		for i in $(seq 0 $((numclients - 1))); do
			$LGSS_SK -t server -f$FSNAME -n c$i \
				-w $SK_PATH/nodemap/c$i.key -d /dev/urandom \
				>/dev/null 2>&1
		done
		# Distribute keys
		if ! local_mode; then
			for lnode in $(all_nodes); do
				scp -r $SK_PATH ${lnode}:$(dirname $SK_PATH)/
			done
		fi
		# Set client keys to client type to generate prime P
		if local_mode; then
			do_nodes $(all_nodes) "$LGSS_SK -t client,server -m \
				$SK_PATH/$FSNAME.key >/dev/null 2>&1"
		else
			do_nodes $clients "$LGSS_SK -t client -m \
				$SK_PATH/$FSNAME.key >/dev/null 2>&1"
			do_nodes $clients "find $SK_PATH/nodemap \
				-name \*.key | xargs -IX $LGSS_SK -t client \
				-m X >/dev/null 2>&1"
			# also have a client key available on server side,
			# for local client mount
			do_nodes $(comma_list $(all_server_nodes)) \
			"cp $SK_PATH/$FSNAME.key $SK_PATH/${FSNAME}_cli.key && \
			 $LGSS_SK -t client -m \
				$SK_PATH/${FSNAME}_cli.key >/dev/null 2>&1"
		fi
		# This is required for servers as well, if S2S in use
		if $SK_S2S; then
			do_nodes $(comma_list $(mdts_nodes)) \
				"cp $SK_PATH/$FSNAME-s2s-server.key \
				$SK_PATH/$FSNAME-s2s-client.key; $LGSS_SK \
				-t client -m $SK_PATH/$FSNAME-s2s-client.key \
				>/dev/null 2>&1"
			do_nodes $(comma_list $(osts_nodes)) \
				"cp $SK_PATH/$FSNAME-s2s-server.key \
				$SK_PATH/$FSNAME-s2s-client.key; $LGSS_SK \
				-t client -m $SK_PATH/$FSNAME-s2s-client.key \
				>/dev/null 2>&1"
			do_nodes $clients "$LGSS_SK -t client \
				-m $SK_PATH/$FSNAME-nmclient.key \
				 >/dev/null 2>&1"
		fi
	fi
	if $GSS_SK; then
		# mount options for servers and clients
		MGS_MOUNT_OPTS=$(add_sk_mntflag $MGS_MOUNT_OPTS)
		MDS_MOUNT_OPTS=$(add_sk_mntflag $MDS_MOUNT_OPTS)
		OST_MOUNT_OPTS=$(add_sk_mntflag $OST_MOUNT_OPTS)
		MOUNT_OPTS=$(add_sk_mntflag $MOUNT_OPTS)
		SEC=$SK_FLAVOR
		if [ -z "$LGSS_KEYRING_DEBUG" ]; then
			LGSS_KEYRING_DEBUG=4
		fi
	fi

	if [ -n "$LGSS_KEYRING_DEBUG" ] && \
	       ( local_mode || from_build_tree ); then
		lctl set_param -n \
		     sptlrpc.gss.lgss_keyring.debug_level=$LGSS_KEYRING_DEBUG
	elif [ -n "$LGSS_KEYRING_DEBUG" ]; then
		do_nodes $(comma_list $(all_nodes)) "modprobe ptlrpc_gss && \
		lctl set_param -n \
		   sptlrpc.gss.lgss_keyring.debug_level=$LGSS_KEYRING_DEBUG"
	fi

	do_nodesv $(comma_list $(all_server_nodes)) \
		"$LCTL set_param sptlrpc.gss.rsi_upcall=$L_GETAUTH"
}

cleanup_gss() {
	if $GSS; then
		stop_gss_daemons
		# maybe cleanup credential cache?
	fi
}

cleanup_sk() {
	if $GSS_SK; then
		if $SK_S2S; then
			do_node $(mgs_node) "$LCTL nodemap_del $SK_S2SNM"
			do_node $(mgs_node) "$LCTL nodemap_del $SK_S2SNMCLI"
			$RPC_MODE || echo "Sleeping for 10 sec for Nodemap.."
			sleep 10
		fi
		stop_gss_daemons
		$RPC_MODE || echo "Cleaning up Shared Key.."
		do_nodes $(comma_list $(all_nodes)) "rm -f \
			$SK_PATH/$FSNAME*.key $SK_PATH/nodemap/$FSNAME*.key"
		do_nodes $(comma_list $(all_nodes)) "keyctl show | \
		  awk '/lustre/ { print \\\$1 }' | xargs -IX keyctl unlink X"
		if from_build_tree; then
			# Remove the mount and clean up the files we added to
			# SK_PATH
			do_nodes $(comma_list $(all_nodes)) "while grep -q \
				request-key.d /proc/mounts; do umount \
				/etc/request-key.d/; done"
			do_nodes $(comma_list $(all_nodes)) "rm -f \
				$SK_OM_PATH/lgssc.conf"
			do_nodes $(comma_list $(all_nodes)) "rmdir $SK_OM_PATH"
		fi
		SK_NO_KEY=true
	fi
}

facet_svc() {
	local facet=$1
	local var=${facet}_svc

	echo -n ${!var}
}

facet_type() {
	local facet=$1

	echo -n $facet | sed -e 's/^fs[0-9]\+//' -e 's/[0-9_]\+//' |
		tr '[:lower:]' '[:upper:]'
}

facet_number() {
	local facet=$1

	if [ $facet == mgs ] || [ $facet == client ]; then
		return 1
	fi

	echo -n $facet | sed -e 's/^fs[0-9]\+//' | sed -e 's/^[a-z]\+//'
}

facet_fstype() {
	local facet=$1
	local var

	var=${facet}_FSTYPE
	if [ -n "${!var}" ]; then
		echo -n ${!var}
		return
	fi

	var=$(facet_type $facet)FSTYPE
	if [ -n "${!var}" ]; then
		echo -n ${!var}
		return
	fi

	if [ -n "$FSTYPE" ]; then
		echo -n $FSTYPE
		return
	fi

	if [[ $facet == mgs ]] && combined_mgs_mds; then
		facet_fstype mds1
		return
	fi

	return 1
}

node_fstypes() {
	local node=$1
	local fstypes
	local fstype
	local facets=$(get_facets)
	local facet

	for facet in ${facets//,/ }; do
		if [[ $node == $(facet_host $facet) ]] ||
		   [[ $node == "$(facet_failover_host $facet)" ]]; then
			fstype=$(facet_fstype $facet)
			if [[ $fstypes != *$fstype* ]]; then
				fstypes+="${fstypes:+,}$fstype"
			fi
		fi
	done
	echo -n $fstypes
}

facet_index() {
	local facet=$1
	local num=$(facet_number $facet)
	local index

	if [[ $(facet_type $facet) = OST ]]; then
		index=OSTINDEX${num}
		if [[ -n "${!index}" ]]; then
			echo -n ${!index}
			return
		fi

		index=${OST_INDICES[num - 1]}
	fi

	[[ -n "$index" ]] || index=$((num - 1))
	echo -n $index
}

devicelabel() {
	local facet=$1
	local dev=$2
	local label
	local fstype=$(facet_fstype $facet)

	case $fstype in
	ldiskfs)
		label=$(do_facet ${facet} "$E2LABEL ${dev} 2>/dev/null");;
	zfs)
		label=$(do_facet ${facet} "$ZFS get -H -o value lustre:svname \
		                           ${dev} 2>/dev/null");;
	*)
		error "unknown fstype!";;
	esac

	echo -n $label
}

#
# Get the device of a facet.
#
facet_device() {
	local facet=$1
	local device

	case $facet in
		mgs) device=$(mgsdevname) ;;
		mds*) device=$(mdsdevname $(facet_number $facet)) ;;
		ost*) device=$(ostdevname $(facet_number $facet)) ;;
		fs2mds) device=$(mdsdevname 1_2) ;;
		fs2ost) device=$(ostdevname 1_2) ;;
		fs3ost) device=$(ostdevname 2_2) ;;
		*) ;;
	esac

	echo -n $device
}

#
# Get the virtual device of a facet.
#
facet_vdevice() {
	local facet=$1
	local device

	case $facet in
		mgs) device=$(mgsvdevname) ;;
		mds*) device=$(mdsvdevname $(facet_number $facet)) ;;
		ost*) device=$(ostvdevname $(facet_number $facet)) ;;
		fs2mds) device=$(mdsvdevname 1_2) ;;
		fs2ost) device=$(ostvdevname 1_2) ;;
		fs3ost) device=$(ostvdevname 2_2) ;;
		*) ;;
	esac

	echo -n $device
}

running_in_vm() {
	local virt=$(virt-what 2> /dev/null)

	[ $? -eq 0 ] && [ -n "$virt" ] && { echo $virt; return; }

	virt=$(dmidecode -s system-product-name | awk '{print $1}')

	case $virt in
		VMware|KVM|VirtualBox|Parallels|Bochs)
			echo $virt | tr '[A-Z]' '[a-z]' && return;;

		*) ;;
	esac

	virt=$(dmidecode -s system-manufacturer | awk '{print $1}')
	case $virt in
		QEMU)
			echo $virt | tr '[A-Z]' '[a-z]' && return;;
		*) ;;
	esac
}

#
# Re-read the partition table on failover partner host.
# After a ZFS storage pool is created on a shared device, the partition table
# on the device may change. However, the operating system on the failover
# host may not notice the change automatically. Without the up-to-date partition
# block devices, 'zpool import ..' cannot find the labels, whose positions are
# relative to partition rather than disk beginnings.
#
# This function performs partprobe on the failover host to make it re-read the
# partition table.
#
refresh_partition_table() {
	local facet=$1
	local device=$2
	local host

	host=$(facet_passive_host $facet)
	if [[ -n "$host" ]]; then
		do_node $host "$PARTPROBE $device"
	fi
}

#
# Get ZFS storage pool name.
#
zpool_name() {
	local facet=$1
	local device
	local poolname

	device=$(facet_device $facet)
	# poolname is string before "/"
	poolname="${device%%/*}"

	echo -n $poolname
}

#
#
# Get ZFS local fsname.
#
zfs_local_fsname() {
	local facet=$1
	local lfsname=$(basename $(facet_device $facet))

	echo -n $lfsname
}

#
# Create ZFS storage pool.
#
create_zpool() {
	local facet=$1
	local poolname=$2
	local vdev=$3
	shift 3
	local opts=${@:-"-o cachefile=none"}

	do_facet $facet "lsmod | grep zfs >&/dev/null || modprobe zfs;
		$ZPOOL list -H $poolname >/dev/null 2>&1 ||
		$ZPOOL create -f $opts $poolname $vdev"
}

#
# Create ZFS file system.
#
create_zfs() {
	local facet=$1
	local dataset=$2
	shift 2
	local opts=${@:-"-o mountpoint=legacy"}

	do_facet $facet "$ZFS list -H $dataset >/dev/null 2>&1 ||
		$ZFS create $opts $dataset"
}

#
# Export ZFS storage pool.
# Before exporting the pool, all datasets within the pool should be unmounted.
#
export_zpool() {
	local facet=$1
	shift
	local opts="$@"
	local poolname

	poolname=$(zpool_name $facet)

	if [[ -n "$poolname" ]]; then
		do_facet $facet "! $ZPOOL list -H $poolname >/dev/null 2>&1 ||
			grep -q ^$poolname/ /proc/mounts ||
			$ZPOOL export $opts $poolname"
	fi
}

#
# Destroy ZFS storage pool.
# Destroy the given pool and free up any devices for other use. This command
# tries to unmount any active datasets before destroying the pool.
# -f    Force any active datasets contained within the pool to be unmounted.
#
destroy_zpool() {
	local facet=$1
	local poolname=${2:-$(zpool_name $facet)}

	if [[ -n "$poolname" ]]; then
		do_facet $facet "! $ZPOOL list -H $poolname >/dev/null 2>&1 ||
			$ZPOOL destroy -f $poolname"
	fi
}

#
# Import ZFS storage pool.
# Force importing, even if the pool appears to be potentially active.
#
import_zpool() {
	local facet=$1
	shift
	local opts=${@:-"-o cachefile=none -o failmode=panic"}
	local poolname

	poolname=$(zpool_name $facet)

	if [[ -n "$poolname" ]]; then
		opts+=" -d $(dirname $(facet_vdevice $facet))"
		do_facet $facet "lsmod | grep zfs >&/dev/null || modprobe zfs;
			$ZPOOL list -H $poolname >/dev/null 2>&1 ||
			$ZPOOL import -f $opts $poolname"
	fi
}

#
# Reimport ZFS storage pool with new name
#
reimport_zpool() {
	local facet=$1
	local newpool=$2
	local opts="-o cachefile=none"
	local poolname=$(zpool_name $facet)

	opts+=" -d $(dirname $(facet_vdevice $facet))"
	do_facet $facet "$ZPOOL export $poolname;
			 $ZPOOL import $opts $poolname $newpool"
}

#
# Set the "cachefile=none" property on ZFS storage pool so that the pool
# is not automatically imported on system startup.
#
# In a failover environment, this will provide resource level fencing which
# will ensure that the same ZFS storage pool will not be imported concurrently
# on different nodes.
#
disable_zpool_cache() {
	local facet=$1
	local poolname

	poolname=$(zpool_name $facet)

	if [[ -n "$poolname" ]]; then
		do_facet $facet "$ZPOOL set cachefile=none $poolname"
	fi
}

#
# This and set_osd_param() shall be used to access OSD parameters
# once existed under "obdfilter":
#
#   mntdev
#   stats
#   read_cache_enable
#   writethrough_cache_enable
#
get_osd_param() {
	local nodes=$1
	local device=${2:-$FSNAME-OST*}
	local name=$3

	do_nodes $nodes "$LCTL get_param -n osd-*.$device.$name"
}

set_osd_param() {
	local nodes=$1
	local device=${2:-$FSNAME-OST*}
	local name=$3
	local value=$4

	do_nodes $nodes "$LCTL set_param -n osd-*.$device.$name=$value"
}

set_default_debug () {
	local debug=${1:-"$PTLDEBUG"}
	local subsys=${2:-"$SUBSYSTEM"}
	local debug_size=${3:-$DEBUG_SIZE}

	[ -n "$debug" ] && lctl set_param debug="$debug" >/dev/null
	[ -n "$subsys" ] &&
		lctl set_param subsystem_debug="${subsys# }" >/dev/null
	[ -n "$debug_size" ] &&
		lctl set_param debug_mb="$debug_size" >/dev/null

	return 0
}

set_default_debug_nodes () {
	local nodes="$1"
	local debug="${2:-"$PTLDEBUG"}"
	local subsys="${3:-"$SUBSYSTEM"}"
	local debug_size="${4:-$DEBUG_SIZE}"

	if [[ ,$nodes, = *,$HOSTNAME,* ]]; then
		nodes=$(exclude_items_from_list "$nodes" "$HOSTNAME")
		set_default_debug
	fi

	[[ -z "$nodes" ]] ||
		do_rpc_nodes "$nodes" set_default_debug \
			\\\"$debug\\\" \\\"$subsys\\\" $debug_size || true
}

set_default_debug_facet () {
	local facet=$1
	local debug="${2:-"$PTLDEBUG"}"
	local subsys="${3:-"$SUBSYSTEM"}"
	local debug_size="${4:-$DEBUG_SIZE}"
	local node=$(facet_active_host $facet)

	[ -n "$node" ] || error "No host defined for facet $facet"

	set_default_debug_nodes $node "$debug" "$subsys" $debug_size
}

set_params_nodes() {
	local nodes=$1
	shift
	local params="$@"

	[[ -n "$params" ]] || return 0

	do_nodes $nodes "$LCTL set_param $params"
}

set_params_clients() {
	(( $# >= 2 )) || return 0
	local clients=${1:-$CLIENTS}
	shift
	local params="${@:-$CLIENT_LCTL_SETPARAM_PARAM}"

	set_params_nodes $clients $params
}

set_params_mdts() {
	(( $# >= 2 )) || return 0
	local mdts=${1:-$(comma_list $(mdts_nodes))}
	shift
	local params="${@:-$MDS_LCTL_SETPARAM_PARAM}"

	set_params_nodes $mdts $params
}

set_params_osts() {
	(( $# >= 2 )) || return 0
	local osts=${1:-$(comma_list $(osts_nodes))}
	shift
	local params="${@:-$OSS_LCTL_SETPARAM_PARAM}"

	set_params_nodes $osts $params
}

set_hostid () {
	local hostid=${1:-$(hostid)}

	if [ ! -s /etc/hostid ]; then
		printf $(echo -n $hostid |
	    sed 's/\(..\)\(..\)\(..\)\(..\)/\\x\4\\x\3\\x\2\\x\1/') >/etc/hostid
	fi
}

# Facet functions
mount_facets () {
	local facets=${1:-$(get_facets)}
	local facet
	local -a mountpids
	local total=0
	local ret=0

	for facet in ${facets//,/ }; do
		mount_facet $facet &
		mountpids[total]=$!
		total=$((total+1))
	done
	for ((index=0; index<$total; index++)); do
		wait ${mountpids[index]}
		local RC=$?
		[ $RC -eq 0 ] && continue

		if [ "$TESTSUITE.$TESTNAME" = "replay-dual.test_0a" ]; then
			skip_noexit "Restart of $facet failed!." &&
				touch $LU482_FAILED
		else
			error "Restart of $facet failed!"
		fi
		ret=$RC
	done
	return $ret
}

#
# Add argument "arg" (e.g., "loop") to the comma-separated list
# of arguments for option "opt" (e.g., "-o") on command
# line "opts" (e.g., "-o flock").
#
csa_add() {
	local opts=$1
	local opt=$2
	local arg=$3
	local opt_pattern="\([[:space:]]\+\|^\)$opt"

	if echo "$opts" | grep -q $opt_pattern; then
		opts=$(echo "$opts" | sed -e \
			"s/$opt_pattern[[:space:]]*[^[:space:]]\+/&,$arg/")
	else
		opts+="${opts:+ }$opt $arg"
	fi
	echo -n "$opts"
}

#
# Associate loop device with a given regular file.
# Return the loop device.
#
setup_loop_device() {
	local facet=$1
	local file=$2

	do_facet $facet "loop_dev=\\\$($LOSETUP -j $file | cut -d : -f 1);
			 if [[ -z \\\$loop_dev ]]; then
				loop_dev=\\\$($LOSETUP -f);
				$LOSETUP \\\$loop_dev $file || loop_dev=;
			 fi;
			 echo -n \\\$loop_dev"
}

#
# Detach a loop device.
#
cleanup_loop_device() {
	local facet=$1
	local loop_dev=$2

	do_facet $facet "! $LOSETUP $loop_dev >/dev/null 2>&1 ||
			 $LOSETUP -d $loop_dev"
}

#
# Check if a given device is a block device.
#
is_blkdev() {
	local facet=$1
	local dev=$2
	local size=${3:-""}

	[[ -n "$dev" ]] || return 1
	do_facet $facet "test -b $dev" || return 1
	if [[ -n "$size" ]]; then
		local in=$(do_facet $facet "dd if=$dev of=/dev/null bs=1k \
					    count=1 skip=$size 2>&1" |
					    awk '($3 == "in") { print $1 }')
		[[ "$in" = "1+0" ]] || return 1
	fi
}

#
# Check if a given device is a device-mapper device.
#
is_dm_dev() {
	local facet=$1
	local dev=$2

	[[ -n "$dev" ]] || return 1
	do_facet $facet "$DMSETUP status $dev >/dev/null 2>&1"
}

#
# Check if a given device is a device-mapper flakey device.
#
is_dm_flakey_dev() {
	local facet=$1
	local dev=$2
	local type

	[[ -n "$dev" ]] || return 1

	type=$(do_facet $facet "$DMSETUP status $dev 2>&1" |
	       awk '{print $3}')
	[[ $type = flakey ]] && return 0 || return 1
}

#
# Check if device-mapper flakey device is supported by the kernel
# of $facet node or not.
#
dm_flakey_supported() {
	local facet=$1

	$FLAKEY || return 1
	do_facet $facet "modprobe dm-flakey;
			 $DMSETUP targets | grep -q flakey" &> /dev/null
}

#
# Get the device-mapper flakey device name of a given facet.
#
dm_facet_devname() {
	local facet=$1
	[[ $facet = mgs ]] && combined_mgs_mds && facet=mds1

	echo -n ${facet}_flakey
}

#
# Get the device-mapper flakey device of a given facet.
# A device created by dmsetup will appear as /dev/mapper/<device-name>.
#
dm_facet_devpath() {
	local facet=$1

	echo -n $DM_DEV_PATH/$(dm_facet_devname $facet)
}

#
# Set a device-mapper device with a new table.
#
# The table has the following format:
# <logical_start_sector> <num_sectors> <target_type> <target_args>
#
# flakey <target_args> includes:
# <destination_device> <offset> <up_interval> <down_interval> \
# [<num_features> [<feature_arguments>]]
#
# linear <target_args> includes:
# <destination_device> <start_sector>
#
dm_set_dev_table() {
	local facet=$1
	local dm_dev=$2
	local target_type=$3
	local num_sectors
	local real_dev
	local tmp
	local table

	read tmp num_sectors tmp real_dev tmp \
		<<< $(do_facet $facet "$DMSETUP table $dm_dev")

	case $target_type in
	flakey)
		table="0 $num_sectors flakey $real_dev 0 0 1800 1 drop_writes"
		;;
	linear)
		table="0 $num_sectors linear $real_dev 0"
		;;
	*) error "invalid target type $target_type" ;;
	esac

	do_facet $facet "$DMSETUP suspend --nolockfs --noflush $dm_dev" ||
		error "failed to suspend $dm_dev"
	do_facet $facet "$DMSETUP load $dm_dev --table \\\"$table\\\"" ||
		error "failed to load $target_type table into $dm_dev"
	do_facet $facet "$DMSETUP resume $dm_dev" ||
		error "failed to resume $dm_dev"
}

#
# Set a device-mapper flakey device as "read-only" by using the "drop_writes"
# feature parameter.
#
# drop_writes:
#	All write I/O is silently ignored.
#	Read I/O is handled correctly.
#
dm_set_dev_readonly() {
	local facet=$1
	local dm_dev=${2:-$(dm_facet_devpath $facet)}

	dm_set_dev_table $facet $dm_dev flakey
}

#
# Set a device-mapper device to traditional linear mapping mode.
#
dm_clear_dev_readonly() {
	local facet=$1
	local dm_dev=${2:-$(dm_facet_devpath $facet)}

	dm_set_dev_table $facet $dm_dev linear
}

#
# Set the device of a given facet as "read-only".
#
set_dev_readonly() {
	local facet=$1
	local svc=${facet}_svc

	if [[ $(facet_fstype $facet) = zfs ]] ||
	   ! dm_flakey_supported $facet; then
		do_facet $facet $LCTL --device ${!svc} readonly
	else
		dm_set_dev_readonly $facet
	fi
}

#
# Get size in 512-byte sectors (BLKGETSIZE64 / 512) of a given device.
#
get_num_sectors() {
	local facet=$1
	local dev=$2
	local num_sectors

	num_sectors=$(do_facet $facet "blockdev --getsz $dev 2>/dev/null")
	[[ ${PIPESTATUS[0]} = 0 && -n "$num_sectors" ]] || num_sectors=0
	echo -n $num_sectors
}

#
# Create a device-mapper device with a given block device or regular file (will
# be associated with loop device).
# Return the full path of the device-mapper device.
#
dm_create_dev() {
	local facet=$1
	local real_dev=$2				   # destination device
	local dm_dev_name=${3:-$(dm_facet_devname $facet)} # device name
	local dm_dev=$DM_DEV_PATH/$dm_dev_name		  # device-mapper device

	# check if the device-mapper device to be created already exists
	if is_dm_dev $facet $dm_dev; then
		# if the existing device was set to "read-only", then clear it
		! is_dm_flakey_dev $facet $dm_dev ||
			dm_clear_dev_readonly $facet $dm_dev

		echo -n $dm_dev
		return 0
	fi

	# check if the destination device is a block device, and if not,
	# associate it with a loop device
	is_blkdev $facet $real_dev ||
		real_dev=$(setup_loop_device $facet $real_dev)
	[[ -n "$real_dev" ]] || { echo -n $real_dev; return 2; }

	# now create the device-mapper device
	local num_sectors=$(get_num_sectors $facet $real_dev)
	local table="0 $num_sectors linear $real_dev 0"
	local rc=0

	do_facet $facet "$DMSETUP create $dm_dev_name --table \\\"$table\\\"" ||
		{ rc=${PIPESTATUS[0]}; dm_dev=; }
	do_facet $facet "$DMSETUP mknodes >/dev/null 2>&1"

	echo -n $dm_dev
	return $rc
}

#
# Map the facet name to its device variable name.
#
facet_device_alias() {
	local facet=$1
	local dev_alias=$facet

	case $facet in
		fs2mds) dev_alias=mds1_2 ;;
		fs2ost) dev_alias=ost1_2 ;;
		fs3ost) dev_alias=ost2_2 ;;
		*) ;;
	esac

	echo -n $dev_alias
}

#
# Save the original value of the facet device and export the new value.
#
export_dm_dev() {
	local facet=$1
	local dm_dev=$2

	local active_facet=$(facet_active $facet)
	local dev_alias=$(facet_device_alias $active_facet)
	local dev_name=${dev_alias}_dev
	local dev=${!dev_name}

	if [[ $active_facet = $facet ]]; then
		local failover_dev=${dev_alias}failover_dev
		if [[ ${!failover_dev} = $dev ]]; then
			eval export ${failover_dev}_saved=$dev
			eval export ${failover_dev}=$dm_dev
		fi
	else
		dev_alias=$(facet_device_alias $facet)
		local facet_dev=${dev_alias}_dev
		if [[ ${!facet_dev} = $dev ]]; then
			eval export ${facet_dev}_saved=$dev
			eval export ${facet_dev}=$dm_dev
		fi
	fi

	eval export ${dev_name}_saved=$dev
	eval export ${dev_name}=$dm_dev
}

#
# Restore the saved value of the facet device.
#
unexport_dm_dev() {
	local facet=$1

	[[ $facet = mgs ]] && combined_mgs_mds && facet=mds1
	local dev_alias=$(facet_device_alias $facet)

	local saved_dev=${dev_alias}_dev_saved
	[[ -z ${!saved_dev} ]] ||
		eval export ${dev_alias}_dev=${!saved_dev}

	saved_dev=${dev_alias}failover_dev_saved
	[[ -z ${!saved_dev} ]] ||
		eval export ${dev_alias}failover_dev=${!saved_dev}
}

#
# Remove a device-mapper device.
# If the destination device is a loop device, then also detach it.
#
dm_cleanup_dev() {
	local facet=$1
	local dm_dev=${2:-$(dm_facet_devpath $facet)}
	local major
	local minor

	is_dm_dev $facet $dm_dev || return 0

	read major minor <<< $(do_facet $facet "$DMSETUP table $dm_dev" |
		awk '{ print $4 }' | awk -F: '{ print $1" "$2 }')

	do_facet $facet "$DMSETUP remove $dm_dev"
	do_facet $facet "$DMSETUP mknodes >/dev/null 2>&1"

	unexport_dm_dev $facet

	# detach a loop device
	[[ $major -ne 7 ]] || cleanup_loop_device $facet /dev/loop$minor

	# unload dm-flakey module
	do_facet $facet "modprobe -r dm-flakey" || true
}

mount_facet() {
	local facet=$1
	shift
	local active_facet=$(facet_active $facet)
	local dev_alias=$(facet_device_alias $active_facet)
	local dev=${dev_alias}_dev
	local opt=${facet}_opt
	local mntpt=$(facet_mntpt $facet)
	local opts="${!opt} $@"
	local fstype=$(facet_fstype $facet)
	local devicelabel
	local dm_dev=${!dev}

	[[ $dev == "mgsfailover_dev" ]] && combined_mgs_mds &&
		dev=mds1failover_dev

	module_loaded lustre || load_modules

	case $fstype in
	ldiskfs)
		if dm_flakey_supported $facet; then
			dm_dev=$(dm_create_dev $facet ${!dev})
			[[ -n "$dm_dev" ]] || dm_dev=${!dev}
		fi

		is_blkdev $facet $dm_dev || opts=$(csa_add "$opts" -o loop)

		devicelabel=$(do_facet ${facet} "$E2LABEL $dm_dev");;
	zfs)
		# import ZFS storage pool
		import_zpool $facet || return ${PIPESTATUS[0]}

		devicelabel=$(do_facet ${facet} "$ZFS get -H -o value \
						lustre:svname $dm_dev");;
	*)
		error "unknown fstype!";;
	esac

	echo "Starting ${facet}: $opts $dm_dev $mntpt"
	# for testing LU-482 error handling in mount_facets() and test_0a()
	if [ -f $TMP/test-lu482-trigger ]; then
		RC=2
	else
		local seq_width=$(($OSTSEQWIDTH / $OSTCOUNT))
		(( $seq_width >= 16384 )) || seq_width=16384
		do_facet ${facet} \
			"mkdir -p $mntpt; $MOUNT_CMD $opts $dm_dev $mntpt"
		RC=${PIPESTATUS[0]}
		if [[ ${facet} =~ ost ]]; then
			do_facet ${facet} "$LCTL set_param \
				seq.cli-$(devicelabel $facet $dm_dev)-super.width=$seq_width"
		fi
	fi

	if [ $RC -ne 0 ]; then
		echo "Start of $dm_dev on ${facet} failed ${RC}"
		return $RC
	fi

	health=$(do_facet ${facet} "$LCTL get_param -n health_check")
	if [[ "$health" != "healthy" ]]; then
		error "$facet is in a unhealthy state"
	fi

	set_default_debug_facet $facet

	if [[ $opts =~ .*nosvc.* ]]; then
		echo "Start $dm_dev without service"
	else

		case $fstype in
		ldiskfs)
			wait_update_facet ${facet} "$E2LABEL $dm_dev \
				2>/dev/null | grep -E ':[a-zA-Z]{3}[0-9]{4}'" \
				"" || error "$dm_dev failed to initialize!";;
		zfs)
			wait_update_facet ${facet} "$ZFS get -H -o value \
				lustre:svname $dm_dev 2>/dev/null | \
				grep -E ':[a-zA-Z]{3}[0-9]{4}'" "" ||
				error "$dm_dev failed to initialize!";;

		*)
			error "unknown fstype!";;
		esac
	fi

	# commit the device label change to disk
	if [[ $devicelabel =~ (:[a-zA-Z]{3}[0-9]{4}) ]]; then
		echo "Commit the device label on ${!dev}"
		do_facet $facet "sync; sleep 1; sync"
	fi


	label=$(devicelabel ${facet} $dm_dev)
	[ -z "$label" ] && echo no label for $dm_dev && exit 1
	eval export ${facet}_svc=${label}
	echo Started ${label}

	export_dm_dev $facet $dm_dev

	return $RC
}

# start facet device options
start() {
	local facet=$1
	shift
	local device=$1
	shift
	local dev_alias=$(facet_device_alias $facet)

	eval export ${dev_alias}_dev=${device}
	eval export ${facet}_opt=\"$*\"

	combined_mgs_mds && [[ ${dev_alias} == mds1 ]] &&
		eval export mgs_dev=${device}

	local varname=${dev_alias}failover_dev
	if [ -n "${!varname}" ] ; then
		eval export ${dev_alias}failover_dev=${!varname}
	else
		eval export ${dev_alias}failover_dev=$device
		combined_mgs_mds && [[ ${dev_alias} == mds1 ]] &&
			eval export mgsfailover_dev=${device}

	fi

	local mntpt=$(facet_mntpt $facet)
	do_facet ${facet} mkdir -p $mntpt
	eval export ${facet}_MOUNT=$mntpt
	mount_facet ${facet}
	RC=$?

	return $RC
}

stop() {
	local running
	local facet=$1
	shift
	local HOST=$(facet_active_host $facet)
	[[ -z $HOST ]] && echo stop: no host for $facet && return 0

	local mntpt=$(facet_mntpt $facet)
	running=$(do_facet ${facet} "grep -c $mntpt' ' /proc/mounts || true")
	if [ ${running} -ne 0 ]; then
		echo "Stopping $mntpt (opts:$*) on $HOST"
		do_facet ${facet} $UMOUNT "$@" $mntpt
	fi

	# umount should block, but we should wait for unrelated obd's
	# like the MGS or MGC to also stop.
	wait_exit_ST ${facet} || return ${PIPESTATUS[0]}

	if [[ $(facet_fstype $facet) == zfs ]]; then
		# export ZFS storage pool
		[ "$KEEP_ZPOOL" = "true" ] || export_zpool $facet
	elif dm_flakey_supported $facet; then
		local host=${facet}_HOST
		local failover_host=${facet}failover_HOST
		if [[ -n ${!failover_host} && ${!failover_host} != ${!host} ]]||
			$CLEANUP_DM_DEV || [[ $facet = fs* ]]; then
			dm_cleanup_dev $facet
		fi
	fi
}

# get mdt quota type
mdt_quota_type() {
	local varsvc=${SINGLEMDS}_svc
	do_facet $SINGLEMDS $LCTL get_param -n \
		osd-$(facet_fstype $SINGLEMDS).${!varsvc}.quota_slave.enabled
}

# get ost quota type
ost_quota_type() {
	# All OSTs should have same quota type
	local varsvc=ost1_svc
	do_facet ost1 $LCTL get_param -n \
		osd-$(facet_fstype ost1).${!varsvc}.quota_slave.enabled
}

# restore old quota type settings
restore_quota() {
	for usr in $QUOTA_USERS; do
		echo "Setting up quota on $HOSTNAME:$MOUNT for $usr..."
		for type in u g; do
			cmd="$LFS setquota -$type $usr -b 0"
			cmd="$cmd -B 0 -i 0 -I 0 $MOUNT"
			echo "+ $cmd"
			eval $cmd || error "$cmd FAILED!"
		done
		# display the quota status
		echo "Quota settings for $usr : "
		$LFS quota -v -u $usr $MOUNT || true
	done
	if [ "$old_MDT_QUOTA_TYPE" ]; then
		if [[ $PERM_CMD == *"set_param -P"* ]]; then
			do_facet mgs $PERM_CMD \
				osd-*.$FSNAME-MDT*.quota_slave.enabled = \
				$old_MDT_QUOTA_TYPE
		else
			do_facet mgs $PERM_CMD \
				$FSNAME.quota.mdt=$old_MDT_QUOTA_TYPE
		fi
	fi
	if [ "$old_OST_QUOTA_TYPE" ]; then
		if [[ $PERM_CMD == *"set_param -P"* ]]; then
			do_facet mgs $PERM_CMD \
				osd-*.$FSNAME-OST*.quota_slave.enabled = \
				$old_OST_QUOTA_TYPE
		else
			do_facet mgs $LCTL conf_param \
				$FSNAME.quota.ost=$old_OST_QUOTA_TYPE
		fi
	fi
}

# Handle the case when there is a space in the lfs df
# "filesystem summary" line the same as when there is no space.
# This will allow fixing the "lfs df" summary line in the future.
lfs_df() {
	$LFS df $* | sed -e 's/filesystem /filesystem_/'
	check_lfs_df_ret_val ${PIPESTATUS[0]}
}

# Get free inodes on the MDT specified by mdt index, free indoes on
# the whole filesystem will be returned when index == -1.
mdt_free_inodes() {
	local index=$1
	local free_inodes
	local mdt_uuid

	if [ $index -eq -1 ]; then
		mdt_uuid="summary"
	else
		mdt_uuid=$(mdtuuid_from_index $index)
	fi

	free_inodes=$(lfs_df -i $MOUNT | grep $mdt_uuid | awk '{print $4}')
	echo $free_inodes
}

#
# Get the OST device status from 'lfs df' with a given OST index.
#
ost_dev_status() {
	local ost_idx=$1
	local mnt_pnt=${2:-$MOUNT}
	local opts=$3
	local ost_uuid

	ost_uuid=$(ostuuid_from_index $ost_idx $mnt_pnt)
	lfs_df $opts $mnt_pnt | awk '/'$ost_uuid'/ { print $7 }'
}

setup_quota(){
	local mntpt=$1

	# save old quota type & set new quota type
	local mdt_qtype=$(mdt_quota_type)
	local ost_qtype=$(ost_quota_type)

	echo "[HOST:$HOSTNAME] [old_mdt_qtype:$mdt_qtype]" \
		"[old_ost_qtype:$ost_qtype] [new_qtype:$QUOTA_TYPE]"

	export old_MDT_QUOTA_TYPE=$mdt_qtype
	export old_OST_QUOTA_TYPE=$ost_qtype

	if [[ $PERM_CMD == *"set_param -P"* ]]; then
		do_facet mgs $PERM_CMD \
			osd-*.$FSNAME-MDT*.quota_slave.enabled=$QUOTA_TYPE
		do_facet mgs $PERM_CMD \
			osd-*.$FSNAME-OST*.quota_slave.enabled=$QUOTA_TYPE
	else
		do_facet mgs $PERM_CMD $FSNAME.quota.mdt=$QUOTA_TYPE ||
			error "set mdt quota type failed"
		do_facet mgs $PERM_CMD $FSNAME.quota.ost=$QUOTA_TYPE ||
			error "set ost quota type failed"
	fi

	local quota_usrs=$QUOTA_USERS

	# get_filesystem_size
	local disksz=$(lfs_df $mntpt | grep "summary" | awk '{print $2}')
	local blk_soft=$((disksz + 1024))
	local blk_hard=$((blk_soft + blk_soft / 20)) # Go 5% over

	local inodes=$(lfs_df -i $mntpt | grep "summary" | awk '{print $2}')
	local i_soft=$inodes
	local i_hard=$((i_soft + i_soft / 20))

	echo "Total disk size: $disksz  block-softlimit: $blk_soft" \
		"block-hardlimit: $blk_hard inode-softlimit: $i_soft" \
		"inode-hardlimit: $i_hard"

	local cmd
	for usr in $quota_usrs; do
		echo "Setting up quota on $HOSTNAME:$mntpt for $usr..."
		for type in u g; do
			cmd="$LFS setquota -$type $usr -b $blk_soft"
			cmd="$cmd -B $blk_hard -i $i_soft -I $i_hard $mntpt"
			echo "+ $cmd"
			eval $cmd || error "$cmd FAILED!"
		done
		# display the quota status
		echo "Quota settings for $usr : "
		$LFS quota -v -u $usr $mntpt || true
	done
}

zconf_mount() {
	local client=$1
	local mnt=$2
	local opts=${3:-$MOUNT_OPTS}
	opts=${opts:+-o $opts}
	local flags=${4:-$MOUNT_FLAGS}

	local device=$MGSNID:/$FSNAME$FILESET
	if [ -z "$mnt" -o -z "$FSNAME" ]; then
		echo "Bad mount command: opt=$flags $opts dev=$device " \
		     "mnt=$mnt"
		exit 1
	fi

	if $GSS_SK; then
		# update mount option with skpath
		opts=$(add_sk_mntflag $opts)
	fi

	echo "Starting client: $client: $flags $opts $device $mnt"
	do_node $client mkdir -p $mnt
	if [ -n "$FILESET" -a -z "$SKIP_FILESET" ];then
		do_node $client $MOUNT_CMD $flags $opts $MGSNID:/$FSNAME \
			$mnt || return 1
		#disable FILESET if not supported
		do_nodes $client lctl get_param -n \
			mdc.$FSNAME-MDT0000*.import | grep -q subtree ||
				device=$MGSNID:/$FSNAME
		do_node $client mkdir -p $mnt/$FILESET
		do_node $client "! grep -q $mnt' ' /proc/mounts ||
			umount $mnt"
	fi
	if $GSS_SK && ($SK_UNIQUE_NM || $SK_S2S); then
		# Mount using nodemap key
		local mountkey=$SK_PATH/$FSNAME-nmclient.key
		if $SK_UNIQUE_NM; then
			mountkey=$SK_PATH/nodemap/c0.key
		fi
		local prunedopts=$(echo $opts |
				sed -e "s#skpath=[^,^ ]*#skpath=$mountkey#g")
		do_node $client $MOUNT_CMD $flags $prunedopts $device $mnt ||
				return 1
	else
		do_node $client $MOUNT_CMD $flags $opts $device $mnt ||
				return 1
	fi

	set_default_debug_nodes $client
	set_params_clients $client

	return 0
}

zconf_umount() {
	local client=$1
	local mnt=$2
	local force
	local busy
	local need_kill
	local running=$(do_node $client "grep -c $mnt' ' /proc/mounts") || true

	[ "$3" ] && force=-f
	[ $running -eq 0 ] && return 0

	echo "Stopping client $client $mnt (opts:$force)"
	do_node $client lsof -t $mnt || need_kill=no
	if [ "x$force" != "x" ] && [ "x$need_kill" != "xno" ]; then
		pids=$(do_node $client lsof -t $mnt | sort -u);
		if [ -n "$pids" ]; then
			do_node $client kill -9 $pids || true
		fi
	fi

	busy=$(do_node $client "umount $force $mnt 2>&1" | grep -c "busy") ||
		true
	if [ $busy -ne 0 ] ; then
		echo "$mnt is still busy, wait one second" && sleep 1
		do_node $client umount $force $mnt
	fi
}

# Mount the file system on the MDS
mount_mds_client() {
	local host=$(facet_active_host $SINGLEMDS)
	echo $host
	zconf_mount $host $MOUNT2 $MOUNT_OPTS ||
		error "unable to mount $MOUNT2 on $host"
}

# Unmount the file system on the MDS
umount_mds_client() {
	local host=$(facet_active_host $SINGLEMDS)
	zconf_umount $host $MOUNT2
	do_facet $SINGLEMDS "rmdir $MOUNT2"
}

# nodes is comma list
sanity_mount_check_nodes () {
	local nodes=$1
	shift
	local mnts="$@"
	local mnt

	# FIXME: assume that all cluster nodes run the same os
	[ "$(uname)" = Linux ] || return 0

	local rc=0
	for mnt in $mnts ; do
		do_nodes $nodes "running=\\\$(grep -c $mnt' ' /proc/mounts);
mpts=\\\$(mount | grep -c $mnt' ');
if [ \\\$running -ne \\\$mpts ]; then
    echo \\\$(hostname) env are INSANE!;
    exit 1;
fi"
		[ $? -eq 0 ] || rc=1
	done
	return $rc
}

sanity_mount_check_servers () {
	[ -n "$CLIENTONLY" ] &&
		{ echo "CLIENTONLY mode, skip mount_check_servers"; return 0; } || true
	echo Checking servers environments

	# FIXME: modify get_facets to display all facets wo params
	local facets="$(get_facets OST),$(get_facets MDS),mgs"
	local node
	local mntpt
	local facet
	for facet in ${facets//,/ }; do
	node=$(facet_host ${facet})
	mntpt=$(facet_mntpt $facet)
	sanity_mount_check_nodes $node $mntpt ||
		{ error "server $node environments are insane!"; return 1; }
	done
}

sanity_mount_check_clients () {
	local clients=${1:-$CLIENTS}
	local mntpt=${2:-$MOUNT}
	local mntpt2=${3:-$MOUNT2}

	[ -z $clients ] && clients=$(hostname)
	echo Checking clients $clients environments

	sanity_mount_check_nodes $clients $mntpt $mntpt2 ||
		error "clients environments are insane!"
}

sanity_mount_check () {
	sanity_mount_check_servers || return 1
	sanity_mount_check_clients || return 2
}

# mount clients if not mouted
zconf_mount_clients() {
	local clients=$1
	local mnt=$2
	local opts=${3:-$MOUNT_OPTS}
	opts=${opts:+-o $opts}
	local flags=${4:-$MOUNT_FLAGS}
	local device=$MGSNID:/$FSNAME$FILESET
	if [ -z "$mnt" -o -z "$FSNAME" ]; then
		echo "Bad conf mount command: opt=$flags $opts dev=$device " \
		     "mnt=$mnt"
		exit 1
	fi

	echo "Starting client $clients: $flags $opts $device $mnt"
	do_nodes $clients mkdir -p $mnt
	if [ -n "$FILESET" -a -z "$SKIP_FILESET" ]; then
		if $GSS_SK && ($SK_UNIQUE_NM || $SK_S2S); then
			# Mount with own nodemap key
			local i=0
			# Mount all server nodes first with per-NM keys
			for nmclient in ${clients//,/ }; do
				do_nodes $(comma_list $(all_server_nodes)) \
				"$LGSS_SK -t server -l $SK_PATH/nodemap/c$i.key"
				i=$((i + 1))
			done
			# set perms for per-nodemap keys else permission denied
			do_nodes $(comma_list $(all_nodes)) \
				"keyctl show | grep lustre | cut -c1-11 |
				sed -e 's/ //g;' |
				xargs -IX keyctl setperm X 0x3f3f3f3f"
			local mountkey=$SK_PATH/$FSNAME-nmclient.key
			i=0
			for nmclient in ${clients//,/ }; do
				if $SK_UNIQUE_NM; then
					mountkey=$SK_PATH/nodemap/c$i.key
				fi
				do_node $nmclient "! grep -q $mnt' ' \
					/proc/mounts || umount $mnt"
				local prunedopts=$(add_sk_mntflag $opts);
				prunedopts=$(echo $prunedopts | sed -e \
					"s#skpath=[^ ^,]*#skpath=$mountkey#g")
				set -x
				do_nodes $(comma_list $(all_server_nodes)) \
					"keyctl show"
				set +x
				do_node $nmclient $MOUNT_CMD $flags \
					$prunedopts $MGSNID:/$FSNAME $mnt ||
					return 1
				i=$((i + 1))
			done
		else
			do_nodes $clients "! grep -q $mnt' ' /proc/mounts ||
					umount $mnt"
			do_nodes $clients $MOUNT_CMD $flags $opts \
					$MGSNID:/$FSNAME $mnt || return 1
		fi
		#disable FILESET if not supported
		do_nodes $clients lctl get_param -n \
			mdc.$FSNAME-MDT0000*.import | grep -q subtree ||
				device=$MGSNID:/$FSNAME
		do_nodes $clients mkdir -p $mnt/$FILESET
		do_nodes $clients "! grep -q $mnt' ' /proc/mounts ||
			umount $mnt"
	fi

	if $GSS_SK && ($SK_UNIQUE_NM || $SK_S2S); then
		# Mount with nodemap key
		local i=0
		local mountkey=$SK_PATH/$FSNAME-nmclient.key
		for nmclient in ${clients//,/ }; do
			if $SK_UNIQUE_NM; then
				mountkey=$SK_PATH/nodemap/c$i.key
			fi
			local prunedopts=$(echo $opts | sed -e \
				"s#skpath=[^ ^,]*#skpath=$mountkey#g");
			do_node $nmclient "! grep -q $mnt' ' /proc/mounts ||
				umount $mnt"
			do_node $nmclient "
		running=\\\$(mount | grep -c $mnt' ');
		rc=0;
		if [ \\\$running -eq 0 ] ; then
			mkdir -p $mnt;
			$MOUNT_CMD $flags $prunedopts $device $mnt;
			rc=\\\$?;
		else
			lustre_mnt_count=\\\$(mount | grep $mnt' ' | \
				grep 'type lustre' | wc -l);
			if [ \\\$running -ne \\\$lustre_mnt_count ] ; then
				echo zconf_mount_clients FAILED: \
					mount count \\\$running, not matching \
					with mount count of 'type lustre' \
					\\\$lustre_mnt_count;
				rc=1;
			fi;
		fi;
	exit \\\$rc" || return ${PIPESTATUS[0]}

			i=$((i + 1))
		done
	else

		local tmpopts=$opts
		if $SHARED_KEY; then
			tmpopts=$(add_sk_mntflag $opts)
		fi
		do_nodes $clients "
running=\\\$(mount | grep -c $mnt' ');
rc=0;
if [ \\\$running -eq 0 ] ; then
	mkdir -p $mnt;
	$MOUNT_CMD $flags $tmpopts $device $mnt;
	rc=\\\$?;
fi;
exit \\\$rc" || return ${PIPESTATUS[0]}
	fi

	echo "Started clients $clients: "
	do_nodes $clients "mount | grep $mnt' '"

	set_default_debug_nodes $clients
	set_params_clients $clients

	return 0
}

zconf_umount_clients() {
	local clients=$1
	local mnt=$2
	local force

	[ "$3" ] && force=-f

	echo "Stopping clients: $clients $mnt (opts:$force)"
	do_nodes $clients "running=\\\$(grep -c $mnt' ' /proc/mounts);
if [ \\\$running -ne 0 ] ; then
echo Stopping client \\\$(hostname) $mnt opts:$force;
lsof $mnt || need_kill=no;
if [ "x$force" != "x" -a "x\\\$need_kill" != "xno" ]; then
    pids=\\\$(lsof -t $mnt | sort -u);
    if [ -n \\\"\\\$pids\\\" ]; then
             kill -9 \\\$pids;
    fi
fi;
while umount $force $mnt 2>&1 | grep -q "busy"; do
    echo "$mnt is still busy, wait one second" && sleep 1;
done;
fi"
}

shutdown_node () {
	local node=$1

	echo + $POWER_DOWN $node
	$POWER_DOWN $node
}

shutdown_node_hard () {
	local host=$1
	local attempts=$SHUTDOWN_ATTEMPTS

	for i in $(seq $attempts) ; do
		shutdown_node $host
		sleep 1
		wait_for_function --quiet "! ping -w 3 -c 1 $host" 5 1 &&
			return 0
		echo "waiting for $host to fail attempts=$attempts"
		[ $i -lt $attempts ] ||
			{ echo "$host still pingable after power down! attempts=$attempts" && return 1; }
	done
}

shutdown_client() {
	local client=$1
	local mnt=${2:-$MOUNT}
	local attempts=3

	if [ "$FAILURE_MODE" = HARD ]; then
		shutdown_node_hard $client
	else
		zconf_umount_clients $client $mnt -f
	fi
}

facets_on_host () {
	local affected
	local host=$1
	local facets="$(get_facets OST),$(get_facets MDS)"

	combined_mgs_mds || facets="$facets,mgs"

	for facet in ${facets//,/ }; do
		if [ $(facet_active_host $facet) == $host ]; then
			affected="$affected $facet"
		fi
	done

	echo $(comma_list $affected)
}

facet_up() {
	local facet=$1
	local host=${2:-$(facet_host $facet)}

	local label=$(convert_facet2label $facet)
	do_node $host $LCTL dl | awk '{ print $4 }' | grep -q "^$label\$"
}

facets_up_on_host () {
	local affected_up
	local host=$1
	local facets=$(facets_on_host $host)

	for facet in ${facets//,/ }; do
		if $(facet_up $facet $host); then
			affected_up="$affected_up $facet"
		fi
	done

	echo $(comma_list $affected_up)
}

shutdown_facet() {
	local facet=$1
	local affected_facet
	local affected_facets

	if [[ "$FAILURE_MODE" = HARD ]]; then
		if [[ $(facet_fstype $facet) = ldiskfs ]] &&
			dm_flakey_supported $facet; then
			affected_facets=$(affected_facets $facet)
			for affected_facet in ${affected_facets//,/ }; do
				unexport_dm_dev $affected_facet
			done
		fi

		shutdown_node_hard $(facet_active_host $facet)
	else
		stop $facet
	fi
}

reboot_node() {
	local node=$1

	echo + $POWER_UP $node
	$POWER_UP $node
}

remount_facet() {
	local facet=$1

	stop $facet
	mount_facet $facet
}

reboot_facet() {
	local facet=$1
	local node=$(facet_active_host $facet)
	local sleep_time=${2:-10}

	if [ "$FAILURE_MODE" = HARD ]; then
		boot_node $node
	else
		sleep $sleep_time
	fi
}

boot_node() {
	local node=$1

	if [ "$FAILURE_MODE" = HARD ]; then
		reboot_node $node
		wait_for_host $node
		if $LOAD_MODULES_REMOTE; then
			echo "loading modules on $node: $facet"
			do_rpc_nodes $node load_modules_local
		fi
	fi
}

facets_hosts () {
	local hosts
	local facets=$1

	for facet in ${facets//,/ }; do
		hosts=$(expand_list $hosts $(facet_host $facet) )
	done

	echo $hosts
}

_check_progs_installed () {
	local progs=$@
	local rc=0

	for prog in $progs; do
		if ! [ "$(which $prog)"  -o  "${!prog}" ]; then
			echo $prog missing on $(hostname)
			rc=1
		fi
	done
	return $rc
}

check_progs_installed () {
	local nodes=$1
	shift

	do_rpc_nodes "$nodes" _check_progs_installed "$@"
}

# recovery-scale functions
node_var_name() {
    echo __$(echo $1 | tr '-' '_' | tr '.' '_')
}

start_client_load() {
	local client=$1
	local load=$2
	local var=$(node_var_name $client)_load
	eval export ${var}=$load

	do_node $client "PATH=$PATH MOUNT=$MOUNT ERRORS_OK=$ERRORS_OK \
			BREAK_ON_ERROR=$BREAK_ON_ERROR \
			END_RUN_FILE=$END_RUN_FILE \
			LOAD_PID_FILE=$LOAD_PID_FILE \
			TESTLOG_PREFIX=$TESTLOG_PREFIX \
			TESTNAME=$TESTNAME \
			DBENCH_LIB=$DBENCH_LIB \
			DBENCH_SRC=$DBENCH_SRC \
			CLIENT_COUNT=$((CLIENTCOUNT - 1)) \
			LFS=$LFS \
			LCTL=$LCTL \
			FSNAME=$FSNAME \
			MPIRUN=$MPIRUN \
			MPIRUN_OPTIONS=\\\"$MPIRUN_OPTIONS\\\" \
			MACHINEFILE_OPTION=\\\"$MACHINEFILE_OPTION\\\" \
			num_clients=$(get_node_count ${CLIENTS//,/ }) \
			ior_THREADS=$ior_THREADS ior_iteration=$ior_iteration \
			ior_blockSize=$ior_blockSize \
			ior_blockUnit=$ior_blockUnit \
			ior_xferSize=$ior_xferSize ior_type=$ior_type \
			ior_DURATION=$ior_DURATION \
			ior_stripe_params=\\\"$ior_stripe_params\\\" \
			ior_custom_params=\\\"$ior_custom_param\\\" \
			mpi_ior_custom_threads=$mpi_ior_custom_threads \
			run_${load}.sh" &
	local ppid=$!
	log "Started client load: ${load} on $client"

	# get the children process IDs
	local pids=$(ps --ppid $ppid -o pid= | xargs)
	CLIENT_LOAD_PIDS="$CLIENT_LOAD_PIDS $ppid $pids"
	return 0
}

start_client_loads () {
	local -a clients=(${1//,/ })
	local numloads=${#CLIENT_LOADS[@]}

	for ((nodenum=0; nodenum < ${#clients[@]}; nodenum++ )); do
		local load=$((nodenum % numloads))
		start_client_load ${clients[nodenum]} ${CLIENT_LOADS[load]}
	done
	# bug 22169: wait the background threads to start
	sleep 2
}

# only for remote client
check_client_load () {
	local client=$1
	local var=$(node_var_name $client)_load
	local testload=run_${!var}.sh

	ps auxww | grep -v grep | grep $client | grep -q $testload || return 1

	# bug 18914: try to connect several times not only when
	# check ps, but  while check_node_health also

	local tries=3
	local RC=254
	while [ $RC = 254 -a $tries -gt 0 ]; do
		let tries=$tries-1
		# assume success
		RC=0
		if ! check_node_health $client; then
			RC=${PIPESTATUS[0]}
			if [ $RC -eq 254 ]; then
				# FIXME: not sure how long we shuold sleep here
				sleep 10
				continue
			fi
			echo "check node health failed: RC=$RC "
			return $RC
		fi
	done
	# We can continue try to connect if RC=254
	# Just print the warning about this
	if [ $RC = 254 ]; then
		echo "got a return status of $RC from do_node while checking " \
		"node health on $client"
	fi

	# see if the load is still on the client
	tries=3
	RC=254
	while [ $RC = 254 -a $tries -gt 0 ]; do
		let tries=$tries-1
		# assume success
		RC=0
		if ! do_node $client \
			"ps auxwww | grep -v grep | grep -q $testload"; then
			RC=${PIPESTATUS[0]}
			sleep 30
		fi
	done
	if [ $RC = 254 ]; then
		echo "got a return status of $RC from do_node while checking " \
		"(node health and 'ps') the client load on $client"
		# see if we can diagnose a bit why this is
	fi

	return $RC
}
check_client_loads () {
	local clients=${1//,/ }
	local client=
	local rc=0

	for client in $clients; do
		check_client_load $client
		rc=${PIPESTATUS[0]}
		if [ "$rc" != 0 ]; then
			log "Client load failed on node $client, rc=$rc"
			return $rc
		fi
	done
}

restart_client_loads () {
	local clients=${1//,/ }
	local expectedfail=${2:-""}
	local client=
	local rc=0

	for client in $clients; do
		check_client_load $client
		rc=${PIPESTATUS[0]}
		if [ "$rc" != 0 -a "$expectedfail" ]; then
			local var=$(node_var_name $client)_load

			start_client_load $client ${!var}
			echo "Restarted client load ${!var}: on $client. Checking ..."
			check_client_load $client
			rc=${PIPESTATUS[0]}
			if [ "$rc" != 0 ]; then
				log "Client load failed to restart on node $client, rc=$rc"
				# failure one client load means test fail
				# we do not need to check other
				return $rc
			fi
		else
			return $rc
		fi
	done
}

# Start vmstat and save its process ID in a file.
start_vmstat() {
	local nodes=$1
	local pid_file=$2

	[ -z "$nodes" -o -z "$pid_file" ] && return 0

	do_nodes $nodes \
        "vmstat 1 > $TESTLOG_PREFIX.$TESTNAME.vmstat.\\\$(hostname -s).log \
        2>/dev/null </dev/null & echo \\\$! > $pid_file"
}

# Display the nodes on which client loads failed.
print_end_run_file() {
	local file=$1
	local node

	[ -s $file ] || return 0

	echo "Found the END_RUN_FILE file: $file"
	cat $file

	# A client load will stop if it finds the END_RUN_FILE file.
	# That does not mean the client load actually failed though.
	# The first node in END_RUN_FILE is the one we are interested in.
	read node < $file

	if [ -n "$node" ]; then
		local var=$(node_var_name $node)_load

		local prefix=$TESTLOG_PREFIX
		[ -n "$TESTNAME" ] && prefix=$prefix.$TESTNAME
		local stdout_log=$prefix.run_${!var}_stdout.$node.log
		local debug_log=$(echo $stdout_log |
			sed 's/\(.*\)stdout/\1debug/')

		echo "Client load ${!var} failed on node $node:"
		echo "$stdout_log"
		echo "$debug_log"
	fi
}

# Stop the process which had its PID saved in a file.
stop_process() {
	local nodes=$1
	local pid_file=$2

	[ -z "$nodes" -o -z "$pid_file" ] && return 0

	do_nodes $nodes "test -f $pid_file &&
		{ kill -s TERM \\\$(cat $pid_file); rm -f $pid_file; }" || true
}

# Stop all client loads.
stop_client_loads() {
	local nodes=${1:-$CLIENTS}
	local pid_file=$2

	# stop the client loads
	stop_process $nodes $pid_file

	# clean up the processes that started them
	[ -n "$CLIENT_LOAD_PIDS" ] &&
		kill -9 $CLIENT_LOAD_PIDS 2>/dev/null || true
}
# End recovery-scale functions

##
# wait for a command to return the expected result
#
# This will run @check on @node repeatedly until the output matches @expect
# based on the supplied condition, or until @max_wait seconds have elapsed,
# whichever comes first.  @cond may be one of the normal bash operators,
# "-gt", "-ge", "-eq", "-le", "-lt", "==", "!=", or "=~", and must be quoted
# in the caller to avoid unintentional evaluation by the shell in the caller.
#
# If @max_wait is not specified, the condition will be checked for up to 90s.
#
# If --verbose is passed as the first argument, the result is printed on each
# value change, otherwise it is only printed after every 10s interval.
#
# If --quiet is passed as the first/second argument, the do_node() command
# will not print the remote command before executing it each time.
#
# Using wait_update_cond() or related helper function is preferable to adding
# a "long enough" wait for some state to change in the background, since
# "long enough" may be too short due to tunables, system config, or running in
# a VM, and must by necessity wait too long for most cases or risk failure.
#
# usage: wait_update_cond [--verbose] [--quiet] node check cond expect [max_wait]
wait_update_cond() {
	local verbose
	local quiet

	[[ "$1" == "--verbose" ]] && verbose="$1" && shift || true
	[[ "$1" == "--quiet" || "$1" == "-q" ]] && quiet="$1" && shift || true

	local node=$1
	local check="$2"
	local cond="$3"
	local expect="$4"
	local max_wait=${5:-90}
	local result
	local prev_result
	local waited=0
	local begin=$SECONDS
	local sleep=1
	local print=10

	while (( $waited <= $max_wait )); do
		result=$(do_node $quiet $node "$check")

		if eval [[ "'$result'" $cond "'$expect'" ]]; then
			[[ -z "$quiet" ]] || return 0
			[[ -z "$result" || $waited -le $sleep ]] ||
				echo "Updated after ${waited}s: want '$expect' got '$result'"
			return 0
		fi
		if [[ -n "$verbose" && "$result" != "$prev_result" ]]; then
			[[ -n "$quiet" || -z "$prev_result" ]] ||
				echo "Changed after ${waited}s: from '$prev_result' to '$result'"
			prev_result="$result"
		fi
		(( $waited % $print != 0 )) || {
			[[ -z "$quiet" ]] &&
			echo "Waiting $((max_wait - waited))s for '$expect'"
		}

		sleep $sleep
		waited=$((SECONDS - begin))
	done

	[[ -n "$quiet" ]] ||
	echo "Update not seen after ${max_wait}s: want '$expect' got '$result'"

	return 3
}

# usage: wait_update [--verbose] [--quiet] node check expect [max_wait]
wait_update() {
	local verbose
	local quiet

	[[ "$1" == "--verbose" ]] && verbose="$1" && shift || true
	[[ "$1" == "--quiet" || "$1" == "-q" ]] && quiet="$1" && shift || true

	local node="$1"
	local check="$2"
	local expect="$3"
	local max_wait=$4

	wait_update_cond $verbose $quiet $node "$check" "==" "$expect" $max_wait
}

# usage: wait_update_facet_cond [--verbose] facet check cond expect [max_wait]
wait_update_facet_cond() {
	local verbose
	local quiet

	[[ "$1" == "--verbose" ]] && verbose="$1" && shift
	[[ "$1" == "--quiet" || "$1" == "-q" ]] && quiet="$1" && shift

	local node=$(facet_active_host $1)
	local check="$2"
	local cond="$3"
	local expect="$4"
	local max_wait=$5

	wait_update_cond $verbose $quiet $node "$check" "$cond" "$expect" $max_wait
}

# usage: wait_update_facet [--verbose] facet check expect [max_wait]
wait_update_facet() {
	local verbose
	local quiet

	[[ "$1" == "--verbose" ]] && verbose="$1" && shift
	[[ "$1" == "--quiet" || "$1" == "-q" ]] && quiet="$1" && shift

	local node=$(facet_active_host $1)
	local check="$2"
	local expect="$3"
	local max_wait=$4

	wait_update_cond $verbose $quiet $node "$check" "==" "$expect" $max_wait
}

sync_all_data_mdts() {
	do_nodes $(comma_list $(mdts_nodes)) \
	    "lctl set_param -n os[cd]*.*MDT*.force_sync=1"
}

sync_all_data_osts() {
	do_nodes $(comma_list $(osts_nodes)) \
	    "lctl set_param -n osd*.*OS*.force_sync=1" 2>&1 |
		grep -v 'Found no match'
}
sync_all_data() {
	sync_all_data_mdts
	sync_all_data_osts
}

wait_zfs_commit() {
	local zfs_wait=${2:-5}

	# the occupied disk space will be released
	# only after TXGs are committed
	if [[ $(facet_fstype $1) == zfs ]]; then
		echo "sleep $zfs_wait for ZFS $(facet_fstype $1)"
		sleep $zfs_wait
	fi
}

fill_ost() {
	local filename=$1
	local ost_idx=$2
	local lwm=$3  #low watermark
	local size_mb #how many MB should we write to pass watermark
	local ost_name=$(ostname_from_index $ost_idx)

	free_kb=$($LFS df $MOUNT | awk "/$ost_name/ { print \$4 }")
	size_mb=0
	if (( $free_kb / 1024 > lwm )); then
		size_mb=$((free_kb / 1024 - lwm))
	fi
	#If 10% of free space cross low watermark use it
	if (( $free_kb / 10240 > size_mb )); then
		size_mb=$((free_kb / 10240))
	else
		#At least we need to store 1.1 of difference between
		#free space and low watermark
		size_mb=$((size_mb + size_mb / 10))
	fi
	if (( lwm <= $free_kb / 1024 )) ||
	   [ ! -f $DIR/${filename}.fill_ost$ost_idx ]; then
		$LFS setstripe -i $ost_idx -c1 $DIR/${filename}.fill_ost$ost_idx
		dd if=/dev/zero of=$DIR/${filename}.fill_ost$ost_idx bs=1M \
			count=$size_mb oflag=append conv=notrunc
	fi

	sleep_maxage

	free_kb=$($LFS df $MOUNT | awk "/$ost_name/ { print \$4 }")
	echo "OST still has $((free_kb / 1024)) MB free"
}

# This checks only the primary MDS
ost_watermarks_get() {
	local ost_idx=$1
	local ost_name=$(ostname_from_index $ost_idx)
	local mdtosc_proc=$(get_mdtosc_proc_path $SINGLEMDS $ost_name)

	local hwm=$(do_facet $SINGLEMDS $LCTL get_param -n \
			osp.$mdtosc_proc.reserved_mb_high)
	local lwm=$(do_facet $SINGLEMDS $LCTL get_param -n \
			osp.$mdtosc_proc.reserved_mb_low)

	echo "$lwm $hwm"
}

# Note that we set watermarks on all MDSes (necessary for striped dirs)
ost_watermarks_set() {
	local ost_idx=$1
	local lwm=$2
	local hwm=$3
	local ost_name=$(ostname_from_index $ost_idx)
	local facets=$(get_facets MDS)

	do_nodes $(comma_list $(mdts_nodes)) $LCTL set_param -n \
		osp.*$ost_name*.reserved_mb_low=$lwm \
		osp.*$ost_name*.reserved_mb_high=$hwm > /dev/null

	# sleep to ensure we see the change
	sleep_maxage
}

ost_watermarks_set_low_space() {
	local ost_idx=$1
	local wms=$(ost_watermarks_get $ost_idx)
	local ost_name=$(ostname_from_index $ost_idx)

	local old_lwm=$(echo $wms | awk '{ print $1 }')
	local old_hwm=$(echo $wms | awk '{ print $2 }')

	local blocks=$($LFS df $MOUNT | awk "/$ost_name/ { print \$4 }")
	# minimal extension size is 64M
	local new_lwm=50
	if (( $blocks / 1024 > 50 )); then
		new_lwm=$((blocks / 1024 - 50))
	fi
	local new_hwm=$((new_lwm + 5))

	ost_watermarks_set $ost_idx $new_lwm $new_hwm
	echo "watermarks: $old_lwm $old_hwm $new_lwm $new_hwm"
}

# Set watermarks to ~current available space & then write data to fill it
# Note OST is not *actually* full after this, it just reports ENOSPC in the
# internal statfs used by the stripe allocator
#
# first parameter is the filename-prefix, which must get under t-f cleanup
# requirements (rm -rf $DIR/[Rdfs][0-9]*), i.e. $tfile work fine
ost_watermarks_set_enospc() {
	local filename=$1
	local ost_idx=$2
	# on the mdt's osc
	local ost_name=$(ostname_from_index $ost_idx)
	local facets=$(get_facets MDS)
	local wms
	local MDS

	for MDS in ${facets//,/ }; do
		local mdtosc_proc=$(get_mdtosc_proc_path $MDS $ost_name)

		do_facet $MDS $LCTL get_param -n \
			osp.$mdtosc_proc.reserved_mb_high ||
			skip  "remote MDS does not support reserved_mb_high"
	done

	wms=$(ost_watermarks_set_low_space $ost_idx)
	local new_lwm=$(echo $wms | awk '{ print $4 }')
	fill_ost $filename $ost_idx $new_lwm
	#First enospc could execute orphan deletion so repeat
	fill_ost $filename $ost_idx $new_lwm
	echo $wms
}

ost_watermarks_enospc_delete_files() {
	local filename=$1
	local ost_idx=$2

	rm -f $DIR/${filename}.fill_ost$ost_idx

	wait_delete_completed
	wait_mds_ost_sync
}

# clean up from "ost_watermarks_set_enospc"
ost_watermarks_clear_enospc() {
	local filename=$1
	local ost_idx=$2
	local old_lwm=$4
	local old_hwm=$5

	ost_watermarks_enospc_delete_files $filename $ost_idx
	ost_watermarks_set $ost_idx $old_lwm $old_hwm
	echo "set OST$ost_idx lwm back to $old_lwm, hwm back to $old_hwm"
}

wait_delete_completed_mds() {
	local max_wait=${1:-20}
	local mds2sync=""
	local stime=$(date +%s)
	local etime
	local node
	local changes

	# find MDS with pending deletions
	for node in $(mdts_nodes); do
		changes=$(do_node $node "$LCTL get_param -n osc.*MDT*.sync_*" \
			2>/dev/null | calc_sum)
		if [[ $changes -eq 0 ]]; then
			continue
		fi
		mds2sync="$mds2sync $node"
	done
	if [ -z "$mds2sync" ]; then
		wait_zfs_commit $SINGLEMDS
		return 0
	fi
	mds2sync=$(comma_list $mds2sync)

	# sync MDS transactions
	do_nodes $mds2sync "$LCTL set_param -n os[cd]*.*MD*.force_sync 1"

	# wait till all changes are sent and commmitted by OSTs
	# for ldiskfs space is released upon execution, but DMU
	# do this upon commit

	local WAIT=0
	while [[ $WAIT -ne $max_wait ]]; do
		changes=$(do_nodes $mds2sync \
			"$LCTL get_param -n osc.*MDT*.sync_*" | calc_sum)
		#echo "$node: $changes changes on all"
		if [[ $changes -eq 0 ]]; then
			wait_zfs_commit $SINGLEMDS

			# the occupied disk space will be released
			# only after TXGs are committed
			wait_zfs_commit ost1
			return 0
		fi
		sleep 1
		WAIT=$((WAIT + 1))
	done

	etime=$(date +%s)
	echo "Delete is not completed in $((etime - stime)) seconds"
	do_nodes $mds2sync "$LCTL get_param osc.*MDT*.sync_*"
	return 1
}

wait_for_host() {
	local hostlist=$1

	# we can use "for" here because we are waiting the slowest
	for host in ${hostlist//,/ }; do
		check_network "$host" 900
	done
	while ! do_nodes $hostlist hostname  > /dev/null; do sleep 5; done
}

wait_for_facet() {
	local facetlist=$1
	local hostlist

	for facet in ${facetlist//,/ }; do
		hostlist=$(expand_list $hostlist $(facet_active_host $facet))
	done
	wait_for_host $hostlist
}

_wait_recovery_complete () {
	local param=$1

	# Use default policy if $2 is not passed by caller.
	local MAX=${2:-$(max_recovery_time)}

	local WAIT=0
	local STATUS=

	while [ $WAIT -lt $MAX ]; do
		STATUS=$(lctl get_param -n $param | grep status)
		echo $param $STATUS
		[[ $STATUS == "status: COMPLETE" ||
			$STATUS == "status: INACTIVE" ]] && return 0
		sleep 5
		WAIT=$((WAIT + 5))
		echo "Waiting $((MAX - WAIT)) secs for $param recovery done. $STATUS"
	done
	echo "$param recovery not done in $MAX sec. $STATUS"
	return 1
}

wait_recovery_complete () {
	local facet=$1

	# with an assumption that at_max is the same on all nodes
	local MAX=${2:-$(max_recovery_time)}

	local facets=$facet
	if [ "$FAILURE_MODE" = HARD ]; then
		facets=$(facets_on_host $(facet_active_host $facet))
	fi
	echo affected facets: $facets

	facets=${facets//,/ }
	# We can use "for" here because we are waiting the slowest.
	# The mgs not having the recovery_status proc entry, exclude it
	# from the facet list.
	for facet in ${facets//mgs/ }; do
		local var_svc=${facet}_svc
		local param="*.${!var_svc}.recovery_status"

		local host=$(facet_active_host $facet)
		do_rpc_nodes "$host" _wait_recovery_complete $param $MAX
	done
}

wait_mds_ost_sync () {
	# just because recovery is done doesn't mean we've finished
	# orphan cleanup. Wait for llogs to get synchronized.
	echo "Waiting for orphan cleanup..."
	# MAX value includes time needed for MDS-OST reconnection
	local MAX=$(( TIMEOUT * 2 ))
	local WAIT_TIMEOUT=${1:-$MAX}
	local WAIT=0
	local new_wait=true
	local list=$(comma_list $(mdts_nodes))
	local cmd="$LCTL get_param -n osp.*osc*.old_sync_processed"
	if ! do_facet $SINGLEMDS \
		"$LCTL list_param osp.*osc*.old_sync_processed 2> /dev/null"
	then
		# old way, use mds_sync
		new_wait=false
		list=$(comma_list $(osts_nodes))
		cmd="$LCTL get_param -n obdfilter.*.mds_sync"
	fi

	echo "wait $WAIT_TIMEOUT secs maximumly for $list mds-ost sync done."
	while [ $WAIT -lt $WAIT_TIMEOUT ]; do
		local -a sync=($(do_nodes $list "$cmd"))
		local con=1
		local i
		for ((i=0; i<${#sync[@]}; i++)); do
			if $new_wait; then
				[ ${sync[$i]} -eq 1 ] && continue
			else
				[ ${sync[$i]} -eq 0 ] && continue
			fi
			# there is a not finished MDS-OST synchronization
			con=0
			break;
		done
		sleep 2 # increase waiting time and cover statfs cache
		[ ${con} -eq 1 ] && return 0
		echo "Waiting $WAIT secs for $list $i mds-ost sync done."
		WAIT=$((WAIT + 2))
	done

	# show which nodes are not finished.
	cmd=$(echo $cmd | sed 's/-n//')
	do_nodes $list "$cmd"
	echo "$facet recovery node $i not done in $WAIT_TIMEOUT sec. $STATUS"
	return 1
}

# Wait OSTs to be active on both client and MDT side.
wait_osts_up() {
	local cmd="$LCTL get_param -n lov.$FSNAME-clilov-*.target_obd |
		awk 'BEGIN {c = 0} /ACTIVE/{c += 1} END {printf \\\"%d\\\", c}'"
	wait_update $HOSTNAME "eval $cmd" $OSTCOUNT ||
		error "wait_update OSTs up on client failed"

	cmd="$LCTL get_param osp.$FSNAME-OST*-MDT0000.prealloc_last_id |
	     awk '/=[1-9][0-9]/ { c += 1 } END { printf \\\"%d\\\", c }'"
	wait_update_facet $SINGLEMDS "eval $cmd" $OSTCOUNT ||
		error "wait_update OSTs up on MDT0000 failed"
}

wait_destroy_complete () {
	echo "Waiting for MDT destroys to complete"
	# MAX value shouldn't be big as this mean server responsiveness
	# never increase this just to make test pass but investigate
	# why it takes so long time
	local MAX=${1:-5}
	local WAIT=0
	local list=$(comma_list $(mdts_nodes))
	while [ $WAIT -lt $MAX ]; do
		local -a RPCs=($(do_nodes $list $LCTL get_param -n osp.*.destroys_in_flight))
		local con=1
		local i

		for ((i=0; i<${#RPCs[@]}; i++)); do
			[ ${RPCs[$i]} -eq 0 ] && continue
			# there are still some destroy RPCs in flight
			con=0
			break;
		done
		[ ${con} -eq 1 ] && return 0 # done waiting
		sleep 1
		echo "Waiting ${WAIT}s for local destroys to complete"
		WAIT=$((WAIT + 1))
	done
	echo "MDT destroys weren't done in $MAX sec."
	return 1
}

fstrim_inram_devs() {
	local i

	[[ "$(facet_fstype ost1)" = "ldiskfs" ]] || return 0
	[[ $OSTDEVBASE == */tmp/* ]] || return 0

	for (( i=1; i <= $OSTCOUNT; i++)); do
		do_facet ost$i "fstrim -v $(facet_mntpt ost$i)" &
	done
	wait

	return 0
}

wait_delete_completed() {
	wait_delete_completed_mds $1 || return $?
	wait_destroy_complete || return $?
	fstrim_inram_devs
}

wait_exit_ST () {
	local facet=$1

	local WAIT=0
	local INTERVAL=1
	local running
	# conf-sanity 31 takes a long time cleanup
	while [ $WAIT -lt 300 ]; do
		running=$(do_facet ${facet} "lsmod | grep lnet > /dev/null &&
lctl dl | grep ' ST ' || true")
		[ -z "${running}" ] && return 0
		echo "waited $WAIT for${running}"
		[ $INTERVAL -lt 64 ] && INTERVAL=$((INTERVAL + INTERVAL))
		sleep $INTERVAL
		WAIT=$((WAIT + INTERVAL))
	done
	echo "service didn't stop after $WAIT seconds.  Still running:"
	echo ${running}
	return 1
}

wait_remote_prog () {
	local prog=$1
	local WAIT=0
	local INTERVAL=5
	local rc=0

	[ "$PDSH" = "no_dsh" ] && return 0

	while [ $WAIT -lt $2 ]; do
		running=$(ps uax | grep "$PDSH.*$prog.*$MOUNT" |
			grep -v grep) || true
		[ -z "${running}" ] && return 0 || true
		echo "waited $WAIT for: "
		echo "$running"
		[ $INTERVAL -lt 60 ] && INTERVAL=$((INTERVAL + INTERVAL))
		sleep $INTERVAL
		WAIT=$((WAIT + INTERVAL))
	done
	local pids=$(ps  uax | grep "$PDSH.*$prog.*$MOUNT" |
			grep -v grep | awk '{print $2}')
	[ -z "$pids" ] && return 0
	echo "$PDSH processes still exists after $WAIT seconds.  Still running: $pids"
	# FIXME: not portable
	for pid in $pids; do
		cat /proc/${pid}/status || true
		cat /proc/${pid}/wchan || true
		echo "Killing $pid"
		kill -9 $pid || true
		sleep 1
		ps -P $pid && rc=1
	done

	return $rc
}

_lfs_df_check() {
	local clients=${1:-$CLIENTS}
	local rc=0

	if [[ -z "$clients" ]]; then
		$LFS df $MOUNT > /dev/null || rc=$?
	else
		$PDSH $clients "$LFS df $MOUNT" > /dev/null || rc=$?
	fi

	return $rc
}

lfs_df_check() {
	local clients=${1:-$CLIENTS}
	local rc=0

	_lfs_df_check "$clients" || rc=$?

	check_lfs_df_ret_val $rc
}

clients_up() {
	# not every config has many clients
	sleep 1
	lfs_df_check
}

all_mds_up() {
	(( MDSCOUNT == 1 )) && return

	# wait so that statfs data on MDT expire
	local delay=$(do_facet mds1 $LCTL \
		get_param -n osp.*MDT*MDT0000.maxage | sort -n | tail -1)

	[ -n "$delay" ] || error "fail to get maxage"
	sleep $delay
	local nodes=$(comma_list $(mdts_nodes))
	# initiate statfs RPC, all to all MDTs
	do_nodes $nodes $LCTL get_param -N osp.*MDT*MDT*.filesfree >&/dev/null
	do_nodes $nodes $LCTL get_param -N osp.*MDT*MDT*.filesfree >&/dev/null
}

client_up() {
	# usually checked on particular client or locally
	sleep 1
	lfs_df_check $1
}

# usage: client_evicted client [evictor, mds1 by default]
# return true if \a client was evicted by \a evictor in current test
client_evicted() {
	local testid=$(echo $TESTNAME | tr '_' ' ')
	local client=$1
	local facet=${2:-mds1}
	local dev=$(facet_svc $facet)

	client_up $client
	$PDSH $client "dmesg | tac | sed \"/$testid/,$ d\"" |
		grep -q "client was evicted by ${dev}"
}

client_reconnect_try() {
	local f=$MOUNT/recon

	uname -n >> $f
	if [ -z "$CLIENTS" ]; then
		$LFS df $MOUNT; uname -n >> $f
	else
		do_nodes $CLIENTS "$LFS df $MOUNT; uname -n >> $f" > /dev/null
	fi
	echo "Connected clients: $(cat $f)"
	ls -l $f > /dev/null
	rm $f
}

client_reconnect() {
	# one client_reconnect_try call does not always do the job...
	while true ; do
		client_reconnect_try && break
		sleep 1
	done
}

affected_facets () {
	local facet=$1

	local host=$(facet_active_host $facet)
	local affected=$facet

	if [ "$FAILURE_MODE" = HARD ]; then
		affected=$(facets_up_on_host $host)
	fi
	echo $affected
}

facet_failover() {
	local E2FSCK_ON_MDT0=false
	if [ "$1" == "--fsck" ]; then
		shift
		[ $(facet_fstype $SINGLEMDS) == ldiskfs ] &&
			E2FSCK_ON_MDT0=true
	fi

	local facets=$1
	local sleep_time=$2
	local -a affecteds
	local facet
	local total=0
	local index=0
	local skip

	#Because it will only get up facets, we need get affected
	#facets before shutdown
	#For HARD Failure mode, it needs make sure facets on the same
	#HOST will only be shutdown and reboot once
	for facet in ${facets//,/ }; do
		local affected_facet
		skip=0
		#check whether facet has been included in other affected facets
		for ((index=0; index<$total; index++)); do
			[[ ,${affecteds[index]}, == *,$facet,* ]] && skip=1
		done

		if [ $skip -eq 0 ]; then
			affecteds[$total]=$(affected_facets $facet)
			total=$((total+1))
		fi
	done

	for ((index=0; index<$total; index++)); do
		facet=$(echo ${affecteds[index]} | tr -s " " | cut -d"," -f 1)
		local host=$(facet_active_host $facet)
		echo "Failing ${affecteds[index]} on $host"
		shutdown_facet $facet
	done

	echo "$(date +'%H:%M:%S (%s)') shut down"

	local hostlist
	local waithostlist

	for facet in ${facets//,/ }; do
		local host=$(facet_active_host $facet)

		hostlist=$(expand_list $hostlist $host)
		if [ $(facet_host $facet) = \
			$(facet_failover_host $facet) ]; then
			waithostlist=$(expand_list $waithostlist $host)
		fi
	done

	if [ "$FAILURE_MODE" = HARD ]; then
		for host in ${hostlist//,/ }; do
			reboot_node $host
		done
		echo "$(date +'%H:%M:%S (%s)') $hostlist rebooted"
		# We need to wait the rebooted hosts in case if
		# facet_HOST == facetfailover_HOST
		if ! [ -z "$waithostlist" ]; then
			wait_for_host $waithostlist
			if $LOAD_MODULES_REMOTE; then
				echo "loading modules on $waithostlist"
				do_rpc_nodes $waithostlist load_modules_local
			fi
		fi
	else
		sleep 10
	fi

	if [[ " ${affecteds[@]} " =~ " $SINGLEMDS " ]]; then
		change_active $SINGLEMDS
	fi

	$E2FSCK_ON_MDT0 && (run_e2fsck $(facet_active_host $SINGLEMDS) \
		$(facet_device $SINGLEMDS) "-n" || error "Running e2fsck")

	local -a mountpids

	for ((index=0; index<$total; index++)); do
		if [[ ${affecteds[index]} != $SINGLEMDS ]]; then
			change_active ${affecteds[index]}
		fi
		if $GSS_SK; then
			init_gss
			init_facets_vars_simple
		fi
		# start mgs first if it is affected
		if ! combined_mgs_mds &&
			list_member ${affecteds[index]} mgs; then
			mount_facet mgs || error "Restart of mgs failed"
			affecteds[index]=$(exclude_items_from_list \
				${affecteds[index]} mgs)
		fi
		if [ -n "${affecteds[index]}" ]; then
			echo mount facets: ${affecteds[index]}
			mount_facets ${affecteds[index]} &
			mountpids[index]=$!
		fi
	done
	for ((index=0; index<$total; index++)); do
		if [ -n "${affecteds[index]}" ]; then
			wait ${mountpids[index]}
		fi

		if $GSS_SK; then
			do_nodes $(comma_list $(all_nodes)) \
				"keyctl show | grep lustre | cut -c1-11 |
				sed -e 's/ //g;' |
				xargs -IX keyctl setperm X 0x3f3f3f3f"
		fi
	done
	echo "$(date +'%H:%M:%S (%s)') targets are mounted"

	if [ "$FAILURE_MODE" = HARD ]; then
		hostlist=$(exclude_items_from_list $hostlist $waithostlist)
		if ! [ -z "$hostlist" ]; then
			wait_for_host $hostlist
			if $LOAD_MODULES_REMOTE; then
				echo "loading modules on $hostlist"
				do_rpc_nodes $hostlist load_modules_local
			fi
		fi
	fi

	echo "$(date +'%H:%M:%S (%s)') facet_failover done"
}

replay_barrier() {
	local facet=$1
	do_facet $facet "sync; sync; sync"
	$LFS df $MOUNT

	# make sure there will be no seq change
	local clients=${CLIENTS:-$HOSTNAME}
	local f=fsa-\\\$\(hostname\)
	do_nodes $clients "mcreate $MOUNT/$f; rm $MOUNT/$f"
	do_nodes $clients "if [ -d $MOUNT2 ]; then mcreate $MOUNT2/$f; rm $MOUNT2/$f; fi"

	local svc=${facet}_svc
	do_facet $facet $LCTL --device ${!svc} notransno
	#
	# If a ZFS OSD is made read-only here, its pool is "freezed". This
	# in-memory state has to be cleared by either rebooting the host or
	# exporting and reimporting the pool.
	#
	# Although the uberblocks are not updated when a pool is freezed,
	# transactions are still written to the disks. Modified blocks may be
	# cached in memory when tests try reading them back. The
	# export-and-reimport process also evicts any cached pool data from
	# memory to provide the correct "data loss" semantics.
	#
	# In the test framework, the exporting and importing operations are
	# handled by stop() and mount_facet() separately, which are used
	# inside fail() and fail_abort().
	#
	set_dev_readonly $facet
	do_facet $facet $LCTL mark "$facet REPLAY BARRIER on ${!svc}"
	$LCTL mark "local REPLAY BARRIER on ${!svc}"
}

replay_barrier_nodf() {
	local facet=$1    echo running=${running}
	do_facet $facet "sync; sync; sync"
	local svc=${facet}_svc
	echo Replay barrier on ${!svc}
	do_facet $facet $LCTL --device ${!svc} notransno
	set_dev_readonly $facet
	do_facet $facet $LCTL mark "$facet REPLAY BARRIER on ${!svc}"
	$LCTL mark "local REPLAY BARRIER on ${!svc}"
}

replay_barrier_nosync() {
	local facet=$1    echo running=${running}
	local svc=${facet}_svc
	echo Replay barrier on ${!svc}
	do_facet $facet $LCTL --device ${!svc} notransno
	set_dev_readonly $facet
	do_facet $facet $LCTL mark "$facet REPLAY BARRIER on ${!svc}"
	$LCTL mark "local REPLAY BARRIER on ${!svc}"
}

#
# Get Lustre client uuid for a given Lustre mount point.
#
get_client_uuid() {
	local mntpnt=${1:-$MOUNT}

	local name=$($LFS getname $mntpnt | cut -d' ' -f1)
	local uuid=$($LCTL get_param -n llite.$name.uuid)

	echo -n $uuid
}

mds_evict_client() {
	local mntpnt=${1:-$MOUNT}
	local uuid=$(get_client_uuid $mntpnt)

	do_facet $SINGLEMDS \
		"$LCTL set_param -n mdt.${mds1_svc}.evict_client $uuid"
}

ost_evict_client() {
	local mntpnt=${1:-$MOUNT}
	local uuid=$(get_client_uuid $mntpnt)

	do_facet ost1 \
		"$LCTL set_param -n obdfilter.${ost1_svc}.evict_client $uuid"
}

fail() {
	local facets=$1
	local clients=${CLIENTS:-$HOSTNAME}

	SK_NO_KEY_save=$SK_NO_KEY
	if $GSS_SK; then
		export SK_NO_KEY=false
	fi
	facet_failover $* || error "failover: $?"
	export SK_NO_KEY=$SK_NO_KEY_save
	# to initiate all OSC idling connections
	clients_up
	wait_clients_import_ready "$clients" "$facets"
	clients_up || error "post-failover stat: $?"
}

fail_nodf() {
	local facet=$1

	facet_failover $facet
}

fail_abort() {
	local facet=$1
	local abort_type=${2:-"abort_recovery"}

	stop $facet
	change_active $facet
	wait_for_facet $facet
	mount_facet $facet -o $abort_type
	clients_up || echo "first stat failed: $?"
	clients_up || error "post-failover stat: $?"
	all_mds_up
}

# LU-16159: abort recovery will cancel update logs, which may leave broken
# directories in the system, remove name entry if necessary
fail_abort_cleanup() {
	rm -rf $DIR/$tdir/*
	find $DIR/$tdir -depth | while read D; do
		rmdir "$D" || $LFS rm_entry "$D" || error "rm $D failed"
	done
}

host_nids_address() {
	local nodes=$1
	local net=${2:-"."}

	do_nodes $nodes "$LCTL list_nids | grep -w $net | cut -f 1 -d @"
}

ip_is_v4() {
	local ipv4_re='^([0-9]{1,3}\.){3,3}[0-9]{1,3}$'

	if ! [[ $1 =~ $ipv4_re ]]; then
		return 1
	fi

	local quads=(${1//\./ })

	(( ${#quads[@]} == 4)) || return 1

	(( quads[0] < 256 && quads[1] < 256 &&
	   quads[2] < 256 && quads[3] < 256 )) || return 1

	return 0
}

ip_is_v6() {
	local ipv6_re='^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$'

	if ! [[ $1 =~ $ipv6_re ]]; then
		return 1
	fi

	local segment
	for segment in ${1//:/ }; do
		((0x$segment <= 0xFFFF)) || return 1
	done

	return 0
}

h2name_or_ip() {
	if [[ "$1" == '*' ]]; then
		echo \'*\'
	elif ip_is_v4 "$1" || ip_is_v6 "$1" ; then
		echo "$1@$2"
	else
		local addr nidlist large_nidlist
		local iplist=$(do_node $1 hostname -I | sed "s/$1://")

		for addr in ${iplist}; do
			nid="${addr}@$2"
			ip_is_v4 "$addr" &&
				nidlist="${nidlist:+$nidlist,}${nid}" ||
				large_nidlist="${large_nidlist:+$large_nidlist,}${nid}"
		done
		if [[ -n $nidlist ]] && [[ -n $large_nidlist ]]; then
			if ${FORCE_LARGE_NID}; then
				echo "$large_nidlist"
			else
				echo "$nidlist"
			fi
		elif [[ -n $nidlist ]]; then
			echo "$nidlist"
		elif [[ -n $large_nidlist ]]; then
			echo "$large_nidlist"
		else
			echo "$1@$2"
		fi
	fi
}

h2nettype() {
	if [[ -n "$NETTYPE" ]]; then
		h2name_or_ip "$1" "$NETTYPE"
	else
		h2name_or_ip "$1" "$2"
	fi
}
declare -fx h2nettype

# This enables variables in cfg/"setup".sh files to support the pdsh HOSTLIST
# expressions format. As a bonus we can then just pass in those variables
# to pdsh. What this function does is take a HOSTLIST type string and
# expand it into a space deliminated list for us.
hostlist_expand() {
	local hostlist=$1
	local offset=$2
	local myList
	local item
	local list

	[ -z "$hostlist" ] && return

	# Translate the case of [..],..,[..] to [..] .. [..]
	list="${hostlist/],/] }"
	front=${list%%[*}
	[[ "$front" == *,* ]] && {
		new="${list%,*} "
		old="${list%,*},"
		list=${list/${old}/${new}}
	}

	for item in $list; do
	# Test if we have any []'s at all
		if [ "$item" != "${item/\[/}" ]; then {
		# Expand the [*] into list
		name=${item%%[*}
		back=${item#*]}

			if [ "$name" != "$item" ]; then
				group=${item#$name[*}
				group=${group%%]*}

				for range in ${group//,/ }; do
					local order

					begin=${range%-*}
					end=${range#*-}

					# Number of leading zeros
					padlen=${#begin}
					padlen2=${#end}
					end=$(echo $end | sed 's/0*//')
					[[ -z "$end" ]] && end=0
					[[ $padlen2 -gt $padlen ]] && {
						[[ $padlen2 -eq ${#end} ]] &&
							padlen2=0
						padlen=$padlen2
					}
					begin=$(echo $begin | sed 's/0*//')
					[ -z $begin ] && begin=0

					if [ ! -z "${begin##[!0-9]*}" ]; then
						order=$(seq -f "%0${padlen}g" $begin $end)
					else
						order=$(eval echo {$begin..$end});
					fi

					for num in $order; do
						value="${name#*,}${num}${back}"

						[ "$value" != "${value/\[/}" ] && {
						    value=$(hostlist_expand "$value")
						}
						myList="$myList $value"
					done
				done
			fi
		} else {
			myList="$myList $item"
		} fi
	done
	myList=${myList//,/ }
	myList=${myList:1} # Remove first character which is a space

	# Filter any duplicates without sorting
	list="$myList "
	myList="${list%% *}"

	while [[ "$list" != ${myList##* } ]]; do
		local tlist=" $list"

		list=${tlist// ${list%% *} / }
		list=${list:1}
		myList="$myList ${list%% *}"
	done
	myList="${myList%* }";

	# We can select an object at an offset in the list
	[ $# -eq 2 ] && {
	cnt=0
	for item in $myList; do
		let cnt=cnt+1
		[ $cnt -eq $offset ] && {
			myList=$item
		}
	done
	[ $(get_node_count $myList) -ne 1 ] && myList=""
	}
	echo $myList
}

facet_host() {
	local facet=$1
	local varname

	[ "$facet" == client ] && echo -n $HOSTNAME && return
	varname=${facet}_HOST
	if [ -z "${!varname}" ]; then
		if [ "${facet:0:3}" == "ost" ]; then
			local fh=${facet%failover}_HOST
			eval export ${facet}_HOST=${!fh}
			if [ -z "${!varname}" ]; then
				eval export ${facet}_HOST=${ost_HOST}
			fi
		elif [ "${facet:0:3}" == "mdt" -o \
			"${facet:0:3}" == "mds" -o \
			"${facet:0:3}" == "mgs" ]; then
			local temp
			if [ "${facet}" == "mgsfailover" ] &&
			   [ -n "$mds1failover_HOST" ]; then
				temp=$mds1failover_HOST
			else
				temp=${mds_HOST}
			fi
			eval export ${facet}_HOST=$temp
		fi
	fi
	echo -n ${!varname}
}

facet_failover_host() {
	local facet=$1
	local varname

	var=${facet}failover_HOST
	if [ -n "${!var}" ]; then
		echo ${!var}
		return
	fi

	if combined_mgs_mds && [ $facet == "mgs" ] &&
		[ -n "$mds1failover_HOST" ]; then
		echo $mds1failover_HOST
		return
	fi

	if [ "${facet:0:3}" == "mdt" -o "${facet:0:3}" == "mds" -o \
	     "${facet:0:3}" == "mgs" ]; then

		eval export ${facet}failover_host=${mds_HOST}
		echo ${mds_HOST}
		return
	fi

	if [[ $facet == ost* ]]; then
		eval export ${facet}failover_host=${ost_HOST}
		echo ${ost_HOST}
		return
	fi
}

facet_active() {
	local facet=$1
	local activevar=${facet}active

	if [ -f $TMP/${facet}active ] ; then
		source $TMP/${facet}active
	fi

	active=${!activevar}
	if [ -z "$active" ] ; then
		echo -n ${facet}
	else
		echo -n ${active}
	fi
}

facet_active_host() {
	facet_host $(facet_active $1)
}

# Get the passive failover partner host of facet.
facet_passive_host() {
	local facet=$1
	[[ $facet = client ]] && return

	local host=${facet}_HOST
	local failover_host=${facet}failover_HOST
	local active_host=$(facet_active_host $facet)

	[[ -z ${!failover_host} || ${!failover_host} = ${!host} ]] && return

	if [[ $active_host = ${!host} ]]; then
		echo -n ${!failover_host}
	else
		echo -n ${!host}
	fi
}

change_active() {
	local facetlist=$1
	local facet

	for facet in ${facetlist//,/ }; do
		local failover=${facet}failover
		local host=`facet_host $failover`

		[ -z "$host" ] && return

		local curactive=`facet_active $facet`

		if [ -z "${curactive}" -o "$curactive" == "$failover" ] ; then
			eval export ${facet}active=$facet
		else
			eval export ${facet}active=$failover
		fi
		# save the active host for this facet
		local activevar=${facet}active

		echo "$activevar=${!activevar}" > $TMP/$activevar
		[[ $facet = mds1 ]] && combined_mgs_mds && \
		echo "mgsactive=${!activevar}" > $TMP/mgsactive
		local TO=`facet_active_host $facet`
		echo "Failover $facet to $TO"
	done
}

do_node() {
	local verbose
	local quiet

	# do not strip off hostname if verbose, b=19215
	[[ "$1" == "--verbose" ]] && verbose="$1" && shift
	[[ "$1" == "--quiet" || "$1" == "-q" ]] && quiet="$1" && shift

	local HOST=$1
	shift
	local myPDSH=$PDSH

	if [ "$HOST" = "$HOSTNAME" ]; then
		myPDSH="no_dsh"
	elif [ -z "$myPDSH" -o "$myPDSH" = "no_dsh" ]; then
		echo "cannot run remote command on $HOST with $myPDSH"
		return 128
	fi
	if $VERBOSE && [[ -z "$quiet" ]]; then
		echo "CMD: $HOST $*" >&2
		$myPDSH $HOST "$LCTL mark \"$*\"" > /dev/null 2>&1 || :
	fi

	if [[ "$myPDSH" == "rsh" ]] ||
	   [[ "$myPDSH" == *pdsh* && "$myPDSH" != *-S* ]]; then
		# we need this because rsh and pdsh do not return
		# exit code of an executed command
		local command_status="$TMP/cs"
		eval $myPDSH $HOST ":> $command_status"
		eval $myPDSH $HOST "(PATH=\$PATH:$RLUSTRE/utils:$RLUSTRE/tests;
				     PATH=\$PATH:/sbin:/usr/sbin;
				     cd $RPWD;
				     LUSTRE=\"$RLUSTRE\" bash -c \"$*\") ||
				     echo command failed >$command_status"
		[[ -n "$($myPDSH $HOST cat $command_status)" ]] && return 1 ||
			return 0
	fi

	if [[ -n "$verbose" ]]; then
		# print HOSTNAME for myPDSH="no_dsh"
		if [[ $myPDSH = no_dsh ]]; then
			$myPDSH $HOST \
			"(PATH=\$PATH:$RLUSTRE/utils:$RLUSTRE/tests:/sbin:/usr/sbin;\
			cd $RPWD; LUSTRE=\"$RLUSTRE\" bash -c \"$*\")" |
			sed -e "s/^/${HOSTNAME}: /"
		else
			$myPDSH $HOST \
			"(PATH=\$PATH:$RLUSTRE/utils:$RLUSTRE/tests:/sbin:/usr/sbin;\
			cd $RPWD; LUSTRE=\"$RLUSTRE\" bash -c \"$*\")"
		fi
	else
		$myPDSH $HOST \
		"(PATH=\$PATH:$RLUSTRE/utils:$RLUSTRE/tests:/sbin:/usr/sbin;\
		cd $RPWD; LUSTRE=\"$RLUSTRE\" bash -c \"$*\")" |
		sed "s/^${HOST}: //"
	fi
	return ${PIPESTATUS[0]}
}

##
# Execute exact command line on host
#
# The \a host may be on a local or remote node, which is determined at
# the time the command is run. Does careful argument quotation to
# ensure that the exact command line is executed without any globbing,
# substitution, or shell interpretation on the remote side. Does not
# support --verbose or --quiet. Does not include "$host: " prefixes on
# output. See also do_facet_vp().
#
# usage: do_node_vp "$host" "$command" "$arg"...
do_node_vp() {
	local host="$1"
	shift

	if [[ "$host" == "$HOSTNAME" ]]; then
		bash -c "$(printf -- ' %q' "$@")"
		return $?
	fi

	if [[ "${PDSH}" != *pdsh* || "${PDSH}" != *-S* ]]; then
		echo "cannot run '$*' on host '${host}' with PDSH='${PDSH}'" >&2
		return 128
	fi

	# -N Disable hostname: prefix on lines of output.

	$PDSH "${host}" -N "cd $RPWD; PATH=\$PATH:$RLUSTRE/utils:$RLUSTRE/tests:/sbin:/usr/sbin; export LUSTRE=$RLUSTRE; $(printf -- ' %q' "$@")"
}

single_local_node () {
	[ "$1" = "$HOSTNAME" ]
}

# Outputs environment variable assignments that should be passed to remote nodes
get_env_vars() {
	local var
	local value
	local facets=$(get_facets)
	local facet

	for var in ${!MODOPTS_*}; do
		value=${!var//\"/\\\"}
		echo -n " ${var}=\"$value\""
	done

	for facet in ${facets//,/ }; do
		var=${facet}_FSTYPE
		if [ -n "${!var}" ]; then
			echo -n " $var=${!var}"
		fi
	done

	for var in MGSFSTYPE MDSFSTYPE OSTFSTYPE; do
		if [ -n "${!var}" ]; then
			echo -n " $var=${!var}"
		fi
	done

	for var in VERBOSE; do
		if [ -n "${!var}" ]; then
			echo -n " $var=${!var}"
		fi
	done

	if [ -n "$FSTYPE" ]; then
		echo -n " FSTYPE=$FSTYPE"
	fi

	for var in LNETLND NETTYPE; do
		if [ -n "${!var}" ]; then
			echo -n " $var=${!var}"
		fi
	done
}

do_nodes() {
	local verbose
	local quiet

	# do not strip off hostname if verbose, b=19215
	[[ "$1" == "--verbose" ]] && verbose="$1" && shift
	[[ "$1" == "--quiet" || "$1" == "-q" ]] && quiet="$1" && shift

	local rnodes=$1
	shift

	if single_local_node $rnodes; then
		do_node $verbose $quiet $rnodes "$@"
		return $?
	fi

	# This is part from do_node
	local myPDSH=$PDSH

	[ -z "$myPDSH" -o "$myPDSH" = "no_dsh" -o "$myPDSH" = "rsh" ] &&
		echo "cannot run remote command on $rnodes with $myPDSH" &&
		return 128

	export FANOUT=$(get_node_count "${rnodes//,/ }")
	if $VERBOSE && [[ -z "$quiet" ]]; then
		echo "CMD: $rnodes $*" >&2
		$myPDSH $rnodes "$LCTL mark \"$*\"" > /dev/null 2>&1 || :
	fi

	# do not replace anything from pdsh output if -N is used
	# -N     Disable hostname: prefix on lines of output.
	if [[ -n "$verbose" || $myPDSH = *-N* ]]; then
		$myPDSH $rnodes "(PATH=\$PATH:$RLUSTRE/utils:$RLUSTRE/tests:/sbin:/usr/sbin; cd $RPWD; LUSTRE=\"$RLUSTRE\" $(get_env_vars) bash -c \"$*\")"
	else
		$myPDSH $rnodes "(PATH=\$PATH:$RLUSTRE/utils:$RLUSTRE/tests:/sbin:/usr/sbin; cd $RPWD; LUSTRE=\"$RLUSTRE\" $(get_env_vars) bash -c \"$*\")" | sed -re "s/^[^:]*: //g"
	fi
	return ${PIPESTATUS[0]}
}

##
# Execute commands on a single service's host
#
# The \a facet (service) may be on a local or remote node, which is
# determined at the time the command is run.
#
# usage: do_facet $facet command [arg ...]
do_facet() {
	local verbose
	local quiet

	[[ "$1" == "--verbose" ]] && verbose="$1" && shift
	[[ "$1" == "--quiet" || "$1" == "-q" ]] && quiet="$1" && shift

	local facet=$1
	shift
	local host=$(facet_active_host $facet)

	[ -z "$host" ] && echo "No host defined for facet ${facet}" && exit 1
	do_node $verbose $quiet $host "$@"
}

##
# Execute exact command line on the host of a facet
#
# The \a facet (service) may be on a local or remote node, which is
# determined at the time the command is run. Does careful argument
# quotation to ensure that the exact command line is executed without
# any globbing, substitution, or shell interpretation on the remote
# side. Does not support --verbose or --quiet. Does not include
# "$host: " prefixes on output.
#
# usage: do_facet_vp "$facet" "$command" "$arg"...
do_facet_vp() {
	local facet="$1"
	local host=$(facet_active_host "$facet")
	shift

	if [[ -z "$host" ]]; then
		echo "no host defined for facet ${facet}" >&2
		exit 1
	fi

	do_node_vp "$host" "$@"
}

# Function: do_facet_random_file $FACET $FILE $SIZE
# Creates FILE with random content on the given FACET of given SIZE

do_facet_random_file() {
	local facet="$1"
	local fpath="$2"
	local fsize="$3"
	local cmd="dd if=/dev/urandom of='$fpath' bs=$fsize count=1"
	do_facet $facet "$cmd 2>/dev/null"
}

do_facet_create_file() {
	local facet="$1"
	local fpath="$2"
	local fsize="$3"
	local cmd="dd if=/dev/zero of='$fpath' bs=$fsize count=1"
	do_facet $facet "$cmd 2>/dev/null"
}

do_nodesv() {
	do_nodes --verbose "$@"
}

add() {
	local facet=$1
	shift
	# make sure its not already running
	stop ${facet} -f
	rm -f $TMP/${facet}active
	[[ $facet = mds1 ]] && combined_mgs_mds && rm -f $TMP/mgsactive

	# make sure in-tree ldiskfs is loaded before mkfs
	if local_mode && [[ $(node_fstypes $HOSTNAME) == *ldiskfs* ]]; then
		load_module ../ldiskfs/ldiskfs
	fi

	do_facet ${facet} $MKFS $* || return ${PIPESTATUS[0]}

	if [[ $(facet_fstype $facet) == zfs ]]; then
		#
		# After formatting a ZFS target, "cachefile=none" property will
		# be set on the ZFS storage pool so that the pool is not
		# automatically imported on system startup. And then the pool
		# will be exported so as to leave the importing and exporting
		# operations handled by mount_facet() and stop() separately.
		#
		refresh_partition_table $facet $(facet_vdevice $facet)
		disable_zpool_cache $facet
		export_zpool $facet
	fi
}

# Device formatted as ost
ostdevname() {
	local num=$1
	local DEVNAME=OSTDEV$num

	local fstype=$(facet_fstype ost$num)

	case $fstype in
		ldiskfs )
			local dev=ost${num}_dev
			[[ -n ${!dev} ]] && eval DEVPTR=${!dev} ||
			#if $OSTDEVn isn't defined, default is $OSTDEVBASE + num
			eval DEVPTR=${!DEVNAME:=${OSTDEVBASE}${num}};;
		zfs )
			#try $OSTZFSDEVn - independent of vdev
			DEVNAME=OSTZFSDEV$num
			eval DEVPTR=${!DEVNAME:=${FSNAME}-ost${num}/ost${num}};;
		* )
			error "unknown fstype!";;
	esac

	echo -n $DEVPTR
}

# Physical device location of data
ostvdevname() {
	local num=$1
	local DEVNAME
	local VDEVPTR

	local fstype=$(facet_fstype ost$num)

	case $fstype in
		ldiskfs )
			# vdevs are not supported by ldiskfs
			eval VDEVPTR="";;
		zfs )
			#if $OSTDEVn isn't defined, default is $OSTDEVBASE{n}
			# Device formatted by zfs
			DEVNAME=OSTDEV$num
			eval VDEVPTR=${!DEVNAME:=${OSTDEVBASE}${num}};;
		* )
			error "unknown fstype!";;
	esac

	echo -n $VDEVPTR
}

# Logical device formatted for lustre
mdsdevname() {
	local num=$1
	local DEVNAME=MDSDEV$num

	local fstype=$(facet_fstype mds$num)

	case $fstype in
		ldiskfs )
			local dev=mds${num}_dev
			[[ -n ${!dev} ]] && eval DEVPTR=${!dev} ||
			#if $MDSDEVn isn't defined, default is $MDSDEVBASE{n}
			eval DEVPTR=${!DEVNAME:=${MDSDEVBASE}${num}};;
		zfs )
			# try $MDSZFSDEVn - independent of vdev
			DEVNAME=MDSZFSDEV$num
			eval DEVPTR=${!DEVNAME:=${FSNAME}-mdt${num}/mdt${num}};;
		* )
			error "unknown fstype!";;
	esac

	echo -n $DEVPTR
}

# Physical location of data
mdsvdevname() {
	local VDEVPTR=""
	local num=$1
	local fstype=$(facet_fstype mds$num)

	case $fstype in
		ldiskfs )
			# vdevs are not supported by ldiskfs
			eval VDEVPTR="";;
		zfs )
			# if $MDSDEVn isn't defined, default is $MDSDEVBASE{n}
			# Device formatted by ZFS
			local DEVNAME=MDSDEV$num
			eval VDEVPTR=${!DEVNAME:=${MDSDEVBASE}${num}};;
		* )
			error "unknown fstype!";;
	esac

	echo -n $VDEVPTR
}

mgsdevname() {
	local DEVPTR
	local fstype=$(facet_fstype mgs)

	case $fstype in
	ldiskfs )
		if [ $(facet_host mgs) = $(facet_host mds1) ] &&
		   ( [ -z "$MGSDEV" ] || [ $MGSDEV = $MDSDEV1 ] ); then
			DEVPTR=$(mdsdevname 1)
		else
			[[ -n $mgs_dev ]] && DEVPTR=$mgs_dev ||
			DEVPTR=$MGSDEV
		fi;;
	zfs )
		if [ $(facet_host mgs) = $(facet_host mds1) ] &&
		    ( [ -z "$MGSZFSDEV" ] &&
			[ -z "$MGSDEV" -o "$MGSDEV" = $(mdsvdevname 1) ] ); then
			DEVPTR=$(mdsdevname 1)
		else
			DEVPTR=${MGSZFSDEV:-${FSNAME}-mgs/mgs}
		fi;;
	* )
		error "unknown fstype!";;
	esac

	echo -n $DEVPTR
}

mgsvdevname() {
	local VDEVPTR=""

	local fstype=$(facet_fstype mgs)

	case $fstype in
	ldiskfs )
		# vdevs are not supported by ldiskfs
		;;
	zfs )
		if [ $(facet_host mgs) = $(facet_host mds1) ] &&
		   ( [ -z "$MGSDEV" ] &&
		       [ -z "$MGSZFSDEV" -o "$MGSZFSDEV" = $(mdsdevname 1) ]); then
			VDEVPTR=$(mdsvdevname 1)
		elif [ -n "$MGSDEV" ]; then
			VDEVPTR=$MGSDEV
		fi;;
	* )
		error "unknown fstype!";;
	esac

	echo -n $VDEVPTR
}

facet_mntpt () {
	local facet=$1
	[[ $facet = mgs ]] && combined_mgs_mds && facet="mds1"

	local var=${facet}_MOUNT
	eval mntpt=${!var:-${MOUNT}-$facet}

	echo -n $mntpt
}

mount_ldiskfs() {
	local facet=$1
	local dev=$(facet_device $facet)
	local mnt=${2:-$(facet_mntpt $facet)}
	local opts
	local dm_dev=$dev

	if dm_flakey_supported $facet; then
		dm_dev=$(dm_create_dev $facet $dev)
		[[ -n "$dm_dev" ]] || dm_dev=$dev
	fi
	is_blkdev $facet $dm_dev || opts=$(csa_add "$opts" -o loop)
	export_dm_dev $facet $dm_dev

	do_facet $facet mount -t ldiskfs $opts $dm_dev $mnt
}

unmount_ldiskfs() {
	local facet=$1
	local dev=$(facet_device $facet)
	local mnt=${2:-$(facet_mntpt $facet)}

	do_facet $facet $UMOUNT $mnt
}

var_name() {
	echo -n "$1" | tr -c '[:alnum:]\n' '_'
}

mount_zfs() {
	local facet=$1
	local ds=$(facet_device $facet)
	local mnt=${2:-$(facet_mntpt $facet)}
	local canmnt
	local mntpt

	import_zpool $facet
	canmnt=$(do_facet $facet $ZFS get -H -o value canmount $ds)
	mntpt=$(do_facet $facet $ZFS get -H -o value mountpoint $ds)
	do_facet $facet $ZFS set canmount=noauto $ds
	#
	# The "legacy" mount method is used here because "zfs unmount $mnt"
	# calls stat(2) on $mnt/../*, which may include $MOUNT.  If certain
	# targets are not available at the time, the stat(2) on $MOUNT will
	# hang.
	#
	do_facet $facet $ZFS set mountpoint=legacy $ds
	do_facet $facet mount -t zfs $ds $mnt
	eval export mz_$(var_name ${facet}_$ds)_canmount=$canmnt
	eval export mz_$(var_name ${facet}_$ds)_mountpoint=$mntpt
}

unmount_zfs() {
	local facet=$1
	local ds=$(facet_device $facet)
	local mnt=${2:-$(facet_mntpt $facet)}
	local var_mntpt=mz_$(var_name ${facet}_$ds)_mountpoint
	local var_canmnt=mz_$(var_name ${facet}_$ds)_canmount
	local mntpt=${!var_mntpt}
	local canmnt=${!var_canmnt}

	unset $var_mntpt
	unset $var_canmnt
	do_facet $facet umount $mnt
	do_facet $facet $ZFS set mountpoint=$mntpt $ds
	do_facet $facet $ZFS set canmount=$canmnt $ds
	export_zpool $facet
}

mount_fstype() {
	local facet=$1
	local mnt=$2
	local fstype=$(facet_fstype $facet)

	mount_$fstype $facet $mnt
}

unmount_fstype() {
	local facet=$1
	local mnt=$2
	local fstype=$(facet_fstype $facet)

	unmount_$fstype $facet $mnt
}

########
## MountConf setup

stopall() {
	# make sure we are using the primary server, so test-framework will
	# be able to clean up properly.
	activemds=`facet_active mds1`
	if [ $activemds != "mds1" ]; then
		fail mds1
	fi

	local clients=$CLIENTS
	[ -z $clients ] && clients=$(hostname)

	zconf_umount_clients $clients $MOUNT "$*" || true
	[ -n "$MOUNT2" ] && zconf_umount_clients $clients $MOUNT2 "$*" || true

	[ -n "$CLIENTONLY" ] && return

	# The add fn does rm ${facet}active file, this would be enough
	# if we use do_facet <facet> only after the facet added, but
	# currently we use do_facet mds in local.sh
	local num
	for num in `seq $MDSCOUNT`; do
		stop mds$num -f
		rm -f ${TMP}/mds${num}active
	done
	combined_mgs_mds && rm -f $TMP/mgsactive

	for num in `seq $OSTCOUNT`; do
		stop ost$num -f
		rm -f $TMP/ost${num}active
	done

	if ! combined_mgs_mds ; then
		stop mgs
	fi

	if $SHARED_KEY; then
		export SK_MOUNTED=false
	fi

	return 0
}

cleanup_echo_devs () {
	trap 0
	local dev
	local devs=$($LCTL dl | grep echo | awk '{print $4}')

	for dev in $devs; do
		$LCTL --device $dev cleanup
		$LCTL --device $dev detach
	done
}

# Allow %pK to print raw pointers and save the initial value
kptr_enable_and_save() {
	# do not overwrite whatever was initially saved:
	[[ -f $TMP/kptr-$PPID-env ]] && return

	declare -A kptr
	for node in $(all_nodes); do
		kptr[$node]=$(do_node $node "sysctl --values kernel/kptr_restrict")
		do_node $node "sysctl -wq kernel/kptr_restrict=1"
	done
	declare -p kptr > $TMP/kptr-$PPID-env
}

# Restore the initial %pK settings
kptr_restore() {
	[[ ! -f $TMP/kptr-$PPID-env ]] && return

	source $TMP/kptr-$PPID-env

	local param
	for node in $(all_nodes); do
		[[ -z ${kptr[$node]} ]] && continue
		param="kernel/kptr_restrict=${kptr[$node]}"
		do_node $node "sysctl -wq ${param} || true"
	done
}

cleanupall() {
	nfs_client_mode && return
	cifs_client_mode && return

	cleanup_echo_devs
	CLEANUP_DM_DEV=true stopall $*

	[[ $KPTR_ON_MOUNT ]] && kptr_restore

	unload_modules
	cleanup_sk
	cleanup_gss
}

combined_mgs_mds () {
	[[ "$(mdsdevname 1)" = "$(mgsdevname)" ]] &&
		[[ "$(facet_host mds1)" = "$(facet_host mgs)" ]]
}

lower() {
	echo -n "$1" | tr '[:upper:]' '[:lower:]'
}

upper() {
	echo -n "$1" | tr '[:lower:]' '[:upper:]'
}

squash_opt() {
	local var="$*"
	local other=""
	local opt_o=""
	local opt_e=""
	local first_e=0
	local first_o=0
	local take=""

	var=$(echo "$var" | sed -e 's/,\( \)*/,/g')
	for i in $(echo "$var"); do
		if [ "$i" == "-O" ]; then
			take="o";
			first_o=$(($first_o + 1))
			continue;
		fi
		if [ "$i" == "-E" ]; then
			take="e";
			first_e=$(($first_e + 1 ))
			continue;
		fi
		case $take in
			"o")
				[ $first_o -gt 1 ] && opt_o+=",";
				opt_o+="$i";
				;;
			"e")
				[ $first_e -gt 1 ] && opt_e+=",";
				opt_e+="$i";
				;;
			*)
				other+=" $i";
				;;
		esac
		take=""
	done

	echo -n "$other"
	[ -n "$opt_o" ] && echo " -O $opt_o"
	[ -n "$opt_e" ] && echo " -E $opt_e"
}

mkfs_opts() {
	local facet=$1
	local dev=$2
	local fsname=${3:-"$FSNAME"}
	local type=$(facet_type $facet)
	local index=$(facet_index $facet)
	local fstype=$(facet_fstype $facet)
	local host=$(facet_host $facet)
	local opts
	local fs_mkfs_opts
	local var
	local varbs=${facet}_BLOCKSIZE

	if [ $type == MGS ] || ( [ $type == MDS ] &&
                                 [ "$dev" == $(mgsdevname) ] &&
				 [ "$host" == "$(facet_host mgs)" ] ); then
		opts="--mgs"
	else
		opts="--mgsnode=$MGSNID"
	fi

	if [ $type != MGS ]; then
		opts+=" --fsname=$fsname --$(lower ${type/MDS/MDT}) \
			--index=$index"
	fi

	var=${facet}failover_HOST
	if [ -n "${!var}" ] && [ ${!var} != $(facet_host $facet) ]; then
		opts+=" --failnode=$(h2nettype ${!var})"
	fi

	opts+=${TIMEOUT:+" --param=sys.timeout=$TIMEOUT"}
	opts+=${LDLM_TIMEOUT:+" --param=sys.ldlm_timeout=$LDLM_TIMEOUT"}

	if [ $type == MDS ]; then
		opts+=${DEF_STRIPE_SIZE:+" --param=lov.stripesize=$DEF_STRIPE_SIZE"}
		opts+=${DEF_STRIPE_COUNT:+" --param=lov.stripecount=$DEF_STRIPE_COUNT"}
		opts+=${L_GETIDENTITY:+" --param=mdt.identity_upcall=$L_GETIDENTITY"}

		if [ $fstype == ldiskfs ]; then
			var=${facet}_JRN
			if [ -n "${!var}" ]; then
				fs_mkfs_opts+=" -J device=${!var}"
			else
				fs_mkfs_opts+=${MDSJOURNALSIZE:+" -J size=$MDSJOURNALSIZE"}
			fi
			fs_mkfs_opts+=${MDSISIZE:+" -i $MDSISIZE"}
		fi
	fi

	if [ $type == OST ]; then
		if [ $fstype == ldiskfs ]; then
			var=${facet}_JRN
			if [ -n "${!var}" ]; then
				fs_mkfs_opts+=" -J device=${!var}"
			else
				fs_mkfs_opts+=${OSTJOURNALSIZE:+" -J size=$OSTJOURNALSIZE"}
			fi
		fi
	fi

	opts+=" --backfstype=$fstype"

	var=${type}SIZE
	if [ -n "${!var}" ]; then
		opts+=" --device-size=${!var}"
	fi

	var=$(upper $fstype)_MKFS_OPTS
	fs_mkfs_opts+=${!var:+" ${!var}"}

	var=${type}_FS_MKFS_OPTS
	fs_mkfs_opts+=${!var:+" ${!var}"}

	[[ "$QUOTA_TYPE" =~ "p" ]] && fs_mkfs_opts+=" -O project"

	[ $fstype == ldiskfs ] && fs_mkfs_opts+=" -b ${!varbs:-$BLCKSIZE}"
	[ $fstype == ldiskfs ] && fs_mkfs_opts=$(squash_opt $fs_mkfs_opts)

	if [ -n "${fs_mkfs_opts## }" ]; then
		opts+=" --mkfsoptions=\\\"${fs_mkfs_opts## }\\\""
	fi

	var=${type}OPT
	opts+=${!var:+" ${!var}"}

	echo -n "$opts"
}

mountfs_opts() {
	local facet=$1
	local type=$(facet_type $facet)
	local var=${type}_MOUNT_FS_OPTS
	local opts=""
	if [ -n "${!var}" ]; then
		opts+=" --mountfsoptions=${!var}"
	fi
	echo -n "$opts"
}

check_ost_indices() {
	local index_count=${#OST_INDICES[@]}
	[[ $index_count -eq 0 || $OSTCOUNT -le $index_count ]] && return 0

	# OST count is greater than the index count in $OST_INDEX_LIST.
	# We need check whether there are duplicate indices.
	local i
	local j
	local index
	for i in $(seq $((index_count + 1)) $OSTCOUNT); do
		index=$(facet_index ost$i)
		for j in $(seq 0 $((index_count - 1))); do
			[[ $index -ne ${OST_INDICES[j]} ]] ||
			error "ost$i has the same index $index as ost$((j+1))"
		done
	done
}

__touch_device()
{
	local facet_type=$1 # mgs || mds || ost
	local facet_num=$2
	local facet=${1}${2}
	local device

	case "$(facet_fstype $facet)" in
	ldiskfs)
		device=$(${facet_type}devname $facet_num)
		;;
	zfs)
		device=$(${facet_type}vdevname $facet_num)
		;;
	*)
		error "Unhandled filesystem type"
		;;
	esac

	do_facet $facet "[ -e \"$device\" ]" && return

	# Note: the following check only works with absolute paths
	[[ ! "$device" =~ ^/dev/ ]] || [[ "$device" =~ ^/dev/shm/ ]] ||
		error "$facet: device '$device' does not exist"

	# zpool create doesn't like empty files
	[[ $(facet_fstype $facet) == zfs ]] && return 0

	do_facet $facet "touch \"${device}\""
}

format_mgs() {
	local quiet

	if ! $VERBOSE; then
		quiet=yes
	fi
	echo "Format mgs: $(mgsdevname)"
	reformat_external_journal mgs

	# touch "device" in case it is a loopback file for testing and needs to
	# be created. mkfs.lustre doesn't do this to avoid accidentally writing
	# to non-existent files in /dev if the admin made a typo during setup
	__touch_device mgs

	add mgs $(mkfs_opts mgs $(mgsdevname)) $(mountfs_opts mgs) --reformat \
		$(mgsdevname) $(mgsvdevname) ${quiet:+>/dev/null} || exit 10
}

format_mdt() {
	local num=$1
	local quiet

	if ! $VERBOSE; then
		quiet=yes
	fi
	echo "Format mds$num: $(mdsdevname $num)"
	reformat_external_journal mds$num

	__touch_device mds $num

	add mds$num $(mkfs_opts mds$num $(mdsdevname ${num})) \
		$(mountfs_opts mds$num) --reformat $(mdsdevname $num) \
		$(mdsvdevname $num) ${quiet:+>/dev/null} || exit 10
}

format_ost() {
	local num=$1

	if ! $VERBOSE; then
		quiet=yes
	fi
	echo "Format ost$num: $(ostdevname $num)"
	reformat_external_journal ost$num

	__touch_device ost $num

	add ost$num $(mkfs_opts ost$num $(ostdevname ${num})) \
		$(mountfs_opts ost$num) --reformat $(ostdevname $num) \
		$(ostvdevname ${num}) ${quiet:+>/dev/null} || exit 10
}

formatall() {
	stopall -f
	# Set hostid for ZFS/SPL zpool import protection
	# (Assumes MDS version is also OSS version)
	if [ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.8.54) ];
	then
		do_rpc_nodes "$(comma_list $(all_server_nodes))" set_hostid
	fi

	# We need ldiskfs here, may as well load them all
	load_modules
	[ -n "$CLIENTONLY" ] && return
	echo Formatting mgs, mds, osts
	if ! combined_mgs_mds ; then
		format_mgs
	fi

	for num in $(seq $MDSCOUNT); do
		format_mdt $num
	done

	export OST_INDICES=($(hostlist_expand "$OST_INDEX_LIST"))
	check_ost_indices
	for num in $(seq $OSTCOUNT); do
		format_ost $num
	done
}

mount_client() {
	grep " $1 " /proc/mounts || zconf_mount $HOSTNAME $*
}

umount_client() {
	grep " $1 " /proc/mounts && zconf_umount $HOSTNAME $*
}

# usage: switch_identity MDSNUM ENABLE_UPCALL
#
# return values:
# 0: success, the identity upcall was previously enabled already.
# 1: success, the identity upcall was previously disabled.
# 2: fail.
switch_identity() {
	local num=$1
	local enable=$2
	local facet=mds$num
	local MDT="$(mdtname_from_index $((num - 1)) $MOUNT)"
	local upcall="$L_GETIDENTITY"

	[[ -n "$MDT" ]] || return 2

	local param="mdt.$MDT.identity_upcall"
	local old="$(do_facet $facet "lctl get_param -n $param")"

	[[ "$enable" == "true" ]] || upcall="NONE"

	do_facet $facet "lctl set_param -n $param='$upcall'" || return 2
	do_facet $facet "lctl set_param -n mdt.$MDT.identity_flush=-1"

	[[ "$old" != "NONE" ]] # implicit "&& return 0 || return 1"
}

remount_client()
{
	zconf_umount $HOSTNAME $1 || error "umount failed"
	zconf_mount $HOSTNAME $1 || error "mount failed"
}

writeconf_facet() {
	local facet=$1
	local dev=$2

	stop ${facet} -f
	rm -f $TMP/${facet}active
	do_facet ${facet} "$TUNEFS --quiet --writeconf $dev" || return 1
	return 0
}

writeconf_all () {
	local mdt_count=${1:-$MDSCOUNT}
	local ost_count=${2:-$OSTCOUNT}
	local rc=0

	for num in $(seq $mdt_count); do
		DEVNAME=$(mdsdevname $num)
		writeconf_facet mds$num $DEVNAME || rc=$?
	done

	for num in $(seq $ost_count); do
		DEVNAME=$(ostdevname $num)
		writeconf_facet ost$num $DEVNAME || rc=$?
	done
	return $rc
}

mountmgs() {
	if ! combined_mgs_mds ; then
		start mgs $(mgsdevname) $MGS_MOUNT_OPTS
		do_facet mgs "$LCTL set_param -P debug_raw_pointers=Y"
	fi
}

mountmds() {
	local num
	local devname
	local host
	local varname
	for num in $(seq $MDSCOUNT); do
		devname=$(mdsdevname $num)
		start mds$num $devname $MDS_MOUNT_OPTS

		# We started mds$num, now we should set mds${num}_HOST
		# and mds${num}failover_HOST variables properly if they
		# are not set.
		host=$(facet_host mds$num)
		for varname in mds${num}_HOST mds${num}failover_HOST; do
			if [[ -z "${!varname}" ]]; then
				eval $varname=$host
			fi
		done
		if [[ "$IDENTITY_UPCALL" != "default" ]]; then
			switch_identity $num $IDENTITY_UPCALL
		fi
	done
	if combined_mgs_mds ; then
		do_facet mgs "$LCTL set_param -P debug_raw_pointers=Y"
	fi
}

unmountoss() {
	local num

	for num in $(seq $OSTCOUNT); do
		stop ost$num -f
		rm -f $TMP/ost${num}active
	done
}

mountoss() {
	local num
	local devname
	local host
	local varname
	for num in $(seq $OSTCOUNT); do
		devname=$(ostdevname $num)
		start ost$num $devname $OST_MOUNT_OPTS

		# We started ost$num, now we should set ost${num}_HOST
		# and ost${num}failover_HOST variables properly if they
		# are not set.
		host=$(facet_host ost$num)
		for varname in ost${num}_HOST ost${num}failover_HOST; do
			if [[ -z "${!varname}" ]]; then
				eval $varname=$host
			fi
		done
	done
}

mountcli() {
	[ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE
	if [ ! -z $arg1 ]; then
		[ "$arg1" = "server_only" ] && return
	fi
	mount_client $MOUNT
	if [ -n "$CLIENTS" ]; then
		zconf_mount_clients $CLIENTS $MOUNT
	fi
	clients_up

	if [ "$MOUNT_2" ]; then
		mount_client $MOUNT2
		if [ -n "$CLIENTS" ]; then
			zconf_mount_clients $CLIENTS $MOUNT2
		fi
	fi
}

sk_nodemap_setup() {
	local sk_map_name=${1:-$SK_S2SNM}
	local sk_map_nodes=${2:-$HOSTNAME}
	do_node $(mgs_node) "$LCTL nodemap_add $sk_map_name"
	for servernode in $sk_map_nodes; do
		local nids=$(do_nodes $servernode "$LCTL list_nids")
		for nid in $nids; do
			do_node $(mgs_node) "$LCTL nodemap_add_range --name \
				$sk_map_name --range $nid"
		done
	done
}

setupall() {
	local arg1=$1

	nfs_client_mode && return
	cifs_client_mode && return

	sanity_mount_check || error "environments are insane!"

	load_modules

	init_gss

	if [ -z "$CLIENTONLY" ]; then
		echo Setup mgs, mdt, osts
		echo $WRITECONF | grep -q "writeconf" && writeconf_all

		if $SK_MOUNTED; then
			echo "Shared Key file system already mounted"
		else
			mountmgs
			mountmds
			mountoss
			if $SHARED_KEY; then
				export SK_MOUNTED=true
			fi
		fi
		if $GSS_SK; then
			echo "GSS_SK: setting kernel keyring perms"
			do_nodes $(comma_list $(all_nodes)) \
				"keyctl show | grep lustre | cut -c1-11 |
				sed -e 's/ //g;' |
				xargs -IX keyctl setperm X 0x3f3f3f3f"

			if $SK_S2S; then
				# Need to start one nodemap for servers,
				# and one for clients.
				sk_nodemap_setup $SK_S2SNM \
					$(comma_list $(all_server_nodes))
				mountcli
				sk_nodemap_setup $SK_S2SNMCLI \
					${CLIENTS:-$HOSTNAME}
				echo "Nodemap set up for SK S2S, remounting."
				stopall
				mountmgs
				mountmds
				mountoss
			fi
		fi
	fi

	# wait a while to allow sptlrpc configuration be propogated to targets,
	# only needed when mounting new target devices.
	if $GSS; then
		sleep 10
	fi

	mountcli
	init_param_vars

	[[ $KPTR_ON_MOUNT ]] && kptr_enable_and_save

	# by remounting mdt before ost, initial connect from mdt to ost might
	# timeout because ost is not ready yet. wait some time to its fully
	# recovery. initial obd_connect timeout is 5s; in GSS case it's
	# preceeded by a context negotiation rpc with $TIMEOUT.
	# FIXME better by monitoring import status.
	if $GSS; then
		if $GSS_SK; then
			set_rule $FSNAME any cli2mdt $SK_FLAVOR
			set_rule $FSNAME any cli2ost $SK_FLAVOR
			if $SK_SKIPFIRST; then
				export SK_SKIPFIRST=false

				sleep 30
				do_nodes $CLIENTS \
					 "lctl set_param osc.*.idle_connect=1"
				return
			else
				wait_flavor cli2mdt $SK_FLAVOR
				wait_flavor cli2ost $SK_FLAVOR
			fi
		else
			set_flavor_all $SEC
		fi
		sleep $((TIMEOUT + 5))
	else
		sleep 5
	fi
}

mounted_lustre_filesystems() {
        awk '($3 ~ "lustre" && $1 ~ ":") { print $2 }' /proc/mounts
}

init_facet_vars () {
	[ -n "$CLIENTONLY" ] && return 0
	local facet=$1
	shift
	local device=$1

	shift

	eval export ${facet}_dev=${device}
	eval export ${facet}_opt=\"$*\"

	local dev=${facet}_dev

	# We need to loop for the label
	# in case its not initialized yet.
	for wait_time in {0,1,3,5,10}; do

		if [ $wait_time -gt 0 ]; then
			echo "${!dev} not yet initialized,"\
				"waiting ${wait_time} seconds."
			sleep $wait_time
		fi

		local label=$(devicelabel ${facet} ${!dev})

		# Check to make sure the label does
		# not include ffff at the end of the label.
		# This indicates it has not been initialized yet.

		if [[ $label =~ [f|F]{4}$ ]]; then
			# label is not initialized, unset the result
			# and either try again or fail
			unset label
		else
			break
		fi
	done

	[ -z "$label" ] && echo no label for ${!dev} && exit 1

	eval export ${facet}_svc=${label}

	local varname=${facet}failover_HOST
	if [ -z "${!varname}" ]; then
		local temp
		if combined_mgs_mds && [ $facet == "mgs" ] &&
		   [ -n "$mds1failover_HOST" ]; then
			temp=$mds1failover_HOST
		else
			temp=$(facet_host $facet)
		fi
		eval export $varname=$temp
	fi

	varname=${facet}_HOST
	if [ -z "${!varname}" ]; then
		eval export $varname=$(facet_host $facet)
 	fi

	# ${facet}failover_dev is set in cfg file
	varname=${facet}failover_dev
	if [ -n "${!varname}" ] ; then
		eval export ${facet}failover_dev=${!varname}
	else
		eval export ${facet}failover_dev=$device
	fi

	# get mount point of already mounted device
	# is facet_dev is already mounted then use the real
	#  mount point of this facet; otherwise use $(facet_mntpt $facet)
	# i.e. ${facet}_MOUNT if specified by user or default
	local mntpt=$(do_facet ${facet} cat /proc/mounts | \
			awk '"'${!dev}'" == $1 && $3 == "lustre" { print $2 }')
	if [ -z $mntpt ]; then
		mntpt=$(facet_mntpt $facet)
	fi
	eval export ${facet}_MOUNT=$mntpt
}

init_facets_vars () {
	local DEVNAME

	if ! remote_mds_nodsh; then
		for num in $(seq $MDSCOUNT); do
			DEVNAME=$(mdsdevname $num)
			init_facet_vars mds$num $DEVNAME $MDS_MOUNT_OPTS
		done
	fi

	init_facet_vars mgs $(mgsdevname) $MGS_MOUNT_OPTS

	if ! remote_ost_nodsh; then
		for num in $(seq $OSTCOUNT); do
			DEVNAME=$(ostdevname $num)
			init_facet_vars ost$num $DEVNAME $OST_MOUNT_OPTS
		done
	fi
}

init_facets_vars_simple () {
	local devname

	if ! remote_mds_nodsh; then
		for num in $(seq $MDSCOUNT); do
			devname=$(mdsdevname $num)
			eval export mds${num}_dev=${devname}
			eval export mds${num}_opt=\"${MDS_MOUNT_OPTS}\"
		done
	fi

	if ! combined_mgs_mds ; then
		eval export mgs_dev=$(mgsdevname)
		eval export mgs_opt=\"${MGS_MOUNT_OPTS}\"
	fi

	if ! remote_ost_nodsh; then
		for num in $(seq $OSTCOUNT); do
			devname=$(ostdevname $num)
			eval export ost${num}_dev=${devname}
			eval export ost${num}_opt=\"${OST_MOUNT_OPTS}\"
		done
	fi
}

osc_ensure_active () {
	local facet=$1
	local timeout=$2
	local period=0

	while [ $period -lt $timeout ]; do
		count=$(do_facet $facet "lctl dl | grep ' IN osc ' 2>/dev/null | wc -l")
		if [ $count -eq 0 ]; then
			break
		fi

		echo "$count OST inactive, wait $period seconds, and try again"
		sleep 3
		period=$((period+3))
	done

	[ $period -lt $timeout ] ||
		log "$count OST are inactive after $timeout seconds, give up"
}

set_conf_param_and_check() {
	local myfacet=$1
	local TEST=$2
	local PARAM=$3
	local ORIG=$(do_facet $myfacet "$TEST")
	if [ $# -gt 3 ]; then
		local FINAL=$4
	else
		local -i FINAL
		FINAL=$((ORIG + 5))
	fi
	echo "Setting $PARAM from $ORIG to $FINAL"
	do_facet mgs "$LCTL conf_param $PARAM='$FINAL'" ||
		error "conf_param $PARAM failed"

	wait_update_facet $myfacet "$TEST" "$FINAL" ||
		error "check $PARAM failed!"
}

set_persistent_param() {
	local myfacet=$1
	local test_param=$2
	local param=$3
	local orig=$(do_facet $myfacet "$LCTL get_param -n $test_param")

	if [ $# -gt 3 ]; then
		local final=$4
	else
		local -i final
		final=$((orig + 5))
	fi

	if [[ $PERM_CMD == *"set_param -P"* ]]; then
		echo "Setting $test_param from $orig to $final"
		do_facet mgs "$PERM_CMD $test_param='$final'" ||
			error "$PERM_CMD $test_param failed"
	else
		echo "Setting $param from $orig to $final"
		do_facet mgs "$PERM_CMD $param='$final'" ||
			error "$PERM_CMD $param failed"
	fi
}

set_persistent_param_and_check() {
	local myfacet=$1
	local test_param=$2
	local param=$3
	local orig=$(do_facet $myfacet "$LCTL get_param -n $test_param")

	if [ $# -gt 3 ]; then
		local final=$4
	else
		local -i final
		final=$((orig + 5))
	fi

	set_persistent_param $myfacet $test_param $param "$final"

	wait_update_facet $myfacet "$LCTL get_param -n $test_param" "$final" ||
		error "check $param failed!"
}

init_param_vars () {
	TIMEOUT=$(lctl get_param -n timeout)
	TIMEOUT=${TIMEOUT:-20}

	if [ -n "$arg1" ]; then
		[ "$arg1" = "server_only" ] && return
	fi

	remote_mds_nodsh && log "Using TIMEOUT=$TIMEOUT" && return 0

	TIMEOUT=$(do_facet $SINGLEMDS "lctl get_param -n timeout")
	log "Using TIMEOUT=$TIMEOUT"

	# tune down to speed up testing on (usually) small setups
	local mgc_timeout=/sys/module/mgc/parameters/mgc_requeue_timeout_min
	do_nodes $(comma_list $(nodes_list)) \
		"[ -f $mgc_timeout ] && echo 1 > $mgc_timeout; exit 0"

	osc_ensure_active $SINGLEMDS $TIMEOUT
	osc_ensure_active client $TIMEOUT
	$LCTL set_param osc.*.idle_timeout=debug

	if [ -n "$(lctl get_param -n mdc.*.connect_flags|grep jobstats)" ]; then
		local current_jobid_var=$($LCTL get_param -n jobid_var)

		if [ $JOBID_VAR = "existing" ]; then
			echo "keeping jobstats as $current_jobid_var"
		elif [ $current_jobid_var != $JOBID_VAR ]; then
			echo "setting jobstats to $JOBID_VAR"

			set_persistent_param_and_check client \
				"jobid_var" "$FSNAME.sys.jobid_var" $JOBID_VAR
		fi
	else
		echo "jobstats not supported by server"
	fi

	if [ $QUOTA_AUTO -ne 0 ]; then
		if [ "$ENABLE_QUOTA" ]; then
			echo "enable quota as required"
			setup_quota $MOUNT || return 2
		else
			echo "disable quota as required"
			# $LFS quotaoff -ug $MOUNT > /dev/null 2>&1
		fi
	fi

	(( MDS1_VERSION <= $(version_code 2.13.52) )) ||
		do_facet mgs "$LCTL set_param -P lod.*.mdt_hash=crush"
	return 0
}

nfs_client_mode () {
	if [ "$NFSCLIENT" ]; then
		echo "NFSCLIENT mode: setup, cleanup, check config skipped"
		local clients=$CLIENTS

		[ -z $clients ] && clients=$(hostname)

		# FIXME: remove hostname when 19215 fixed
		do_nodes $clients "echo \\\$(hostname); grep ' '$MOUNT' ' /proc/mounts"
		declare -a nfsexport=(`grep ' '$MOUNT' ' /proc/mounts |
			awk '{print $1}' | awk -F: '{print $1 " "  $2}'`)
		if [[ ${#nfsexport[@]} -eq 0 ]]; then
			error_exit NFSCLIENT=$NFSCLIENT mode, but no NFS export found!
		fi
		do_nodes ${nfsexport[0]} "echo \\\$(hostname); df -T  ${nfsexport[1]}"
		return
	fi
	return 1
}

cifs_client_mode () {
	[ x$CIFSCLIENT = xyes ] &&
		echo "CIFSCLIENT=$CIFSCLIENT mode: setup, cleanup, check config skipped"
}

check_config_client () {
	local mntpt=$1
	local mounted=$(mount | grep " $mntpt ")

	if [ -n "$CLIENTONLY" ]; then
		# bug 18021
		# CLIENTONLY should not depend on *_HOST settings
		local mgc=$($LCTL device_list | awk '/MGC/ {print $4}')
		# in theory someone could create a new,
		# client-only config file that assumed lustre was already
		# configured and didn't set the MGSNID. If MGSNID is not set,
		# then we should use the mgs nid currently being used
		# as the default value. bug 18021
		[[ x$MGSNID = x ]] &&
		MGSNID=${mgc//MGC/}

		if [[ x$mgc != xMGC$MGSNID ]]; then
			if [ "$mgs_HOST" ]; then
				local mgc_ip=$(ping -q -c1 -w1 $mgs_HOST |
					grep PING | awk '{print $3}' |
					sed -e "s/(//g" -e "s/)//g")

				# [[ x$mgc = xMGC$mgc_ip@$NETTYPE ]] ||
				# error_exit "MGSNID=$MGSNID, mounted: $mounted, MGC : $mgc"
			fi
		fi
		return 0
	fi

	echo Checking config lustre mounted on $mntpt
	local mgshost=$(mount | grep " $mntpt " | awk -F@ '{print $1}')
	mgshost=$(echo $mgshost | awk -F: '{print $1}')

}

check_config_clients () {
	local clients=${CLIENTS:-$HOSTNAME}
	local mntpt=$1

	nfs_client_mode && return
	cifs_client_mode && return

	do_rpc_nodes "$clients" check_config_client $mntpt

	sanity_mount_check || error "environments are insane!"
}

check_timeout () {
	local mdstimeout=$(do_facet $SINGLEMDS "lctl get_param -n timeout")
	local cltimeout=$(lctl get_param -n timeout)
	if [ $mdstimeout -ne $TIMEOUT ] || [ $mdstimeout -ne $cltimeout ]; then
		error "timeouts are wrong! mds: $mdstimeout, client: $cltimeout, TIMEOUT=$TIMEOUT"
		return 1
	fi
}

is_mounted () {
	local mntpt=$1
	[ -z $mntpt ] && return 1
	local mounted=$(mounted_lustre_filesystems)

	echo $mounted' ' | grep -w -q $mntpt' '
}

create_pools () {
	local pool=$1
	local ostsn=${2:-$OSTCOUNT}
	local npools=${FS_NPOOLS:-$((OSTCOUNT / ostsn))}
	local n

	echo ostsn=$ostsn npools=$npools
	if [[ $ostsn -gt $OSTCOUNT ]];  then
		echo "request to use $ostsn OSTs in the pool, \
			using max available OSTCOUNT=$OSTCOUNT"
		ostsn=$OSTCOUNT
	fi
	for (( n=0; n < $npools; n++ )); do
		p=${pool}$n
		if ! $DELETE_OLD_POOLS; then
			log "request to not delete old pools: $FSNAME.$p exist?"
			if ! check_pool_not_exist $FSNAME.$p; then
				echo "Using existing $FSNAME.$p"
				$LCTL pool_list $FSNAME.$p
				continue
			fi
		fi
		create_pool $FSNAME.$p $KEEP_POOLS ||
			error "create_pool $FSNAME.$p failed"

		local first=$(( (n * ostsn) % OSTCOUNT ))
		local last=$(( (first + ostsn - 1) % OSTCOUNT ))
		if [[ $first -le $last ]]; then
			pool_add_targets $p $first $last ||
				error "pool_add_targets $p $first $last failed"
		else
			pool_add_targets $p $first $(( OSTCOUNT - 1 )) ||
				error "pool_add_targets $p $first \
					$(( OSTCOUNT - 1 )) failed"
			pool_add_targets $p 0 $last ||
				error "pool_add_targets $p 0 $last failed"
		fi
	done
}

set_pools_quota () {
	local u
	local o
	local p
	local i
	local j

	[[ $ENABLE_QUOTA ]] || error "Required Pool Quotas: \
		$POOLS_QUOTA_USERS_SET, but ENABLE_QUOTA not set!"

	# POOLS_QUOTA_USERS_SET=
	#              "quota15_1:20M          -- for all of the found pools
	#               quota15_2:1G:gpool0
	#               quota15_3              -- for global limit only
	#               quota15_4:200M:gpool0
	#               quota15_4:200M:gpool1"

	declare -a pq_userset=(${POOLS_QUOTA_USERS_SET="mpiuser"})
	declare -a pq_users
	declare -A pq_limits

	for ((i=0; i<${#pq_userset[@]}; i++)); do
		u=${pq_userset[i]%%:*}
		o=""
		# user gets no pool limits if
		# POOLS_QUOTA_USERS_SET does not specify it
		[[ ${pq_userset[i]} =~ : ]] && o=${pq_userset[i]##$u:}
		pq_limits[$u]+=" $o"
	done
	pq_users=(${!pq_limits[@]})

	declare -a opts
	local pool

	for ((i=0; i<${#pq_users[@]}; i++)); do
		u=${pq_users[i]}
		# set to max limit (_u64)
		$LFS setquota -u $u -B $((2**24 - 1))T $DIR
		opts=(${pq_limits[$u]})
		for ((j=0; j<${#opts[@]}; j++)); do
			p=${opts[j]##*:}
			o=${opts[j]%%:*}
			# Set limit for all existing pools if
			# no pool specified
			if [ $p == $o ];  then
				p=$(list_pool $FSNAME | sed "s/$FSNAME.//")
				echo "No pool specified for $u,
					set limit $o for all existing pools"
			fi
			for pool in $p; do
				$LFS setquota -u $u -B $o --pool $pool $DIR ||
                                        error "setquota -u $u -B $o \
						--pool $pool failed"
			done
		done
		$LFS quota -uv $u --pool  $DIR
	done
}

do_check_and_setup_lustre() {
	# If auster does not want us to setup, then don't.
	! ${do_setup} && return

	log "=== $TESTSUITE: start setup $(date +'%H:%M:%S (%s)') ==="

	sanitize_parameters
	nfs_client_mode && return
	cifs_client_mode && return

	local MOUNTED=$(mounted_lustre_filesystems)

	local do_check=true
	# 1.
	# both MOUNT and MOUNT2 are not mounted
	if ! is_mounted $MOUNT && ! is_mounted $MOUNT2; then
		[ "$REFORMAT" = "yes" ] && CLEANUP_DM_DEV=true formatall
		# setupall mounts both MOUNT and MOUNT2 (if MOUNT_2 is set)
		setupall
		is_mounted $MOUNT || error "NAME=$NAME not mounted"
		export I_MOUNTED=yes
		do_check=false
	# 2.
	# MOUNT2 is mounted
	elif is_mounted $MOUNT2; then
		# 3.
		# MOUNT2 is mounted, while MOUNT_2 is not set
		if ! [ "$MOUNT_2" ]; then
			cleanup_mount $MOUNT2
			export I_UMOUNTED2=yes

		# 4.
		# MOUNT2 is mounted, MOUNT_2 is set
		else
			# FIXME: what to do if check_config failed?
			# i.e. if:
			# 1) remote client has mounted other Lustre fs ?
			# 2) it has insane env ?
			# try to umount MOUNT2 on all clients and mount again:
			if ! check_config_clients $MOUNT2; then
				cleanup_mount $MOUNT2
				restore_mount $MOUNT2
				export I_MOUNTED2=yes
			fi
		fi
	# 5.
	# MOUNT is mounted MOUNT2 is not mounted
	elif [ "$MOUNT_2" ]; then
		restore_mount $MOUNT2
		export I_MOUNTED2=yes
	fi

	if $do_check; then
		# FIXME: what to do if check_config failed?
		# i.e. if:
		# 1) remote client has mounted other Lustre fs?
		# 2) lustre is mounted on remote_clients atall ?
		check_config_clients $MOUNT
		init_facets_vars
		init_param_vars

		set_default_debug_nodes $(comma_list $(nodes_list))
		set_params_clients
	fi

	if [ -z "$CLIENTONLY" -a $(lower $OSD_TRACK_DECLARES_LBUG) == 'yes' ]; then
		local facets=""
		[ "$(facet_fstype ost1)" = "ldiskfs" ] &&
			facets="$(get_facets OST)"
		[ "$(facet_fstype mds1)" = "ldiskfs" ] &&
			facets="$facets,$(get_facets MDS)"
		[ "$(facet_fstype mgs)" = "ldiskfs" ] &&
			facets="$facets,mgs"
		local nodes="$(facets_hosts ${facets})"
		if [ -n "$nodes" ] ; then
			do_nodes $nodes "$LCTL set_param \
				 osd-ldiskfs.track_declares_assert=1 || true"
		fi
	fi

	if [ -n "$fs_STRIPEPARAMS" ]; then
		setstripe_getstripe $MOUNT $fs_STRIPEPARAMS
	fi

	if $GSS_SK; then
		set_flavor_all null
	elif $GSS; then
		set_flavor_all $SEC
	fi

	if $DELETE_OLD_POOLS; then
		destroy_all_pools
	fi

	if [[ -n "$FS_POOL" ]]; then
		create_pools $FS_POOL $FS_POOL_NOSTS
	fi

	if [[ -n "$POOLS_QUOTA_USERS_SET" ]]; then
		set_pools_quota
	fi

	# set tunable parameters passed to test environment
	set_params_clients
	set_params_mdts
	set_params_osts

	TESTNAME="start setup" check_dmesg_for_errors ||
		TESTNAME="test_setup" error "Error in dmesg detected"

	log "=== $TESTSUITE: finish setup $(date +'%H:%M:%S (%s)') ==="

	if [[ "$ONLY" == "setup" ]]; then
		exit 0
	fi
}

check_and_setup_lustre() {
	local start_stamp=$(date +%s)
	local saved_umask=$(umask)
	local log=$TESTLOG_PREFIX.test_setup.test_log.$(hostname -s).log
	local status='PASS'
	local stop_stamp=0
	local duration=0
	local error=''
	local rc=0

	umask 0022

	log_sub_test_begin test_setup

	if ! do_check_and_setup_lustre 2>&1 > >(tee -i $log); then
		error=$(tail -1 $log)
		status='FAIL'
		rc=1
	fi

	stop_stamp=$(date +%s)
	duration=$((stop_stamp - start_stamp))

	log_sub_test_end "$status" "$duration" "$rc" "$error"

	umask $saved_umask

	return $rc
}

restore_mount () {
	local clients=${CLIENTS:-$HOSTNAME}
	local mntpt=$1

	zconf_mount_clients $clients $mntpt
}

cleanup_mount () {
	local clients=${CLIENTS:-$HOSTNAME}
	local mntpt=$1

	zconf_umount_clients $clients $mntpt
}

cleanup_and_setup_lustre() {
	if [[ "$ONLY" == "cleanup" ]] || grep -q "$MOUNT" /proc/mounts; then
		lctl set_param debug=0 || true
		cleanupall

		if [[ "$ONLY" == "cleanup" ]]; then
			exit 0
		fi
	fi

	do_check_and_setup_lustre
}

# Run e2fsck on MDT or OST device.
run_e2fsck() {
	local node=$1
	local target_dev=$2
	local extra_opts=$3
	local cmd="$E2FSCK -d -v -t -t -f $extra_opts $target_dev"
	local log=$TMP/e2fsck.log
	local rc=0

	# turn on pfsck if it is supported
	do_node $node $E2FSCK -h 2>&1 | grep -qw -- -m && cmd+=" -m8"
	echo $cmd
	do_node $node $cmd 2>&1 | tee $log
	rc=${PIPESTATUS[0]}
	if [ -n "$(grep "DNE mode isn't supported" $log)" ]; then
		rm -f $log
		if [ $MDSCOUNT -gt 1 ]; then
			skip_noexit "DNE mode isn't supported!"
			cleanupall
			exit_status
		else
			error "It's not DNE mode."
		fi
	fi
	rm -f $log

	[ $rc -le $FSCK_MAX_ERR ] ||
		error "$cmd returned $rc, should be <= $FSCK_MAX_ERR"

	return 0
}

#
# Run resize2fs on MDT or OST device.
#
run_resize2fs() {
	local facet=$1
	local device=$2
	local size=$3
	shift 3
	local opts="$@"

	do_facet $facet "$RESIZE2FS $opts $device $size"
}

# verify a directory is shared among nodes.
check_shared_dir() {
	local dir=$1
	local list=${2:-$(comma_list $(nodes_list))}

	[ -z "$dir" ] && return 1
	do_rpc_nodes "$list" check_logdir $dir
	check_write_access $dir "$list" || return 1
	return 0
}

run_lfsck() {
	do_nodes $(comma_list $(mdts_nodes) $(osts_nodes)) \
		$LCTL set_param printk=+lfsck
	do_facet $SINGLEMDS "$LCTL lfsck_start -M $FSNAME-MDT0000 -r -A -t all"

	for k in $(seq $MDSCOUNT); do
		# wait up to 10+1 minutes for LFSCK to complete
		wait_update_facet --verbose mds${k} "$LCTL get_param -n \
			mdd.$(facet_svc mds${k}).lfsck_layout |
			awk '/^status/ { print \\\$2 }'" "completed" 600 ||
			error "MDS${k} layout isn't the expected 'completed'"
		wait_update_facet --verbose mds${k} "$LCTL get_param -n \
			mdd.$(facet_svc mds${k}).lfsck_namespace |
			awk '/^status/ { print \\\$2 }'" "completed" 60 ||
			error "MDS${k} namespace isn't the expected 'completed'"
	done
	local rep_mdt=$(do_nodes $(comma_list $(mdts_nodes)) \
			$LCTL get_param -n mdd.$FSNAME-*.lfsck_* |
			awk '/repaired/ { print $2 }' | calc_sum)
	local rep_ost=$(do_nodes $(comma_list $(osts_nodes)) \
			$LCTL get_param -n obdfilter.$FSNAME-*.lfsck_* |
			awk '/repaired/ { print $2 }' | calc_sum)
	local repaired=$((rep_mdt + rep_ost))
	[ $repaired -eq 0 ] ||
		error "lfsck repaired $rep_mdt MDT and $rep_ost OST errors"
}

dump_file_contents() {
	local nodes=$1
	local dir=$2
	local logname=$3
	local node

	if [ -z "$nodes" -o -z "$dir" -o -z "$logname" ]; then
		error_noexit false \
			"Invalid parameters for dump_file_contents()"
		return 1
	fi
	for node in ${nodes//,/ }; do
		do_node $node "for i in \\\$(find $dir -type f); do
				echo ====\\\${i}=======================;
				cat \\\${i};
				done" >> ${logname}.${node}.log
	done
}

dump_command_output() {
	local nodes=$1
	local cmd=$2
	local logname=$3
	local node

	if [ -z "$nodes" -o -z "$cmd" -o -z "$logname" ]; then
		error_noexit false \
			"Invalid parameters for dump_command_output()"
		return 1
	fi

	for node in ${nodes//,/ }; do
		do_node $node "echo ====${cmd}=======================;
				$cmd" >> ${logname}.${node}.log
	done
}

log_zfs_info() {
	local logname=$1

	# dump file contents from /proc/spl in case of zfs test
	if [ "$(facet_fstype ost1)" = "zfs" ]; then
		dump_file_contents "$(osts_nodes)" "/proc/spl" "${logname}"
		dump_command_output \
			"$(osts_nodes)" "zpool events -v" "${logname}"
	fi

	if [ "$(facet_fstype $SINGLEMDS)" = "zfs" ]; then
		dump_file_contents "$(mdts_nodes)" "/proc/spl" "${logname}"
		dump_command_output \
			"$(mdts_nodes)" "zpool events -v" "${logname}"
	fi
}

do_check_and_cleanup_lustre() {
	log "=== $TESTSUITE: start cleanup $(date +'%H:%M:%S (%s)') ==="

	if [[ "$LFSCK_ALWAYS" == "yes" && "$TESTSUITE" != "sanity-lfsck" && \
	      "$TESTSUITE" != "sanity-scrub" ]]; then
		run_lfsck
	fi

	if is_mounted $MOUNT; then
		if $DO_CLEANUP; then
			[[ -n "$DIR" ]] && rm -rf $DIR/[Rdfs][0-9]* ||
				error "remove sub-test dirs failed"
		else
			echo "skip cleanup"
		fi
		[[ -n "$ENABLE_QUOTA" ]] && restore_quota || true
	fi

	if [[ "$I_UMOUNTED2" == "yes" ]]; then
		restore_mount $MOUNT2 || error "restore $MOUNT2 failed"
	fi

	if [[ "$I_MOUNTED2" == "yes" ]]; then
		cleanup_mount $MOUNT2
	fi

	if [[ "$I_MOUNTED" == "yes" ]] && ! $AUSTER_CLEANUP; then
		cleanupall -f || error "cleanup failed"
		unset I_MOUNTED
	fi

	TESTNAME="start cleanup" check_dmesg_for_errors ||
		TESTNAME="test_cleanup" error "Error in dmesg detected"

	log "=== $TESTSUITE: finish cleanup $(date +'%H:%M:%S (%s)') ==="
}

check_and_cleanup_lustre() {
	local start_stamp=$(date +%s)
	local saved_umask=$(umask)
	local log=$TESTLOG_PREFIX.test_cleanup.test_log.$(hostname -s).log
	local status='PASS'
	local stop_stamp=0
	local duration=0
	local error=''
	local rc=0

	umask 0022

	log_sub_test_begin test_cleanup

	if ! do_check_and_cleanup_lustre 2>&1 > >(tee -i $log); then
		error=$(tail -1 $log)
		status='FAIL'
		rc=1
	fi

	stop_stamp=$(date +%s)
	duration=$((stop_stamp - start_stamp))

	log_sub_test_end "$status" "$duration" "$rc" "$error"

	umask $saved_umask

	return $rc
}

#######
# General functions

wait_for_function () {
	local quiet=""

	# suppress fn both stderr and stdout
	if [ "$1" = "--quiet" ]; then
		shift
		quiet=" > /dev/null 2>&1"
	fi

	local fn=$1
	local max=${2:-900}
	local sleep=${3:-5}

	local wait=0

	while true; do

		eval $fn $quiet && return 0

		[ $wait -lt $max ] || return 1
		echo waiting $fn, $((max - wait)) secs left ...
		wait=$((wait + sleep))
		[ $wait -gt $max ] && ((sleep -= wait - max))
		sleep $sleep
	done
}

check_network() {
	local host=$1
	local max=$2
	local sleep=${3:-5}

	[ "$host" = "$HOSTNAME" ] && return 0

	if ! wait_for_function --quiet "ping -c 1 -w 3 $host" $max $sleep; then
		echo "$(date +'%H:%M:%S (%s)') waited for $host network ${max}s"
		exit 1
	fi
}

no_dsh() {
	shift
	eval "$@"
}

# Convert a space-delimited list to a comma-delimited list.  If the input is
# only whitespace, ensure the output is empty (i.e. "") so [ -n $list ] works
comma_list() {
	# echo is used to convert newlines to spaces, since it doesn't
	# introduce a trailing space as using "tr '\n' ' '" does
	echo $(tr -s ", " "\n" <<< $* | sort -b -u) | tr ' ' ','
}

list_member () {
	local list=$1
	local item=$2

	echo $list | grep -qw $item
}

# list, excluded are the comma separated lists
exclude_items_from_list () {
	local list=$1
	local excluded=$2
	local item

	list=${list//,/ }
	for item in ${excluded//,/ }; do
		list=$(echo " $list " | sed -re "s/\s+$item\s+/ /g")
	done
	echo $(comma_list $list)
}

# list, expand  are the comma separated lists
expand_list () {
	local list=${1//,/ }
	local expand=${2//,/ }
	local expanded=

	expanded=$(for i in $list $expand; do echo $i; done | sort -u)
	echo $(comma_list $expanded)
}

testslist_filter () {
	local script=$LUSTRE/tests/${TESTSUITE}.sh

	[ -f $script ] || return 0

	local start_at=$START_AT
	local stop_at=$STOP_AT

	local var=${TESTSUITE//-/_}_START_AT
	[ x"${!var}" != x ] && start_at=${!var}
	var=${TESTSUITE//-/_}_STOP_AT
	[ x"${!var}" != x ] && stop_at=${!var}

	sed -n 's/^test_\([^ (]*\).*/\1/p' $script |
        awk ' BEGIN { if ("'${start_at:-0}'" != 0) flag = 1 }
            /^'${start_at}'$/ {flag = 0}
            {if (flag == 1) print $0}
            /^'${stop_at}'$/ { flag = 1 }'
}

absolute_path() {
	(cd `dirname $1`; echo $PWD/`basename $1`)
}

get_facets () {
	local types=${*:-"OST MDS MGS"}

	local list=""

	for entry in $types; do
		local name=$(echo $entry | tr "[:upper:]" "[:lower:]")
		local type=$(echo $entry | tr "[:lower:]" "[:upper:]")

		case $type in
			MGS ) list="$list $name";;
			MDS|OST|AGT ) local count=${type}COUNT
				for ((i=1; i<=${!count}; i++)) do
					list="$list ${name}$i"
				done;;
			* ) error "Invalid facet type"
				exit 1;;
		esac
	done
	echo $(comma_list $list)
}

##################################
# Adaptive Timeouts funcs

at_is_enabled() {
	# only check mds, we assume at_max is the same on all nodes
	local at_max=$(do_facet $SINGLEMDS "lctl get_param -n at_max")

	if [ $at_max -eq 0 ]; then
		return 1
	else
		return 0
	fi
}

at_get() {
	local facet=$1
	local at=$2

	# suppose that all ost-s have the same $at value set
	[ $facet != "ost" ] || facet=ost1

	do_facet $facet "lctl get_param -n $at"
}

at_max_get() {
	at_get $1 at_max
}

at_max_set() {
	local at_max=$1
	shift

	local facet
	local hosts

	for facet in "$@"; do
		if [ $facet == "ost" ]; then
			facet=$(get_facets OST)
		elif [ $facet == "mds" ]; then
			facet=$(get_facets MDS)
		fi
		hosts=$(expand_list $hosts $(facets_hosts $facet))
	done

	do_nodes $hosts lctl set_param at_max=$at_max
}

at_min_get() {
	at_get $1 at_min
}

at_min_set() {
	local at_min=$1
	shift

	local facet
	local hosts

	for facet in "$@"; do
		if [ $facet == "ost" ]; then
			facet=$(get_facets OST)
		elif [ $facet == "mds" ]; then
			facet=$(get_facets MDS)
		fi
		hosts=$(expand_list $hosts $(facets_hosts $facet))
	done

	do_nodes $hosts lctl set_param at_min=$at_min
}

##################################
# OBD_FAIL funcs

drop_request() {
# OBD_FAIL_MDS_ALL_REQUEST_NET
	RC=0
	do_facet $SINGLEMDS lctl set_param fail_val=0 fail_loc=0x123
	do_facet client "$1" || RC=$?
	do_facet $SINGLEMDS lctl set_param fail_loc=0
	return $RC
}

drop_reply() {
# OBD_FAIL_MDS_ALL_REPLY_NET
	RC=0
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x122
	eval "$@" || RC=$?
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
	return $RC
}

drop_reint_reply() {
# OBD_FAIL_MDS_REINT_NET_REP
	RC=0
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x119
	eval "$@" || RC=$?
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
	return $RC
}

drop_update_reply() {
# OBD_FAIL_OUT_UPDATE_NET_REP
	local index=$1
	shift 1
	RC=0
	do_facet mds${index} lctl set_param fail_loc=0x1701
	do_facet client "$@" || RC=$?
	do_facet mds${index} lctl set_param fail_loc=0
	return $RC
}

pause_bulk() {
#define OBD_FAIL_OST_BRW_PAUSE_BULK      0x214
	RC=0

	local timeout=${2:-0}
	# default is (obd_timeout / 4) if unspecified
	echo "timeout is $timeout/$2"
	do_facet ost1 lctl set_param fail_val=$timeout fail_loc=0x80000214
	do_facet client "$1" || RC=$?
	do_facet client "sync"
	do_facet ost1 lctl set_param fail_loc=0
	return $RC
}

drop_ldlm_cancel() {
#define OBD_FAIL_LDLM_CANCEL_NET			0x304
	local RC=0
	local list=$(comma_list $(mdts_nodes) $(osts_nodes))
	do_nodes $list lctl set_param fail_loc=0x304

	do_facet client "$@" || RC=$?

	do_nodes $list lctl set_param fail_loc=0
	return $RC
}

drop_bl_callback_once() {
	local rc=0
	do_facet client lctl set_param ldlm.namespaces.*.early_lock_cancel=0
#define OBD_FAIL_LDLM_BL_CALLBACK_NET			0x305
	do_facet client lctl set_param fail_loc=0x80000305
	do_facet client "$@" || rc=$?
	do_facet client lctl set_param fail_loc=0
	do_facet client lctl set_param fail_val=0
	do_facet client lctl set_param ldlm.namespaces.*.early_lock_cancel=1
	return $rc
}

drop_bl_callback() {
	rc=0
	do_facet client lctl set_param ldlm.namespaces.*.early_lock_cancel=0
#define OBD_FAIL_LDLM_BL_CALLBACK_NET			0x305
	do_facet client lctl set_param fail_loc=0x305
	do_facet client "$@" || rc=$?
	do_facet client lctl set_param fail_loc=0
	do_facet client lctl set_param fail_val=0
	do_facet client lctl set_param ldlm.namespaces.*.early_lock_cancel=1
	return $rc
}

drop_mdt_ldlm_reply() {
#define OBD_FAIL_MDS_LDLM_REPLY_NET	0x157
	RC=0
	local list=$(comma_list $(mdts_nodes))

	do_nodes $list lctl set_param fail_loc=0x157

	do_facet client "$@" || RC=$?

	do_nodes $list lctl set_param fail_loc=0
	return $RC
}

drop_mdt_ldlm_reply_once() {
#define OBD_FAIL_MDS_LDLM_REPLY_NET	0x157
	RC=0
	local list=$(comma_list $(mdts_nodes))

	do_nodes $list lctl set_param fail_loc=0x80000157

	do_facet client "$@" || RC=$?

	do_nodes $list lctl set_param fail_loc=0
	return $RC
}

clear_failloc() {
	facet=$1
	pause=$2
	sleep $pause
	echo "clearing fail_loc on $facet"
	do_facet $facet "lctl set_param fail_loc=0 2>/dev/null || true"
}

set_nodes_failloc () {
	local fv=${3:-0}
	do_nodes $(comma_list $1)  lctl set_param fail_val=$fv fail_loc=$2
}

# Print the total of the lock_unused_count across all namespaces containing the
# given wildcard. If the namespace wildcard is omitted, all namespaces will be
# matched.
# Usage: total_unused_locks [namespace_wildcard]
total_unused_locks() {
	$LCTL get_param -n "ldlm.namespaces.*$1*.lock_unused_count" | calc_sum
}

# Print the total of the lock_count across all namespaces containing the given
# wildcard. If the namespace wilcard is omitted, all namespaces will be matched.
# Usage: total_used_locks [namespace_wildcard]
total_used_locks() {
	$LCTL get_param -n "ldlm.namespaces.*$1*.lock_count" | calc_sum
}

# Cancel lru locks across all namespaces containing the given wildcard. If the
# wilcard is omitted, lru locks will be canceled across all namespaces.
# Usage: cancel_lru_locks [namespace_wildcard]
cancel_lru_locks() {
	#$LCTL mark "cancel_lru_locks $1 start"
	$LCTL set_param -t4 -n "ldlm.namespaces.*$1*.lru_size=clear"
	$LCTL get_param "ldlm.namespaces.*$1*.lock_unused_count" | grep -v '=0'
	#$LCTL mark "cancel_lru_locks $1 stop"
}

default_lru_size()
{
	local nr_cpu=$(grep -c "processor" /proc/cpuinfo)

	echo $((100 * nr_cpu))
}

lru_resize_enable()
{
	$LCTL set_param -n ldlm.namespaces.*$1*.lru_size=0
}

lru_resize_disable()
{
	local dev=${1}
	local lru_size=${2:-$(default_lru_size)}
	local size_param="ldlm.namespaces.*$dev*.lru_size"
	local age_param="ldlm.namespaces.*$dev*.lru_max_age"
	local old_age=($($LCTL get_param -n $age_param))
	# can't save/restore lru_size since it reports the *current* lru count

	echo "$size_param=0->$lru_size"
	echo "$age_param=$old_age->3900s"

	# increase lru_max_age also, to prevent lock cancel due to age
	$LCTL set_param -n $size_param=$lru_size
	$LCTL set_param -n $age_param=3900s
	stack_trap "cancel_lru_locks $dev || true"
	stack_trap "lru_resize_enable $dev || true"
	stack_trap "$LCTL set_param -n $age_param=$old_age || true"
}

flock_is_enabled()
{
	local mountpath=${1:-$MOUNT}
	local RC=0

	[ -z "$(mount | grep "$mountpath .*flock" | grep -v noflock)" ] && RC=1
	return $RC
}

pgcache_empty() {
	local FILE

	for FILE in `lctl get_param -N "llite.*.dump_page_cache"`; do
		if [ `lctl get_param -n $FILE | wc -l` -gt 1 ]; then
			echo there is still data in page cache $FILE ?
			lctl get_param -n $FILE
			return 1
		fi
	done
	return 0
}

debugsave() {
	DEBUGSAVE="$(lctl get_param -n debug)"
	DEBUGSAVE_SERVER=$(do_facet $SINGLEMDS "$LCTL get_param -n debug")
}

debugrestore() {
	[ -n "$DEBUGSAVE" ] &&
		do_nodes $CLIENTS $LCTL set_param -n debug=${DEBUGSAVE// /+} ||
		true
	DEBUGSAVE=""

	[ -n "$DEBUGSAVE_SERVER" ] &&
		do_nodes $(comma_list $(all_server_nodes)) \
			 $LCTL set_param -n debug=${DEBUGSAVE_SERVER// /+} ||
			 true
	DEBUGSAVE_SERVER=""
}

debug_size_save() {
	DEBUG_SIZE_SAVED="$(lctl get_param -n debug_mb)"
}

debug_size_restore() {
	[ -n "$DEBUG_SIZE_SAVED" ] &&
		do_nodes $(comma_list $(nodes_list)) "$LCTL set_param debug_mb=$DEBUG_SIZE_SAVED"
	DEBUG_SIZE_SAVED=""
}

start_full_debug_logging() {
	debugsave
	debug_size_save

	local fulldebug=-1
	local debug_size=150
	local nodes=$(comma_list $(nodes_list))

	do_nodes $nodes "$LCTL set_param debug=$fulldebug debug_mb=$debug_size"
}

stop_full_debug_logging() {
	debug_size_restore
	debugrestore
}

# prints bash call stack
print_stack_trace() {
	local skip=${1:-1}
	echo "  Trace dump:"
	for (( i=$skip; i < ${#BASH_LINENO[*]} ; i++ )) ; do
		local src=${BASH_SOURCE[$i]}
		local lineno=${BASH_LINENO[$i-1]}
		local funcname=${FUNCNAME[$i]}
		echo "  = $src:$lineno:$funcname()"
	done
}

report_error() {
	local TYPE=${TYPE:-"FAIL"}

	local dump=true
	# do not dump logs if $1=false
	if [ "x$1" = "xfalse" ]; then
		shift
		dump=false
	fi

	log " ${TESTSUITE} ${TESTNAME}: @@@@@@ ${TYPE}: $* "
	(print_stack_trace 2) >&2
	mkdir -p $LOGDIR
	# We need to dump the logs on all nodes
	if $dump; then
		gather_logs $(comma_list $(nodes_list))
	fi

	debugrestore
	[ "$TESTSUITELOG" ] &&
		echo "$TESTSUITE: $TYPE: $TESTNAME $*" >> $TESTSUITELOG
	if [ -z "$*" ]; then
		echo "error() without useful message, please fix" > $LOGDIR/err
	else
		if [[ `echo $TYPE | grep ^IGNORE` ]]; then
			echo "$@" > $LOGDIR/ignore
		else
			echo "$@" > $LOGDIR/err
		fi
	fi

	# cleanup the env for failed tests
	reset_fail_loc
}

##################################
# Test interface
##################################

# usage: stack_trap arg sigspec
#
# stack_trap() behaves like bash's built-in trap, except that it "stacks" the
# command "arg" on top of previously defined commands for "sigspec" instead
# of overwriting them.
# stacked traps are executed in reverse order of their registration
#
# arg and sigspec have the same meaning as in man (1) trap
stack_trap()
{
	local arg="$1"
	local sigspec="${2:-EXIT}"

	# Use "trap -p" to get the quoting right
	local old_trap="$(trap -p "$sigspec")"
	# Append ";" and remove the leading "trap -- '" added by "trap -p"
	old_trap="${old_trap:+"; ${old_trap#trap -- \'}"}"

	# Once again, use "trap -p" to get the quoting right
	local new_trap="$(trap -- "$arg" "$sigspec"
			  trap -p "$sigspec"
			  trap -- '' "$sigspec")"

	# Remove the trailing "' $sigspec" part added by "trap -p" and merge
	#
	# The resulting string should be safe to "eval" as it is (supposedly
	# correctly) quoted by "trap -p"
	eval "${new_trap%\' $sigspec}${old_trap:-"' $sigspec"}"
}

error_noexit() {
	report_error "$@"
}

exit_status () {
	local status=0
	local logs="$TESTSUITELOG $1"

	for log in $logs; do
		if [ -f "$log" ]; then
			grep -qw FAIL $log && status=1
		fi
	done

	exit $status
}

error() {
	report_error "$@"
	exit 1
}

error_exit() {
	report_error "$@"
	exit 1
}

# use only if we are ignoring failures for this test, bugno required.
# (like ALWAYS_EXCEPT, but run the test and ignore the results.)
# e.g. error_ignore bz5494 "your message" or
# error_ignore LU-5494 "your message"
error_ignore() {
	local TYPE="IGNORE ($1)"
	shift
	report_error "$@"
}

error_and_remount() {
	report_error "$@"
	remount_client $MOUNT
	exit 1
}

# Throw an error if it's not running in vm - usually for performance
# verification
error_not_in_vm() {
	local virt=$(running_in_vm)
	if [[ -n "$virt" ]]; then
		echo "running in VM '$virt', ignore error"
		error_ignore env=$virt "$@"
	else
		error "$@"
	fi
}

#
# Function: skip_env()
# Purpose:  to skip a test during developer testing because some tool
#           is missing, but fail the test in release testing because the test
#           environment is not configured properly".
#
skip_env () {
	$FAIL_ON_SKIP_ENV && error false "$@" || skip "$@"
}

skip_noexit() {
	echo
	log " SKIP: $TESTSUITE $TESTNAME $*"

	if [[ -n "$ALWAYS_SKIPPED" ]]; then
		skip_logged $TESTNAME "$@"
	else
		mkdir -p $LOGDIR
		echo "$@" > $LOGDIR/skip
	fi

	[[ -n "$TESTSUITELOG" ]] &&
		echo "$TESTSUITE: SKIP: $TESTNAME $*" >> $TESTSUITELOG || true
	unset TESTNAME
}

skip() {
	skip_noexit "$@"
	exit 0
}

#
# For interop testing treate EOPNOTSUPP as success
# and skip
#
skip_eopnotsupp() {
	local retstr=$@

	echo $retstr | awk -F'|' '{print $1}' |
		grep -E unsupported\|"(Operation not supported)"
	(( $? == 0 )) || error "$retstr"
	skip $retstr
}

# Add a list of tests to ALWAYS_EXCEPT due to an issue.
# Usage: always_except LU-4815 23 42q ...
#
function \
always_except() {
	local issue="${1:-}" # single jira style issue ("LU-4815")
	local test_num

	shift

	if ! [[ "$issue" =~ ^[[:upper:]]+-[[:digit:]]+$ ]]; then
		error "always_except: invalid issue '$issue' for tests '$*'"
	fi

	for test_num in "$@"; do
		ALWAYS_EXCEPT+=" $test_num"
	done
}

build_test_filter() {
	EXCEPT="$EXCEPT $(testslist_filter)"

	# allow test numbers separated by '+', or ',', in addition to ' '
	# to avoid issues with multiple arguments handling by shell/autotest
	for O in ${ONLY//[+,]/ }; do
		if [[ $O =~ [0-9]*-[0-9]* ]]; then
			for ((num=${O%-[0-9]*}; num <= ${O#[0-9]*-}; num++)); do
				eval ONLY_$num=true
			done
		else
			eval ONLY_${O}=true
		fi
	done

	local nodes=$(comma_list $(facets_nodes mds1,ost1))
	local exceptions="$LUSTRE/tests/except/$TESTSUITE.*ex"

	do_nodes --verbose $nodes "ls $exceptions || true"
	while read facet op need_ver jira subs; do
		local have_ver_code=${facet^^*}_VERSION
		local need_ver_code

		[[ "$facet" =~ "#" ]] && continue
		[[ "$need_ver" =~ _VERSION ]] && need_ver_code=$need_ver ||
			need_ver_code=$(version_code $need_ver)

		(( ${!have_ver_code} $op $need_ver_code )) &&
			echo "- see $facet $op $need_ver for $jira, go $subs" ||
		{
			log "- need $facet $op $need_ver for $jira, skip $subs"
			for E in $subs; do
				eval EXCEPT_${E}=true
			done
		}
	done < <(do_nodes $nodes "cat $exceptions 2>/dev/null ||true" | sort -u)

	[[ -z "$EXCEPT$ALWAYS_EXCEPT" ]] ||
		log "excepting tests: $(echo $EXCEPT $ALWAYS_EXCEPT)"
	[[ -z "$EXCEPT_SLOW" ]] ||
		log "skipping tests SLOW=no: $(echo $EXCEPT_SLOW)"
	for E in ${EXCEPT//[+,]/ }; do
		eval EXCEPT_${E}=true
	done
	for E in ${ALWAYS_EXCEPT//[+,]/ }; do
		eval EXCEPT_ALWAYS_${E}=true
	done
	for E in ${EXCEPT_SLOW//[+,]/ }; do
		eval EXCEPT_SLOW_${E}=true
	done
	for G in ${GRANT_CHECK_LIST//[+,]/ }; do
		eval GCHECK_ONLY_${G}=true
	done
	# similar to $EXCEPT, STOP_ON_ERROR is a list of test numbers,
	# e.g. [30d, 34a].  Now set variable STOP_ON_ERROR_30d, etc.
	for T in $STOP_ON_ERROR; do
		eval STOP_ON_ERROR_${T}=true
	done
}

basetest() {
	if [[ $1 = [a-z]* ]]; then
		echo $1
	else
		echo ${1%%[a-zA-Z]*}
	fi
}

# print a newline if the last test was skipped
export LAST_SKIPPED=
export ALWAYS_SKIPPED=
#
# Main entry into test-framework. This is called with the number and
# description of a test. The number is used to find the function to run
# the test using "test_$name".
#
# This supports a variety of methods of specifying specific test to
# run or not run:
# - ONLY= env variable with space-separated list of test numbers to run
# - EXCEPT= env variable with space-separated list of test numbers to exclude
#
run_test() {
	assert_DIR
	local testnum=$1
	local testmsg=$2
	export base=$(basetest $testnum)
	export TESTNAME=test_$testnum
	LAST_SKIPPED=
	ALWAYS_SKIPPED=

	# Check the EXCEPT, ALWAYS_EXCEPT and SLOW lists to see if we
	# need to skip the current test. If so, set the ALWAYS_SKIPPED flag.
	local isexcept=EXCEPT_$testnum
	local isexcept_base=EXCEPT_$base
	if [ ${!isexcept}x != x ]; then
		ALWAYS_SKIPPED="y"
		skip_message="skipping excluded test $testnum"
	elif [ ${!isexcept_base}x != x ]; then
		ALWAYS_SKIPPED="y"
		skip_message="skipping excluded test $testnum (base $base)"
	fi

	isexcept=EXCEPT_ALWAYS_$testnum
	isexcept_base=EXCEPT_ALWAYS_$base
	if [ ${!isexcept}x != x ]; then
		ALWAYS_SKIPPED="y"
		skip_message="skipping ALWAYS excluded test $testnum"
	elif [ ${!isexcept_base}x != x ]; then
		ALWAYS_SKIPPED="y"
		skip_message="skipping ALWAYS excluded test $testnum (base $base)"
	fi

	isexcept=EXCEPT_SLOW_$testnum
	isexcept_base=EXCEPT_SLOW_$base
	if [ ${!isexcept}x != x ]; then
		ALWAYS_SKIPPED="y"
		skip_message="skipping SLOW test $testnum"
	elif [ ${!isexcept_base}x != x ]; then
		ALWAYS_SKIPPED="y"
		skip_message="skipping SLOW test $testnum (base $base)"
	fi

	# If there are tests on the ONLY list, check if the current test
	# is on that list and, if so, check if the test is to be skipped
	# and if we are supposed to honor the skip lists.
	if [ -n "$ONLY" ]; then
		local isonly=ONLY_$testnum
		local isonly_base=ONLY_$base
		if [[ ${!isonly}x != x || ${!isonly_base}x != x ]]; then

			if [[ -n "$ALWAYS_SKIPPED" &&
					-n "$HONOR_EXCEPT" ]]; then
				LAST_SKIPPED="y"
				skip_noexit "$skip_message"
				return 0
			else
				[ -n "$LAST_SKIPPED" ] &&
					echo "" && LAST_SKIPPED=
				ALWAYS_SKIPPED=
				run_one_logged $testnum "$testmsg"
				return $?
			fi

		else
			LAST_SKIPPED="y"
			return 0
		fi
	fi

	if [ -n "$ALWAYS_SKIPPED" ]; then
		LAST_SKIPPED="y"
		skip_noexit "$skip_message"
		return 0
	else
		run_one_logged $testnum "$testmsg"
		return $?
	fi
}

log() {
	echo "$*" >&2
	load_module ../libcfs/libcfs/libcfs

	local MSG="$*"
	# Get rid of '
	MSG=${MSG//\'/\\\'}
	MSG=${MSG//\*/\\\*}
	MSG=${MSG//\(/\\\(}
	MSG=${MSG//\)/\\\)}
	MSG=${MSG//\;/\\\;}
	MSG=${MSG//\|/\\\|}
	MSG=${MSG//\>/\\\>}
	MSG=${MSG//\</\\\<}
	MSG=${MSG//\//\\\/}
	do_nodes $(comma_list $(nodes_list)) $LCTL mark "$MSG" 2> /dev/null || true
}

trace() {
	log "STARTING: $*"
	strace -o $TMP/$1.strace -ttt $*
	RC=$?
	log "FINISHED: $*: rc $RC"
	return 1
}

complete_test() {
	local duration=$1

	banner "test complete, duration $duration sec"
	[ -f "$TESTSUITELOG" ] && egrep .FAIL $TESTSUITELOG || true
	echo "duration $duration" >>$TESTSUITELOG
}

pass() {
	# Set TEST_STATUS here. It will be used for logging the result.
	TEST_STATUS="PASS"

	if [[ -f $LOGDIR/err ]]; then
		TEST_STATUS="FAIL"
	elif [[ -f $LOGDIR/skip ]]; then
		TEST_STATUS="SKIP"
	fi
	echo "$TEST_STATUS $*" 2>&1 | tee -a $TESTSUITELOG
}

check_mds() {
	local FFREE=$(do_node $SINGLEMDS \
        lctl get_param -n osd*.*MDT*.filesfree | calc_sum)
	local FTOTAL=$(do_node $SINGLEMDS \
        lctl get_param -n osd*.*MDT*.filestotal | calc_sum)

	[ $FFREE -ge $FTOTAL ] && error "files free $FFREE > total $FTOTAL" ||
		true
}

reset_fail_loc () {
	#echo -n "Resetting fail_loc on all nodes..."
	do_nodes --quiet $(comma_list $(nodes_list)) \
		"lctl set_param -n fail_loc=0 fail_val=0 2>/dev/null" || true
	#echo done.
}


#
# Log a message (on all nodes) padded with "=" before and after.
# Also appends a timestamp and prepends the testsuite name.
#

# ======================================================== 15:06:12 (1624050372)
EQUALS="========================================================"
banner() {
	msg="== ${TESTSUITE} $*"
	last=${msg: -1:1}
	[[ $last != "=" && $last != " " ]] && msg="$msg "
	msg=$(printf '%s%.*s'  "$msg"  $((${#EQUALS} - ${#msg})) $EQUALS )
	# always include at least == after the message
	log "$msg== $(date +"%H:%M:%S (%s)")"
}

check_dmesg_for_errors() {
	local res
	local errors
	local testid=$(tr '_' ' ' <<< $TESTNAME)

	errors="VFS: Busy inodes after unmount of"
	errors+="\|ldiskfs_check_descriptors: Checksum for group 0 failed"
	errors+="\|group descriptors corrupted"
	errors+="\|UBSAN\|KASAN"

	res=$(do_nodes -q $(comma_list $(nodes_list)) "dmesg" |
		tac | sed "/$testid/,$ d" | grep "$errors")
	[[ -n "$res" ]] || return 0
	echo "Kernel error detected: $res"
	return 1
}

#
# Run a single test function and cleanup after it.
#
# This function should be run in a subshell so the test func can
# exit() without stopping the whole script.
#
run_one() {
	local testnum=$1
	local testmsg="$2"
	local SAVE_UMASK=`umask`
	umask 0022

	if ! grep -q $DIR /proc/mounts; then
		$SETUP
	fi

	banner "test $testnum: $testmsg"
	test_${testnum} || error "test_$testnum failed with $?"
	cd $SAVE_PWD
	reset_fail_loc
	check_grant ${testnum} || error "check_grant $testnum failed with $?"
	check_node_health
	check_dmesg_for_errors || error "Error in dmesg detected"
	if [ "$PARALLEL" != "yes" ]; then
		ps auxww | grep -v grep | grep -q "multiop " &&
					error "multiop still running"
	fi
	umask $SAVE_UMASK
	$CLEANUP
	return 0
}

#
# Wrapper around run_one to ensure:
#  - test runs in subshell
#  - output of test is saved to separate log file for error reporting
#  - test result is saved to data file
#
run_one_logged() {
	local before=$SECONDS
	local testnum=$1
	local testmsg=$2
	export tfile=f${testnum}.${TESTSUITE}
	export tdir=d${testnum}.${TESTSUITE}
	local test_log=$TESTLOG_PREFIX.$TESTNAME.test_log.$(hostname -s).log
	local zfs_debug_log=$TESTLOG_PREFIX.$TESTNAME.zfs_log
	local SAVE_UMASK=$(umask)
	local rc=0
	local node
	umask 0022

	[[ $KPTR_ON_MOUNT ]] || kptr_enable_and_save

	rm -f $LOGDIR/err $LOGDIR/ignore $LOGDIR/skip
	echo

	# process ONLY options:
	# - $ONLY_REPEAT will run the subtest $ONLY_REPEAT times
	# - $ONLY_MINUTES will run the subtest for $ONLY_MINUTES
	# - $ONLY_REPEAT and $ONLY_MINUTES can be set to run the subtest for
	#   $ONLY_REPEAT times but not to exceed $ONLY_MINUTES
	# - if $ONLY_REPEAT and ONLY_MINUTES are unset, subtest will run once
	local repeat=${ONLY:+$ONLY_REPEAT}
	if [[ -n "$ONLY" && "$ONLY_MINUTES" ]]; then
		local repeat_end_sec=$((SECONDS + ONLY_MINUTES * 60))
	fi

	export ONLY_REPEAT_ITER=1
	while true; do
		local before_sub=$SECONDS

		log_sub_test_begin $TESTNAME
		# remove temp files between repetitions to avoid test failures
		if [[ -n "$append" ]]; then
			[[ -n "$tdir" ]] && rm -rvf $DIR/$tdir*
			[[ -n "$tfile" ]] && rm -vf $DIR/$tfile*
			echo "subtest iteration $ONLY_REPEAT_ITER/$repeat " \
				"($(((SECONDS-before)/60))/$ONLY_MINUTES min)"
		fi
		# loop around subshell so stack_trap EXIT triggers each time
		(run_one $testnum "$testmsg") 2>&1 | tee -i $append $test_log
		rc=${PIPESTATUS[0]}
		local append=-a
		local duration_sub=$((SECONDS - before_sub))
		local test_error

		[[ $rc != 0 && ! -f $LOGDIR/err ]] &&
			echo "$TESTNAME returned $rc" | tee $LOGDIR/err

		if [[ -f $LOGDIR/err ]]; then
			test_error=$(cat $LOGDIR/err)
			TEST_STATUS="FAIL"
		elif [[ -f $LOGDIR/ignore ]]; then
			test_error=$(cat $LOGDIR/ignore)
		elif [[ -f $LOGDIR/skip ]]; then
			test_error=$(cat $LOGDIR/skip)
			TEST_STATUS="SKIP"
		else
			TEST_STATUS="PASS"
		fi

		pass "$testnum" "(${duration_sub}s)"
		if [ -n "${DUMP_OK}" ]; then
			gather_logs $(comma_list $(nodes_list))
		fi

		log_sub_test_end $TEST_STATUS $duration_sub "$rc" "$test_error"

		# exit test suite if the failed test is in STOP_ON_ERROR list
		[[ $TEST_STATUS == "FAIL" ]] &&
			[[ -v STOP_ON_ERROR_$testnum ]] &&
			exit $STOP_NOW_RC

		[[ $rc != 0 || "$TEST_STATUS" != "PASS" ]] && break

		# no repeat options were set, break after the first iteration
		[[ -z "$repeat" && -z "$repeat_end_sec" ]] && break
		# break if any repeat options were set and have been met
		[[ -n "$repeat" ]] && (( ONLY_REPEAT_ITER >= repeat )) && break
		[[ -n "$repeat_end_sec" ]] &&
			(( $SECONDS >= $repeat_end_sec )) && break
		((ONLY_REPEAT_ITER++))
	done

	[[ $KPTR_ON_MOUNT ]] || kptr_restore

	if [[ "$TEST_STATUS" != "SKIP" && -f $TF_SKIP ]]; then
		rm -f $TF_SKIP
	fi

	if [ -f $LOGDIR/err ]; then
		log_zfs_info "$zfs_debug_log"
		$FAIL_ON_ERROR && exit $rc
	fi

	umask $SAVE_UMASK

	unset TESTNAME
	unset tdir
	unset tfile

	return 0
}

#
# Print information of skipped tests to result.yml
#
skip_logged(){
	log_sub_test_begin $1
	shift
	log_sub_test_end "SKIP" "0" "0" "$@"
}

grant_from_clients() {
	local nodes="$1"

	# get client grant
	do_nodes $nodes "$LCTL get_param -n osc.${FSNAME}-*.cur_*grant_bytes" |
		calc_sum
}

grant_from_servers() {
	local nodes="$1"

	# get server grant
	# which is tot_granted less grant_precreate
	do_nodes $nodes "$LCTL get_param obdfilter.${FSNAME}-OST*.tot_granted" \
		" obdfilter.${FSNAME}-OST*.tot_pending" \
		" obdfilter.${FSNAME}-OST*.grant_precreate" |
		tr '=' ' ' | awk '/tot_granted/{ total += $2 };
				  /tot_pending/{ total -= $2 };
				  /grant_precreate/{ total -= $2 };
				  END { printf("%0.0f", total) }'
}

check_grant() {
	export base=$(basetest $1)
	[ "$CHECK_GRANT" == "no" ] && return 0

	local isonly_base=GCHECK_ONLY_${base}
	local isonly=GCHECK_ONLY_$1
	[ ${!isonly_base}x == x -a ${!isonly}x == x ] && return 0

	echo -n "checking grant......"

	local osts=$(comma_list $(osts_nodes))
	local clients=$CLIENTS
	[ -z "$clients" ] && clients=$(hostname)

	# sync all the data and make sure no pending data on server
	do_nodes $clients sync
	do_nodes $clients $LFS df # initiate all idling connections

	# get client grant
	cli_grant=$(grant_from_clients $clients)

	# get server grant
	# which is tot_granted less grant_precreate
	srv_grant=$(grant_from_servers $osts)

	count=0
	# check whether client grant == server grant
	while [[ $cli_grant != $srv_grant && count++ -lt 30 ]]; do
		echo "wait for client:$cli_grant == server:$srv_grant"
		sleep 1
		cli_grant=$(grant_from_clients $clients)
		srv_grant=$(grant_from_servers $osts)
	done
	if [[ $cli_grant -ne $srv_grant ]]; then
		do_nodes $(comma_list $(osts_nodes)) \
			"$LCTL get_param obdfilter.${FSNAME}-OST*.tot*" \
			"obdfilter.${FSNAME}-OST*.grant_*"
		do_nodes $clients "$LCTL get_param osc.${FSNAME}-*.cur_*_bytes"
		error "failed grant check: client:$cli_grant server:$srv_grant"
	else
		echo "pass grant check: client:$cli_grant server:$srv_grant"
	fi
}

########################
# helper functions

osc_to_ost() {
	local osc=$1

	echo ${osc/-osc*/}
}

ostuuid_from_index() {
	# only print the first UUID, if 'lfs osts' shows multiple mountpoints
	local uuid=($($LFS osts $2 | sed -ne "/^$1: /s/.* \(.*\) .*$/\1/p"))

	echo ${uuid}
}

ostname_from_index() {
	local uuid=$(ostuuid_from_index $1 $2)

	echo ${uuid/_UUID/}
}

mdtuuid_from_index() {
	# only print the first UUID, if 'lfs osts' shows multiple mountpoints
	local uuid=($($LFS mdts $2 | sed -ne "/^$1: /s/.* \(.*\) .*$/\1/p"))

	echo ${uuid}
}

mdtname_from_index() {
	local uuid=$(mdtuuid_from_index $1 $2)

	echo ${uuid/_UUID/}
}

mdssize_from_index() {
	local mdt=$(mdtname_from_index $2)

	$LFS df $1 | awk "/$mdt/ { print \$2 }"
}

index_from_ostuuid()
{
	# only print the first index, if 'lfs osts' shows multiple mountpoints
	local ostidx=($($LFS osts $2 | sed -ne "/${1}/s/\(.*\): .* .*$/\1/p"))

	echo ${ostidx}
}

# Description:
#   Return unique identifier for given hostname
host_id() {
	local host_name=$1
	echo $host_name | md5sum | cut -d' ' -f1
}

# Description:
#   Returns list of ip addresses for each interface
local_addr_list() {
	ip -o a s | awk '{print $4}' | awk -F/ '{print $1}'
}

# Description:
#   Returns list of interfaces configured for LNet
lnet_if_list() {
	local nids=( $($LCTL list_nids | xargs echo) )

	[[ -z ${nids[@]} ]] &&
		return 0

	if [[ ${NETTYPE} =~ kfi* ]]; then
		$LNETCTL net show 2>/dev/null | awk '/ cxi[0-9]+$/{print $NF}' |
			sort -u | xargs echo
		return 0
	fi

	declare -a INTERFACES

	for ((i = 0; i < ${#nids[@]}; i++)); do
		ip=$(sed 's/^\(.*\)@.*$/\1/'<<<${nids[i]})
		INTERFACES[i]=$(ip -o a s |
				awk '$4 ~ /^'$ip'\//{print $2}')
		INTERFACES=($(echo "${INTERFACES[@]}" | tr ' ' '\n' | uniq | tr '\n' ' '))
		if [[ -z ${INTERFACES[i]} ]]; then
			error "Can't determine interface name for NID ${nids[i]}"
		elif [[ 1 -ne $(wc -w <<<${INTERFACES[i]}) ]]; then
			error "Found $(wc -w <<<${INTERFACES[i]}) interfaces for NID ${nids[i]}. Expect 1"
		fi
	done

	echo "${INTERFACES[@]}"

	return 0
}

# return 1 if addr is remote
# return 0 if addr is local
is_local_addr() {
	local addr=$1
	# Cache address list to avoid mutiple execution of local_addr_list
	LOCAL_ADDR_LIST=${LOCAL_ADDR_LIST:-$(local_addr_list)}
	local i
	for i in $LOCAL_ADDR_LIST ; do
		[[ "$i" == "$addr" ]] && return 0
	done
	return 1
}

# return true(0) if host_name is local
# return false(1) if host_name is remote
local_node() {
	local host_name=$1
	local is_local="IS_LOCAL_$(host_id $host_name)"

	if [ -z "${!is_local-}" ] ; then
		eval $is_local=false
		local ip4=$(getent ahostsv4 $host_name |
			    awk 'NR == 1 { print $1 }')
		local ip6=$(getent ahostsv6 $host_name |
			    awk 'NR == 1 { print $1 }')
		if is_local_addr $ip4 || is_local_addr $ip6 ; then
			eval $is_local=true
		fi
	fi
	${!is_local}
}

remote_node () {
	local node=$1

	! local_node $node
}

remote_mds ()
{
	local node
	for node in $(mdts_nodes); do
		remote_node $node && return 0
	done
	return 1
}

remote_mds_nodsh()
{
	[ -n "$CLIENTONLY" ] && return 0 || true
	remote_mds && [ "$PDSH" = "no_dsh" -o -z "$PDSH" -o -z "$mds_HOST" ]
}

require_dsh_mds()
{
	remote_mds_nodsh && echo "SKIP: $TESTSUITE: remote MDS with nodsh" &&
		MSKIPPED=1 && return 1
	return 0
}

# return true if any OST is on a remote node
remote_ost()
{
	local osts=$(osts_nodes)
	local node

	for node in ${osts//,/ }; do
		remote_node $node && return 0
	done

	return 1
}

# return true if any OST is on a remote node and no remote shell is configured
remote_ost_nodsh()
{
	[ -n "$CLIENTONLY" ] && return 0 || true
	remote_ost && [ "$PDSH" = "no_dsh" -o -z "$PDSH" -o -z "$ost_HOST" ]
}

require_dsh_ost()
{
	remote_ost_nodsh && echo "SKIP: $TESTSUITE: remote OST with nodsh" &&
		OSKIPPED=1 && return 1
	return 0
}

remote_mgs_nodsh()
{
	[ -n "$CLIENTONLY" ] && return 0 || true
	local MGS
	MGS=$(facet_host mgs)
	remote_node $MGS && [ "$PDSH" = "no_dsh" -o -z "$PDSH" -o -z "$ost_HOST" ]
}

local_mode ()
{
	remote_mds_nodsh || remote_ost_nodsh ||
		$(single_local_node $(comma_list $(nodes_list)))
}

remote_servers () {
	remote_ost && remote_mds
}

# Get the active nodes for facets.
facets_nodes () {
	local facets=$1
	local facet
	local nodes
	local nodes_sort
	local i

	for facet in ${facets//,/ }; do
		nodes="$nodes $(facet_active_host $facet)"
	done

	nodes_sort=$(for i in ${nodes//,/ }; do echo $i; done | sort -u)
	echo -n $nodes_sort
}

# Get name of the active MGS node.
mgs_node () {
		echo -n $(facets_nodes $(get_facets MGS))
	}

# Get all of the active MDS nodes.
mdts_nodes () {
	echo -n $(facets_nodes $(get_facets MDS))
}

# Get all of the active OSS nodes.
osts_nodes () {
	echo -n $(facets_nodes $(get_facets OST))
}

# Get all of the client nodes and active server nodes.
nodes_list () {
	local nodes=$HOSTNAME
	local nodes_sort
	local i

	# CLIENTS (if specified) contains the local client
	[ -n "$CLIENTS" ] && nodes=${CLIENTS//,/ }

	if [ "$PDSH" -a "$PDSH" != "no_dsh" ]; then
		nodes="$nodes $(facets_nodes $(get_facets))"
	fi

	nodes_sort=$(for i in ${nodes//,/ }; do echo $i; done | sort -u)
	echo -n $nodes_sort
}

# Get all of the remote client nodes and remote active server nodes.
remote_nodes_list () {
	echo -n $(nodes_list) | sed -re "s/\<$HOSTNAME\>//g"
}

# Get all of the MDS nodes, including active and passive nodes.
all_mdts_nodes () {
	local host
	local failover_host
	local nodes
	local nodes_sort
	local i

	for i in $(seq $MDSCOUNT); do
		host=mds${i}_HOST
		failover_host=mds${i}failover_HOST
		nodes="$nodes ${!host} ${!failover_host}"
	done

	[ -n "$nodes" ] || nodes="${mds_HOST} ${mdsfailover_HOST}"
	nodes_sort=$(for i in $nodes; do echo $i; done | sort -u)
	echo -n $nodes_sort
}

# Get all of the OSS nodes, including active and passive nodes.
all_osts_nodes () {
	local host
	local failover_host
	local nodes=
	local nodes_sort
	local i

	for i in $(seq $OSTCOUNT); do
		host=ost${i}_HOST
		failover_host=ost${i}failover_HOST
		nodes="$nodes ${!host} ${!failover_host}"
	done

	[ -n "$nodes" ] || nodes="${ost_HOST} ${ostfailover_HOST}"
	nodes_sort=$(for i in $nodes; do echo $i; done | sort -u)
	echo -n $nodes_sort
}

# Get all of the server nodes, including active and passive nodes.
all_server_nodes () {
	local nodes
	local nodes_sort
	local i

	nodes="$mgs_HOST $mgsfailover_HOST $(all_mdts_nodes) $(all_osts_nodes)"

	nodes_sort=$(for i in ${nodes//,/ }; do echo $i; done | sort -u)
	echo -n $nodes_sort
}

# Get all of the client and server nodes, including active and passive nodes.
all_nodes () {
	local nodes=$HOSTNAME
	local nodes_sort
	local i

	# CLIENTS (if specified) contains the local client
	[ -n "$CLIENTS" ] && nodes=${CLIENTS//,/ }

	if [ "$PDSH" -a "$PDSH" != "no_dsh" ]; then
		nodes="$nodes $(all_server_nodes)"
	fi

	nodes_sort=$(for i in ${nodes//,/ }; do echo $i; done | sort -u)
	echo -n $nodes_sort
}

init_clients_lists () {
	# Sanity check: exclude the local client from RCLIENTS
	local clients=$(hostlist_expand "$RCLIENTS")
	local rclients=$(exclude_items_from_list "$clients" $HOSTNAME)

	# Sanity check: exclude the dup entries
	RCLIENTS=$(for i in ${rclients//,/ }; do echo $i; done | sort -u)

	export CLIENT1=${CLIENT1:-$HOSTNAME}
	export SINGLECLIENT=$CLIENT1

	clients="$SINGLECLIENT $HOSTNAME $RCLIENTS"

	# Sanity check: exclude the dup entries from CLIENTS
	# for those configs which has SINGLCLIENT set to local client
	clients=$(for i in $clients; do echo $i; done | sort -u)

	export CLIENTS=$(comma_list $clients)
	local -a remoteclients=($RCLIENTS)
	for ((i=0; $i<${#remoteclients[@]}; i++)); do
		varname=CLIENT$((i + 2))

		eval export $varname=${remoteclients[i]}
	done

	export CLIENTCOUNT=$((${#remoteclients[@]} + 1))
}

get_random_entry () {
	local rnodes=$1

	rnodes=${rnodes//,/ }

	local -a nodes=($rnodes)
	local num=${#nodes[@]}
	local i=$((RANDOM * num * 2 / 65536))

	echo ${nodes[i]}
}

client_only () {
	[ -n "$CLIENTONLY" ] || [ "x$CLIENTMODSONLY" = "xyes" ]
}

check_versions () {
	# this should already have been called, but just in case
	[[ -n "$CLIENT_VERSION" && -n "$MDS1_VERSION" && -n "$OST1_VERSION" ]]||
		get_lustre_env

	echo "client=$CLIENT_VERSION MDS=$MDS1_VERSION OSS=$OST1_VERSION"

	[[ -n "$CLIENT_VERSION" && -n "$MDS1_VERSION" && -n "$OST1_VERSION" ]]||
		error "unable to determine node versions"

	(( "$CLIENT_VERSION" == "$MDS1_VERSION" &&
	   "$CLIENT_VERSION" == "$OST1_VERSION"))
}

get_node_count() {
	local nodes="$@"

	echo ${nodes//,/ } | wc -w || true
}

mixed_mdt_devs () {
	local nodes=$(mdts_nodes)
	local mdtcount=$(get_node_count "$nodes")

	[ ! "$MDSCOUNT" = "$mdtcount" ]
}

generate_machine_file() {
	local nodes=${1//,/ }
	local machinefile=$2

	rm -f $machinefile
	for node in $nodes; do
		echo $node >>$machinefile ||
			{ echo "can not generate machinefile $machinefile" &&
				return 1; }
	done
}

get_stripe () {
	local file=$1/stripe

	touch $file
	$LFS getstripe -v $file || error "getstripe $file failed"
	rm -f $file
}

# Check and add a test group.
add_group() {
	local group_id=$1
	local group_name=$2
	local rc=0

	local gid=$(getent group $group_name | cut -d: -f3)
	if [[ -n "$gid" ]]; then
		[[ "$gid" -eq "$group_id" ]] || {
			error_noexit "inconsistent group ID:" \
				     "new: $group_id, old: $gid"
			rc=1
		}
	else
		echo "adding group $group_name:$group_id"
		getent group $group_name || true
		getent group $group_id || true
		groupadd -g $group_id $group_name
		rc=${PIPESTATUS[0]}
	fi

	return $rc
}

# Check and add a test user.
add_user() {
	local user_id=$1
	shift
	local user_name=$1
	shift
	local group_name=$1
	shift
	local home=$1
	shift
	local opts="$@"
	local rc=0

	local uid=$(getent passwd $user_name | cut -d: -f3)
	if [[ -n "$uid" ]]; then
		if [[ "$uid" -eq "$user_id" ]]; then
			local dir=$(getent passwd $user_name | cut -d: -f6)
			if [[ "$dir" != "$home" ]]; then
				mkdir -p $home
				usermod -d $home $user_name
				rc=${PIPESTATUS[0]}
			fi
		else
			error_noexit "inconsistent user ID:" \
				     "new: $user_id, old: $uid"
			rc=1
		fi
	else
		mkdir -p $home
		useradd -M -u $user_id -d $home -g $group_name $opts $user_name
		rc=${PIPESTATUS[0]}
	fi

	return $rc
}

check_runas_id_ret() {
	local myRC=0
	local myRUNAS_UID=$1
	local myRUNAS_GID=$2
	shift 2
	local myRUNAS=$@

	if [ -z "$myRUNAS" ]; then
		error_exit "check_runas_id_ret requires myRUNAS argument"
	fi

	$myRUNAS true ||
		error "Unable to execute $myRUNAS"

	id $myRUNAS_UID > /dev/null ||
		error "Invalid RUNAS_ID $myRUNAS_UID. Please set RUNAS_ID to " \
		      "some UID which exists on MDS and client or add user " \
		      "$myRUNAS_UID:$myRUNAS_GID on these nodes."

	if $GSS_KRB5; then
		$myRUNAS krb5_login.sh ||
			error "Failed to refresh krb5 TGT for UID $myRUNAS_ID."
	fi
	mkdir $DIR/d0_runas_test
	chmod 0755 $DIR
	chown $myRUNAS_UID:$myRUNAS_GID $DIR/d0_runas_test
	$myRUNAS touch $DIR/d0_runas_test/f$$ || myRC=$?
	rm -rf $DIR/d0_runas_test
	return $myRC
}

check_runas_id() {
	local myRUNAS_UID=$1
	local myRUNAS_GID=$2
	shift 2
	local myRUNAS=$@

	check_runas_id_ret $myRUNAS_UID $myRUNAS_GID $myRUNAS || \
		error "unable to write to $DIR/d0_runas_test as " \
		      "UID $myRUNAS_UID."
}

# obtain the UID/GID for MPI_USER
get_mpiuser_id() {
	local mpi_user=$1

	MPI_USER_UID=$(do_facet client "getent passwd $mpi_user | cut -d: -f3;
exit \\\${PIPESTATUS[0]}") || error_exit "failed to get the UID for $mpi_user"

	MPI_USER_GID=$(do_facet client "getent passwd $mpi_user | cut -d: -f4;
exit \\\${PIPESTATUS[0]}") || error_exit "failed to get the GID for $mpi_user"
}

# Run multiop in the background, but wait for it to print
# "PAUSING" to its stdout before returning from this function.
multiop_bg_pause() {
	MULTIOP_PROG=${MULTIOP_PROG:-$MULTIOP}
	FILE=$1
	ARGS=$2

	TMPPIPE=/tmp/multiop_open_wait_pipe.$$
	mkfifo $TMPPIPE

	echo "$MULTIOP_PROG $FILE v$ARGS"
	$MULTIOP_PROG $FILE v$ARGS > $TMPPIPE &
	local pid=$!

	echo "TMPPIPE=${TMPPIPE}"
	read -t 60 multiop_output < $TMPPIPE
	if [ $? -ne 0 ]; then
		rm -f $TMPPIPE
		return 1
	fi
	rm -f $TMPPIPE
	if [ "$multiop_output" != "PAUSING" ]; then
		echo "Incorrect multiop output: $multiop_output"
		kill -9 $pid
		return 1
	fi

	return 0
}

do_and_time () {
	local cmd="$1"
	local start
	local rc

	start=$SECONDS
	eval '$cmd'
	[ ${PIPESTATUS[0]} -eq 0 ] || rc=1

	echo $((SECONDS - start))
	return $rc
}

inodes_available () {
	local IFree=$($LFS df -i $MOUNT | grep ^$FSNAME | awk '{ print $4 }' |
		sort -un | head -n1) || return 1

	echo $((IFree))
}

mdsrate_inodes_available () {
	local min_inodes=$(inodes_available)

	echo $((min_inodes * 99 / 100))
}

bytes_available () {
	echo $(df -P -B 1 "$MOUNT" | awk 'END {print $4}')
}

mdsrate_bytes_available () {
	local bytes=$(bytes_available)

	echo $((bytes * 99 / 100))
}

# reset stat counters
clear_stats() {
	local paramfile="$1"

	lctl set_param -n $paramfile=0
}

# sum stat items
calc_stats() {
	local paramfile="$1"
	local stat="$2"

	lctl get_param -n $paramfile |
		awk '/^'$stat'/ { sum += $2 } END { printf("%0.0f", sum) }'
}

calc_sum () {
	awk '{sum += $1} END { printf("%0.0f", sum) }'
}

calc_osc_kbytes () {
	$LFS df $MOUNT > /dev/null
	$LCTL get_param -n osc.*[oO][sS][cC][-_][0-9a-f]*.$1 | calc_sum
}

free_min_max () {
	wait_delete_completed
	AVAIL=($(lctl get_param -n osc.*[oO][sS][cC]-[^M]*.kbytesavail))
	echo "OST kbytes available: ${AVAIL[*]}"
	MAXV=${AVAIL[0]}
	MAXI=0
	MINV=${AVAIL[0]}
	MINI=0
	for ((i = 0; i < ${#AVAIL[@]}; i++)); do
		#echo OST $i: ${AVAIL[i]}kb
		if [[ ${AVAIL[i]} -gt $MAXV ]]; then
			MAXV=${AVAIL[i]}
			MAXI=$i
		fi
		if [[ ${AVAIL[i]} -lt $MINV ]]; then
			MINV=${AVAIL[i]}
			MINI=$i
		fi
	done
	echo "Min free space: OST $MINI: $MINV"
	echo "Max free space: OST $MAXI: $MAXV"
}

# save_lustre_params(comma separated facet list, parameter_mask)
# generate a stream of formatted strings (<facet> <param name>=<param value>)
save_lustre_params() {
	local facets=$1
	local facet
	local facet_svc

	for facet in ${facets//,/ }; do
		facet_svc=$(facet_svc $facet)
		do_facet $facet \
			"params=\\\$($LCTL get_param $2);
			 [[ -z \\\"$facet_svc\\\" ]] && param= ||
			 param=\\\$(grep $facet_svc <<< \\\"\\\$params\\\");
			 [[ -z \\\$param ]] && param=\\\"\\\$params\\\";
			 while read s; do echo $facet \\\$s;
			 done <<< \\\"\\\$param\\\""
	done
}

# restore lustre parameters from input stream, produces by save_lustre_params
restore_lustre_params() {
	local facet
	local name
	local val

	while IFS=" =" read facet name val; do
		do_facet $facet "$LCTL set_param -n $name=$val"
	done
}

check_node_health() {
	local nodes=${1:-$(comma_list $(nodes_list))}
	local health=$TMP/node_health.$$

	do_nodes -q $nodes "$LCTL get_param catastrophe 2>&1" | tee $health |
		grep "catastrophe=1" && error "LBUG/LASSERT detected"
	# Only check/report network health if get_param isn't reported, since
	# *clearly* the network is working if get_param returned something.
	if (( $(grep -c catastro $health) != $(wc -w <<< ${nodes//,/ }) )); then
		for node in ${nodes//,/ }; do
			check_network $node 60
		done
	fi
	rm -f $health
}

mdsrate_cleanup () {
	if [ -d $4 ]; then
		mpi_run ${MACHINEFILE_OPTION} $2 -np $1 ${MDSRATE} --unlink \
			--nfiles $3 --dir $4 --filefmt $5 $6
		rmdir $4
	fi
}

run_mdtest () {
	local test_type="$1"
	local file_size=0
	local num_files=0
	local num_cores=0
	local num_procs=0
	local num_hosts=0
	local free_space=0
	local num_inodes=0
	local num_entries=0
	local num_dirs=0
	local np=0
	local rc=0

	local mdtest_basedir
	local mdtest_actions
	local mdtest_options
	local stripe_options
	local params_file

	case "$test_type" in
	create-small)
		stripe_options=(-c 1 -i 0)
		mdtest_actions=(-F -R)
		file_size=1024
		num_files=100000
		;;
	create-large)
		stripe_options=(-c -1)
		mdtest_actions=(-F -R)
		file_size=$((1024 * 1024 * 1024))
		num_files=16
		;;
	lookup-single)
		stripe_options=(-c 1)
		mdtest_actions=(-C -D -E -k -r)
		num_dirs=1
		num_files=100000
		;;
	lookup-multi)
		stripe_options=(-c 1)
		mdtest_actions=(-C -D -E -k -r)
		num_dirs=100
		num_files=1000
		;;
	*)
		stripe_options=(-c -1)
		mdtest_actions=()
		num_files=100000
		;;
	esac

	if [[ -n "$MDTEST_DEBUG" ]]; then
		mdtest_options+=(-v -v -v)
	fi

	num_dirs=${NUM_DIRS:-$num_dirs}
	num_files=${NUM_FILES:-$num_files}
	file_size=${FILE_SIZE:-$file_size}
	free_space=$(mdsrate_bytes_available)

	if (( file_size * num_files > free_space )); then
		file_size=$((free_space / num_files))
		log "change file size to $file_size due to" \
			"number of files $num_files and" \
			"free space limit in $free_space"
	fi

	if (( file_size > 0 )); then
		log "set file size to $file_size"
		mdtest_options+=(-w=$file_size)
	fi

	params_file=$TMP/$TESTSUITE-$TESTNAME.parameters
	mdtest_basedir=$MOUNT/mdtest
	mdtest_options+=(-d=$mdtest_basedir)

	num_cores=$(nproc)
	num_hosts=$(get_node_count ${CLIENTS//,/ })
	num_procs=$((num_cores * num_hosts))
	num_inodes=$(mdsrate_inodes_available)

	if (( num_inodes < num_files )); then
		log "change the number of files $num_files to the" \
			"number of available inodes $num_inodes"
		num_files=$num_inodes
	fi

	if (( num_dirs > 1 )); then
		num_entries=$((num_files / num_dirs))
		# md_validate_tests requires items must be a multiple of
		# items per directory
		num_files=$((num_entries * num_dirs))
		log "split $num_files files to $num_dirs" \
			"with $num_entries files each"
		mdtest_options+=(-I=$num_entries)
	fi

	generate_machine_file $CLIENTS $MACHINEFILE ||
		error "can not generate machinefile"

	install -v -d -m 0777 $mdtest_basedir

	setstripe_getstripe $mdtest_basedir ${stripe_options[@]}

	save_lustre_params $(get_facets MDS) \
		mdt.*.enable_remote_dir_gid > $params_file

	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param mdt.*.enable_remote_dir_gid=-1

	stack_trap "restore_lustre_params < $params_file" EXIT

	for np in 1 $num_procs; do
		num_entries=$((num_files / np ))

		mpi_run $MACHINEFILE_OPTION $MACHINEFILE \
			-np $np -npernode $num_cores $MDTEST \
			${mdtest_options[@]} -n=$num_entries \
			${mdtest_actions[@]} 2>&1 | tee -a "$LOG"

		rc=${PIPESTATUS[0]}

		if (( rc != 0 )); then
			mpi_run $MACHINEFILE_OPTION $MACHINEFILE \
				-np $np -npernode $num_cores $MDTEST \
				${mdtest_options[@]} -n=$num_entries \
				-r 2>&1 | tee -a "$LOG"
			break
		fi
	done

	rmdir -v $mdtest_basedir
	rm -v $state $MACHINEFILE

	return $rc
}

########################

convert_facet2label() {
	local facet=$1

	if [ x$facet = xost ]; then
		facet=ost1
	elif [ x$facet = xmgs ] && combined_mgs_mds ; then
		facet=mds1
	fi

	local varsvc=${facet}_svc

	if [ -n "${!varsvc}" ]; then
		echo ${!varsvc}
	else
		error "No label for $facet!"
	fi
}

get_clientosc_proc_path() {
	echo "${1}-osc-[-0-9a-f]*"
}

get_mdtosc_proc_path() {
	local mds_facet=$1
	local ost_label=${2:-"*OST*"}

	[ "$mds_facet" = "mds" ] && mds_facet=$SINGLEMDS
	local mdt_label=$(convert_facet2label $mds_facet)
	local mdt_index=$(echo $mdt_label | sed -e 's/^.*-//')

	if [[ $ost_label = *OST* ]]; then
		echo "${ost_label}-osc-${mdt_index}"
	else
		echo "${ost_label}-osp-${mdt_index}"
	fi
}

get_osc_import_name() {
	local facet=$1
	local ost=$2
	local label=$(convert_facet2label $ost)

	if [ "${facet:0:3}" = "mds" ]; then
		get_mdtosc_proc_path $facet $label
		return 0
	fi

	get_clientosc_proc_path $label
	return 0
}

_wait_import_state () {
	local expected="$1"
	local CONN_PROC="$2"
	local maxtime=${3:-$(max_recovery_time)}
	local err_on_fail=${4:-1}
	local CONN_STATE
	local i=0

	CONN_STATE=$($LCTL get_param -n $CONN_PROC 2>/dev/null | cut -f2 | uniq)
	while ! echo "${CONN_STATE}" | egrep -q "^${expected}\$" ; do
		if [[ "${expected}" == "DISCONN" ]]; then
			# for disconn we can check after proc entry is removed
			[[ -z "${CONN_STATE}" ]] && return 0
			# with AT, we can have connect request timeout near
			# reconnect timeout and test can't see real disconnect
			[[ "${CONN_STATE}" == "CONNECTING" ]] && return 0
		fi
		if (( $i >= $maxtime )); then
			(( $err_on_fail != 0 )) &&
				error "can't put import for $CONN_PROC into ${expected} state after $i sec, have ${CONN_STATE}"
			return 1
		fi
		sleep 1
		# Add uniq for multi-mount case
		CONN_STATE=$($LCTL get_param -n $CONN_PROC 2>/dev/null |
			     cut -f2 | uniq)
		i=$((i + 1))
	done

	log "$CONN_PROC in ${CONN_STATE} state after $i sec"
	return 0
}

wait_import_state() {
	local expected="$1"
	local params="$2"
	local maxtime=${3:-$(max_recovery_time)}
	local err_on_fail=${4:-1}
	local param

	for param in ${params//,/ }; do
		_wait_import_state "$expected" "$param" $maxtime $err_on_fail ||
		return
	done
}

wait_import_state_mount() {
	if ! is_mounted $MOUNT && ! is_mounted $MOUNT2; then
		return 0
	fi

	wait_import_state "$@"
}

# One client request could be timed out because server was not ready
# when request was sent by client.
# The request timeout calculation details :
# ptl_send_rpc ()
#      /* We give the server rq_timeout secs to process the req, and
#      add the network latency for our local timeout. */
#      request->rq_deadline = request->rq_sent + request->rq_timeout +
#           ptlrpc_at_get_net_latency(request) ;
#
# ptlrpc_connect_import ()
#      request->rq_timeout = INITIAL_CONNECT_TIMEOUT
#
# init_imp_at () ->
#   -> at_init(&at->iat_net_latency, 0, 0) -> iat_net_latency=0
# ptlrpc_at_get_net_latency(request) ->
#       at_get (max (iat_net_latency=0, at_min)) = at_min
#
# i.e.:
# request->rq_timeout + ptlrpc_at_get_net_latency(request) =
# INITIAL_CONNECT_TIMEOUT + at_min
#
# We will use obd_timeout instead of INITIAL_CONNECT_TIMEOUT
# because we can not get this value in runtime,
# the value depends on configure options, and it is not stored in /proc.
# obd_support.h:
# #define CONNECTION_SWITCH_MIN 5U
# #define INITIAL_CONNECT_TIMEOUT max(CONNECTION_SWITCH_MIN,obd_timeout/20)

request_timeout () {
	local facet=$1

	# request->rq_timeout = INITIAL_CONNECT_TIMEOUT
	local init_connect_timeout=$TIMEOUT
	[[ $init_connect_timeout -ge 5 ]] || init_connect_timeout=5

	local at_min=$(at_get $facet at_min)

	echo $(( init_connect_timeout + at_min ))
}

_wait_osc_import_state() {
	local facet=$1
	local ost_facet=$2
	local expected=$3
	local target=$(get_osc_import_name $facet $ost_facet)
	local param="os[cp].${target}.ost_server_uuid"
	local params=$param
	local i=0

	# 1. wait the deadline of client 1st request (it could be skipped)
	# 2. wait the deadline of client 2nd request
	local maxtime=$(( 2 * $(request_timeout $facet)))

	if [[ $facet == client* ]]; then
		# During setup time, the osc might not be setup, it need wait
		# until list_param can return valid value.
		params=$($LCTL list_param $param 2>/dev/null | head -1)
		while [ -z "$params" ]; do
			if [ $i -ge $maxtime ]; then
				echo "can't get $param in $maxtime secs"
				return 1
			fi
			sleep 1
			i=$((i + 1))
			params=$($LCTL list_param $param 2>/dev/null | head -1)
		done
	fi

	if [[ $ost_facet = mds* ]]; then
		# no OSP connection to itself
		if [[ $facet = $ost_facet ]]; then
			return 0
		fi
		param="osp.${target}.mdt_server_uuid"
		params=$param
	fi

	local plist=$(comma_list $params)
	if ! do_rpc_nodes "$(facet_active_host $facet)" \
			wait_import_state $expected $plist $maxtime; then
		error "$facet: import is not in $expected state after $maxtime"
		return 1
	fi

	return 0
}

wait_osc_import_state() {
	local facet=$1
	local ost_facet=$2
	local expected=$3
	local num

	if [[ $facet = mds ]]; then
		for num in $(seq $MDSCOUNT); do
			_wait_osc_import_state mds$num "$ost_facet" "$expected"
		done
	else
		_wait_osc_import_state "$facet" "$ost_facet" "$expected"
	fi
}

wait_osc_import_ready() {
	wait_osc_import_state $1 $2 "\(FULL\|IDLE\)"
}

_wait_mgc_import_state() {
	local facet=$1
	local expected=$2
	local error_on_failure=${3:-1}
	local param="mgc.*.mgs_server_uuid"
	local params=$param
	local i=0

	# 1. wait the deadline of client 1st request (it could be skipped)
	# 2. wait the deadline of client 2nd request
	local maxtime=$(( 2 * $(request_timeout $facet)))

	if [[ $facet == client* ]]; then
		# During setup time, the osc might not be setup, it need wait
		# until list_param can return valid value. And also if there
		# are mulitple osc entries we should list all of them before
		# go to wait.
		params=$($LCTL list_param $param 2>/dev/null || true)
		while [ -z "$params" ]; do
			if [ $i -ge $maxtime ]; then
				echo "can't get $param in $maxtime secs"
				return 1
			fi
			sleep 1
			i=$((i + 1))
			params=$($LCTL list_param $param 2>/dev/null || true)
		done
	fi
	local plist=$(comma_list $params)
	if ! do_rpc_nodes "$(facet_active_host $facet)" \
			wait_import_state $expected $plist $maxtime \
					  $error_on_failure; then
		if [ $error_on_failure -ne 0 ]; then
		    error "import is not in ${expected} state"
		fi
		return 1
	fi

	return 0
}

wait_mgc_import_state() {
	local facet=$1
	local expected=$2
	local error_on_failure=${3:-1}
	local num

	if [[ $facet = mds ]]; then
		for num in $(seq $MDSCOUNT); do
			_wait_mgc_import_state mds$num "$expected" \
					       $error_on_failure || return
		done
	else
		_wait_mgc_import_state "$facet" "$expected" \
				       $error_on_failure || return
	fi
}

wait_dne_interconnect() {
	local num

	if [ $MDSCOUNT -gt 1 ]; then
		for num in $(seq $MDSCOUNT); do
			wait_osc_import_ready mds mds$num
		done
	fi
}

get_clientmdc_proc_path() {
    echo "${1}-mdc-*"
}

get_clientmgc_proc_path() {
    echo "*"
}

do_rpc_nodes () {
	local quiet

	[[ "$1" == "--quiet" || "$1" == "-q" ]] && quiet="$1" && shift

	local list=$1
	shift

	[ -z "$list" ] && return 0

	# Add paths to lustre tests for 32 and 64 bit systems.
	local LIBPATH="/usr/lib/lustre/tests:/usr/lib64/lustre/tests:"
	local TESTPATH="$RLUSTRE/tests:"
	local RPATH="PATH=${TESTPATH}${LIBPATH}${PATH}:/sbin:/bin:/usr/sbin:"
	do_nodes ${quiet:-"--verbose"} $list "${RPATH} NAME=${NAME} \
		TESTLOG_PREFIX=$TESTLOG_PREFIX TESTNAME=$TESTNAME \
		CONFIG=${CONFIG} bash rpc.sh $* "
}

wait_clients_import_state () {
	local list="$1"
	local facet="$2"
	local expected="$3"
	local facets="$facet"

	if [ "$FAILURE_MODE" = HARD ]; then
		facets=$(for f in ${facet//,/ }; do
			facets_on_host $(facet_active_host $f) | tr "," "\n"
		done | sort -u | paste -sd , )
	fi

	for facet in ${facets//,/ }; do
		local label=$(convert_facet2label $facet)
		local proc_path
		case $facet in
		ost* ) proc_path="osc.$(get_clientosc_proc_path \
					$label).ost_server_uuid" ;;
		mds* ) proc_path="mdc.$(get_clientmdc_proc_path \
					$label).mds_server_uuid" ;;
		mgs* ) proc_path="mgc.$(get_clientmgc_proc_path \
					$label).mgs_server_uuid" ;;
		*) error "unknown facet!" ;;
		esac

		local params=$(expand_list $params $proc_path)
	done

	if ! do_rpc_nodes "$list" wait_import_state_mount "$expected" $params;
	then
		error "import is not in ${expected} state"
		return 1
	fi
}

wait_clients_import_ready() {
	wait_clients_import_state "$1" "$2" "\(FULL\|IDLE\)"
}

import_param() {
	local tgt=$1
	local param=$2

	$LCTL get_param osc.$tgt.import | awk "/$param/ { print \$2 }"
}

wait_osp_active() {
	local facet=$1
	local tgt_name=$2
	local tgt_idx=$3
	local expected=$4
	local num
	local max=30
	local wait=0

	# wait until all MDTs are in the expected state
	for ((num = 1; num <= $MDSCOUNT; num++)); do
		local mdtosp=$(get_mdtosc_proc_path mds${num} ${tgt_name})
		local mproc

		if [ $facet = "mds" ]; then
			mproc="osp.$mdtosp.active"
			[ $num -eq $((tgt_idx + 1)) ] && continue
		else
			mproc="osc.$mdtosp.active"
		fi

		while true; do
			local val rc=0

			val=$(do_facet mds${num} "$LCTL get_param -n $mproc")
			rc=$?
			if (( rc != 0 )); then
				echo "Can't read $mproc (rc = $rc)"
			elif [[ "$val" == "$expected" ]]; then
				echo "$mproc updated after $wait sec (got $val)"
				break
			fi

			(( wait < max )) ||
				error "$tgt_name: wanted $expected got $val"

			echo "Waiting $((max - wait)) secs for $mproc"
			sleep 5
			(( wait += 5 ))
		done
	done
}

oos_full() {
	local -a AVAILA
	local -a GRANTA
	local -a TOTALA
	local OSCFULL=1
	AVAILA=($(do_nodes $(comma_list $(osts_nodes)) \
	          $LCTL get_param obdfilter.*.kbytesavail))
	GRANTA=($(do_nodes $(comma_list $(osts_nodes)) \
	          $LCTL get_param -n obdfilter.*.tot_granted))
	TOTALA=($(do_nodes $(comma_list $(osts_nodes)) \
	          $LCTL get_param -n obdfilter.*.kbytestotal))
	for ((i=0; i<${#AVAILA[@]}; i++)); do
		local -a AVAIL1=(${AVAILA[$i]//=/ })
		local -a TOTAL=(${TOTALA[$i]//=/ })
		GRANT=$((${GRANTA[$i]}/1024))
		# allow 1% of total space in bavail because of delayed
		# allocation with ZFS which might release some free space after
		# txg commit.  For small devices, we set a mininum of 8MB
		local LIMIT=$((${TOTAL} / 100 + 8000))
		echo -n $(echo ${AVAIL1[0]} | cut -d"." -f2) avl=${AVAIL1[1]} \
			grnt=$GRANT diff=$((AVAIL1[1] - GRANT)) limit=${LIMIT}
		[ $((AVAIL1[1] - GRANT)) -lt $LIMIT ] && OSCFULL=0 && \
			echo " FULL" || echo
	done
	return $OSCFULL
}

list_pool() {
	echo -e "$(do_facet $SINGLEMDS $LCTL pool_list $1 | sed '1d')"
}

check_pool_not_exist() {
	local fsname=${1%%.*}
	local poolname=${1##$fsname.}
	[[ $# -ne 1 ]] && return 0
	[[ x$poolname = x ]] &&  return 0
	list_pool $fsname | grep -w $1 && return 1
	return 0
}

create_pool() {
	local fsname=${1%%.*}
	local poolname=${1##$fsname.}
	local keep_pools=${2:-false}

	stack_trap "destroy_test_pools $fsname" EXIT
	do_facet mgs lctl pool_new $1
	local RC=$?
	# get param should return err unless pool is created
	[[ $RC -ne 0 ]] && return $RC

	for mds_id in $(seq $MDSCOUNT); do
		local mdt_id=$((mds_id-1))
		local lodname=$fsname-MDT$(printf "%04x" $mdt_id)-mdtlov
		wait_update_facet mds$mds_id \
			"lctl get_param -n lod.$lodname.pools.$poolname \
				2>/dev/null || echo foo" "" ||
			error "mds$mds_id: pool_new failed $1"
	done
	wait_update $HOSTNAME "lctl get_param -n lov.$fsname-*.pools.$poolname \
		2>/dev/null || echo foo" "" || error "pool_new failed $1"

	$keep_pools || add_pool_to_list $1
	return $RC
}

add_pool_to_list () {
	local fsname=${1%%.*}
	local poolname=${1##$fsname.}

	local listvar=${fsname}_CREATED_POOLS
	local temp=${listvar}=$(expand_list ${!listvar} $poolname)
	eval export $temp
}

remove_pool_from_list () {
	local fsname=${1%%.*}
	local poolname=${1##$fsname.}

	local listvar=${fsname}_CREATED_POOLS
	local temp=${listvar}=$(exclude_items_from_list "${!listvar}" $poolname)
	eval export $temp
}

# cleanup all pools exist on $FSNAME
destroy_all_pools () {
	local i
	for i in $(list_pool $FSNAME); do
		destroy_pool $i
	done
}

destroy_pool_int() {
	local ost
	local OSTS=$(list_pool $1)
	for ost in $OSTS; do
		do_facet mgs lctl pool_remove $1 $ost
	done
	wait_update_facet $SINGLEMDS "lctl pool_list $1 | wc -l" "1" ||
		error "MDS: pool_list $1 failed"
	do_facet mgs lctl pool_destroy $1
}

# <fsname>.<poolname> or <poolname>
destroy_pool() {
	local fsname=${1%%.*}
	local poolname=${1##$fsname.}

	[[ x$fsname = x$poolname ]] && fsname=$FSNAME

	local RC

	check_pool_not_exist $fsname.$poolname && return 0 || true

	destroy_pool_int $fsname.$poolname
	RC=$?
	[[ $RC -ne 0 ]] && return $RC
	for mds_id in $(seq $MDSCOUNT); do
		local mdt_id=$((mds_id-1))
		local lodname=$fsname-MDT$(printf "%04x" $mdt_id)-mdtlov
		wait_update_facet mds$mds_id \
			"lctl get_param -n lod.$lodname.pools.$poolname \
				2>/dev/null || echo foo" "foo" ||
			error "mds$mds_id: destroy pool failed $1"
	done
	wait_update $HOSTNAME "lctl get_param -n lov.$fsname-*.pools.$poolname \
		2>/dev/null || echo foo" "foo" || error "destroy pool failed $1"

	remove_pool_from_list $fsname.$poolname

	return $RC
}

destroy_pools () {
	local fsname=${1:-$FSNAME}
	local poolname
	local listvar=${fsname}_CREATED_POOLS

	[ x${!listvar} = x ] && return 0

	echo "Destroy the created pools: ${!listvar}"
	for poolname in ${!listvar//,/ }; do
		destroy_pool $fsname.$poolname
	done
}

destroy_test_pools () {
	local fsname=${1:-$FSNAME}
	destroy_pools $fsname || true
}

gather_logs () {
	local list=$1

	local ts=$(date +%s)
	local docp=true

	if [[ ! -f "$YAML_LOG" ]]; then
		# init_logging is not performed before gather_logs,
		# so the $LOGDIR needs to be checked here
		check_shared_dir $LOGDIR && touch $LOGDIR/shared
	fi

	[ -f $LOGDIR/shared ] && docp=false

	# dump lustre logs, dmesg, and journal if GSS_SK=true

	prefix="$TESTLOG_PREFIX.$TESTNAME"
	suffix="$ts.log"
	echo "Dumping lctl log to ${prefix}.*.${suffix}"

	if [ -n "$CLIENTONLY" -o "$PDSH" == "no_dsh" ]; then
		echo "Dumping logs only on local client."
		$LCTL dk > ${prefix}.debug_log.$(hostname -s).${suffix}
		dmesg > ${prefix}.dmesg.$(hostname -s).${suffix}
		[ "$SHARED_KEY" = true ] && find $SK_PATH -name '*.key' -exec \
			$LGSS_SK -r {} \; &> \
			${prefix}.ssk_keys.$(hostname -s).${suffix}
		[ "$SHARED_KEY" = true ] && lctl get_param 'nodemap.*.*' > \
			${prefix}.nodemaps.$(hostname -s).${suffix}
		[ "$GSS" = true ] && keyctl show > \
			${prefix}.keyring.$(hostname -s).${suffix}
		[ "$GSS" = true ] && journalctl -a > \
			${prefix}.journal.$(hostname -s).${suffix}
		return
	fi

	do_nodesv $list \
		"$LCTL dk > ${prefix}.debug_log.\\\$(hostname -s).${suffix};
		dmesg > ${prefix}.dmesg.\\\$(hostname -s).${suffix}"
	if [ "$SHARED_KEY" = true ]; then
		do_nodesv $list "find $SK_PATH -name '*.key' -exec \
			$LGSS_SK -r {} \; &> \
			${prefix}.ssk_keys.\\\$(hostname -s).${suffix}"
		do_facet mds1 "lctl get_param 'nodemap.*.*' > \
			${prefix}.nodemaps.\\\$(hostname -s).${suffix}"
	fi
	if [ "$GSS" = true ]; then
		do_nodesv $list "keyctl show > \
			${prefix}.keyring.\\\$(hostname -s).${suffix}"
		do_nodesv $list "journalctl -a > \
			${prefix}.journal.\\\$(hostname -s).${suffix}"
	fi

	if [ ! -f $LOGDIR/shared ]; then
		local remote_nodes=$(exclude_items_from_list $list $HOSTNAME)

		for node in ${remote_nodes//,/ }; do
			rsync -az -e ssh $node:${prefix}.'*'.${suffix} $LOGDIR &
		done
	fi
}

do_ls () {
	local mntpt_root=$1
	local num_mntpts=$2
	local dir=$3
	local i
	local cmd
	local pids
	local rc=0

	for i in $(seq 0 $num_mntpts); do
		cmd="ls -laf ${mntpt_root}$i/$dir"
		echo + $cmd;
		$cmd > /dev/null &
		pids="$pids $!"
	done
	echo pids=$pids
	for pid in $pids; do
		wait $pid || rc=$?
	done

	return $rc
}

# check_and_start_recovery_timer()
#	service_time = at_est2timeout(service_time);
#	service_time += 2 * INITIAL_CONNECT_TIMEOUT;
#	service_time += 2 * (CONNECTION_SWITCH_MAX + CONNECTION_SWITCH_INC);

#define INITIAL_CONNECT_TIMEOUT max(CONNECTION_SWITCH_MIN, obd_timeout/20)
#define CONNECTION_SWITCH_MAX min(50, max(CONNECTION_SWITCH_MIN, obd_timeout))
#define CONNECTION_SWITCH_MIN 5
#define CONNECTION_SWITCH_INC 5
max_recovery_time() {
	local init_connect_timeout=$((TIMEOUT / 20))
	((init_connect_timeout >= 5)) || init_connect_timeout=5

	local service_time=$(($(at_max_get client) * 9 / 4 + 5))
	service_time=$((service_time + 2 * (init_connect_timeout + 50 + 5)))

	echo -n $service_time
}

recovery_time_min() {
	local connection_switch_min=5
	local connection_switch_inc=5
	local connection_switch_max
	local reconnect_delay_max
	local initial_connect_timeout
	local max
	local timout_20

	#connection_switch_max=min(50, max($connection_switch_min,$TIMEOUT)
	(($connection_switch_min > $TIMEOUT)) &&
		max=$connection_switch_min || max=$TIMEOUT
	(($max < 50)) && connection_switch_max=$max || connection_switch_max=50

	#initial_connect_timeout = max(connection_switch_min, obd_timeout/20)
	timeout_20=$((TIMEOUT/20))
	(($connection_switch_min > $timeout_20)) &&
		initial_connect_timeout=$connection_switch_min ||
		initial_connect_timeout=$timeout_20

	reconnect_delay_max=$((connection_switch_max + connection_switch_inc +
			       initial_connect_timeout))
	echo $((2 * reconnect_delay_max))
}

get_clients_mount_count () {
	local clients=${CLIENTS:-$HOSTNAME}

	# we need to take into account the clients mounts and
	# exclude mds/ost mounts if any;
	do_nodes $clients cat /proc/mounts | grep lustre |
		grep -w $MOUNT | wc -l
}

# gss functions
PROC_CLI="srpc_info"
PROC_CON="srpc_contexts"

combination()
{
	local M=$1
	local N=$2
	local R=1

	if [ $M -lt $N ]; then
		R=0
	else
		N=$((N + 1))
		while [ $N -lt $M ]; do
			R=$((R * N))
			N=$((N + 1))
		done
	fi

	echo $R
	return 0
}

calc_connection_cnt() {
	local dir=$1

	# MDT->MDT = 2 * C(M, 2)
	# MDT->OST = M * O
	# CLI->OST = C * O
	# CLI->MDT = C * M
	comb_m2=$(combination $MDSCOUNT 2)

	local num_clients=$(get_clients_mount_count)

	local cnt_mdt2mdt=$((comb_m2 * 2))
	local cnt_mdt2ost=$((MDSCOUNT * OSTCOUNT))
	local cnt_cli2ost=$((num_clients * OSTCOUNT))
	local cnt_cli2mdt=$((num_clients * MDSCOUNT))
	if is_mounted $MOUNT2; then
		cnt_cli2mdt=$((cnt_cli2mdt * 2))
		cnt_cli2ost=$((cnt_cli2ost * 2))
	fi
	if local_mode; then
		cnt_mdt2mdt=0
		cnt_mdt2ost=0
		cnt_cli2ost=2
		cnt_cli2mdt=1
	fi
	local cnt_all2ost=$((cnt_mdt2ost + cnt_cli2ost))
	local cnt_all2mdt=$((cnt_mdt2mdt + cnt_cli2mdt))
	local cnt_all2all=$((cnt_mdt2ost + cnt_mdt2mdt \
		+ cnt_cli2ost + cnt_cli2mdt))

	local var=cnt_$dir
	local res=${!var}

	echo $res
}

set_rule()
{
	local tgt=$1
	local net=$2
	local dir=$3
	local flavor=$4
	local cmd="$tgt.srpc.flavor"

	if [ $net == "any" ]; then
		net="default"
	fi
	cmd="$cmd.$net"

	if [ $dir != "any" ]; then
		cmd="$cmd.$dir"
	fi

	cmd="$cmd=$flavor"
	log "Setting sptlrpc rule: $cmd"
	do_facet mgs "$LCTL conf_param $cmd"
}

count_contexts()
{
	local output=$1
	local total_ctx=$(echo "$output" | grep -c "expire.*key.*hdl")
	echo $total_ctx
}

count_flvr()
{
	local output=$1
	local flavor=$2
	local count=0

	rpc_flvr=`echo $flavor | awk -F - '{ print $1 }'`
	bulkspec=`echo $flavor | awk -F - '{ print $2 }'`

	count=`echo "$output" | grep "rpc flavor" | grep $rpc_flvr | wc -l`

	if [ "x$bulkspec" != "x" ]; then
		algs=`echo $bulkspec | awk -F : '{ print $2 }'`

		if [ "x$algs" != "x" ]; then
			bulk_count=`echo "$output" | grep "bulk flavor" |
				grep $algs | wc -l`
		else
			bulk=`echo $bulkspec | awk -F : '{ print $1 }'`

			if [ $bulk == "bulkn" ]; then
				bulk_count=`echo "$output" |
					grep "bulk flavor" | grep "null/null" |
					wc -l`
			elif [ $bulk == "bulki" ]; then
				bulk_count=`echo "$output" |
					grep "bulk flavor" | grep "/null" |
					grep -v "null/" | wc -l`
			else
				bulk_count=`echo "$output" |
					grep "bulk flavor" | grep -v "/null" |
					grep -v "null/" | wc -l`
			fi
		fi
		[ $bulk_count -lt $count ] && count=$bulk_count
	fi

	echo $count
}

flvr_cnt_cli2mdt()
{
	local flavor=$1
	local cnt

	local clients=${CLIENTS:-$HOSTNAME}

	for c in ${clients//,/ }; do
		local output=$(do_node $c lctl get_param -n \
			 mdc.*-*-mdc-*.$PROC_CLI 2>/dev/null)
		local tmpcnt=$(count_flvr "$output" $flavor)

		if $GSS_SK && [ $flavor != "null" ]; then
			# tmpcnt=min(contexts,flavors) to ensure SK context is
			# on
			output=$(do_node $c lctl get_param -n \
				 mdc.*-MDT*-mdc-*.$PROC_CON 2>/dev/null)
			local outcon=$(count_contexts "$output")

			if [ "$outcon" -lt "$tmpcnt" ]; then
				tmpcnt=$outcon
			fi
		fi
		cnt=$((cnt + tmpcnt))
	done
	echo $cnt
}

flvr_dump_cli2mdt()
{
	local clients=${CLIENTS:-$HOSTNAME}

	for c in ${clients//,/ }; do
		do_node $c lctl get_param \
			 mdc.*-*-mdc-*.$PROC_CLI 2>/dev/null

		if $GSS_SK; then
			do_node $c lctl get_param \
				 mdc.*-MDT*-mdc-*.$PROC_CON 2>/dev/null
		fi
	done
}

flvr_cnt_cli2ost()
{
	local flavor=$1
	local cnt

	local clients=${CLIENTS:-$HOSTNAME}

	for c in ${clients//,/ }; do
		# reconnect if idle
		do_node $c lctl set_param osc.*.idle_connect=1 >/dev/null 2>&1
		local output=$(do_node $c lctl get_param -n \
			 osc.*OST*-osc-[^M][^D][^T]*.$PROC_CLI 2>/dev/null)
		local tmpcnt=$(count_flvr "$output" $flavor)

		if $GSS_SK && [ $flavor != "null" ]; then
			# tmpcnt=min(contexts,flavors) to ensure SK context is on
			output=$(do_node $c lctl get_param -n \
				 osc.*OST*-osc-[^M][^D][^T]*.$PROC_CON 2>/dev/null)
			local outcon=$(count_contexts "$output")

			if [ "$outcon" -lt "$tmpcnt" ]; then
				tmpcnt=$outcon
			fi
		fi
		cnt=$((cnt + tmpcnt))
	done
	echo $cnt
}

flvr_dump_cli2ost()
{
	local clients=${CLIENTS:-$HOSTNAME}

	for c in ${clients//,/ }; do
		do_node $c lctl get_param \
			osc.*OST*-osc-[^M][^D][^T]*.$PROC_CLI 2>/dev/null

		if $GSS_SK; then
			do_node $c lctl get_param \
			       osc.*OST*-osc-[^M][^D][^T]*.$PROC_CON 2>/dev/null
		fi
	done
}

flvr_cnt_mdt2mdt()
{
	local flavor=$1
	local cnt=0

	if [ $MDSCOUNT -le 1 ]; then
		echo 0
		return
	fi

	for num in `seq $MDSCOUNT`; do
		local output=$(do_facet mds$num lctl get_param -n \
			osp.*-MDT*osp-MDT*.$PROC_CLI 2>/dev/null)
		local tmpcnt=$(count_flvr "$output" $flavor)

		if $GSS_SK && [ $flavor != "null" ]; then
			# tmpcnt=min(contexts,flavors) to ensure SK context is on
			output=$(do_facet mds$num lctl get_param -n \
				osp.*-MDT*osp-MDT*.$PROC_CON 2>/dev/null)
			local outcon=$(count_contexts "$output")

			if [ "$outcon" -lt "$tmpcnt" ]; then
				tmpcnt=$outcon
			fi
		fi
		cnt=$((cnt + tmpcnt))
	done
	echo $cnt;
}

flvr_dump_mdt2mdt()
{
	for num in `seq $MDSCOUNT`; do
		do_facet mds$num lctl get_param \
			osp.*-MDT*osp-MDT*.$PROC_CLI 2>/dev/null

		if $GSS_SK; then
			do_facet mds$num lctl get_param \
				osp.*-MDT*osp-MDT*.$PROC_CON 2>/dev/null
		fi
	done
}

flvr_cnt_mdt2ost()
{
	local flavor=$1
	local cnt=0
	local mdtosc

	for num in `seq $MDSCOUNT`; do
		mdtosc=$(get_mdtosc_proc_path mds$num)
		mdtosc=${mdtosc/-MDT*/-MDT\*}
		local output=$(do_facet mds$num lctl get_param -n \
				os[cp].$mdtosc.$PROC_CLI 2>/dev/null)
		# Ensure SK context is on
		local tmpcnt=$(count_flvr "$output" $flavor)

		if $GSS_SK && [ $flavor != "null" ]; then
			output=$(do_facet mds$num lctl get_param -n \
				 os[cp].$mdtosc.$PROC_CON 2>/dev/null)
			local outcon=$(count_contexts "$output")

			if [ "$outcon" -lt "$tmpcnt" ]; then
				tmpcnt=$outcon
			fi
		fi
		cnt=$((cnt + tmpcnt))
	done
	echo $cnt;
}

flvr_dump_mdt2ost()
{
	for num in `seq $MDSCOUNT`; do
		mdtosc=$(get_mdtosc_proc_path mds$num)
		mdtosc=${mdtosc/-MDT*/-MDT\*}
		do_facet mds$num lctl get_param \
				os[cp].$mdtosc.$PROC_CLI 2>/dev/null

		if $GSS_SK; then
			do_facet mds$num lctl get_param \
				os[cp].$mdtosc.$PROC_CON 2>/dev/null
		fi
	done
}

flvr_cnt_mgc2mgs()
{
	local flavor=$1

	local output=$(do_facet client lctl get_param -n mgc.*.$PROC_CLI \
			2>/dev/null)
	count_flvr "$output" $flavor
}

do_check_flavor()
{
	local dir=$1        # from to
	local flavor=$2     # flavor expected
	local res=0

	if [ $dir == "cli2mdt" ]; then
		res=`flvr_cnt_cli2mdt $flavor`
	elif [ $dir == "cli2ost" ]; then
		res=`flvr_cnt_cli2ost $flavor`
	elif [ $dir == "mdt2mdt" ]; then
		res=`flvr_cnt_mdt2mdt $flavor`
	elif [ $dir == "mdt2ost" ]; then
		res=`flvr_cnt_mdt2ost $flavor`
	elif [ $dir == "all2ost" ]; then
		res1=`flvr_cnt_mdt2ost $flavor`
		res2=`flvr_cnt_cli2ost $flavor`
		res=$((res1 + res2))
	elif [ $dir == "all2mdt" ]; then
		res1=`flvr_cnt_mdt2mdt $flavor`
		res2=`flvr_cnt_cli2mdt $flavor`
		res=$((res1 + res2))
	elif [ $dir == "all2all" ]; then
		res1=`flvr_cnt_mdt2ost $flavor`
		res2=`flvr_cnt_cli2ost $flavor`
		res3=`flvr_cnt_mdt2mdt $flavor`
		res4=`flvr_cnt_cli2mdt $flavor`
		res=$((res1 + res2 + res3 + res4))
	fi

	echo $res
}

do_dump_imp_state()
{
	local clients=${CLIENTS:-$HOSTNAME}
	local type=$1

	for c in ${clients//,/ }; do
		[ "$type" == "osc" ] &&
			do_node $c lctl get_param osc.*.idle_timeout
		do_node $c lctl get_param $type.*.import |
			grep -E "name:|state:"
	done
}

do_dump_flavor()
{
	local dir=$1        # from to

	if [ $dir == "cli2mdt" ]; then
		do_dump_imp_state mdc
		flvr_dump_cli2mdt
	elif [ $dir == "cli2ost" ]; then
		do_dump_imp_state osc
		flvr_dump_cli2ost
	elif [ $dir == "mdt2mdt" ]; then
		flvr_dump_mdt2mdt
	elif [ $dir == "mdt2ost" ]; then
		flvr_dump_mdt2ost
	elif [ $dir == "all2ost" ]; then
		flvr_dump_mdt2ost
		do_dump_imp_state osc
		flvr_dump_cli2ost
	elif [ $dir == "all2mdt" ]; then
		flvr_dump_mdt2mdt
		do_dump_imp_state mdc
		flvr_dump_cli2mdt
	elif [ $dir == "all2all" ]; then
		flvr_dump_mdt2ost
		do_dump_imp_state osc
		flvr_dump_cli2ost
		flvr_dump_mdt2mdt
		do_dump_imp_state mdc
		flvr_dump_cli2mdt
	fi
}

wait_flavor()
{
	local dir=$1        # from to
	local flavor=$2     # flavor expected
	local expect=${3:-$(calc_connection_cnt $dir)} # number expected
	local WAITFLAVOR_MAX=20 # how many retries before abort?

	local res=0
	for ((i = 0; i < $WAITFLAVOR_MAX; i++)); do
		echo -n "checking $dir..."
		res=$(do_check_flavor $dir $flavor)
		echo "found $res/$expect $flavor connections"
		[ $res -ge $expect ] && return 0
		sleep 4
	done

	echo "Error checking $flavor of $dir: expect $expect, actual $res"
	do_nodes $(comma_list $(all_server_nodes)) "keyctl show"
	do_dump_flavor $dir
	if $dump; then
		gather_logs $(comma_list $(nodes_list))
	fi
	return 1
}

restore_to_default_flavor()
{
	local proc="mgs.MGS.live.$FSNAME"

	echo "restoring to default flavor..."

	local nrule=$(do_facet mgs lctl get_param -n $proc 2>/dev/null |
		grep ".srpc.flavor" | wc -l)

	# remove all existing rules if any
	if [ $nrule -ne 0 ]; then
		echo "$nrule existing rules"
		for rule in $(do_facet mgs lctl get_param -n $proc 2>/dev/null |
		    grep ".srpc.flavor."); do
			echo "remove rule: $rule"
			spec=`echo $rule | awk -F = '{print $1}'`
			do_facet mgs "$LCTL conf_param -d $spec"
		done
	fi

	# verify no rules left
	nrule=$(do_facet mgs lctl get_param -n $proc 2>/dev/null |
		grep ".srpc.flavor." | wc -l)
	[ $nrule -ne 0 ] && error "still $nrule rules left"

	# wait for default flavor to be applied
	if $GSS_SK; then
		if $SK_S2S; then
			set_rule $FSNAME any any $SK_FLAVOR
			wait_flavor all2all $SK_FLAVOR
		else
			set_rule $FSNAME any cli2mdt $SK_FLAVOR
			set_rule $FSNAME any cli2ost $SK_FLAVOR
			wait_flavor cli2mdt $SK_FLAVOR
			wait_flavor cli2ost $SK_FLAVOR
		fi
		echo "GSS_SK now at default flavor: $SK_FLAVOR"
	else
		wait_flavor all2all null
	fi
}

set_flavor_all()
{
	local flavor=${1:-null}
	local maxtime=$(( 2 * $(request_timeout client)))
	local clients=${CLIENTS:-$HOSTNAME}

	echo "setting all flavor to $flavor"

	# make sure all oscs are connected
	for c in ${clients//,/ }; do
		do_node $c lfs df -h
		do_rpc_nodes $c wait_import_state "FULL" \
			"osc.*.ost_server_uuid" $maxtime ||
		error "OSCs not in FULL state for client $c"
	done

	# FIXME need parameter to this fn
	# and remove global vars
	local cnt_all2all=$(calc_connection_cnt all2all)

	local res=$(do_check_flavor all2all $flavor)
	if [ $res -eq $cnt_all2all ]; then
		echo "already have total $res $flavor connections"
		return
	fi

	echo "found $res $flavor out of total $cnt_all2all connections"
	restore_to_default_flavor

	[[ $flavor = null ]] && return 0

	if $GSS_SK && [ $flavor != "null" ]; then
		if $SK_S2S; then
			set_rule $FSNAME any any $flavor
			wait_flavor all2all $flavor
		else
			set_rule $FSNAME any cli2mdt $flavor
			set_rule $FSNAME any cli2ost $flavor
			set_rule $FSNAME any mdt2ost null
			set_rule $FSNAME any mdt2mdt null
			wait_flavor cli2mdt $flavor
			wait_flavor cli2ost $flavor
		fi
		echo "GSS_SK now at flavor: $flavor"
	else
		set_rule $FSNAME any cli2mdt $flavor
		set_rule $FSNAME any cli2ost $flavor
		set_rule $FSNAME any mdt2ost null
		set_rule $FSNAME any mdt2mdt null
		wait_flavor cli2mdt $flavor
		wait_flavor cli2ost $flavor
	fi
}


check_logdir() {
	local dir=$1
	# Checking for shared logdir
	if [ ! -d $dir ]; then
		# Not found. Create local logdir
		mkdir -p $dir
	else
		touch $dir/check_file.$(hostname -s)
	fi
	return 0
}

check_write_access() {
	local dir=$1
	local list=${2:-$(comma_list $(nodes_list))}
	local node
	local file

	for node in ${list//,/ }; do
		file=$dir/check_file.$(short_nodename $node)
		if [[ ! -f "$file" ]]; then
			# Logdir not accessible/writable from this node.
			return 1
		fi
		rm -f $file || return 1
	done
	return 0
}

init_logging() {
	[[ -n $YAML_LOG ]] && return
	local save_umask=$(umask)
	umask 0000

	export YAML_LOG=${LOGDIR}/results.yml
	mkdir -p $LOGDIR
	init_clients_lists

	# If the yaml log already exists then we will just append to it
	if [ ! -f $YAML_LOG ]; then
		if check_shared_dir $LOGDIR; then
			touch $LOGDIR/shared
			echo "Logging to shared log directory: $LOGDIR"
		else
			echo "Logging to local directory: $LOGDIR"
		fi

		yml_nodes_file $LOGDIR >> $YAML_LOG
		yml_results_file >> $YAML_LOG
	fi

	umask $save_umask

	# log actual client and server versions if needed for debugging
	log "Client: $(lustre_build_version client)"
	log "MDS: $(lustre_build_version mds1)"
	log "OSS: $(lustre_build_version ost1)"
}

log_test() {
	yml_log_test $1 >> $YAML_LOG
}

log_test_status() {
	yml_log_test_status "$@" >> $YAML_LOG
}

log_sub_test_begin() {
	yml_log_sub_test_begin "$@" >> $YAML_LOG
}

log_sub_test_end() {
	yml_log_sub_test_end "$@" >> $YAML_LOG
}

run_llverdev()
{
	local dev=$1; shift
	local llverdev_opts="$*"
	local devname=$(basename $dev)
	local size=$(awk "/$devname$/ {print \$3}" /proc/partitions)
	# loop devices aren't in /proc/partitions
	[[ -z "$size" ]] && size=$(stat -c %s $dev)

	local size_gb=$((size / 1024 / 1024)) # Gb

	local partial_arg=""
	# Run in partial (fast) mode if the size of a partition > 1 GB
	(( $size == 0 || $size_gb > 1 )) && partial_arg="-p"

	llverdev --force $partial_arg $llverdev_opts $dev
}

run_llverfs()
{
	local dir=$1
	local llverfs_opts=$2
	local use_partial_arg=$3
	local partial_arg=""
	local size=$(df -B G $dir |tail -n 1 |awk '{print $2}' |sed 's/G//') #GB

	# Run in partial (fast) mode if the size of a partition > 1 GB
	[ "x$use_partial_arg" != "xno" ] && [ $size -gt 1 ] && partial_arg="-p"

	llverfs $partial_arg $llverfs_opts $dir
}

run_sgpdd () {
	local devs=${1//,/ }
	shift
	local params=$@
	local rslt=$TMP/sgpdd_survey

	# sgpdd-survey cleanups ${rslt}.* files

	local cmd="rslt=$rslt $params scsidevs=\"$devs\" $SGPDDSURVEY"
	echo + $cmd
	eval $cmd
	cat ${rslt}.detail
}

# returns the canonical name for an ldiskfs device
ldiskfs_canon() {
	local dev="$1"
	local facet="$2"

	do_facet $facet "dv=\\\$($LCTL get_param -n $dev);
			 if foo=\\\$(lvdisplay -c \\\$dv 2>/dev/null); then
				echo dm-\\\${foo##*:};
			 else
				name=\\\$(basename \\\$dv);
				if [[ \\\$name = *flakey* ]]; then
					name=\\\$(lsblk -o NAME,KNAME |
						awk /\\\$name/'{print \\\$NF}');
				fi;
				echo \\\$name;
			 fi;"
}

is_sanity_benchmark() {
	local benchmarks="dbench bonnie iozone fsx"
	local suite=$1

	for b in $benchmarks; do
		if [ "$b" == "$suite" ]; then
			return 0
		fi
	done
	return 1
}

min_ost_size () {
	$LFS df | grep OST | awk '{print $4}' | sort -un | head -1
}

#
# Get the available size (KB) of a given obd target.
#
get_obd_size() {
	local facet=$1
	local obd=$2
	local size

	[[ $facet != client ]] || return 0

	size=$(do_facet $facet $LCTL get_param -n *.$obd.kbytesavail | head -n1)
	echo -n $size
}

#
# Get the page size (bytes) on a given facet node.
# The local client page_size is directly available in PAGE_SIZE.
#
get_page_size() {
	local facet=$1
	local page_size=$(getconf PAGE_SIZE 2>/dev/null)

	[ -z "$CLIENTONLY" -a "$facet" != "client" ] &&
		page_size=$(do_facet $facet getconf PAGE_SIZE)
	echo -n ${page_size:-4096}
}

#
# Get the block count of the filesystem.
#
get_block_count() {
	local facet=$1
	local device=$2
	local count

	[ -z "$CLIENTONLY" ] &&
		count=$(do_facet $facet "$DUMPE2FS -h $device 2>&1" |
			awk '/^Block count:/ {print $3}')
	echo -n ${count:-0}
}

# Check whether the "ea_inode" feature is enabled or not, to allow
# ldiskfs xattrs over one block in size.  Allow both the historical
# Lustre feature name (large_xattr) and the upstream name (ea_inode).
large_xattr_enabled() {
	[[ $(facet_fstype $SINGLEMDS) == zfs ]] && return 0

	local mds_dev=$(mdsdevname ${SINGLEMDS//mds/})

	do_facet $SINGLEMDS "$DUMPE2FS -h $mds_dev 2>&1 |
		grep -E -q '(ea_inode|large_xattr)'"
	return ${PIPESTATUS[0]}
}

# Get the maximum xattr size supported by the filesystem.
max_xattr_size() {
	$LCTL get_param -n llite.*.max_easize
}

# Dump the value of the named xattr from a file.
get_xattr_value() {
	local xattr_name=$1
	local file=$2

	echo "$(getfattr -n $xattr_name --absolute-names --only-values $file)"
}

# Generate a string with size of $size bytes.
generate_string() {
	local size=${1:-1024} # in bytes

	echo "$(head -c $size < /dev/zero | tr '\0' y)"
}

reformat_external_journal() {
	local facet=$1
	local var

	var=${facet}_JRN
	local varbs=${facet}_BLOCKSIZE
	if [ -n "${!var}" ]; then
		local rcmd="do_facet $facet"
		local bs=${!varbs:-$BLCKSIZE}

		bs="-b $bs"
		echo "reformat external journal on $facet:${!var}"
		${rcmd} mke2fs -O journal_dev $bs ${!var} || return 1
	fi
}

# MDT file-level backup/restore
mds_backup_restore() {
	local facet=$1
	local igif=$2
	local devname=$(mdsdevname $(facet_number $facet))
	local mntpt=$(facet_mntpt brpt)
	local rcmd="do_facet $facet"
	local metadata=${TMP}/backup_restore.tgz
	local opts=${MDS_MOUNT_FS_OPTS}
	local svc=${facet}_svc

	if ! ${rcmd} test -b ${devname}; then
		opts=$(csa_add "$opts" -o loop)
	fi

	echo "file-level backup/restore on $facet:${devname}"

	# step 1: build mount point
	${rcmd} mkdir -p $mntpt
	# step 2: cleanup old backup
	${rcmd} rm -f $metadata
	# step 3: mount dev
	${rcmd} mount -t ldiskfs $opts $devname $mntpt || return 3
	if [ ! -z $igif ]; then
		# step 3.5: rm .lustre
		${rcmd} rm -rf $mntpt/ROOT/.lustre || return 3
	fi
	# step 4: backup metadata
	echo "backup data"
	${rcmd} tar zcf $metadata --xattrs --xattrs-include="trusted.*" \
		--sparse -C $mntpt/ . > /dev/null 2>&1 || return 4
	# step 5: umount
	${rcmd} $UMOUNT $mntpt || return 5
	# step 6: reformat dev
	echo "reformat new device"
	format_mdt $(facet_number $facet)
	# step 7: mount dev
	${rcmd} mount -t ldiskfs $opts $devname $mntpt || return 7
	# step 8: restore metadata
	echo "restore data"
	${rcmd} tar zxfp $metadata --xattrs --xattrs-include="trusted.*" \
		--sparse -C $mntpt > /dev/null 2>&1 || return 8
	# step 9: remove recovery logs
	echo "remove recovery logs"
	${rcmd} rm -fv $mntpt/OBJECTS/* $mntpt/CATALOGS
	# step 10: umount dev
	${rcmd} $UMOUNT $mntpt || return 10
	# step 11: cleanup tmp backup
	${rcmd} rm -f $metaea $metadata
	# step 12: reset device label - it's not virgin on
	${rcmd} e2label $devname ${!svc}
}

# remove OI files
mds_remove_ois() {
	local facet=$1
	local idx=$2
	local devname=$(mdsdevname $(facet_number $facet))
	local mntpt=$(facet_mntpt brpt)
	local rcmd="do_facet $facet"
	local opts=${MDS_MOUNT_FS_OPTS}

	if ! ${rcmd} test -b ${devname}; then
		opts=$(csa_add "$opts" -o loop)
	fi

	echo "removing OI files on $facet: idx=${idx}"

	# step 1: build mount point
	${rcmd} mkdir -p $mntpt
	# step 2: mount dev
	${rcmd} mount -t ldiskfs $opts $devname $mntpt || return 1
	if [ -z $idx ]; then
		# step 3: remove all OI files
		${rcmd} rm -fv $mntpt/oi.16*
	elif [ $idx -lt 2 ]; then
		${rcmd} rm -fv $mntpt/oi.16.${idx}
	else
		local i

		# others, rm oi.16.[idx, idx * idx, idx ** ...]
		for ((i=${idx}; i<64; i=$((i * idx)))); do
			${rcmd} rm -fv $mntpt/oi.16.${i}
		done
	fi
	# step 4: umount
	${rcmd} $UMOUNT $mntpt || return 2
	# OI files will be recreated when mounted as lustre next time.
}

# generate maloo upload-able log file name
# \param logname specify unique part of file name
generate_logname() {
	local logname=${1:-"default_logname"}

	echo "$TESTLOG_PREFIX.$TESTNAME.$logname.$(hostname -s).log"
}

# make directory on different MDTs
test_mkdir() {
	local path
	local p_option
	local hash_type
	local hash_name=("all_char" "fnv_1a_64" "crush")
	local dirstripe_count=${DIRSTRIPE_COUNT:-"2"}
	local dirstripe_index=${DIRSTRIPE_INDEX:-$((base % $MDSCOUNT))}
	local OPTIND=1
	local overstripe_count
	local stripe_command="-c"

	(( $MDS1_VERSION > $(version_code v2_15_50-185-g1ac4b9598a) )) &&
		hash_name+=("crush2")

	while getopts "c:C:H:i:p" opt; do
		case $opt in
			c) dirstripe_count=$OPTARG;;
			C) overstripe_count=$OPTARG;;
			H) hash_type=$OPTARG;;
			i) dirstripe_index=$OPTARG;;
			p) p_option="-p";;
			\?) error "only support -c -H -i -p";;
		esac
	done

	shift $((OPTIND - 1))
	[ $# -eq 1 ] || error "Only creating single directory is supported"
	path="$*"

	local parent=$(dirname $path)
	if [ "$p_option" == "-p" ]; then
		[ -d $path ] && return 0
		if [ ! -d ${parent} ]; then
			mkdir -p ${parent} ||
				error "mkdir parent '$parent' failed"
		fi
	fi

	if [[ -n "$overstripe_count" ]]; then
		stripe_command="-C"
		dirstripe_count=$overstripe_count
	fi

	if [ $MDSCOUNT -le 1 ] || ! is_lustre ${parent}; then
		mkdir $path || error "mkdir '$path' failed"
	else
		local mdt_index

		if [ $dirstripe_index -eq -1 ]; then
			mdt_index=$((base % MDSCOUNT))
		else
			mdt_index=$dirstripe_index
		fi

		# randomly choose hash type
		[ -z "$hash_type" ] &&
			hash_type=${hash_name[$((RANDOM % ${#hash_name[@]}))]}

		if (($MDS1_VERSION >= $(version_code 2.8.0))); then
			if [ $dirstripe_count -eq -1 ]; then
				dirstripe_count=$((RANDOM % MDSCOUNT + 1))
			fi
		else
			dirstripe_count=1
		fi

		echo "striped dir -i$mdt_index $stripe_command$dirstripe_count -H $hash_type $path"
		$LFS mkdir -i$mdt_index $stripe_command$dirstripe_count -H $hash_type $path ||
			error "mkdir -i $mdt_index $stripe_command$dirstripe_count -H $hash_type $path failed"
	fi
}

# free_fd: find the smallest and not in use file descriptor [above @last_fd]
#
# If called many times, passing @last_fd will avoid repeated searching
# already-open FDs repeatedly if we know they are still in use.
#
# usage: free_fd [last_fd]
free_fd()
{
	local max_fd=$(ulimit -n)
	local fd=$((${1:-2} + 1))

	while [[ $fd -le $max_fd && -e /proc/self/fd/$fd ]]; do
		((++fd))
	done
	[ $fd -lt $max_fd ] || error "finding free file descriptor failed"
	echo $fd
}

check_mount_and_prep()
{
	is_mounted $MOUNT || setupall

	rm -rf $DIR/[df][0-9]* || error "Fail to cleanup the env!"
	mkdir_on_mdt0 $DIR/$tdir || error "Fail to mkdir $DIR/$tdir."
	for idx in $(seq $MDSCOUNT); do
		local name="MDT$(printf '%04x' $((idx - 1)))"
		rm -rf $MOUNT/.lustre/lost+found/$name/*
	done
}

# calcule how many ost-objects to be created.
precreated_ost_obj_count()
{
	local mdt_idx=$1
	local ost_idx=$2
	local mdt_name="MDT$(printf '%04x' $mdt_idx)"
	local ost_name="OST$(printf '%04x' $ost_idx)"
	local proc_path="${FSNAME}-${ost_name}-osc-${mdt_name}"
	local last_id=$(do_facet mds$((mdt_idx + 1)) lctl get_param -n \
			osp.$proc_path.prealloc_last_id)
	local next_id=$(do_facet mds$((mdt_idx + 1)) lctl get_param -n \
			osp.$proc_path.prealloc_next_id)
	local ost_obj_count=$((last_id - next_id + 1))

	echo " - precreated_ost_obj_count $proc_path" \
	     "prealloc_last_id: $last_id" \
	     "prealloc_next_id: $next_id" \
	     "count: $ost_obj_count" 1>&2

	echo $ost_obj_count
}

check_file_in_pool()
{
	local file=$1
	local pool=$2
	local tlist="$3"
	local res=$($LFS getstripe $file | grep 0x | cut -f2)
	for i in $res
	do
		for t in $tlist ; do
			[ "$i" -eq "$t" ] && continue 2
		done

		echo "pool list: $tlist"
		echo "striping: $res"
		error_noexit "$file not allocated in $pool"
		return 1
	done
	return 0
}

pool_add() {
	echo "Creating new pool"
	local pool=$1

	create_pool $FSNAME.$pool ||
		{ error_noexit "No pool created, result code $?"; return 1; }
	[ $($LFS pool_list $FSNAME | grep -c "$FSNAME.${pool}\$") -eq 1 ] ||
		{ error_noexit "$pool not in lfs pool_list"; return 2; }
}

pool_add_targets() {
	echo "Adding targets to pool"
	local pool=$1
	local first=$2
	local last=${3:-$first}
	local step=${4:-1}

	local list=$(seq $first $step $last)

	local t=$(for i in $list; do printf "$FSNAME-OST%04x_UUID " $i; done)
	local tg=$(for i in $list;
		do printf -- "-e $FSNAME-OST%04x_UUID " $i; done)
	local firstx=$(printf "%04x" $first)
	local lastx=$(printf "%04x" $last)

	do_facet mgs $LCTL pool_add \
		$FSNAME.$pool $FSNAME-OST[$firstx-$lastx/$step]
	# ignore EEXIST(17)
	if (( $? != 0 && $? != 17 )); then
		error_noexit "pool_add $FSNAME-OST[$firstx-$lastx/$step] failed"
		return 3
	fi

	# wait for OSTs to be added to the pool
	for mds_id in $(seq $MDSCOUNT); do
		local mdt_id=$((mds_id-1))
		local lodname=$FSNAME-MDT$(printf "%04x" $mdt_id)-mdtlov
		wait_update_facet mds$mds_id \
			"lctl get_param -n lod.$lodname.pools.$pool |
				grep $tg | sort -u | tr '\n' ' '" "$t" || {
			error_noexit "mds$mds_id: Add to pool failed"
			return 2
		}
	done
	wait_update $HOSTNAME "lctl get_param -n lov.$FSNAME-*.pools.$pool |
			grep $tg | sort -u | tr '\n' ' ' " "$t" || {
		error_noexit "Add to pool failed"
		return 1
	}
}

pool_set_dir() {
	local pool=$1
	local tdir=$2
	echo "Setting pool on directory $tdir"

	$LFS setstripe -c 2 -p $pool $tdir && return 0

	error_noexit "Cannot set pool $pool to $tdir"
	return 1
}

pool_check_dir() {
	local pool=$1
	local tdir=$2
	echo "Checking pool on directory $tdir"

	local res=$($LFS getstripe --pool $tdir | sed "s/\s*$//")
	[ "$res" = "$pool" ] && return 0

	error_noexit "Pool on '$tdir' is '$res', not '$pool'"
	return 1
}

pool_dir_rel_path() {
	echo "Testing relative path works well"
	local pool=$1
	local tdir=$2
	local root=$3

	mkdir -p $root/$tdir/$tdir
	cd $root/$tdir
	pool_set_dir $pool $tdir          || return 1
	pool_set_dir $pool ./$tdir        || return 2
	pool_set_dir $pool ../$tdir       || return 3
	pool_set_dir $pool ../$tdir/$tdir || return 4
	rm -rf $tdir; cd - > /dev/null
}

pool_alloc_files() {
	echo "Checking files allocation from directory pool"
	local pool=$1
	local tdir=$2
	local count=$3
	local tlist="$4"

	local failed=0
	for i in $(seq -w 1 $count)
	do
		local file=$tdir/file-$i
		touch $file
		check_file_in_pool $file $pool "$tlist" || \
			failed=$((failed + 1))
	done
	[ "$failed" = 0 ] && return 0

	error_noexit "$failed files not allocated in $pool"
	return 1
}

pool_create_files() {
	echo "Creating files in pool"
	local pool=$1
	local tdir=$2
	local count=$3
	local tlist="$4"

	mkdir -p $tdir
	local failed=0
	for i in $(seq -w 1 $count)
	do
		local file=$tdir/spoo-$i
		$LFS setstripe -p $pool $file
		check_file_in_pool $file $pool "$tlist" || \
			failed=$((failed + 1))
	done
	[ "$failed" = 0 ] && return 0

	error_noexit "$failed files not allocated in $pool"
	return 1
}

pool_lfs_df() {
	echo "Checking 'lfs df' output"
	local pool=$1

	local t=$($LCTL get_param -n lov.$FSNAME-clilov-*.pools.$pool |
			tr '\n' ' ')
	local res=$($LFS df --pool $FSNAME.$pool |
			awk '{print $1}' |
			grep "$FSNAME-OST" |
			tr '\n' ' ')
	[ "$res" = "$t" ] && return 0

	error_noexit "Pools OSTs '$t' is not '$res' that lfs df reports"
	return 1
}

pool_file_rel_path() {
	echo "Creating files in a pool with relative pathname"
	local pool=$1
	local tdir=$2

	mkdir -p $tdir ||
		{ error_noexit "unable to create $tdir"; return 1 ; }
	local file="/..$tdir/$tfile-1"
	$LFS setstripe -p $pool $file ||
		{ error_noexit "unable to create $file" ; return 2 ; }

	cd $tdir
	$LFS setstripe -p $pool $tfile-2 || {
		error_noexit "unable to create $tfile-2 in $tdir"
		return 3
	}
}

pool_remove_first_target() {
	echo "Removing first target from a pool"
	pool_remove_target $1 -1
}

pool_remove_target() {
	local pool=$1
	local index=$2

	local pname="lov.$FSNAME-*.pools.$pool"
	if [ $index -eq -1 ]; then
		local t=$($LCTL get_param -n $pname | head -1)
	else
		local t=$(printf "$FSNAME-OST%04x_UUID" $index)
	fi

	echo "Removing $t from $pool"
	do_facet mgs $LCTL pool_remove $FSNAME.$pool $t
	for mds_id in $(seq $MDSCOUNT); do
		local mdt_id=$((mds_id-1))
		local lodname=$FSNAME-MDT$(printf "%04x" $mdt_id)-mdtlov
		wait_update_facet mds$mds_id \
			"lctl get_param -n lod.$lodname.pools.$pool |
				grep $t" "" || {
			error_noexit "mds$mds_id: $t not removed from" \
			"$FSNAME.$pool"
			return 2
		}
	done
	wait_update $HOSTNAME "lctl get_param -n $pname | grep $t" "" || {
		error_noexit "$t not removed from $FSNAME.$pool"
		return 1
	}
}

pool_remove_all_targets() {
	echo "Removing all targets from pool"
	local pool=$1
	local file=$2
	local pname="lov.$FSNAME-*.pools.$pool"
	for t in $($LCTL get_param -n $pname | sort -u)
	do
		do_facet mgs $LCTL pool_remove $FSNAME.$pool $t
	done
	for mds_id in $(seq $MDSCOUNT); do
		local mdt_id=$((mds_id-1))
		local lodname=$FSNAME-MDT$(printf "%04x" $mdt_id)-mdtlov
		wait_update_facet mds$mds_id "lctl get_param -n \
			lod.$lodname.pools.$pool" "" || {
			error_noexit "mds$mds_id: Pool $pool not drained"
			return 4
		}
	done
	wait_update $HOSTNAME "lctl get_param -n $pname" "" || {
		error_noexit "Pool $FSNAME.$pool cannot be drained"
		return 1
	}
	# striping on an empty/nonexistant pool should fall back
	# to "pool of everything"
	touch $file || {
		error_noexit "failed to use fallback striping for empty pool"
		return 2
	}
	# setstripe on an empty pool should fail
	$LFS setstripe -p $pool $file 2>/dev/null && {
		error_noexit "expected failure when creating file" \
							"with empty pool"
		return 3
	}
	return 0
}

pool_remove() {
	echo "Destroying pool"
	local pool=$1
	local file=$2

	do_facet mgs $LCTL pool_destroy $FSNAME.$pool

	sleep 2
	# striping on an empty/nonexistant pool should fall back
	# to "pool of everything"
	touch $file || {
		error_noexit "failed to use fallback striping for missing pool"
		return 1
	}
	# setstripe on an empty pool should fail
	$LFS setstripe -p $pool $file 2>/dev/null && {
		error_noexit "expected failure when creating file" \
							"with missing pool"
		return 2
	}

	# get param should return err once pool is gone
	if wait_update $HOSTNAME "lctl get_param -n \
		lov.$FSNAME-*.pools.$pool 2>/dev/null || echo foo" "foo"
	then
		remove_pool_from_list $FSNAME.$pool
		return 0
	fi
	error_noexit "Pool $FSNAME.$pool is not destroyed"
	return 3
}

# Get and check the actual stripe count of one file.
# Usage: check_stripe_count <file> <expected_stripe_count>
check_stripe_count() {
	local file=$1
	local expected=$2
	local actual

	[[ -z "$file" || -z "$expected" ]] &&
		error "check_stripe_count: invalid argument"

	local cmd="$LFS getstripe -c $file"
	actual=$($cmd) || error "$cmd failed"
	actual=${actual%% *}

	if [[ $actual -ne $expected ]]; then
		[[ $expected -eq -1 ]] || { $LFS getstripe $file;
			error "$cmd not expected ($expected): found $actual"; }
		[[ $actual -eq $OSTCOUNT ]] || { $LFS getstripe $file;
			error "$cmd not OST count ($OSTCOUNT): found $actual"; }
	fi
}

# Get and check the actual list of OST indices on one file.
# Usage: check_obdidx <file> <expected_comma_separated_list_of_ost_indices>
check_obdidx() {
	local file=$1
	local expected=$2
	local obdidx

	[[ -z "$file" || -z "$expected" ]] &&
		error "check_obdidx: invalid argument!"

	obdidx=$(comma_list $($LFS getstripe $file | grep -A $OSTCOUNT obdidx |
			      grep -v obdidx | awk '{print $1}' | xargs))

	[[ $obdidx = $expected ]] ||
		error "list of OST indices on $file is $obdidx," \
		      "should be $expected"
}

# Get and check the actual OST index of the first stripe on one file.
# Usage: check_start_ost_idx <file> <expected_start_ost_idx>
check_start_ost_idx() {
	local file=$1
	local expected=$2
	local start_ost_idx

	[[ -z "$file" || -z "$expected" ]] &&
		error "check_start_ost_idx: invalid argument!"

	start_ost_idx=$($LFS getstripe $file | grep -A 1 obdidx |
			 grep -v obdidx | awk '{print $1}')

	[[ $start_ost_idx = $expected ]] ||
		error "OST index of the first stripe on $file is" \
		      "$start_ost_idx, should be $expected"
}

killall_process () {
	local clients=${1:-$(hostname)}
	local name=$2
	local signal=$3
	local rc=0

	do_nodes $clients "killall $signal $name"
}

lsnapshot_create()
{
	do_facet mgs "$LCTL snapshot_create -F $FSNAME $*"
}

lsnapshot_destroy()
{
	do_facet mgs "$LCTL snapshot_destroy -F $FSNAME $*"
}

lsnapshot_modify()
{
	do_facet mgs "$LCTL snapshot_modify -F $FSNAME $*"
}

lsnapshot_list()
{
	do_facet mgs "$LCTL snapshot_list -F $FSNAME $*"
}

lsnapshot_mount()
{
	do_facet mgs "$LCTL snapshot_mount -F $FSNAME $*"
}

lsnapshot_umount()
{
	do_facet mgs "$LCTL snapshot_umount -F $FSNAME $*"
}

lss_err()
{
	local msg=$1

	do_facet mgs "cat $LSNAPSHOT_LOG"
	error $msg
}

lss_cleanup()
{
	echo "Cleaning test environment ..."

	# Every lsnapshot command takes exclusive lock with others,
	# so can NOT destroy the snapshot during list with 'xargs'.
	while true; do
		local ssname=$(lsnapshot_list | grep snapshot_name |
			grep lss_ | awk '{ print $2 }' | head -n 1)
		[ -z "$ssname" ] && break

		lsnapshot_destroy -n $ssname -f ||
			lss_err "Fail to destroy $ssname by force"
	done
}

lss_gen_conf_one()
{
	local facet=$1
	local role=$2
	local idx=$3

	local host=$(facet_active_host $facet)
	local dir=$(dirname $(facet_vdevice $facet))
	local pool=$(zpool_name $facet)
	local lfsname=$(zfs_local_fsname $facet)
	local label=${FSNAME}-${role}$(printf '%04x' $idx)

	do_facet mgs \
		"echo '$host - $label zfs:${dir}/${pool}/${lfsname} - -' >> \
		$LSNAPSHOT_CONF"
}

lss_gen_conf()
{
	do_facet mgs "rm -f $LSNAPSHOT_CONF"
	echo "Generating $LSNAPSHOT_CONF on MGS ..."

	if ! combined_mgs_mds ; then
		[ $(facet_fstype mgs) != zfs ] &&
			skip "Lustre snapshot 1 only works for ZFS backend"

		local host=$(facet_active_host mgs)
		local dir=$(dirname $(facet_vdevice mgs))
		local pool=$(zpool_name mgs)
		local lfsname=$(zfs_local_fsname mgs)

		do_facet mgs \
			"echo '$host - MGS zfs:${dir}/${pool}/${lfsname} - -' \
			>> $LSNAPSHOT_CONF" || lss_err "generate lss conf (mgs)"
	fi

	for num in `seq $MDSCOUNT`; do
		[ $(facet_fstype mds$num) != zfs ] &&
			skip "Lustre snapshot 1 only works for ZFS backend"

		lss_gen_conf_one mds$num MDT $((num - 1)) ||
			lss_err "generate lss conf (mds$num)"
	done

	for num in `seq $OSTCOUNT`; do
		[ $(facet_fstype ost$num) != zfs ] &&
			skip "Lustre snapshot 1 only works for ZFS backend"

		lss_gen_conf_one ost$num OST $((num - 1)) ||
			lss_err "generate lss conf (ost$num)"
	done

	do_facet mgs "cat $LSNAPSHOT_CONF"
}

# Parse 'lfs getstripe -d <path_with_dir_name>' for non-composite dir
parse_plain_dir_param()
{
	local invalues=($1)
	local param=""

	if [[ ${invalues[0]} =~ "stripe_count:" ]]; then
		(( ${invalues[1]} == $OSTCOUNT - 1 )) &&
			param="-c $OSTCOUNT" || param="-c ${invalues[1]}"
	fi
	if [[ ${invalues[2]} =~ "stripe_size:" ]]; then
		param="$param -S ${invalues[3]}"
	fi
	if [[ ${invalues[4]} =~ "pattern:" ]]; then
		if [[ ${invalues[5]} =~ "stripe_offset:" ]]; then
			param="$param -i ${invalues[6]}"
		else
			param="$param -L ${invalues[5]} -i ${invalues[7]}"
		fi
	elif [[ ${invalues[4]} =~ "stripe_offset:" ]]; then
		param="$param -i ${invalues[5]}"
	fi
	echo "$param"
}

parse_plain_param()
{
	local line=$1
	local val=$(awk '{print $2}' <<< $line)

	if [[ $line =~ ^"lmm_stripe_count:" ]]; then
		(( $val == $OSTCOUNT - 1 )) &&
			param="-c $OSTCOUNT" || param="-c $val"
		echo "-c $val"
	elif [[ $line =~ ^"lmm_stripe_size:" ]]; then
		echo "-S $val"
	elif [[ $line =~ ^"lmm_stripe_offset:" && $SKIP_INDEX != yes ]]; then
		echo "-i $val"
	elif [[ $line =~ ^"lmm_pattern:" ]]; then
		echo "-L $val"
	fi
}

parse_dir_param()
{
	local line=$1
	local val=$(awk '{print $2}' <<< $line)

	if [[ $line =~ ^"lmv_stripe_count:" ]]; then
		echo "-c $val"
	elif [[ $line =~ ^"lmv_stripe_offset:" ]]; then
		echo "-i $val"
	elif [[ $line =~ ^"lmv_hash_type:" ]]; then
		echo "-H $val"
	elif [[ $line =~ ^"lmv_max_inherit:" ]]; then
		echo "-X $val"
	fi
}

parse_layout_param()
{
	local mode=""
	local val=""
	local param=""

	while read line; do
		if [[ ! -z $line ]]; then
			if [[ -z $mode ]]; then
				if [[ $line =~ ^"stripe_count:" ]]; then
					mode="plain_dir"
				elif [[ $line =~ ^"lmm_stripe_count:" ]]; then
					mode="plain_file"
				elif [[ $line =~ ^"lcm_layout_gen:" ]]; then
					mode="pfl"
				elif [[ $line =~ ^"lmv_stripe_count" ]]; then
					mode="dne"
				fi
			fi

			if [[ $mode = "plain_dir" ]]; then
				param=$(parse_plain_dir_param "$line")
			elif [[ $mode = "plain_file" ]]; then
				val=$(parse_plain_param "$line")
				[[ ! -z $val ]] && param="$param $val"
			elif [[ $mode = "pfl" ]]; then
				val=$(echo $line | awk '{print $2}')
				if [[ $line =~ ^"lcme_extent.e_end:" ]]; then
					if [[ $val = "EOF" ]]; then
						param="$param -E -1"
					else
						param="$param -E $val"
					fi
				elif [[ $line =~ ^"stripe_count:" ]]; then
					# pfl dir
					val=$(parse_plain_dir_param "$line")
					param="$param $val"
				else
					#pfl file
					val=$(parse_plain_param "$line")
					[[ ! -z $val ]] && param="$param $val"
				fi
			elif [[ $mode = "dne" ]]; then
				val=$(parse_dir_param "$line")
				[[ ! -z $val ]] && param="$param $val"
			fi
		fi
	done
	echo "$param"
}

get_layout_param()
{
	local param=$($LFS getstripe -dy $1 | parse_layout_param)
	echo "$param"
}

get_dir_layout_param()
{
	local param=$($LFS getdirstripe -y $1 | parse_layout_param)
	echo "$param"
}

lfsck_verify_pfid()
{
	local f
	local rc=0

	# Cancel locks before setting lfsck_verify_pfid so that errors are more
        # controllable
	cancel_lru_locks mdc
	cancel_lru_locks osc

	# make sure PFID is set correctly for files
	do_nodes $(comma_list $(osts_nodes)) \
	       "$LCTL set_param -n obdfilter.${FSNAME}-OST*.lfsck_verify_pfid=1"

	for f in "$@"; do
		cat $f &> /dev/nullA ||
			{ rc=$?; echo "verify $f failed"; break; }
	done

	do_nodes $(comma_list $(osts_nodes)) \
	       "$LCTL set_param -n obdfilter.${FSNAME}-OST*.lfsck_verify_pfid=0"
	return $rc
}

# check that clients "oscs" was evicted after "before"
check_clients_evicted() {
	local before=$1
	shift
	local oscs=${@}
	local osc
	local rc=0

	for osc in $oscs; do
		echo "Check state for $osc"
		local evicted=$(do_facet client $LCTL get_param osc.$osc.state |
			tail -n 5 | awk -F"[ ,]" \
			'/EVICTED/ { if (mx<$4) { mx=$4; } } END { print mx }')
		if (($? == 0)) && (($evicted > $before)); then
			echo "$osc is evicted at $evicted"
		else
			((rc++))
			echo "$osc was not evicted after $before:"
			do_facet client $LCTL get_param osc.$osc.state |
				tail -n 8
		fi
	done

	[ $rc -eq 0 ] || error "client not evicted from OST"
}

# check that clients OSCS current_state is FULL
check_clients_full() {
	local timeout=$1
	shift
	local oscs=${@}

	for osc in $oscs; do
		wait_update_facet client \
			"lctl get_param -n osc.$osc.state |
			grep 'current_state: FULL'" \
			"current_state: FULL" $timeout
		[ $? -eq 0 ] || error "$osc state is not FULL"
	done
}

#Changelogs
__changelog_deregister() {
	local facet=$1
	local mdt="$(facet_svc $facet)"
	local cl_user=$2
	local rc=0

	# skip cleanup if no user registered for this MDT
	[ -z "$cl_user" ] && echo "$mdt: no changelog user" && return 0
	# user is no longer registered, skip cleanup
	changelog_users "$facet" | grep -q "$cl_user" ||
		{ echo "$mdt: changelog user '$cl_user' not found"; return 0; }

	# From this point, if any operation fails, it is an error
	__changelog_clear $facet $cl_user 0 ||
		error_noexit "$mdt: changelog_clear $cl_user 0 fail: $rc"
	do_facet $facet $LCTL --device $mdt changelog_deregister $cl_user ||
		error_noexit "$mdt: changelog_deregister '$cl_user' fail: $rc"
}

declare -Ax CL_USERS
changelog_register() {
	for M in $(seq $MDSCOUNT); do
		local facet=mds$M
		local mdt="$(facet_svc $facet)"
		local cl_mask

		cl_mask=$(do_facet $facet $LCTL get_param \
			     mdd.${mdt}.changelog_mask -n)
		stack_trap "do_facet $facet $LCTL \
			set_param mdd.$mdt.changelog_mask=\'$cl_mask\' -n" EXIT
		do_facet $facet $LCTL set_param mdd.$mdt.changelog_mask=+hsm ||
			error "$mdt: changelog_mask=+hsm failed: $?"

		local cl_user
		cl_user=$(do_facet $facet $LCTL --device $mdt \
			changelog_register -n "$@") ||
			error "$mdt: register changelog user failed: $?"
		stack_trap "__changelog_deregister $facet $cl_user" EXIT

		stack_trap "CL_USERS[$facet]='${CL_USERS[$facet]}'" EXIT
		# Bash does not support nested arrays, but the format of a
		# cl_user is constrained enough to use whitespaces as separators
		CL_USERS[$facet]+="$cl_user "
	done
	echo "Registered $MDSCOUNT changelog users: '${CL_USERS[*]% }'"
}

changelog_deregister() {
	local cl_user
	# bash assoc arrays do not guarantee to list keys in created order
	# so reorder to get same order than in changelog_register()
	local cl_facets=$(echo "${!CL_USERS[@]}" | tr " " "\n" | sort |
			  tr "\n" " ")

	for facet in $cl_facets; do
		for cl_user in ${CL_USERS[$facet]}; do
			__changelog_deregister $facet $cl_user || return $?
		done
		unset CL_USERS[$facet]
	done
}

changelog_users() {
	local facet=$1
	local service=$(facet_svc $facet)

	do_facet $facet $LCTL get_param -n mdd.$service.changelog_users
}

changelog_user_rec() {
	local facet=$1
	local cl_user=$2
	local service=$(facet_svc $facet)

	changelog_users $facet | awk '$1 == "'$cl_user'" { print $2 }'
}

changelog_chmask() {
	local mask=$1

	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param mdd.*.changelog_mask="$mask"
}

# usage: __changelog_clear FACET CL_USER [+]INDEX
__changelog_clear()
{
	local facet=$1
	local mdt="$(facet_svc $facet)"
	local cl_user=$2
	local -i rec

	case "$3" in
	+*)
		# Remove the leading '+'
		rec=${3:1}
		rec+=$(changelog_user_rec $facet $cl_user)
		;;
	*)
		rec=$3
		;;
	esac

	if [ $rec -eq 0 ]; then
		echo "$mdt: clear the changelog for $cl_user of all records"
	else
		echo "$mdt: clear the changelog for $cl_user to record #$rec"
	fi
	$LFS changelog_clear $mdt $cl_user $rec
}

# usage: changelog_clear [+]INDEX [facet]...
#
# If INDEX is prefixed with '+', increment every changelog user's record index
# by INDEX. Otherwise, clear the changelog up to INDEX for every changelog
# users.
changelog_clear() {
	local rc
	local idx=$1
	shift
	local cl_facets="$@"
	# bash assoc arrays do not guarantee to list keys in created order
	# so reorder to get same order than in changelog_register()
	[[ -n "$cl_facets" ]] ||
		cl_facets=$(echo "${!CL_USERS[@]}" | tr " " "\n" | sort |
			tr "\n" " ")
	local cl_user

	for facet in $cl_facets; do
		for cl_user in ${CL_USERS[$facet]}; do
			__changelog_clear $facet $cl_user $idx || rc=${rc:-$?}
		done
	done

	return ${rc:-0}
}

changelog_dump() {
	local rc

	for M in $(seq $MDSCOUNT); do
		local facet=mds$M
		local mdt="$(facet_svc $facet)"
		local output
		local ret

		output=$($LFS changelog $mdt)
		ret=$?
		if [ $ret -ne 0 ]; then
			rc=${rc:-$ret}
		elif [ -n "$output" ]; then
			echo "$output" | sed -e 's/^/'$mdt'./'
		fi
	done

	return ${rc:-0}
}

changelog_extract_field() {
	local cltype=$1
	local file=$2
	local identifier=$3

	changelog_dump | gawk "/$cltype.*$file$/ {
		print gensub(/^.* "$identifier'(\[[^\]]*\]).*$/,"\\1",1)}' |
		tail -1
}

# Prints a changelog record produced by "lfs changelog" as an associative array
#
# Example:
# $> changelog2array 16 01CREAT 10:28:46.968438800 2018.03.09 0x0 \
#                    t=[0x200000401:0x10:0x0] j=touch.501 ef=0xf u=501:501 \
#                    nid=0@lo p=[0x200000007:0x1:0x0] blob
# ([index]='16' [type]='CREAT' [time]='10:28:46.968438800'
#  [date]='2018.03.09' [flags]=0x0 ['target-fid']='[0x200000401:0x10:0x0]'
#  ['jobid']='touch.501' ['extra-flags']='0x0f' [uid]='0' ['gid']='0'
#  ['nid']='0@lo' ['parent-fid']='[0x200000007:0x1:0x0]')
#
# Note that the changelog record is not quoted
# Also note that the line breaks in the output were only added for readability
#
# Typically, you want to eval the output of the command to fill an actual
# associative array, like this:
# $> eval declare -A changelog=$(changelog2array $entry)
#
# It can then be accessed like any bash associative array:
# $> echo "${changelog[index]}" "${changelog[type]}" "${changelog[flags]}"
# 16 CREAT 0x0
# $> echo "${changelog[uid]}":"${changelog[gid]}"
# 501:501
#
changelog2array()
{
	# Start the array
	printf '('

	# A changelog, as printed by "lfs changelog" typically looks like this:
	# <index> <type> <time> <date> <flags> <key1=value1> <key2=value2> ...

	# Parse the positional part of the changelog

	# changelog_dump() prefixes records with their mdt's name
	local index="${1##*.}"

	printf "[index]='%s' [type]='%s' [time]='%s' [date]='%s' [flags]='%s'" \
	       "$index" "${2:2}" "$3" "$4" "$5"

	# Parse the key/value part of the changelog
	for arg in "${@:5}"; do
		# Check it matches a key=value syntax
		[[ "$arg" =~ ^[[:alpha:]]+= ]] || continue

		local key="${arg%%=*}"
		local value="${arg#*=}"

		case "$key" in
		u)
			# u is actually for uid AND gid: u=UID:GID
			printf " [uid]='%s'" "${value%:*}"
			key=gid
			value="${value#*:}"
			;;
		t)
			key=target-fid
			value="${value#[}"
			value="${value%]}"
			;;
		j)
			key=jobid
			;;
		p)
			key=parent-fid
			value="${value#[}"
			value="${value%]}"
			;;
		ef)
			key=extra-flags
			;;
		m)
			key=mode
			;;
		x)
			key=xattr
			;;
		*)
			;;
		esac

		printf " ['%s']='%s'" "$key" "$value"
	done

	# end the array
	printf ')'
}

# Format and print a changelog record
#
# Interpreted sequences are:
#	%%	a single %
#	%f	the "flags" attribute of a changelog record
__changelog_printf()
{
	local format="$1"

	local -i i
	for ((i = 0; i < ${#format}; i++)); do
		local char="${format:$i:1}"
		if [ "$char" != % ]; then
			printf '%c' "$char"
			continue
		fi

		i+=1
		char="${format:$i:1}"
		case "$char" in
		f)
			printf '%s' "${changelog[flags]}"
			;;
		%)
			printf '%'
			;;
		esac
	done
	printf '\n'
}

# Filter changelog records
changelog_find()
{
	local -A filter
	local action='print'
	local format

	while [ $# -gt 0 ]; do
		case "$1" in
		-print)
			action='print'
			;;
		-printf)
			action='printf'
			format="$2"
			shift
			;;
		-*)
			filter[${1#-}]="$2"
			shift
			;;
		esac
		shift
	done

	local found=false
	local record
	changelog_dump | { while read -r record; do
		eval local -A changelog=$(changelog2array $record)
		for key in "${!filter[@]}"; do
			case "$key" in
			*)
				[ "${changelog[$key]}" == "${filter[$key]}" ]
				;;
			esac || continue 2
		done

		found=true

		case "${action:-print}" in
		print)
			printf '%s\n' "$record"
			;;
		printf)
			__changelog_printf "$format"
			;;
		esac
	done; $found; }
}

restore_layout() {
	local dir=$1
	local layout=$2

	[ ! -d "$dir" ] && return

	[ -z "$layout" ] && {
		$LFS setstripe -d $dir || error "error deleting stripe '$dir'"
		return
	}

	setfattr -n trusted.lov -v $layout $dir ||
		error "error restoring layout '$layout' to '$dir'"
}

# save the layout of a directory, the returned string will be used by
# restore_layout() to restore the layout
save_layout() {
	local dir=$1
	local str=$(getfattr -n trusted.lov --absolute-names -e hex $dir \
		    2> /dev/null | awk -F'=' '/trusted.lov/{ print $2 }')
	echo "$str"
}

# save layout of a directory and restore it at exit
save_layout_restore_at_exit() {
	local dir=$1
	local layout=$(save_layout $dir)

	stack_trap "restore_layout $dir $layout" EXIT
}

verify_yaml_layout() {
	local src=$1
	local dst=$2
	local temp=$3
	local msg_prefix=$4

	echo "getstripe --yaml $src"
	$LFS getstripe --yaml $src > $temp || error "getstripe $src failed"
	echo "setstripe --yaml=$temp $dst"
	$LFS setstripe --yaml=$temp $dst|| error "setstripe $dst failed"

	echo "compare"
	local layout1=$(get_layout_param $src)
	local layout2=$(get_layout_param $dst)
	# compare their layout info
	[ "$layout1" == "$layout2" ] ||
		error "$msg_prefix $src/$dst layouts are not equal"
}

is_project_quota_supported() {
	$ENABLE_PROJECT_QUOTAS || return 1
	[[ -z "$SAVE_PROJECT_SUPPORTED" ]] || return $SAVE_PROJECT_SUPPORTED
	local save_project_supported=1

	[[ "$(facet_fstype $SINGLEMDS)" == "ldiskfs" &&
	   $(lustre_version_code $SINGLEMDS) -gt $(version_code 2.9.55) ]] &&
		do_facet mds1 lfs --list-commands |& grep -q project &&
			save_project_supported=0

	[[ "$(facet_fstype $SINGLEMDS)" == "zfs" &&
	   $(lustre_version_code $SINGLEMDS) -gt $(version_code 2.10.53) ]] &&
		do_facet mds1 $ZPOOL get all | grep -q project_quota &&
			save_project_supported=0

	# cache state of project quotas once instead of re-checking each time
	export SAVE_PROJECT_SUPPORTED=$save_project_supported
	echo "using SAVE_PROJECT_SUPPORTED=$SAVE_PROJECT_SUPPORTED"

	return $save_project_supported
}

# ZFS project quota enable/disable:
#   This  feature  will  become  active as soon as it is enabled and will never
#   return to being disabled. Each filesystem will be upgraded automatically
#   when remounted or when [a] new file is created under that filesystem. The
#   upgrade can also be triggered on filesystems via `zfs set version=current
#   <pool/fs>`. The upgrade process runs in the background and may take a
#   while to complete for the filesystems containing a large number of files.
enable_project_quota() {
	is_project_quota_supported || return 0
	local zkeeper=${KEEP_ZPOOL}
	stack_trap "KEEP_ZPOOL=$zkeeper" EXIT
	KEEP_ZPOOL="true"
	stopall || error "failed to stopall (1)"

	local zfeat_en="feature@project_quota=enabled"
	for facet in $(seq -f mds%g $MDSCOUNT) $(seq -f ost%g $OSTCOUNT); do
		local facet_fstype=${facet:0:3}1_FSTYPE
		local devname

		if [ "${!facet_fstype}" = "zfs" ]; then
			devname=$(zpool_name ${facet})
			do_facet ${facet} $ZPOOL set "$zfeat_en" $devname ||
				error "$ZPOOL set $zfeat_en $devname"
		else
			[ ${facet:0:3} == "mds" ] &&
				devname=$(mdsdevname ${facet:3}) ||
				devname=$(ostdevname ${facet:3})
			do_facet ${facet} $TUNE2FS -O project $devname ||
				error "tune2fs $devname failed"
		fi
	done

	KEEP_ZPOOL="${zkeeper}"
	mount
	setupall
}

disable_project_quota() {
	is_project_quota_supported || return 0
	[ "$mds1_FSTYPE" != "ldiskfs" ] && return 0
	stopall || error "failed to stopall (1)"

	for num in $(seq $MDSCOUNT); do
		do_facet mds$num $TUNE2FS -Q ^prj $(mdsdevname $num) ||
			error "tune2fs $(mdsdevname $num) failed"
	done

	for num in $(seq $OSTCOUNT); do
		do_facet ost$num $TUNE2FS -Q ^prj $(ostdevname $num) ||
			error "tune2fs $(ostdevname $num) failed"
	done

	mount
	setupall
}

change_project() {
	echo "$LFS project $*"
	$LFS project $* || error "$LFS project $* failed"
}

# get quota for a user or a group
# usage: getquota -u|-g|-p <username>|<groupname>|<projid> global|<obd_uuid> \
#		  bhardlimit|bsoftlimit|bgrace|ihardlimit|isoftlimit|igrace \
#		  <pool_name>
getquota() {
	local spec
	local uuid
	local pool_arg

	sync_all_data > /dev/null 2>&1 || true

	[ "$#" != 4 -a "$#" != 5 ] &&
		error "getquota: wrong number of arguments: $#"
	[ "$1" != "-u" -a "$1" != "-g" -a "$1" != "-p" ] &&
		error "getquota: wrong u/g/p specifier $1 passed"

	uuid="$3"

	case "$4" in
		curspace)   spec=1;;
		bsoftlimit) spec=2;;
		bhardlimit) spec=3;;
		bgrace)     spec=4;;
		curinodes)  spec=5;;
		isoftlimit) spec=6;;
		ihardlimit) spec=7;;
		igrace)     spec=8;;
		*)          error "unknown quota parameter $4";;
	esac

	[ ! -z "$5" ] && pool_arg="--pool $5 "
	[ "$uuid" = "global" ] && uuid=$DIR

	$LFS quota -v "$1" "$2" $pool_arg $DIR 1>&2
	$LFS quota -v "$1" "$2" $pool_arg $DIR |
		awk 'BEGIN { num='$spec' } { if ($1 ~ "'$uuid'") \
		{ if (NF == 1) { getline } else { num++ } ; print $num;} }' \
		| tr -d "*"
}

# set mdt quota type
# usage: set_mdt_qtype ugp|u|g|p|none
set_mdt_qtype() {
	local qtype=$1
	local varsvc
	local mdts=$(get_facets MDS)
	local cmd
	[[ "$qtype" =~ "p" ]] && ! is_project_quota_supported &&
		qtype=$(tr -d 'p' <<<$qtype)

	if [[ $PERM_CMD == *"set_param -P"* ]]; then
		do_facet mgs $PERM_CMD \
			osd-*.$FSNAME-MDT*.quota_slave.enabled=$qtype
	else
		do_facet mgs $PERM_CMD $FSNAME.quota.mdt=$qtype
	fi
	# we have to make sure each MDT received config changes
	for mdt in ${mdts//,/ }; do
		varsvc=${mdt}_svc
		cmd="$LCTL get_param -n "
		cmd=${cmd}osd-$(facet_fstype $mdt).${!varsvc}
		cmd=${cmd}.quota_slave.enabled

		if $(facet_up $mdt); then
			wait_update_facet $mdt "$cmd" "$qtype" || return 1
		fi
	done
	return 0
}

# set ost quota type
# usage: set_ost_qtype ugp|u|g|p|none
set_ost_qtype() {
	local qtype=$1
	local varsvc
	local osts=$(get_facets OST)
	local cmd
	[[ "$qtype" =~ "p" ]] && ! is_project_quota_supported &&
		qtype=$(tr -d 'p' <<<$qtype)

	if [[ $PERM_CMD == *"set_param -P"* ]]; then
		do_facet mgs $PERM_CMD \
			osd-*.$FSNAME-OST*.quota_slave.enabled=$qtype
	else
		do_facet mgs $PERM_CMD $FSNAME.quota.ost=$qtype
	fi
	# we have to make sure each OST received config changes
	for ost in ${osts//,/ }; do
		varsvc=${ost}_svc
		cmd="$LCTL get_param -n "
		cmd=${cmd}osd-$(facet_fstype $ost).${!varsvc}
		cmd=${cmd}.quota_slave.enabled

		if $(facet_up $ost); then
			wait_update_facet $ost "$cmd" "$qtype" || return 1
		fi
	done
	return 0
}

#
# In order to test multiple remote HSM agents, a new facet type named "AGT" and
# the following associated variables are added:
#
# AGTCOUNT: number of agents
# AGTDEV{N}: target HSM mount point (root path of the backend)
# agt{N}_HOST: hostname of the agent agt{N}
# SINGLEAGT: facet of the single agent
#
# The number of agents is initialized as the number of remote client nodes.
# By default, only single copytool is started on a remote client/agent. If there
# was no remote client, then the copytool will be started on the local client.
#
init_agt_vars() {
	local n
	local agent

	export AGTCOUNT=${AGTCOUNT:-$((CLIENTCOUNT - 1))}
	[[ $AGTCOUNT -gt 0 ]] || AGTCOUNT=1

	export SHARED_DIRECTORY=${SHARED_DIRECTORY:-$TMP}
	if [[ $CLIENTCOUNT -gt 1 ]] &&
		! check_shared_dir $SHARED_DIRECTORY $CLIENTS; then
		skip_env "SHARED_DIRECTORY should be accessible"\
			 "on all client nodes"
		exit 0
	fi

	# We used to put the HSM archive in $SHARED_DIRECTORY but that
	# meant NFS issues could hose sanity-hsm sessions. So now we
	# use $TMP instead.
	for n in $(seq $AGTCOUNT); do
		eval export AGTDEV$n=\$\{AGTDEV$n:-"$TMP/arc$n"\}
		agent=CLIENT$((n + 1))
		if [[ -z "${!agent}" ]]; then
			[[ $CLIENTCOUNT -eq 1 ]] && agent=CLIENT1 ||
				agent=CLIENT2
		fi
		eval export agt${n}_HOST=\$\{agt${n}_HOST:-${!agent}\}
		local var=agt${n}_HOST
		[[ ! -z "${!var}" ]] || error "agt${n}_HOST is empty!"
	done

	export SINGLEAGT=${SINGLEAGT:-agt1}

	export HSMTOOL=${HSMTOOL:-"lhsmtool_posix"}
	export HSMTOOL_PID_FILE=${HSMTOOL_PID_FILE:-"/var/run/lhsmtool_posix.pid"}
	export HSMTOOL_VERBOSE=${HSMTOOL_VERBOSE:-""}
	export HSMTOOL_UPDATE_INTERVAL=${HSMTOOL_UPDATE_INTERVAL:=""}
	export HSMTOOL_EVENT_FIFO=${HSMTOOL_EVENT_FIFO:=""}
	export HSMTOOL_TESTDIR
	export HSMTOOL_ARCHIVE_FORMAT=${HSMTOOL_ARCHIVE_FORMAT:-v2}

	if ! [[ $HSMTOOL =~ hsmtool ]]; then
		echo "HSMTOOL = '$HSMTOOL' does not contain 'hsmtool', GLWT" >&2
	fi

	HSM_ARCHIVE_NUMBER=2

	# The test only support up to 10 MDTs
	MDT_PREFIX="mdt.$FSNAME-MDT000"
	HSM_PARAM="${MDT_PREFIX}0.hsm"

	# archive is purged at copytool setup
	HSM_ARCHIVE_PURGE=true

	# Don't allow copytool error upon start/setup
	HSMTOOL_NOERROR=false
}

# Get the backend root path for the given agent facet.
copytool_device() {
	local facet=$1
	local dev=AGTDEV$(facet_number $facet)

	echo -n ${!dev}
}

get_mdt_devices() {
	local mdtno
	# get MDT device for each mdc
	for mdtno in $(seq 1 $MDSCOUNT); do
		local idx=$(($mdtno - 1))
		MDT[$idx]=$($LCTL get_param -n \
			mdc.$FSNAME-MDT000${idx}-mdc-*.mds_server_uuid |
			awk '{gsub(/_UUID/,""); print $1}' | head -n1)
	done
}

pkill_copytools() {
	local hosts="$1"
	local signal="$2"

	do_nodes "$hosts" \
		"pkill --pidfile=$HSMTOOL_PID_FILE --signal=$signal hsmtool"
}

copytool_continue() {
	local agents=${1:-$(facet_active_host $SINGLEAGT)}

	pkill_copytools "$agents" CONT || return 0
	echo "Copytool is continued on $agents"
}

kill_copytools() {
	local hosts=${1:-$(facet_active_host $SINGLEAGT)}

	echo "Killing existing copytools on $hosts"
	pkill_copytools "$hosts" TERM || return 0
	copytool_continue "$hosts"
}

copytool_monitor_cleanup() {
	local facet=${1:-$SINGLEAGT}
	local agent=$(facet_active_host $facet)

	if [ -n "$HSMTOOL_MONITOR_DIR" ]; then
		# Should die when the copytool dies, but just in case.
		local cmd="kill \\\$(cat $HSMTOOL_MONITOR_DIR/monitor_pid)"
		cmd+=" 2>/dev/null || true"
		do_node $agent "$cmd"
		do_node $agent "rm -fr $HSMTOOL_MONITOR_DIR"
		export HSMTOOL_MONITOR_DIR=
	fi

	# The pdsh should die on its own when the monitor dies. Just
	# in case, though, try to clean up to avoid any cruft.
	if [ -n "$HSMTOOL_MONITOR_PDSH" ]; then
		kill $HSMTOOL_MONITOR_PDSH 2>/dev/null || true
		export HSMTOOL_MONITOR_PDSH=
	fi
}

copytool_logfile()
{
	local host="$(facet_host "$1")"
	local prefix=$TESTLOG_PREFIX
	[ -n "$TESTNAME" ] && prefix+=.$TESTNAME

	printf "${prefix}.copytool${archive_id}_log.${host}.log"
}

__lhsmtool_rebind()
{
	do_facet $facet $HSMTOOL \
		"${hsmtool_options[@]}" --rebind "$@" "$mountpoint"
}

__lhsmtool_import()
{
	mkdir -p "$(dirname "$2")" ||
		error "cannot create directory '$(dirname "$2")'"
	do_facet $facet $HSMTOOL \
		"${hsmtool_options[@]}" --import "$@" "$mountpoint"
}

__lhsmtool_setup()
{
	local host="$(facet_host "$facet")"
	local cmd="$HSMTOOL ${hsmtool_options[@]} --daemon --pid-file=$HSMTOOL_PID_FILE"

	[ -n "$bandwidth" ] && cmd+=" --bandwidth $bandwidth"
	[ -n "$archive_id" ] && cmd+=" --archive $archive_id"
	#	[ ${#misc_options[@]} -gt 0 ] &&
#		cmd+=" $(IFS=" " echo "$@")"
	cmd+=" $@ \"$mountpoint\""

	echo "Starting copytool '$facet' on '$host' with cmdline '$cmd'"
	stack_trap "pkill_copytools $host TERM || true" EXIT
	do_node "$host" "$cmd < /dev/null > \"$(copytool_logfile $facet)\" 2>&1"
}

hsm_root() {
	local facet="${1:-$SINGLEAGT}"

	printf "$(copytool_device "$facet")/${TESTSUITE}.${TESTNAME}/"
}

# Main entry point to perform copytool related operations
#
# Sub-commands:
#
#	setup	setup a copytool to run in the background, that copytool will be
#		killed on EXIT
#	import	import a file from an HSM backend
#	rebind	rebind an archived file to a new fid
#
# Although the semantics might suggest otherwise, one does not need to 'setup'
# a copytool before a call to 'copytool import' or 'copytool rebind'.
#
copytool()
{
	local action=$1
	shift

	# Use default values
	local facet=$SINGLEAGT
	local mountpoint="${MOUNT2:-$MOUNT}"

	# Parse arguments
	local fail_on_error=true
	local -a hsmtool_options=()
	local -a action_options=()

	if [[ -n "$HSMTOOL_ARCHIVE_FORMAT" ]]; then
		hsmtool_options+=("--archive-format=$HSMTOOL_ARCHIVE_FORMAT")
	fi

	if [[ -n "$HSMTOOL_VERBOSE" ]]; then
		hsmtool_options+=("$HSMTOOL_VERBOSE")
	fi

	while [ $# -gt 0 ]; do
		case "$1" in
		-f|--facet)
			shift
			facet="$1"
			;;
		-m|--mountpoint)
			shift
			mountpoint="$1"
			;;
		-a|--archive-id)
			shift
			local archive_id="$1"
			;;
		-h|--hsm-root)
			shift
			local hsm_root="$1"
			;;
		-b|--bwlimit)
			shift
			local bandwidth="$1" # in MB/s
			;;
		-n|--no-fail)
			local fail_on_error=false
			;;
		*)
			# Uncommon(/copytool dependent) option
			action_options+=("$1")
			;;
		esac
		shift
	done

	local hsm_root="${hsm_root:-$(hsm_root "$facet")}"
	hsmtool_options+=("--hsm-root=$hsm_root")

	stack_trap "do_facet $facet rm -rf '$hsm_root'" EXIT
	do_facet $facet mkdir -p "$hsm_root" ||
		error "mkdir '$hsm_root' failed"

	case "$HSMTOOL" in
	lhsmtool_posix)
		local copytool=lhsmtool
		;;
	esac

	__${copytool}_${action} "${action_options[@]}"
	if [ $? -ne 0 ]; then
		local error_msg

		case $action in
		setup)
			local host="$(facet_host $facet)"
			error_msg="Failed to start copytool $facet on '$host'"
			;;
		import)
			local src="${action_options[0]}"
			local dest="${action_options[1]}"
			error_msg="Failed to import '$src' to '$dest'"
			;;
		rebind)
			error_msg="could not rebind file"
			;;
		esac

		$fail_on_error && error "$error_msg" || echo "$error_msg"
	fi
}

needclients() {
	local client_count=$1
	if [[ $CLIENTCOUNT -lt $client_count ]]; then
		skip "Need $client_count or more clients, have $CLIENTCOUNT"
		return 1
	fi
	return 0
}

path2fid() {
	$LFS path2fid $1 | tr -d '[]'
	return ${PIPESTATUS[0]}
}

get_hsm_flags() {
	local f=$1
	local u=$2
	local st

	if [[ $u == "user" ]]; then
		st=$($RUNAS $LFS hsm_state $f)
	else
		u=root
		st=$($LFS hsm_state $f)
	fi

	[[ $? == 0 ]] || error "$LFS hsm_state $f failed (run as $u)"

	st=$(echo $st | cut -f 2 -d" " | tr -d "()," )
	echo $st
}

check_hsm_flags() {
	local f=$1
	local fl=$2

	local st=$(get_hsm_flags $f)
	[[ $st == $fl ]] || error "hsm flags on $f are $st != $fl"
}

mdts_set_param() {
	local arg=$1
	local key=$2
	local value=$3
	local mdtno
	local rc=0
	if [[ "$value" != "" ]]; then
		value="='$value'"
	fi
	for mdtno in $(seq 1 $MDSCOUNT); do
		local idx=$(($mdtno - 1))
		local facet=mds${mdtno}
		# if $arg include -P option, run 1 set_param per MDT on the MGS
		# else, run set_param on each MDT
		[[ $arg = *"-P"* ]] && facet=mgs
		do_facet $facet $LCTL set_param $arg mdt.${MDT[$idx]}.$key$value
		[[ $? != 0 ]] && rc=1
	done
	return $rc
}

mdts_check_param() {
	local key="$1"
	local target="$2"
	local timeout="$3"
	local mdtno

	for mdtno in $(seq 1 $MDSCOUNT); do
		local idx=$(($mdtno - 1))
		wait_update_facet --verbose mds${mdtno} \
			"$LCTL get_param -n $MDT_PREFIX${idx}.$key" "$target" \
			$timeout ||
			error "$key state is not '$target' on mds${mdtno}"
	done
}

cdt_set_mount_state() {
	mdts_set_param "-P" hsm_control "$1"
	# set_param -P is asynchronous operation and could race with set_param.
	# In such case configs could be retrieved and applied at mgc after
	# set_param -P completion. Sleep here to avoid race with set_param.
	# We need at least 20 seconds. 10 for mgc_requeue_thread to wake up
	# MGC_TIMEOUT_MIN_SECONDS + MGC_TIMEOUT_RAND_CENTISEC(5 + 5)
	# and 10 seconds to retrieve config from server.
	sleep 20
}

cdt_check_state() {
	mdts_check_param hsm_control "$1" 20
}

cdt_set_sanity_policy() {
	if [[ "$CDT_POLICY_HAD_CHANGED" ]]
	then
		# clear all
		mdts_set_param "" hsm.policy "+NRA"
		mdts_set_param "" hsm.policy "-NBR"
		CDT_POLICY_HAD_CHANGED=
	fi
}

set_hsm_param() {
	local param=$1
	local value=$2
	local opt=$3
	mdts_set_param "$opt -n" "hsm.$param" "$value"
	return $?
}

wait_request_state() {
	local fid=$1
	local request=$2
	local state=$3
	# 4th arg (mdt index) is optional
	local mdtidx=${4:-0}
	local mds=mds$(($mdtidx + 1))

	local cmd="$LCTL get_param -n ${MDT_PREFIX}${mdtidx}.hsm.actions"
	cmd+=" | awk '/'$fid'.*action='$request'/ {print \\\$13}' | cut -f2 -d="

	wait_update_facet --verbose $mds "$cmd" "$state" 200 ||
		error "request on $fid is not $state on $mds"
}


rmultiop_start() {
	local client=$1
	local file=$2
	local cmds=$3
	local WAIT_MAX=${4:-60}
	local wait_time=0

	# We need to run do_node in bg, because pdsh does not exit
	# if child process of run script exists.
	# I.e. pdsh does not exit when runmultiop_bg_pause exited,
	# because of multiop_bg_pause -> $MULTIOP_PROG &
	# By the same reason we need sleep a bit after do_nodes starts
	# to let runmultiop_bg_pause start muliop and
	# update /tmp/multiop_bg.pid ;
	# The rm /tmp/multiop_bg.pid guarantees here that
	# we have the updated by runmultiop_bg_pause
	# /tmp/multiop_bg.pid file

	local pid_file=$TMP/multiop_bg.pid.$$

	do_node $client "MULTIOP_PID_FILE=$pid_file LUSTRE= \
			runmultiop_bg_pause $file $cmds" &
	local pid=$!
	local multiop_pid

	while [[ $wait_time -lt $WAIT_MAX ]]; do
		sleep 3
		wait_time=$((wait_time + 3))
		multiop_pid=$(do_node $client cat $pid_file)
		if [ -n "$multiop_pid" ]; then
			break
		fi
	done

	[ -n "$multiop_pid" ] ||
		error "$client : Can not get multiop_pid from $pid_file "

	eval export $(node_var_name $client)_multiop_pid=$multiop_pid
	eval export $(node_var_name $client)_do_node_pid=$pid
	local var=$(node_var_name $client)_multiop_pid
	echo client $client multiop_bg started multiop_pid=${!var}
	return $?
}

rmultiop_stop() {
	local client=$1
	local multiop_pid=$(node_var_name $client)_multiop_pid
	local do_node_pid=$(node_var_name $client)_do_node_pid

	echo "Stopping multiop_pid=${!multiop_pid} (kill ${!multiop_pid} on $client)"
	do_node $client kill -USR1 ${!multiop_pid}

	wait ${!do_node_pid}
}

sleep_maxage() {
	local delay=$(do_facet mds1 lctl get_param -n lod.*.qos_maxage |
		      awk '{ print $1 + 5; exit; }')
	sleep $delay
}

sleep_maxage_lmv() {
	local delay=$(lctl get_param -n lmv.*.qos_maxage |
		      awk '{ print $1 + 5; exit; }')
	sleep $delay
}

check_component_count() {
	local comp_cnt=$($LFS getstripe --component-count $1)
	[ $comp_cnt -eq $2 ] || error "$1, component count $comp_cnt != $2"
}

# Verify there are no init components with "extension" flag
verify_no_init_extension() {
	local flg_opts="--component-flags init,extension"
	local found=$($LFS find $flg_opts $1 | wc -l)
	[ $found -eq 0 ] || error "$1 has component with initialized extension"
}

# Verify there is at least one component starting at 0
verify_comp_at_zero() {
	flg_opts="--component-flags init"
	found=$($LFS find --component-start 0M $flg_opts $1 | wc -l)
	[ $found -eq 1 ] ||
		error "No component starting at zero(!)"
}

# version after which Self-Extending Layouts are available
SEL_VER="2.12.55"

sel_layout_sanity() {
	local file=$1
	local comp_cnt=$2

	verify_no_init_extension $file
	verify_comp_at_zero $file
	check_component_count $file $comp_cnt
}

statx_supported() {
	$STATX --quiet --version
	return $?
}

# lfs rm_entry is disabled on native client
is_rmentry_supported() {
	$LFS rm_entry $DIR/dir/not/exists > /dev/null
	# is return code ENOENT?
	(( $? == 2 ))
}

#
# wrappers for createmany and unlinkmany
# to set debug=0 if number of creates is high enough
# this is to speedup testing
#
function createmany() {
	local count=${!#}
	local rc

	if (( count > 100 )); then
		debugsave
		do_nodes $(comma_list $(all_nodes)) $LCTL set_param -n debug=0
	fi
	$LUSTRE/tests/createmany $*
	rc=$?
	debugrestore > /dev/null

	return $rc
}

function unlinkmany() {
	local count=${!#}
	local rc

	if (( count > 100 )); then
		debugsave
		do_nodes $(comma_list $(all_nodes)) $LCTL set_param -n debug=0
	fi
	$LUSTRE/tests/unlinkmany $*
	rc=$?
	debugrestore > /dev/null

	return $rc
}

# Check if fallocate on facet is working. Returns fallocate mode if enabled.
# Takes optional facet name as argument, to allow separate MDS/OSS checks.
function check_fallocate_supported()
{
	local facet=${1:-ost1}
	local supported="FALLOCATE_SUPPORTED_$facet"
	local fstype="${facet}_FSTYPE"

	if [[ -n "${!supported}" ]]; then
		echo "${!supported}"
		return 0
	fi
	if [[ -z "${!fstype}" ]]; then
		eval export $fstype=$(facet_fstype $facet)
	fi
	if [[ "${!fstype}" != "ldiskfs" ]]; then
		echo "fallocate on ${!fstype} doesn't consume space" 1>&2
		return 1
	fi

	local fa_mode="osd-ldiskfs.$(facet_svc $facet).fallocate_zero_blocks"
	local mode=$(do_facet $facet $LCTL get_param -n $fa_mode 2>/dev/null |
		     head -n 1)
	! [[ "$facet" =~ "mds" ]] || # older MDS doesn't support fallocate
		(( MDS1_VERSION >= $(version_code v2_14_53-10-g163870abfb) )) ||
			mode=""

	if [[ -z "$mode" ]]; then
		echo "fallocate not supported on $facet" 1>&2
		return 1
	fi
	eval export $supported="$mode"

	echo ${!supported}
	return 0
}

# Check if fallocate supported on OSTs, enable if unset, skip if unavailable.
# Takes optional facet name as argument.
function check_fallocate_or_skip()
{
	local facet=$1

	check_fallocate_supported $1 || skip "fallocate not supported"
}

# Check if fallocate supported on OSTs, enable if unset, default mode=0
# Optionally pass the OST fallocate mode (0=unwritten extents, 1=zero extents)
function check_set_fallocate()
{
	local new_mode="$1"
	local fa_mode="osd-ldiskfs.*.fallocate_zero_blocks"
	local old_mode="$(check_fallocate_supported)"

	[[ -n "$old_mode" ]] || { echo "fallocate not supported"; return 1; }
	[[ -z "$new_mode" && "$old_mode" != "-1" ]] &&
		{ echo "keep default fallocate mode: $old_mode"; return 0; }
	[[ "$new_mode" && "$old_mode" == "$new_mode" ]] &&
		{ echo "keep current fallocate mode: $old_mode"; return 0; }
	local osts=$(comma_list $(osts_nodes))

	stack_trap "do_nodes $osts $LCTL set_param $fa_mode=$old_mode"
	do_nodes $osts $LCTL set_param $fa_mode=${new_mode:-0} ||
		error "set $fa_mode=$new_mode"
}

# Check if fallocate supported on OSTs, enable if unset, skip if unavailable
function check_set_fallocate_or_skip()
{
	check_set_fallocate || skip "need >= 2.13.57 and ldiskfs for fallocate"
}

function disable_opencache()
{
	local state=$($LCTL get_param -n "llite.*.opencache_threshold_count" |
			head -1)

	test -z "${saved_OPENCACHE_value}" &&
					export saved_OPENCACHE_value="$state"

	[[ "$state" = "off" ]] && return

	$LCTL set_param -n "llite.*.opencache_threshold_count"=off
}

function set_opencache()
{
	local newvalue="$1"
	local state=$($LCTL get_param -n "llite.*.opencache_threshold_count")

	[[ -n "$newvalue" ]] || return

	[[ -n "${saved_OPENCACHE_value}" ]] ||
					export saved_OPENCACHE_value="$state"

	$LCTL set_param -n "llite.*.opencache_threshold_count"=$newvalue
}



function restore_opencache()
{
	[[ -z "${saved_OPENCACHE_value}" ]] ||
		$LCTL set_param -n "llite.*.opencache_threshold_count"=${saved_OPENCACHE_value}
}

# LU-13417: XXX lots of tests assume the directory to be created under MDT0,
# created on MDT0, use this function to create directory on specific MDT
# explicitly, and set default LMV to create subdirs on the same MDT too.
mkdir_on_mdt() {
	local mdt
	local OPTIND=1

	while getopts "i:" opt $*; do
		case $opt in
			i) mdt=$OPTARG;;
		esac
	done

	shift $((OPTIND - 1))

	$LFS mkdir -i $mdt -c 1 $*
}

mkdir_on_mdt0() {
	mkdir_on_mdt -i0 $*
}

# Wait for nodemap synchronization
wait_nm_sync() {
	local nodemap_name=$1
	local key=$2
	local value=$3
	local opt=$4
	local proc_param
	local is_active=$(do_facet mgs $LCTL get_param -n nodemap.active)
	local max_retries=20
	local is_sync
	local out1=""
	local out2
	local mgs_ip=$(host_nids_address $mgs_HOST $NETTYPE | cut -d' ' -f1)
	local i

	if [ "$nodemap_name" == "active" ]; then
		proc_param="active"
	elif [ -z "$key" ]; then
		proc_param=${nodemap_name}
	else
		proc_param="${nodemap_name}.${key}"
	fi
	if [ "$opt" == "inactive" ]; then
		# check nm sync even if nodemap is not activated
		is_active=1
		opt=""
	fi
	(( is_active == 0 )) && [ "$proc_param" != "active" ] && return

	if [ -z "$value" ]; then
		out1=$(do_facet mgs $LCTL get_param $opt \
			nodemap.${proc_param} 2>/dev/null)
		echo "On MGS ${mgs_ip}, ${proc_param} = $out1"
	else
		out1=$value;
	fi

	# if servers run on the same node, it is impossible to tell if they get
	# synced with the mgs, so just wait an arbitrary 10 seconds
	if [ $(facet_active_host mgs) == $(facet_active_host mds) ] &&
	   [ $(facet_active_host mgs) == $(facet_active_host ost1) ]; then
		echo "waiting 10 secs for sync"
		sleep 10
		return
	fi

	# wait up to 10 seconds for other servers to sync with mgs
	for i in $(seq 1 10); do
		for node in $(all_server_nodes); do
			local node_ip=$(host_nids_address $node $NETTYPE |
					cut -d' ' -f1)

			is_sync=true
			if [ -z "$value" ]; then
				[ $node_ip == $mgs_ip ] && continue
			fi

			out2=$(do_node $node $LCTL get_param $opt \
			       nodemap.$proc_param 2>/dev/null)
			echo "On $node ${node_ip}, ${proc_param} = $out2"
			[ "$out1" != "$out2" ] && is_sync=false && break
		done
		$is_sync && break
		sleep 1
	done
	if ! $is_sync; then
		echo MGS
		echo $out1
		echo OTHER - IP: $node_ip
		echo $out2
		error "mgs and $nodemap_name ${key} mismatch, $i attempts"
	fi
	echo "waited $((i - 1)) seconds for sync"
}

consume_precreations() {
	local dir=$1
	local mfacet=$2
	local OSTIDX=$3
	local extra=${4:-2}
	local OST=$(ostname_from_index $OSTIDX $dir)

	mkdir_on_mdt -i $(facet_index $mfacet) $dir/${OST}
	$LFS setstripe -i $OSTIDX -c 1 ${dir}/${OST}

	# on the mdt's osc
	local mdtosc_proc=$(get_mdtosc_proc_path $mfacet $OST)
	local last_id=$(do_facet $mfacet $LCTL get_param -n \
			osp.$mdtosc_proc.prealloc_last_id)
	local next_id=$(do_facet $mfacet $LCTL get_param -n \
			osp.$mdtosc_proc.prealloc_next_id)
	echo "Creating to objid $last_id on ost $OST..."
	createmany -o $dir/${OST}/f $next_id $((last_id - next_id + extra))
}

__exhaust_precreations() {
	local OSTIDX=$1
	local FAILLOC=$2
	local FAILIDX=${3:-$OSTIDX}
	local ofacet=ost$((OSTIDX + 1))

	mkdir_on_mdt0 $DIR/$tdir
	local mdtidx=$($LFS getstripe -m $DIR/$tdir)
	local mfacet=mds$((mdtidx + 1))
	echo OSTIDX=$OSTIDX MDTIDX=$mdtidx

	local mdtosc_proc=$(get_mdtosc_proc_path $mfacet)
	do_facet $mfacet $LCTL get_param osp.$mdtosc_proc.prealloc*

#define OBD_FAIL_OST_ENOSPC              0x215
	do_facet $ofacet $LCTL set_param fail_val=$FAILIDX fail_loc=0x215

	consume_precreations $DIR/$tdir $mfacet $OSTIDX

	do_facet $mfacet $LCTL get_param osp.$mdtosc_proc.prealloc*
	do_facet $ofacet $LCTL set_param fail_loc=$FAILLOC
}

exhaust_precreations() {
	__exhaust_precreations $1 $2 $3
	sleep_maxage
}

exhaust_all_precreations() {
	local i
	for (( i=0; i < OSTCOUNT; i++ )) ; do
		__exhaust_precreations $i $1 -1
	done
	sleep_maxage
}

force_new_seq_ost() {
	local dir=$1
	local mfacet=$2
	local OSTIDX=$3
	local OST=$(ostname_from_index $OSTIDX)
	local mdtosc_proc=$(get_mdtosc_proc_path $mfacet $OST)

	do_facet $mfacet $LCTL set_param \
		osp.$mdtosc_proc.prealloc_force_new_seq=1
	# consume preallocated objects, to wake up precreate thread
	consume_precreations $dir $mfacet $OSTIDX
	do_facet $mfacet $LCTL set_param \
		osp.$mdtosc_proc.prealloc_force_new_seq=0
}

force_new_seq() {
	local mfacet=$1
	local MDTIDX=$(facet_index $mfacet)
	local MDT=$(mdtname_from_index $MDTIDX $DIR)
	local i

	mkdir_on_mdt -i $MDTIDX $DIR/${MDT}
	for (( i=0; i < OSTCOUNT; i++ )) ; do
		force_new_seq_ost $DIR/${MDT} $mfacet $i &
	done
	wait
	rm -rf $DIR/${MDT}
}

force_new_seq_all() {
	local i

	for (( i=0; i < MDSCOUNT; i++ )) ; do
		force_new_seq mds$((i + 1)) &
	done
	wait
	sleep_maxage
}

ost_set_temp_seq_width_all() {
	local osts=$(comma_list $(osts_nodes))
	local width=$(do_facet ost1 $LCTL get_param -n seq.*OST0000-super.width)

	do_nodes $osts $LCTL set_param seq.*OST*-super.width=$1
	stack_trap "do_nodes $osts $LCTL set_param seq.*OST*-super.width=$width"
}

verify_yaml_available() {
	python3 -c "import yaml; yaml.safe_load('''a: b''')"
}

verify_yaml() {
	python3 -c "import sys, yaml; obj = yaml.safe_load(sys.stdin)"
}

verify_compare_yaml() {
	python3 -c "import sys, yaml; f=open(\"$1\", \"r\"); obj1 = yaml.safe_load(f); f=open(\"$2\", \"r\"); obj2 = yaml.safe_load(f); sys.exit(obj1 != obj2)"
}

zfs_or_rotational() {
	local ost_idx=0
	local ost_name=$(ostname_from_index $ost_idx $MOUNT)
	local param="get_param -n osd-*.${ost_name}.nonrotational"
	local nonrotat=$(do_facet ost1 $LCTL $param)

	if [[ -z "$nonrotat" ]]; then
		# At this point there is no point moving ahead.
		# Will stop here and dump all the info
		set -x
		local ost_name=$(ostname_from_index $ost_idx)
		set +x
		error "$LCTL $input_str"
	fi

	if [[ "$ost1_FSTYPE" == "zfs" ]] || (( "$nonrotat" == 0 )); then
		return 0
	else
		return 1
	fi
}
