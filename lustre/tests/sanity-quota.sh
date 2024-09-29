#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
set -e

ONLY=${ONLY:-"$*"}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
init_logging

ALWAYS_EXCEPT="$SANITY_QUOTA_EXCEPT "
# Bug number for skipped test:
ALWAYS_EXCEPT+=""
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

# Test duration:                   30 min
[ "$SLOW" = "no" ] && EXCEPT_SLOW="61"

if [ "$mds1_FSTYPE" = zfs ]; then
	# bug number:                        LU-2887
	# Test duration:                     21      9 min"
	[ "$SLOW" = "no" ] && EXCEPT_SLOW+=" 12a     9"
fi

build_test_filter

DIRECTIO=${DIRECTIO:-$LUSTRE/tests/directio}
ORIG_PWD=${PWD}
TSTID=${TSTID:-"$(id -u $TSTUSR)"}
TSTID2=${TSTID2:-"$(id -u $TSTUSR2)"}
TSTPRJID=${TSTPRJID:-1000}
BLK_SZ=1024
MAX_DQ_TIME=604800
MAX_IQ_TIME=604800
QTYPE="ugp"
VERSION_WITH_QP="2.13.53"
mds_supports_qp() {
	[ $MDS1_VERSION -lt $(version_code $VERSION_WITH_QP) ] &&
		skip "Needs MDS version $VERSION_WITH_QP or later."
}

require_dsh_mds || exit 0
require_dsh_ost || exit 0

# Does e2fsprogs support quota feature?
if [ "$mds1_FSTYPE" == ldiskfs ] &&
	do_facet $SINGLEMDS "! $DEBUGFS -c -R supported_features |
		grep -q 'quota'"; then
	skip_env "e2fsprogs doesn't support quota"
fi

QUOTALOG=${TESTSUITELOG:-$TMP/$(basename $0 .sh).log}

[ "$QUOTALOG" ] && rm -f $QUOTALOG || true

DIR=${DIR:-$MOUNT}
DIR2=${DIR2:-$MOUNT2}

QUOTA_AUTO_OLD=$QUOTA_AUTO
export QUOTA_AUTO=0

check_and_setup_lustre

ENABLE_PROJECT_QUOTAS=${ENABLE_PROJECT_QUOTAS:-true}
is_project_quota_supported || echo "project quota not supported/enabled"

SHOW_QUOTA_USER="$LFS quota -v -u $TSTUSR $DIR"
SHOW_QUOTA_USERID="$LFS quota -v -u $TSTID $DIR"
SHOW_QUOTA_GROUP="$LFS quota -v -g $TSTUSR $DIR"
SHOW_QUOTA_GROUPID="$LFS quota -v -g $TSTID $DIR"
SHOW_QUOTA_PROJID="eval is_project_quota_supported && $LFS quota -v -p $TSTPRJID $DIR"
SHOW_QUOTA_INFO_USER="$LFS quota -t -u $DIR"
SHOW_QUOTA_INFO_GROUP="$LFS quota -t -g $DIR"
SHOW_QUOTA_INFO_PROJID="eval is_project_quota_supported && $LFS quota -t -p $DIR"

lustre_fail() {
	local fail_node=$1
	local fail_loc=$2
	local fail_val=${3:-0}
	local NODES=

	case $fail_node in
	mds_ost|mdt_ost) NODES="$(comma_list $(mdts_nodes) $(osts_nodes))";;
	mds|mdt) NODES="$(comma_list $(mdts_nodes))";;
	ost) NODES="$(comma_list $(osts_nodes))";;
	esac

	do_nodes $NODES "lctl set_param fail_val=$fail_val fail_loc=$fail_loc"
}

RUNAS="runas -u $TSTID -g $TSTID"
RUNAS2="runas -u $TSTID2 -g $TSTID2"
DD="dd if=/dev/zero bs=1M"

FAIL_ON_ERROR=false

# clear quota limits for a user or a group
# usage: resetquota -u username
#        resetquota -g groupname
#	 resetquota -p projid

resetquota_one() {
	$LFS setquota "$1" "$2" -b 0 -B 0 -i 0 -I 0 $MOUNT ||
		error "clear quota for [type:$1 name:$2] failed"
}

resetquota() {
	(( "$#" == 2 )) || error "resetquota: wrong number of arguments: '$*'"
	[[ "$1" == "-u" || "$1" == "-g" || "$1" == "-p" ]] ||
		error "resetquota: wrong quota type '$1' passed"

	resetquota_one "$1" "$2"

	# give a chance to slave to release space
	sleep 1
}

quota_scan() {
	local local_ugp=$1
	local local_id=$2
	local count

	if [ "$local_ugp" == "a" -o "$local_ugp" == "u" ]; then
		$LFS quota -v -u $local_id $DIR
		count=$($LFS find --user $local_id $DIR | wc -l)
		log "Files for user ($local_id), count=$count:"
		($LFS find --user $local_id $DIR | head -n 4 |
			xargs stat 2>/dev/null)
	fi

	if [ "$local_ugp" == "a" -o "$local_ugp" == "g" ]; then
		$LFS quota -v -g $local_id $DIR
		count=$($LFS find --group $local_id $DIR | wc -l)
		log "Files for group ($local_id), count=$count:"
		($LFS find --group $local_id $DIR | head -n 4 |
			xargs stat 2>/dev/null)
	fi

	is_project_quota_supported || return 0
	if [ "$local_ugp" == "a" -o "$local_ugp" == "p" ]; then
		$LFS quota -v -p $TSTPRJID $DIR
		count=$($LFS find --projid $TSTPRJID $DIR | wc -l)
		log "Files for project ($TSTPRJID), count=$count:"
		($LFS find --projid $TSTPRJID $DIR | head -n 4 |
			xargs stat 2>/dev/null)
	fi
}

quota_error() {
	quota_scan $1 $2
	shift 2
	error "$*"
}

quota_log() {
	quota_scan $1 $2
	shift 2
	log "$*"
}

wait_reintegration() {
	local ntype=$1
	local qtype=$2
	local max=$3
	local result="glb[1],slv[1],reint[0]"
	local varsvc
	local cmd
	local tgts

	if [ $ntype == "mdt" ]; then
		tgts=$(get_facets MDS)
	else
		tgts=$(get_facets OST)
	fi

	for tgt in ${tgts//,/ }; do
		varsvc=${tgt}_svc
		cmd="$LCTL get_param -n "
		cmd=${cmd}osd-$(facet_fstype $tgt).${!varsvc}
		cmd=${cmd}.quota_slave.info

		if $(facet_up $tgt); then
			# reintegration starts after recovery completion
			wait_recovery_complete $tgt
			wait_update_facet $tgt "$cmd |
				grep "$qtype" | awk '{ print \\\$3 }'" \
					"$result" $max || return 1
		fi
	done
	return 0
}

wait_mdt_reint() {
	local qtype=$1
	local max=${2:-90}

	if [[ "$qtype" =~ "u" ]]; then
		wait_reintegration "mdt" "user" $max || return 1
	fi

	if [[ "$qtype" =~ "g" ]]; then
		wait_reintegration "mdt" "group" $max || return 1
	fi

	if [[ "$qtype" =~ "p" ]]; then
		! is_project_quota_supported && return 0
		wait_reintegration "mdt" "project" $max || return 1
	fi
	return 0
}

wait_ost_reint() {
	local qtype=$1
	local max=${2:-90}

	if [[ "$qtype" =~ "u" ]]; then
		wait_reintegration "ost" "user" $max || return 1
	fi

	if [[ "$qtype" =~ "g" ]]; then
		wait_reintegration "ost" "group" $max || return 1
	fi

	if [[ "$qtype" =~ "p" ]]; then
		! is_project_quota_supported && return 0
		wait_reintegration "ost" "project" $max || return 1
	fi
	return 0
}

wait_grace_time() {
	local qtype=$1
	local flavour=$2
	local pool=${3:-}
	local extrasleep=${4:-5}
	local qarg
	local parg

	case $qtype in
		u|g) qarg=$TSTUSR ;;
		p) qarg=$TSTPRJID ;;
		*) error "get_grace_time: Invalid quota type: $qtype"
	esac

	if [ $pool ]; then
		parg="--pool "$pool
		echo "Quota info for $pool:"
		$LFS quota -$qtype $qarg $parg $DIR
	fi

	case $flavour in
		block)
			time=$(lfs quota -$qtype $qarg $parg $DIR|
				   awk 'NR == 3{ print $5 }')
			;;
		file)
			time=$(lfs quota -$qtype $qarg $DIR|
				   awk 'NR == 3{ print $9 }')
			;;
		*)
			error "Unknown quota type: $flavour"
			;;
	esac

	local sleep_seconds=0
	local orig_time=$time

	echo "Grace time is $time"
	# from lfs.c:__sec2str()
	# const char spec[] = "smhdw";
	# {1, 60, 60*60, 24*60*60, 7*24*60*60};
	[[ $time == *w* ]] && w_time=${time%w*} &&
		let sleep_seconds+=$((w_time*7*24*60*60));
	time=${time#*w}
	[[ $time == *d* ]] && d_time=${time%d*} &&
		let sleep_seconds+=$((d_time*24*60*60));
	time=${time#*d}
	[[ $time == *h* ]] && h_time=${time%h*} &&
		let sleep_seconds+=$((h_time*60*60));
	time=${time#*h}
	[[ $time == *m* ]] && m_time=${time%m*} &&
		let sleep_seconds+=$((m_time*60));
	time=${time#*m}
	[[ $time == *s* ]] && s_time=${time%s*} &&
		let sleep_seconds+=$s_time

	echo "Sleep through grace ..."
	[ "$orig_time" == "-" ] &&
	    error "Grace timeout was not set or quota not exceeded"
	if [ "$orig_time" == "expired" -o "$orig_time" == "none" ]; then
	    echo "...Grace timeout already expired"
	else
		let sleep_seconds+=$extrasleep
		echo "...sleep $sleep_seconds seconds"
		sleep $sleep_seconds
	fi
}

setup_quota_test() {
	wait_delete_completed
	echo "Creating test directory"
	mkdir_on_mdt0 $DIR/$tdir || return 1
	chmod 0777 $DIR/$tdir || return 2
	# always clear fail_loc in case of fail_loc isn't cleared
	# properly when previous test failed
	lustre_fail mds_ost 0
	stack_trap cleanup_quota_test EXIT
}

cleanup_quota_test() {
	echo "Delete files..."
	rm -rf $DIR/$tdir
	[ -d $DIR/${tdir}_dom ] && rm -rf $DIR/${tdir}_dom
	echo "Wait for unlink objects finished..."
	wait_delete_completed
	sync_all_data || true
	reset_quota_settings
}

quota_show_check() {
	local bf=$1
	local ugp=$2
	local qid=$3
	local usage

	$LFS quota -v -$ugp $qid $DIR

	if [ "$bf" == "a" -o "$bf" == "b" ]; then
		usage=$(getquota -$ugp $qid global curspace)
		if [ -z $usage ]; then
			quota_error $ugp $qid \
				"Query block quota failed ($ugp:$qid)."
		else
			[ $usage -ne 0 ] && quota_log $ugp $qid \
				"Block quota isn't 0 ($ugp:$qid:$usage)."
		fi
	fi

	if [ "$bf" == "a" -o "$bf" == "f" ]; then
		usage=$(getquota -$ugp $qid global curinodes)
		if [ -z $usage ]; then
			quota_error $ugp $qid \
				"Query file quota failed ($ugp:$qid)."
		else
			[ $usage -ne 0 ] && quota_log $ugp $qid \
				"File quota isn't 0 ($ugp:$qid:$usage)."
		fi
	fi
}

project_quota_enabled () {
	local rc=0
	local zfeat="feature@project_quota"

	for facet in $(seq -f mds%g $MDSCOUNT) $(seq -f ost%g $OSTCOUNT); do
		local facet_fstype=${facet:0:3}1_FSTYPE
		local devname

		if [ "${!facet_fstype}" = "zfs" ]; then
			devname=$(zpool_name ${facet})
			do_facet ${facet} $ZPOOL get -H "$zfeat" $devname |
				grep -wq active || rc=1
		else
			[ ${facet:0:3} == "mds" ] &&
				devname=$(mdsdevname ${facet:3}) ||
				devname=$(ostdevname ${facet:3})
			do_facet ${facet} $DEBUGFS -R features $devname |
				grep -q project || rc=1
		fi
	done
	[ $rc -eq 0 ] && PQ_CLEANUP=false || PQ_CLEANUP=true
	return $rc
}

project_quota_enabled || enable_project_quota

reset_quota_settings() {
	resetquota_one -u $TSTUSR
	[[ $(id -u $TSTUSR) == $TSTID ]] || resetquota_one -u $TSTID
	resetquota_one -g $TSTUSR
	[[ $(id -g $TSTUSR) == $TSTID ]] || resetquota_one -g $TSTID
	resetquota_one -u $TSTUSR2
	[[ $(id -u $TSTUSR2) == $TSTID2 ]] || resetquota_one -u $TSTID2
	resetquota_one -g $TSTUSR2
	[[ $(id -g $TSTUSR2) == $TSTID2 ]] || resetquota_one -g $TSTID2
	is_project_quota_supported && resetquota_one -p $TSTPRJID

	$LFS setquota -U -b 0 -B 0 -i 0 -I 0 $MOUNT ||
		error "failed to reset default user quota"
	$LFS setquota -G -b 0 -B 0 -i 0 -I 0 $MOUNT ||
		error "failed to reset default group quota"
	is_project_quota_supported &&
		$LFS setquota -P -b 0 -B 0 -i 0 -I 0 $MOUNT ||
			error "failed to reset default project quota"

	sleep 1
}

get_quota_on_qsd() {
	local facet
	local device
	local spec
	local qid
	local qtype
	local output

	facet=$1
	device=$2
	case "$3" in
		usr) qtype="limit_user";;
		grp) qtype="limit_group";;
		prj) qtype="limit_project";;
		*)	   error "unknown quota parameter $3";;
	esac

	qid=$4
	case "$5" in
		hardlimit) spec=4;;
		softlimit) spec=6;;
		*)	   error "unknown quota parameter $5";;
	esac

	do_facet $facet $LCTL get_param osd-*.*-${device}.quota_slave.$qtype |
		awk '($3 == '$qid') {getline; print $'$spec'; exit;}' | tr -d ,
}

wait_quota_synced() {
	local value
	local facet=$1
	local device=$2
	local qtype=$3
	local qid=$4
	local limit_type=$5
	local limit_val=$6
	local interval=0

	value=$(get_quota_on_qsd $facet $device $qtype $qid $limit_type)
	while [[ $value != $limit_val ]]; do
		(( interval != 0 )) ||
			do_facet $facet $LCTL set_param \
				osd-*.*-${device}.quota_slave.force_reint=1

		echo $value
		(( interval <= 20 )) ||
			error "quota ($value) don't update on QSD, $limit_val"

		interval=$((interval + 1))
		sleep 1

		value=$(get_quota_on_qsd $facet $device $qtype $qid $limit_type)
	done
}

# make sure the system is clean
check_system_is_clean() {
	local used

	lfs quota -v -u $TSTUSR $MOUNT
	for cur in "curspace" "curinodes";
	do
		used=$(getquota -u $TSTUSR global $cur)
		[ $used -ne 0 ] && quota_error u $TSTUSR \
			"Used ${cur:3}($used) for user $TSTUSR isn't 0."

		used=$(getquota -u $TSTUSR2 global $cur)
		[ $used -ne 0 ] && quota_error u $TSTUSR2 \
			"Used ${cur:3}($used) for user $TSTUSR2 isn't 0."

		used=$(getquota -g $TSTUSR global $cur)
		[ $used -ne 0 ] && quota_error g $TSTUSR \
			"Used ${cur:3}($used) for group $TSTUSR isn't 0."

		used=$(getquota -g $TSTUSR2 global $cur)
		[ $used -ne 0 ] && quota_error g $TSTUSR2 \
			"Used ${cur:3}($used) for group $TSTUSR2 isn't 0."

		if is_project_quota_supported; then
			used=$(getquota -p $TSTPRJID global $cur)
			[ $used -ne 0 ] && quota_error p $TSTPRJID \
				"Used ${cur:3}($used) for project $TSTPRJID isn't 0"
		fi
	done
	return 0
}

# enable quota debug
quota_init() {
	do_nodes $(comma_list $(nodes_list)) \
		"$LCTL set_param -n debug=+quota+trace"
}
quota_init
reset_quota_settings

check_runas_id_ret $TSTUSR $TSTUSR $RUNAS ||
	error "Please create user $TSTUSR($TSTID) and group $TSTUSR($TSTID)"
check_runas_id_ret $TSTUSR2 $TSTUSR2 $RUNAS2 ||
	error "Please create user $TSTUSR2($TSTID2) and group $TSTUSR2($TSTID2)"
check_system_is_clean

test_quota_performance() {
	local TESTFILE="$DIR/$tdir/$tfile-0"
	local size=$1 # in MB
	local stime=$(date +%s)
	$RUNAS $DD of=$TESTFILE count=$size conv=fsync ||
		quota_error u $TSTUSR "write failure"
	local etime=$(date +%s)
	delta=$((etime - stime))
	if [ $delta -gt 0 ]; then
		rate=$((size * 1024 / delta))
		if [ "$mds1_FSTYPE" = zfs ]; then
			# LU-2872 - see LU-2887 for fix
			[ $rate -gt 64 ] ||
				error "SLOW IO for $TSTUSR (user): $rate KB/sec"
		else
			[ $rate -gt 1024 ] ||
				error "SLOW IO for $TSTUSR (user): $rate KB/sec"
		fi
	fi
	rm -f $TESTFILE
}

# test basic quota performance b=21696
test_0() {
	local MB=100 # MB
	[ "$SLOW" = "no" ] && MB=10

	local free_space=$(lfs_df | grep "summary" | awk '{print $4}')
	[ $free_space -le $((MB * 1024)) ] &&
		skip "not enough space ${free_space} KB, " \
			"required $((MB * 1024)) KB"
	setup_quota_test || error "setup quota failed with $?"

	set_ost_qtype "none" || error "disable ost quota failed"
	test_quota_performance $MB

	set_ost_qtype $QTYPE || error "enable ost quota failed"
	$LFS setquota -u $TSTUSR -b 0 -B 10G -i 0 -I 0 $DIR ||
		error "set quota failed"
	test_quota_performance $MB
}
run_test 0 "Test basic quota performance"

# usage: test_1_check_write tfile user|group|project
test_1_check_write() {
	local testfile="$1"
	local qtype="$2"
	local limit=$3
	local short_qtype=${qtype:0:1}

	log "Write..."
	$RUNAS $DD of=$testfile count=$((limit/2)) ||
		quota_error $short_qtype $TSTUSR \
			"$qtype write failure, but expect success"
	log "Write out of block quota ..."
	# this time maybe cache write, ignore it's failure
	$RUNAS $DD of=$testfile count=$((limit/2)) seek=$((limit/2)) || true
	# flush cache, ensure noquota flag is set on client
	cancel_lru_locks osc
	sync; sync_all_data || true
	# sync means client wrote all it's cache, but id doesn't
	# guarantee that slave received new edquot through glimpse.
	# so wait a little to be sure slave got it.
	sleep 5
	$RUNAS $DD of=$testfile count=1 seek=$limit &&
		quota_error $short_qtype $TSTUSR \
			"user write success, but expect EDQUOT"
	return 0
}

check_write_fallocate() {
	local testfile="$1"
	local qtype="$2"
	local limit=$3
	local short_qtype=${qtype:0:1}

	count=$((limit/2))
	log "Write ${count}MiB Using Fallocate"
	$RUNAS fallocate -l${count}MiB $testfile ||
		quota_error $short_qtype $TSTUSR "Write ${count}MiB fail"

	cancel_lru_locks osc
	sync; sync_all_data || true
	sleep 2

	count=$((limit + 1))
	log "Write ${count}MiB Using Fallocate"
	$RUNAS fallocate -l${count}MiB $testfile &&
		quota_error $short_qtype $TSTUSR \
		"Write success, expect EDQUOT" || true
}

# test block hardlimit
test_1a() {
	local limit=10 # MB
	local testfile="$DIR/$tdir/$tfile-0"

	setup_quota_test || error "setup quota failed with $?"

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# test for user
	log "User quota (block hardlimit:$limit MB)"
	$LFS setquota -u $TSTUSR -b 0 -B ${limit}M -i 0 -I 0 $DIR ||
		error "set user quota failed"

	# make sure the system is clean
	local used=$(getquota -u $TSTUSR global curspace)
	[ $used -ne 0 ] && error "Used space($used) for user $TSTUSR isn't 0."

	$LFS setstripe $testfile -i 0 -c 1 || error "setstripe $testfile failed"
	chown $TSTUSR.$TSTUSR $testfile || error "chown $testfile failed"

	wait_quota_synced ost1 OST0000 usr $TSTID hardlimit $((limit*1024))

	test_1_check_write $testfile "user" $limit

	rm -f $testfile
	wait_delete_completed || error "wait_delete_completed failed"
	sync_all_data || true
	used=$(getquota -u $TSTUSR global curspace)
	[ $used -ne 0 ] && quota_error u $TSTUSR \
		"user quota isn't released after deletion"
	resetquota -u $TSTUSR

	# test for group
	log "--------------------------------------"
	log "Group quota (block hardlimit:$limit MB)"
	$LFS setquota -g $TSTUSR -b 0 -B ${limit}M -i 0 -I 0 $DIR ||
		error "set group quota failed"

	testfile="$DIR/$tdir/$tfile-1"
	# make sure the system is clean
	used=$(getquota -g $TSTUSR global curspace)
	[ $used -ne 0 ] && error "Used space ($used) for group $TSTUSR isn't 0"

	$LFS setstripe $testfile -i 0 -c 1 || error "setstripe $testfile failed"
	chown $TSTUSR.$TSTUSR $testfile || error "chown $testfile failed"

	wait_quota_synced ost1 OST0000 grp $TSTID hardlimit $((limit*1024))

	test_1_check_write $testfile "group" $limit
	rm -f $testfile
	wait_delete_completed || error "wait_delete_completed failed"
	sync_all_data || true
	used=$(getquota -g $TSTUSR global curspace)
	[ $used -ne 0 ] && quota_error g $TSTUSR \
				"Group quota isn't released after deletion"
	resetquota -g $TSTUSR

	if ! is_project_quota_supported; then
		echo "Project quota is not supported"
		return 0
	fi

	testfile="$DIR/$tdir/$tfile-2"
	# make sure the system is clean
	used=$(getquota -p $TSTPRJID global curspace)
	[ $used -ne 0 ] &&
		error "used space($used) for project $TSTPRJID isn't 0"

	# test for Project
	log "--------------------------------------"
	log "Project quota (block hardlimit:$limit mb)"
	$LFS setquota -p $TSTPRJID -b 0 -B ${limit}M -i 0 -I 0 $DIR ||
		error "set project quota failed"

	$LFS setstripe $testfile -i 0 -c 1 || error "setstripe $testfile failed"
	chown $TSTUSR:$TSTUSR $testfile || error "chown $testfile failed"
	change_project -p $TSTPRJID $testfile

	wait_quota_synced ost1 OST0000 prj $TSTPRJID hardlimit $((limit*1024))

	test_1_check_write $testfile "project" $limit

	# cleanup
	cleanup_quota_test

	used=$(getquota -p $TSTPRJID global curspace)
	[ $used -ne 0 ] && quota_error p $TSTPRJID \
		"project quota isn't released after deletion"

	resetquota -p $TSTPRJID
}
run_test 1a "Block hard limit (normal use and out of quota)"

test_1b() {
	(( MDS1_VERSION >= $(version_code 2.15.55) )) ||
		skip "Need MDS version at least 2.15.55"

	local limit=10 # MB
	local global_limit=20 # MB
	local testfile="$DIR/$tdir/$tfile-0"
	local qpool="qpool1"

	mds_supports_qp
	setup_quota_test || error "setup quota failed with $?"

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# test for user
	log "User quota (block hardlimit:$global_limit MB)"
	$LFS setquota -u $TSTUSR -b 0 -B ${global_limit}M -i 0 -I 0 $DIR ||
		error "set user quota failed"

	wait_quota_synced ost1 OST0000 usr $TSTID hardlimit \
							$((global_limit*1024))

	pool_add $qpool || error "pool_add failed"
	pool_add_targets $qpool 0 $(($OSTCOUNT - 1)) ||
		error "pool_add_targets failed"

	# check qmt_pool_add dmesg error
	local msg_rgx="QMT0000: can't add to $FSNAME-OST0000.*pool.*$qpool"
	local dmesg_err
	dmesg_err=$(do_facet mds1 dmesg | grep "$msg_rgx" | tail -1)
	[[ -z "$dmesg_err" ]] || error "found qmt_pool_add error: $dmesg_err"

	$LFS setquota -u $TSTUSR -B ${limit}M --pool $qpool $DIR ||
		error "set user quota failed"

	# make sure the system is clean
	local used=$(getquota -u $TSTUSR global curspace)
	echo "used $used"
	[ $used -ne 0 ] && error "Used space($used) for user $TSTUSR isn't 0."

	used=$(getquota -u $TSTUSR global bhardlimit $qpool)

	$LFS setstripe $testfile -i 0 -c 1 || error "setstripe $testfile failed"
	chown $TSTUSR.$TSTUSR $testfile || error "chown $testfile failed"

	test_1_check_write $testfile "user" $limit

	rm -f $testfile
	wait_delete_completed || error "wait_delete_completed failed"
	sync_all_data || true
	used=$(getquota -u $TSTUSR global curspace $qpool)
	[ $used -ne 0 ] && quota_error u $TSTUSR \
		"user quota isn't released after deletion"
	resetquota -u $TSTUSR

	# test for group
	log "--------------------------------------"
	log "Group quota (block hardlimit:$global_limit MB)"
	$LFS setquota -g $TSTUSR -b 0 -B ${global_limit}M -i 0 -I 0 $DIR ||
		error "set group quota failed"

	$LFS setquota -g $TSTUSR -b 0 -B ${limit}M --pool $qpool $DIR ||
		error "set group quota failed"

	wait_quota_synced ost1 OST0000 grp $TSTID hardlimit \
							$((global_limit*1024))

	testfile="$DIR/$tdir/$tfile-1"
	# make sure the system is clean
	used=$(getquota -g $TSTUSR global curspace $qpool)
	[ $used -ne 0 ] && error "Used space ($used) for group $TSTUSR isn't 0"

	$LFS setstripe $testfile -i 0 -c 1 || error "setstripe $testfile failed"
	chown $TSTUSR.$TSTUSR $testfile || error "chown $testfile failed"

	test_1_check_write $testfile "group" $limit

	rm -f $testfile
	wait_delete_completed || error "wait_delete_completed failed"
	sync_all_data || true
	used=$(getquota -g $TSTUSR global curspace $qpool)
	[ $used -ne 0 ] && quota_error g $TSTUSR \
				"Group quota isn't released after deletion"
	resetquota -g $TSTUSR

	if ! is_project_quota_supported; then
		echo "Project quota is not supported"
		return 0
	fi

	testfile="$DIR/$tdir/$tfile-2"
	# make sure the system is clean
	used=$(getquota -p $TSTPRJID global curspace $qpool)
	[ $used -ne 0 ] &&
		error "used space($used) for project $TSTPRJID isn't 0"

	# test for Project
	log "--------------------------------------"
	log "Project quota (block hardlimit:$global_limit mb)"
	$LFS setquota -p $TSTPRJID -b 0 -B ${global_limit}M -i 0 -I 0 $DIR ||
		error "set project quota failed"

	$LFS setquota -p $TSTPRJID -b 0 -B ${limit}M --pool $qpool $DIR ||
		error "set project quota failed"

	wait_quota_synced ost1 OST0000 prj $TSTPRJID hardlimit \
							$((global_limit*1024))

	$LFS setstripe $testfile -i 0 -c 1 || error "setstripe $testfile failed"
	chown $TSTUSR:$TSTUSR $testfile || error "chown $testfile failed"
	change_project -p $TSTPRJID $testfile

	test_1_check_write $testfile "project" $limit

	# cleanup
	cleanup_quota_test

	used=$(getquota -p $TSTPRJID global curspace)
	[ $used -eq 0 ] || quota_error p $TSTPRJID \
		"project quota isn't released after deletion"
}
run_test 1b "Quota pools: Block hard limit (normal use and out of quota)"

test_1c() {
	local global_limit=20 # MB
	local testfile="$DIR/$tdir/$tfile-0"
	local qpool1="qpool1"
	local qpool2="qpool2"

	mds_supports_qp
	setup_quota_test || error "setup quota failed with $?"

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# test for user
	log "User quota (block hardlimit:$global_limit MB)"
	$LFS setquota -u $TSTUSR -b 0 -B ${global_limit}M -i 0 -I 0 $DIR ||
		error "set user quota failed"

	wait_quota_synced ost1 OST0000 usr $TSTID hardlimit \
							$((global_limit*1024))

	pool_add $qpool1 || error "pool_add failed"
	pool_add_targets $qpool1 0 $(($OSTCOUNT - 1)) ||
		error "pool_add_targets failed"

	pool_add $qpool2 || error "pool_add failed"
	pool_add_targets $qpool2 0 $(($OSTCOUNT - 1)) ||
		error "pool_add_targets failed"

	# create pools without hard limit
	# initially such case raised several bugs
	$LFS setquota -u $TSTUSR -B 0M --pool $qpool1 $DIR ||
		error "set user quota failed"

	$LFS setquota -u $TSTUSR -B 0M --pool $qpool2 $DIR ||
		error "set user quota failed"

	# make sure the system is clean
	local used=$(getquota -u $TSTUSR global curspace)
	echo "used $used"
	[ $used -ne 0 ] && error "Used space($used) for user $TSTUSR isn't 0."

	used=$(getquota -u $TSTUSR global bhardlimit $qpool)

	$LFS setstripe $testfile -i 0 -c 1 || error "setstripe $testfile failed"
	chown $TSTUSR.$TSTUSR $testfile || error "chown $testfile failed"

	test_1_check_write $testfile "user" $global_limit

	used=$(getquota -u $TSTUSR global curspace $qpool1)
	echo "qpool1 used $used"
	used=$(getquota -u $TSTUSR global curspace $qpool2)
	echo "qpool2 used $used"

	rm -f $testfile
	wait_delete_completed || error "wait_delete_completed failed"
	sync_all_data || true

	used=$(getquota -u $TSTUSR global curspace $qpool1)
	[ $used -eq 0 ] || quota_error u $TSTUSR \
		"user quota isn't released after deletion"
}
run_test 1c "Quota pools: check 3 pools with hardlimit only for global"

test_1d() {
	local limit1=10 # MB
	local limit2=12 # MB
	local global_limit=20 # MB
	local testfile="$DIR/$tdir/$tfile-0"
	local qpool1="qpool1"
	local qpool2="qpool2"

	mds_supports_qp
	setup_quota_test || error "setup quota failed with $?"

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# test for user
	log "User quota (block hardlimit:$global_limit MB)"
	$LFS setquota -u $TSTUSR -b 0 -B ${global_limit}M -i 0 -I 0 $DIR ||
		error "set user quota failed"

	pool_add $qpool1 || error "pool_add failed"
	pool_add_targets $qpool1 0 $(($OSTCOUNT - 1)) ||
		error "pool_add_targets failed"

	pool_add $qpool2 || error "pool_add failed"
	pool_add_targets $qpool2 0 $(($OSTCOUNT - 1)) ||
		error "pool_add_targets failed"

	$LFS setquota -u $TSTUSR -B ${limit1}M --pool $qpool1 $DIR ||
		error "set user quota failed"

	$LFS setquota -u $TSTUSR -B ${limit2}M --pool $qpool2 $DIR ||
	error "set user quota failed"

	# make sure the system is clean
	local used=$(getquota -u $TSTUSR global curspace)
	echo "used $used"
	[ $used -ne 0 ] && error "used space($used) for user $TSTUSR isn't 0."

	used=$(getquota -u $TSTUSR global bhardlimit $qpool)

	test_1_check_write $testfile "user" $limit1

	used=$(getquota -u $TSTUSR global curspace $qpool1)
	echo "qpool1 used $used"
	used=$(getquota -u $TSTUSR global curspace $qpool2)
	echo "qpool2 used $used"

	rm -f $testfile
	wait_delete_completed || error "wait_delete_completed failed"
	sync_all_data || true

	used=$(getquota -u $TSTUSR global curspace $qpool1)
	[ $used -eq 0 ] || quota_error u $TSTUSR \
		"user quota isn't released after deletion"
}
run_test 1d "Quota pools: check block hardlimit on different pools"

test_1e() {
	local limit1=10 # MB
	local global_limit=53000000 # MB
	local testfile="$DIR/$tdir/$tfile-0"
	local testfile2="$DIR/$tdir/$tfile-1"
	local qpool1="qpool1"

	mds_supports_qp
	setup_quota_test || error "setup quota failed with $?"

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# global_limit is much greater than limit1 to get
	# different qunit's on osts. Since 1st qunit shrinking
	# on OST1(that belongs to qpool1), this qunit should
	# be sent to OST1.
	log "User quota (block hardlimit:$global_limit MB)"
	$LFS setquota -u $TSTUSR -b 0 -B ${global_limit}M -i 0 -I 0 $DIR ||
		error "set user quota failed"

	pool_add $qpool1 || error "pool_add failed"
	pool_add_targets $qpool1 1 1 ||
		error "pool_add_targets failed"

	$LFS setquota -u $TSTUSR -B ${limit1}M --pool $qpool1 $DIR ||
		error "set user quota failed"

	# make sure the system is clean
	local used=$(getquota -u $TSTUSR global curspace)
	[ $used -ne 0 ] && error "Used space($used) for user $TSTUSR isn't 0."

	$LFS setstripe $testfile -c 1 -i 1 || error "setstripe $testfile failed"
	chown $TSTUSR.$TSTUSR $testfile || error "chown $testfile failed"

	test_1_check_write $testfile "user" $limit1

	$LFS setstripe $testfile2 -c 1 -i 0 ||
		error "setstripe $testfile2 failed"
	chown $TSTUSR.$TSTUSR $testfile2 || error "chown $testfile2 failed"
	# Now write to file with a stripe on OST0, that doesn't belong to qpool1
	log "Write..."
	$RUNAS $DD of=$testfile2 count=20 ||
		quota_error u $TSTUSR \
			"$qtype write failure, but expect success"

	rm -f $testfile
	rm -f $testfile2
	wait_delete_completed || error "wait_delete_completed failed"
	sync_all_data || true

	used=$(getquota -u $TSTUSR global curspace $qpool1)
	[ $used -eq 0 ] || quota_error u $TSTUSR \
		"user quota isn't released after deletion"
}
run_test 1e "Quota pools: global pool high block limit vs quota pool with small"

test_1f() {
	local global_limit=200 # MB
	local limit1=10 # MB
	local TESTDIR="$DIR/$tdir/"
	local testfile="$TESTDIR/$tfile-0"
	local qpool1="qpool1"

	mds_supports_qp
	setup_quota_test || error "setup quota failed with $?"

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	log "User quota (block hardlimit:$global_limit MB)"
	$LFS setquota -u $TSTUSR -b 0 -B ${global_limit}M -i 0 -I 0 $DIR ||
		error "set user quota failed"

	pool_add $qpool1 || error "pool_add failed"
	pool_add_targets $qpool1 0 0 ||
		error "pool_add_targets failed"

	$LFS setquota -u $TSTUSR -B ${limit1}M --pool $qpool1 $DIR ||
		error "set user quota failed"

	# make sure the system is clean
	local used=$(getquota -u $TSTUSR global curspace)
	[ $used -ne 0 ] && error "Used space($used) for user $TSTUSR isn't 0."

	$LFS setstripe $TESTDIR -c 1 -i 0 || error "setstripe $TESTDIR failed"

	test_1_check_write $testfile "user" $limit1

	pool_remove_target $qpool1 0
	rm -f $testfile
	wait_delete_completed || error "wait_delete_completed failed"
	sync_all_data || true

	pool_add_targets $qpool1 0 0 || error "pool_add_targets failed"
	# qunit for appropriate element in lgd array should be set
	# correctly(4096). Earlier it was not changed continuing to be 1024.
	# This caused write to hung when it hit limit1 - qunit shrinking to 1024
	# for qpool1 lqe didn't cause changing qunit for OST0 in gld array
	# as it already was 1024. As flag "need_update" for this qunit was
	# not set, new qunit wasn't sent to OST0. Thus revoke was not set
	# for "qpool1" lqe and it couldn't set EDQUOT despite granted
	# became > 10M. QMT returned EINPROGRESS in a loop.
	# Check that it doesn't hung anymore.
	test_1_check_write $testfile "user" $limit1
}
run_test 1f "Quota pools: correct qunit after removing/adding OST"

test_1g() {
	local limit=20 # MB
	local global_limit=40 # MB
	local testfile="$DIR/$tdir/$tfile-0"
	local qpool="qpool1"
	local mdmb_param="osc.*.max_dirty_mb"
	local max_dirty_mb=$($LCTL get_param -n $mdmb_param | head -1)

	mds_supports_qp
	setup_quota_test || error "setup quota failed with $?"
	$LCTL set_param $mdmb_param=1
	stack_trap "$LCTL set_param $mdmb_param=$max_dirty_mb" EXIT

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# test for user
	log "User quota (block hardlimit:$global_limit MB)"
	$LFS setquota -u $TSTUSR -b 0 -B ${global_limit}M -i 0 -I 0 $DIR ||
		error "set user quota failed"

	pool_add $qpool || error "pool_add failed"
	pool_add_targets $qpool 0 $(($OSTCOUNT - 1)) ||
		error "pool_add_targets failed"

	$LFS setquota -u $TSTUSR -B ${limit}M --pool $qpool $DIR ||
		error "set user quota failed"

	# make sure the system is clean
	local used=$(getquota -u $TSTUSR global curspace)
	echo "used $used"
	[ $used -ne 0 ] && error "Used space($used) for user $TSTUSR isn't 0."

	$LFS setstripe $testfile -C 200 || error "setstripe $testfile failed"
	chown $TSTUSR.$TSTUSR $testfile || error "chown $testfile failed"

	log "Write..."
	$RUNAS $DD of=$testfile count=$((limit/2)) ||
		quota_error u $TSTUSR \
			"$qtype write failure, but expect success"
	log "Write out of block quota ..."
	# this time maybe cache write,  ignore it's failure
	$RUNAS $DD of=$testfile count=$((limit/2)) seek=$((limit/2)) || true
	# flush cache, ensure noquota flag is set on client
	cancel_lru_locks osc
	sync; sync_all_data || true
	sleep 5
	$RUNAS $DD of=$testfile count=$((OSTCOUNT*3)) seek=$limit &&
		quota_error u $TSTUSR \
			"user write success, but expect EDQUOT"

	rm -f $testfile
	wait_delete_completed || error "wait_delete_completed failed"
	sync_all_data || true

	used=$(getquota -u $TSTUSR global curspace $qpool)
	[ $used -ne 0 ] && quota_error u $TSTUSR \
		"user quota isn't released after deletion"
	return 0
}
run_test 1g "Quota pools: Block hard limit with wide striping"

test_1h() {
	local limit=10 # MB
	local testfile="$DIR/$tdir/$tfile-0"

	check_set_fallocate_or_skip

	setup_quota_test || error "setup quota failed with $?"

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# test for user
	log "User quota (block hardlimit:$limit MB)"
	$LFS setquota -u $TSTUSR -b 0 -B ${limit}M -i 0 -I 0 $DIR ||
		error "set user quota failed"

	# make sure the system is clean
	local used=$(getquota -u $TSTUSR global curspace)
	[ $used -ne 0 ] && error "Used space($used) for user $TSTUSR isn't 0."

	$LFS setstripe $testfile -i 0 -c 1 || error "setstripe $testfile failed"
	chown $TSTUSR.$TSTUSR $testfile || error "chown $testfile failed"

	wait_quota_synced ost1 OST0000 usr $TSTID hardlimit $((limit*1024))

	check_write_fallocate $testfile "user" $limit

	rm -f $testfile
	wait_delete_completed || error "wait_delete_completed failed"
	sync_all_data || true
	used=$(getquota -u $TSTUSR global curspace)
	[ $used -eq 0 ] || quota_error u $TSTUSR \
		"user quota isn't released after deletion"
}
run_test 1h "Block hard limit test using fallocate"

test_1i() {
	local global_limit=200  # 200M
	local limit1=10  # 10M
	local TESTDIR="$DIR/$tdir/"
	local testfile="$TESTDIR/$tfile-0"
	local testfile1="$TESTDIR/$tfile-1"
	local testfile2="$TESTDIR/$tfile-2"
	local qpool1="qpool1"

	mds_supports_qp
	setup_quota_test || error "setup quota failed with $?"

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	log "User quota (block hardlimit:$global_limit MB)"
	$LFS setquota -u $TSTUSR -b 0 -B ${global_limit}M -i 0 -I 0 $DIR ||
		error "set user quota failed"

	pool_add $qpool1 || error "pool_add failed"
	pool_add_targets $qpool1 0 0 ||
		error "pool_add_targets failed"

	$LFS setquota -u $TSTUSR -B ${limit1}M --pool $qpool1 $DIR ||
		error "set user quota failed"

	# make sure the system is clean
	local used=$(getquota -u $TSTUSR global curspace)
	[ $used -ne 0 ] && error "Used space($used) for user $TSTUSR isn't 0."

	$LFS setstripe $TESTDIR -c 1 -i 0 || error "setstripe $TESTDIR failed"

	# hit pool limit
	test_1_check_write $testfile "user" $limit1
	$LFS setquota -u $TSTUSR -B 0 --pool $qpool1 $DIR ||
		error "set user quota failed"

	$LFS quota -v -u $TSTUSR --pool $qpool1 $DIR
	$RUNAS $DD of=$testfile1 count=$((limit1/2)) ||
		quota_error u $TSTUSR "write failure, but expect success"

	rm -f $testfile
	rm -f $testfile1
	wait_delete_completed || error "wait_delete_completed failed"
	sync_all_data || true

	$LFS setquota -u $TSTUSR -B ${limit1}M --pool $qpool1 $DIR ||
		error "set user quota failed"
	test_1_check_write $testfile "user" $limit1
	local tmp_limit=$(($limit1*2))
	# increase pool limit
	$LFS setquota -u $TSTUSR -B ${tmp_limit}M --pool $qpool1 $DIR ||
		error "set user quota failed"
	# now write shouldn't fail
	$RUNAS $DD of=$testfile1 count=$((limit1/3)) ||
		quota_error u $TSTUSR "write failure, but expect success"
	# decrease pool limit
	$LFS setquota -u $TSTUSR -B ${limit1}M --pool $qpool1 $DIR ||
		error "set user quota failed"
	$RUNAS $DD of=$testfile2 count=$((limit1/3))
	# flush cache, ensure noquota flag is set on client
	cancel_lru_locks osc
	sync; sync_all_data || true
	$RUNAS $DD of=$testfile2 seek=$((limit1/3)) count=1 &&
		quota_error u $TSTUSR "write success, but expect failure"
	return 0
}
run_test 1i "Quota pools: different limit and usage relations"

test_1j() {
	local limit=20 # MB
	local testfile="$DIR/$tdir/$tfile-0"

	(( $OST1_VERSION >= $(version_code 2.15.52.206) )) ||
		skip "need OST at least 2.15.52.206"

	is_project_quota_supported ||
		skip "skip project quota unsupported"

	setup_quota_test || error "setup quota failed with $?"

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# test for Project
	log "--------------------------------------"
	log "Project quota (block hardlimit:$limit mb)"
	$LFS setquota -p $TSTPRJID -b 0 -B ${limit}M -i 0 -I 0 $DIR ||
		error "set project quota failed"

	$LFS setstripe $testfile -c 1 -i 0 || error "setstripe $testfile failed"
	change_project -p $TSTPRJID $testfile

	local procf=osd-$ost1_FSTYPE.$FSNAME-OST0000.quota_slave.root_prj_enable
	do_facet ost1 $LCTL set_param $procf=1 ||
		error "enable root quotas for project failed"
	stack_trap "do_facet ost1 $LCTL set_param $procf=0"

	runas -u 0 -g 0 $DD of=$testfile count=$limit oflag=direct || true
	runas -u 0 -g 0 $DD of=$testfile count=$((limit/2)) seek=$limit oflag=direct &&
		quota_error "project" $TSTPRJID "root write to project success"

	do_facet ost1 $LCTL set_param $procf=0 ||
		error "disable root quotas for project failed"

	runas -u 0 -g 0 $DD of=$testfile count=$limit seek=$limit oflag=direct ||
		quota_error "project" $TSTPRJID "root write to project failed"

	# cleanup
	cleanup_quota_test

	used=$(getquota -p $TSTPRJID global curspace)
	(( $used == 0 )) || quota_error p $TSTPRJID \
		"project quota isn't released after deletion"
}
run_test 1j "Enable project quota enforcement for root"

# test inode hardlimit
test_2() {
	local testfile="$DIR/$tdir/$tfile-0"
	local least_qunit=$(do_facet mds1 $LCTL get_param -n \
		qmt.$FSNAME-QMT0000.md-0x0.info |
		sed -e 's/least qunit/least_qunit/' |
		awk '/least_qunit/{ print $2 }')
	local limit

	[ "$SLOW" = "no" ] && limit=$((least_qunit * 2)) ||
		limit=$((least_qunit * 1024))
	echo "least_qunit: '$least_qunit', limit: '$limit'"

	local free_inodes=$(mdt_free_inodes 0)
	echo "$free_inodes free inodes on master MDT"
	[ $free_inodes -lt $limit ] &&
		skip "not enough free inodes $free_inodes required $limit"

	setup_quota_test || error "setup quota failed with $?"

	# enable mdt quota
	set_mdt_qtype $QTYPE || error "enable mdt quota failed"

	# test for user
	log "User quota (inode hardlimit:$limit files)"
	$LFS setquota -u $TSTUSR -b 0 -B 0 -i 0 -I $limit $DIR ||
		error "set user quota failed"

	# make sure the system is clean
	local used=$(getquota -u $TSTUSR global curinodes)
	[ $used -ne 0 ] && error "Used inodes($used) for user $TSTUSR isn't 0."

	log "Create $((limit - least_qunit)) files ..."
	$RUNAS createmany -m ${testfile} $((limit - least_qunit)) ||
		quota_error u $TSTUSR "user create failure, but expect success"
	# it is ok, if it fails on the last qunit
	$RUNAS createmany -m ${testfile}_yyy $least_qunit || true
	log "Create out of file quota ..."
	$RUNAS touch ${testfile}_xxx &&
		quota_error u $TSTUSR "user create success, but expect EDQUOT"

	# cleanup
	unlinkmany ${testfile} $((limit - least_qunit)) ||
		error "unlinkmany $testfile failed"
	# if 2nd createmany got EDQUOT, not all of nodes would be created
	unlinkmany ${testfile}_yyy $least_qunit || true
	rm -f ${testfile}_xxx
	wait_delete_completed

	used=$(getquota -u $TSTUSR global curinodes)
	[ $used -ne 0 ] && quota_error u $TSTUSR \
		"user quota isn't released after deletion"
	resetquota -u $TSTUSR

	# test for group
	log "--------------------------------------"
	log "Group quota (inode hardlimit:$limit files)"
	$LFS setquota -g $TSTUSR -b 0 -B 0 -i 0 -I $limit $DIR ||
		error "set group quota failed"

	testfile=$DIR/$tdir/$tfile-1
	# make sure the system is clean
	used=$(getquota -g $TSTUSR global curinodes)
	[ $used -ne 0 ] && error "Used inodes($used) for group $TSTUSR isn't 0."

	log "Create $limit files ..."
	$RUNAS createmany -m ${testfile} $((limit - least_qunit)) ||
		quota_error g $TSTUSR "group create failure, but expect success"
	$RUNAS createmany -m ${testfile}_yyy $least_qunit ||
	log "Create out of file quota ..."
	$RUNAS touch ${testfile}_xxx &&
		quota_error g $TSTUSR "group create success, but expect EDQUOT"

	# cleanup
	unlinkmany ${testfile} $((limit - least_qunit)) ||
		error "unlinkmany $testfile failed"
	unlinkmany ${testfile}_yyy $least_qunit || true
	rm -f ${testfile}_xxx
	wait_delete_completed

	used=$(getquota -g $TSTUSR global curinodes)
	[ $used -ne 0 ] && quota_error g $TSTUSR \
		"user quota isn't released after deletion"

	resetquota -g $TSTUSR
	! is_project_quota_supported &&
		echo "Skip project quota is not supported" && return 0

	# test for project
	log "--------------------------------------"
	log "Project quota (inode hardlimit:$limit files)"
	$LFS setquota -p $TSTPRJID -b 0 -B 0 -i 0 -I $limit $DIR ||
		error "set project quota failed"

	testfile=$DIR/$tdir/$tfile-1
	# make sure the system is clean
	used=$(getquota -p $TSTPRJID global curinodes)
	[ $used -ne 0 ] &&
		error "Used inodes($used) for project $TSTPRJID isn't 0"

	change_project -sp $TSTPRJID $DIR/$tdir
	log "Create $limit files ..."
	$RUNAS createmany -m ${testfile} $((limit-least_qunit)) ||
		quota_error p $TSTPRJID \
			"project create fail, but expect success"
	$RUNAS createmany -m ${testfile}_yyy $least_qunit || true
	log "Create out of file quota ..."
	$RUNAS touch ${testfile}_xxx && quota_error p $TSTPRJID \
		"project create success, but expect EDQUOT"
	change_project -C $DIR/$tdir

	cleanup_quota_test
	used=$(getquota -p $TSTPRJID global curinodes)
	[ $used -eq 0 ] || quota_error p $TSTPRJID \
		"project quota isn't released after deletion"

}
run_test 2 "File hard limit (normal use and out of quota)"

test_block_soft() {
	local testfile=$1
	local grace=$2
	local limit=$3
	local OFFSET=0
	local qtype=$4
	local pool=$5
	local soft_limit=$(do_facet $SINGLEMDS $LCTL get_param -n \
		qmt.$FSNAME-QMT0000.dt-0x0.soft_least_qunit)

	setup_quota_test

	$LFS setstripe $testfile -c 1 -i 0
	chown $TSTUSR.$TSTUSR $testfile
	[ "$qtype" == "p" ] && is_project_quota_supported &&
		change_project -p $TSTPRJID $testfile

	echo "Write up to soft limit"
	$RUNAS $DD of=$testfile count=$limit ||
		quota_error a $TSTUSR "write failure, but expect success"
	OFFSET=$((limit * 1024))
	cancel_lru_locks osc

	echo "Write to exceed soft limit"
	$RUNAS dd if=/dev/zero of=$testfile bs=1K count=10 seek=$OFFSET ||
		quota_error a $TSTUSR "write failure, but expect success"
	OFFSET=$((OFFSET + 1024)) # make sure we don't write to same block
	cancel_lru_locks osc

	echo "mmap write when over soft limit"
	$RUNAS $MULTIOP $testfile.mmap OT40960SMW ||
		quota_error a $TSTUSR "mmap write failure, but expect success"
	cancel_lru_locks osc

	$SHOW_QUOTA_USER
	$SHOW_QUOTA_GROUP
	$SHOW_QUOTA_PROJID
	$SHOW_QUOTA_INFO_USER
	$SHOW_QUOTA_INFO_GROUP
	$SHOW_QUOTA_INFO_PROJID

	echo "Write before timer goes off"
	$RUNAS dd if=/dev/zero of=$testfile bs=1K count=10 seek=$OFFSET ||
		quota_error a $TSTUSR "write failure, but expect success"
	OFFSET=$((OFFSET + 1024))
	cancel_lru_locks osc

	wait_grace_time $qtype "block" $pool

	$SHOW_QUOTA_USER
	$SHOW_QUOTA_GROUP
	$SHOW_QUOTA_PROJID
	$SHOW_QUOTA_INFO_USER
	$SHOW_QUOTA_INFO_GROUP
	$SHOW_QUOTA_INFO_PROJID

	log "Write after timer goes off"
	# maybe cache write, ignore.
	# write up to soft least quint to consume all
	# possible slave granted space.
	$RUNAS dd if=/dev/zero of=$testfile bs=1K \
		count=$soft_limit seek=$OFFSET || true
	OFFSET=$((OFFSET + soft_limit))
	cancel_lru_locks osc
	log "Write after cancel lru locks"
	$RUNAS dd if=/dev/zero of=$testfile bs=1K count=10 seek=$OFFSET &&
		quota_error a $TSTUSR "write success, but expect EDQUOT"

	$SHOW_QUOTA_USER
	$SHOW_QUOTA_GROUP
	$SHOW_QUOTA_PROJID
	$SHOW_QUOTA_INFO_USER
	$SHOW_QUOTA_INFO_GROUP
	$SHOW_QUOTA_INFO_PROJID

	echo "Unlink file to stop timer"
	rm -f $testfile
	wait_delete_completed
	sync_all_data || true

	$SHOW_QUOTA_USER
	$SHOW_QUOTA_GROUP
	$SHOW_QUOTA_PROJID
	$SHOW_QUOTA_INFO_USER
	$SHOW_QUOTA_INFO_GROUP
	$SHOW_QUOTA_INFO_PROJID

	$LFS setstripe $testfile -c 1 -i 0
	chown $TSTUSR.$TSTUSR $testfile
	[ "$qtype" == "p" ] && change_project -p $TSTPRJID $testfile

	echo "Write ..."
	$RUNAS $DD of=$testfile count=$limit ||
		quota_error a $TSTUSR "write failure, but expect success"
	# cleanup
	cleanup_quota_test
}

# block soft limit
test_3a() {
	local grace=20 # seconds
	if [ $(facet_fstype $SINGLEMDS) = "zfs" ]; then
	    grace=60
	fi
	local testfile=$DIR/$tdir/$tfile-0

	# get minimum soft qunit size
	local limit=$(( $(do_facet $SINGLEMDS $LCTL get_param -n \
		qmt.$FSNAME-QMT0000.dt-0x0.soft_least_qunit) / 1024 ))

	set_ost_qtype $QTYPE || error "enable ost quota failed"

	echo "User quota (soft limit:$limit MB  grace:$grace seconds)"
	# make sure the system is clean
	local used=$(getquota -u $TSTUSR global curspace)
	[ $used -ne 0 ] && error "Used space($used) for user $TSTUSR isn't 0."

	$LFS setquota -t -u --block-grace $grace --inode-grace \
		$MAX_IQ_TIME $DIR || error "set user grace time failed"
	$LFS setquota -u $TSTUSR -b ${limit}M -B 0 -i 0 -I 0 $DIR ||
		error "set user quota failed"

	test_block_soft $testfile $grace $limit "u"

	echo "Group quota (soft limit:$limit MB  grace:$grace seconds)"
	testfile=$DIR/$tdir/$tfile-1
	# make sure the system is clean
	used=$(getquota -g $TSTUSR global curspace)
	[ $used -ne 0 ] && error "Used space($used) for group $TSTUSR isn't 0."

	$LFS setquota -t -g --block-grace $grace --inode-grace \
		$MAX_IQ_TIME $DIR || error "set group grace time failed"
	$LFS setquota -g $TSTUSR -b ${limit}M -B 0 -i 0 -I 0 $DIR ||
		error "set group quota failed"

	test_block_soft $testfile $grace $limit "g"

	if is_project_quota_supported; then
		echo "Project quota (soft limit:$limit MB  grace:$grace sec)"
		testfile=$DIR/$tdir/$tfile-2
		# make sure the system is clean
		used=$(getquota -p $TSTPRJID global curspace)
		[ $used -ne 0 ] && error \
			"Used space($used) for project $TSTPRJID isn't 0."

		$LFS setquota -t -p --block-grace $grace --inode-grace \
			$MAX_IQ_TIME $DIR ||
				error "set project grace time failed"
		$LFS setquota -p $TSTPRJID -b ${limit}M -B 0 -i 0 -I 0 \
			$DIR || error "set project quota failed"

		test_block_soft $testfile $grace $limit "p"
		resetquota -p $TSTPRJID
		$LFS setquota -t -p --block-grace $MAX_DQ_TIME --inode-grace \
			$MAX_IQ_TIME $DIR ||
				error "restore project grace time failed"
	fi

	# cleanup
	$LFS setquota -t -u --block-grace $MAX_DQ_TIME --inode-grace \
		$MAX_IQ_TIME $DIR || error "restore user grace time failed"
	$LFS setquota -t -g --block-grace $MAX_DQ_TIME --inode-grace \
		$MAX_IQ_TIME $DIR || error "restore group grace time failed"
}
run_test 3a "Block soft limit (start timer, timer goes off, stop timer)"

test_3b() {
	local grace=20 # seconds
	local qpool="qpool1"
	if [ $(facet_fstype $SINGLEMDS) = "zfs" ]; then
		grace=60
	fi
	local testfile=$DIR/$tdir/$tfile-0

	mds_supports_qp
	# get minimum soft qunit size
	local limit=$(( $(do_facet $SINGLEMDS $LCTL get_param -n \
		qmt.$FSNAME-QMT0000.dt-0x0.soft_least_qunit) / 1024 ))
	local glbl_limit=$((2*limit))
	local glbl_grace=$((2*grace))
	echo "limit $limit glbl_limit $glbl_limit"
	echo "grace $grace glbl_grace $glbl_grace"

	set_ost_qtype $QTYPE || error "enable ost quota failed"

	echo "User quota in $qpool(soft limit:$limit MB  grace:$grace seconds)"
	# make sure the system is clean
	local used=$(getquota -u $TSTUSR global curspace)
	[ $used -ne 0 ] && error "Used space($used) for user $TSTUSR isn't 0."

	pool_add $qpool || error "pool_add failed"
	pool_add_targets $qpool 0 1 ||
		error "pool_add_targets failed"

	$LFS setquota -t -u --block-grace $glbl_grace --inode-grace \
		$MAX_IQ_TIME $DIR || error "set user grace time failed"
	$LFS setquota -t -u --block-grace $grace \
		--pool $qpool $DIR || error "set user grace time failed"

	$LFS setquota -u $TSTUSR -b ${glbl_limit}M -B 0 -i 0 -I 0 $DIR ||
		error "set user quota failed"
	$LFS setquota -u $TSTUSR -b ${limit}M -B 0 --pool $qpool $DIR ||
		error "set user quota failed"

	test_block_soft $testfile $grace $limit "u" $qpool

	echo "Group quota in $qpool(soft limit:$limit MB  grace:$grace seconds)"
	testfile=$DIR/$tdir/$tfile-1
	# make sure the system is clean
	used=$(getquota -g $TSTUSR global curspace)
	[ $used -ne 0 ] && error "Used space($used) for group $TSTUSR isn't 0."

	$LFS setquota -t -g --block-grace $glbl_grace --inode-grace \
		$MAX_IQ_TIME $DIR || error "set group grace time failed"
	$LFS setquota -t -g --block-grace $grace \
		--pool $qpool $DIR || error "set group grace time failed"

	$LFS setquota -g $TSTUSR -b ${glbl_limit}M -B 0 -i 0 -I 0 $DIR ||
		error "set group quota failed"
	$LFS setquota -g $TSTUSR -b ${limit}M -B 0 --pool $qpool $DIR ||
		error "set group quota failed"

	test_block_soft $testfile $grace $limit "g" $qpool

	if is_project_quota_supported; then
		echo "Project quota in $qpool(soft:$limit MB  grace:$grace sec)"
		testfile=$DIR/$tdir/$tfile-2
		# make sure the system is clean
		used=$(getquota -p $TSTPRJID global curspace)
		[ $used -ne 0 ] && error \
			"Used space($used) for project $TSTPRJID isn't 0."

		$LFS setquota -t -p --block-grace $glbl_grace --inode-grace \
			$MAX_IQ_TIME $DIR ||
				error "set project grace time failed"
		$LFS setquota -t -p --block-grace $grace \
			--pool $qpool $DIR ||
				error "set project grace time failed"

		$LFS setquota -p $TSTPRJID -b ${glbl_limit}M -B 0 -i 0 -I 0 \
			$DIR || error "set project quota failed"
		$LFS setquota -p $TSTPRJID -b ${limit}M -B 0 \
			--pool $qpool $DIR || error "set project quota failed"

		test_block_soft $testfile $grace $limit "p" $qpool
		resetquota -p $TSTPRJID
		$LFS setquota -t -p --block-grace $MAX_DQ_TIME --inode-grace \
			$MAX_IQ_TIME $DIR ||
				error "restore project grace time failed"
		$LFS setquota -t -p --block-grace $MAX_DQ_TIME --pool $qpool \
			$DIR ||	error "set project grace time failed"
	fi

	# cleanup
	$LFS setquota -t -u --block-grace $MAX_DQ_TIME --inode-grace \
		$MAX_IQ_TIME $DIR || error "restore user grace time failed"
	$LFS setquota -t -u --block-grace $MAX_DQ_TIME \
		--pool $qpool $DIR || error "restore user grace time failed"
	$LFS setquota -t -g --block-grace $MAX_DQ_TIME --inode-grace \
		$MAX_IQ_TIME $DIR || error "restore group grace time failed"
	$LFS setquota -t -g --block-grace $MAX_DQ_TIME \
		--pool $qpool $DIR || error "restore group grace time failed"
}
run_test 3b "Quota pools: Block soft limit (start timer, expires, stop timer)"

test_3c() {
	local grace=20 # seconds
	local qpool="qpool1"
	local qpool2="qpool2"
	if [ $(facet_fstype $SINGLEMDS) = "zfs" ]; then
		grace=60
	fi
	local testfile=$DIR/$tdir/$tfile-0

	mds_supports_qp
	# get minimum soft qunit size
	local limit=$(( $(do_facet $SINGLEMDS $LCTL get_param -n \
		qmt.$FSNAME-QMT0000.dt-0x0.soft_least_qunit) / 1024 ))
	local limit2=$((limit+4))
	local glbl_limit=$((limit+8))
	local grace1=$((grace+10))
	local grace2=$grace
	local glbl_grace=$((grace+20))
	echo "limit $limit limit2 $limit2 glbl_limit $glbl_limit"
	echo "grace1 $grace1 grace2 $grace2 glbl_grace $glbl_grace"

	set_ost_qtype $QTYPE || error "enable ost quota failed"

	echo "User quota in qpool2(soft:$limit2 MB grace:$grace2 seconds)"
	# make sure the system is clean
	local used=$(getquota -u $TSTUSR global curspace)
	[ $used -ne 0 ] && error "Used space($used) for user $TSTUSR isn't 0."

	pool_add $qpool || error "pool_add failed"
	pool_add_targets $qpool 0 1 ||
		error "pool_add_targets failed"

	pool_add $qpool2 || error "pool_add failed"
	pool_add_targets $qpool2 0 1 ||
		error "pool_add_targets failed"

	$LFS setquota -t -u --block-grace $glbl_grace --inode-grace \
		$MAX_IQ_TIME $DIR || error "set user grace time failed"
	$LFS setquota -t -u --block-grace $grace1 \
		--pool $qpool $DIR || error "set user grace time failed"
	$LFS setquota -t -u --block-grace $grace2 \
		--pool $qpool2 $DIR || error "set user grace time failed"

	$LFS setquota -u $TSTUSR -b ${glbl_limit}M -B 0 -i 0 -I 0 $DIR ||
		error "set user quota failed"
	$LFS setquota -u $TSTUSR -b ${limit}M -B 0 --pool $qpool $DIR ||
		error "set user quota failed"
	# qpool has minimum soft limit, but its grace is greater than
	# the grace period of qpool2. Thus write shouldn't fail when
	# hit qpool soft limit - only when reaches up qpool2 limit
	# after grace2 seconds.
	$LFS setquota -u $TSTUSR -b ${limit2}M -B 0 --pool $qpool2 $DIR ||
		error "set user quota failed"

	test_block_soft $testfile $grace2 $limit2 "u" $qpool2

	# cleanup
	$LFS setquota -t -u --block-grace $MAX_DQ_TIME --inode-grace \
		$MAX_IQ_TIME $DIR || error "restore user grace time failed"
	$LFS setquota -t -u --block-grace $MAX_DQ_TIME \
		--pool $qpool $DIR || error "restore user grace time failed"
	$LFS setquota -t -u --block-grace $MAX_DQ_TIME \
		--pool $qpool2 $DIR || error "restore user grace time failed"
}
run_test 3c "Quota pools: check block soft limit on different pools"

test_file_soft() {
	local TESTFILE=$1
	local LIMIT=$2
	local grace=$3
	local qtype=$4
	local SOFT_LIMIT=$(do_facet $SINGLEMDS $LCTL get_param -n \
		qmt.$FSNAME-QMT0000.md-0x0.soft_least_qunit)

	setup_quota_test
	$LFS setstripe -c 1 -i 0 $DIR/$tdir || error "setstripe failed"
	is_project_quota_supported && change_project -sp $TSTPRJID $DIR/$tdir

	echo "Create files to exceed soft limit"
	$RUNAS createmany -m ${TESTFILE}_ $((LIMIT + 1)) ||
		quota_error a $TSTUSR "create failure, but expect success"
	local trigger_time=$(date +%s)

	sync_all_data_mdts || true
	do_facet ost1 "lctl set_param -n osd*.*OST0000.force_sync=1"

	local cur_time=$(date +%s)
	[ $(($cur_time - $trigger_time)) -ge $grace ] &&
		error "Passed grace time $grace, $trigger_time, $cur_time"
	echo "========= Passed grace time $grace, $trigger_time, $cur_time"

	echo "Create file before timer goes off"
	$RUNAS touch ${TESTFILE}_before ||
		quota_error a $TSTUSR "failed create before timer expired," \
			"but expect success. $trigger_time, $cur_time"
	sync_all_data_mdts || true
	do_facet ost1 "lctl set_param -n osd*.*OST0000.force_sync=1"

	wait_grace_time $qtype "file"

	$SHOW_QUOTA_USER
	$SHOW_QUOTA_GROUP
	$SHOW_QUOTA_PROJID
	$SHOW_QUOTA_INFO_USER
	$SHOW_QUOTA_INFO_GROUP
	$SHOW_QUOTA_INFO_PROJID

	echo "Create file after timer goes off"
	# exceed least soft limit is possible
	$RUNAS createmany -m ${TESTFILE}_after_3 $((SOFT_LIMIT + 1)) &&
		quota_error a $TSTUSR "create after timer expired," \
			"but expect EDQUOT"
	sync_all_data_mdts || true
	do_facet ost1 "lctl set_param -n osd*.*OST0000.force_sync=1"

	$SHOW_QUOTA_USER
	$SHOW_QUOTA_GROUP
	$SHOW_QUOTA_PROJID
	$SHOW_QUOTA_INFO_USER
	$SHOW_QUOTA_INFO_GROUP
	$SHOW_QUOTA_INFO_PROJID

	echo "Unlink files to stop timer"
	find $(dirname $TESTFILE) -name "$(basename ${TESTFILE})*" | xargs rm -f
	wait_delete_completed

	echo "Create file"
	$RUNAS touch ${TESTFILE}_xxx ||
		quota_error a $TSTUSR "touch after timer stop failure," \
			"but expect success"
	sync_all_data_mdts || true
	do_facet ost1 "lctl set_param -n osd*.*OST0000.force_sync=1"

	# cleanup
	cleanup_quota_test
}

# file soft limit
test_4a() {
	local LIMIT=$(do_facet $SINGLEMDS $LCTL get_param -n \
		qmt.$FSNAME-QMT0000.md-0x0.soft_least_qunit)
	local TESTFILE=$DIR/$tdir/$tfile-0
	local GRACE=12

	[ "$mds1_FSTYPE" = zfs ] && GRACE=20
	set_mdt_qtype $QTYPE || error "enable mdt quota failed"

	echo "User quota (soft limit:$LIMIT files  grace:$GRACE seconds)"
	# make sure the system is clean
	local USED=$(getquota -u $TSTUSR global curinodes)
	[ $USED -ne 0 ] && error "Used space($USED) for user $TSTUSR isn't 0."

	$LFS setquota -t -u --block-grace $MAX_DQ_TIME --inode-grace \
		$GRACE $DIR || error "set user grace time failed"
	$LFS setquota -u $TSTUSR -b 0 -B 0 -i $LIMIT -I 0 $DIR ||
		error "set user quota failed"

	test_file_soft $TESTFILE $LIMIT $GRACE "u"

	echo "Group quota (soft limit:$LIMIT files  grace:$GRACE seconds)"
	# make sure the system is clean
	USED=$(getquota -g $TSTUSR global curinodes)
	[ $USED -ne 0 ] && error "Used space($USED) for group $TSTUSR isn't 0."

	$LFS setquota -t -g --block-grace $MAX_DQ_TIME --inode-grace \
		$GRACE $DIR || error "set group grace time failed"
	$LFS setquota -g $TSTUSR -b 0 -B 0 -i $LIMIT -I 0 $DIR ||
		error "set group quota failed"
	TESTFILE=$DIR/$tdir/$tfile-1

	test_file_soft $TESTFILE $LIMIT $GRACE "g"

	if is_project_quota_supported; then
		echo "Project quota (soft limit:$LIMIT files grace:$GRACE sec)"
		# make sure the system is clean
		USED=$(getquota -p $TSTPRJID global curinodes)
		[ $USED -ne 0 ] && error \
			"Used space($USED) for project $TSTPRJID isn't 0."

		$LFS setquota -t -p --block-grace $MAX_DQ_TIME --inode-grace \
			$GRACE $DIR || error "set project grace time failed"
		$LFS setquota -p $TSTPRJID -b 0 -B 0 -i $LIMIT -I 0 $DIR ||
			error "set project quota failed"

		TESTFILE=$DIR/$tdir/$tfile-1
		# one less than limit, because of parent directory included.
		test_file_soft $TESTFILE $((LIMIT-1)) $GRACE "p"
		resetquota -p $TSTPRJID
		$LFS setquota -t -p --block-grace $MAX_DQ_TIME --inode-grace \
			$MAX_IQ_TIME $DIR ||
				error "restore project grace time failed"
	fi

	# cleanup
	$LFS setquota -t -u --block-grace $MAX_DQ_TIME --inode-grace \
		$MAX_IQ_TIME $DIR || error "restore user grace time failed"
	$LFS setquota -t -g --block-grace $MAX_DQ_TIME --inode-grace \
		$MAX_IQ_TIME $DIR || error "restore group grace time failed"
}
run_test 4a "File soft limit (start timer, timer goes off, stop timer)"

test_4b() {
	local GR_STR1="1w3d"
	local GR_STR2="1000s"
	local GR_STR3="5s"
	local GR_STR4="1w2d3h4m5s"
	local GR_STR5="5c"
	local GR_STR6="18446744073709551615"
	local GR_STR7="-1"

	wait_delete_completed

	# test of valid grace strings handling
	echo "Valid grace strings test"
	$LFS setquota -t -u --block-grace $GR_STR1 --inode-grace \
		$GR_STR2 $DIR || error "set user grace time failed"
	$LFS quota -u -t $DIR | grep "Block grace time: $GR_STR1"
	$LFS setquota -t -g --block-grace $GR_STR3 --inode-grace \
		$GR_STR4 $DIR || error "set group grace time quota failed"
	$LFS quota -g -t $DIR | grep "Inode grace time: $GR_STR4"

	# test of invalid grace strings handling
	echo "  Invalid grace strings test"
	! $LFS setquota -t -u --block-grace $GR_STR4 --inode-grace $GR_STR5 $DIR
	! $LFS setquota -t -g --block-grace $GR_STR4 --inode-grace $GR_STR6 $DIR
	! $LFS setquota -t -g --block-grace $GR_STR4 --inode-grace \
		$GR_STR7 $DIR

	# cleanup
	$LFS setquota -t -u --block-grace $MAX_DQ_TIME --inode-grace \
		$MAX_IQ_TIME $DIR || error "restore user grace time failed"
	$LFS setquota -t -g --block-grace $MAX_DQ_TIME --inode-grace \
		$MAX_IQ_TIME $DIR || error "restore group grace time failed"
}
run_test 4b "Grace time strings handling"

# chown & chgrp (chown & chgrp successfully even out of block/file quota)
test_5() {
	local BLIMIT=10 # MB
	local ILIMIT=10 # inodes

	setup_quota_test || error "setup quota failed with $?"

	set_mdt_qtype $QTYPE || error "enable mdt quota failed"
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	echo "Set quota limit (0 ${BLIMIT}M 0 $ILIMIT) for $TSTUSR.$TSTUSR"
	$LFS setquota -u $TSTUSR -b 0 -B ${BLIMIT}M -i 0 -I $ILIMIT $DIR ||
		error "set user quota failed"
	$LFS setquota -g $TSTUSR -b 0 -B ${BLIMIT}M -i 0 -I $ILIMIT $DIR ||
	if is_project_quota_supported; then
		error "set group quota failed"
		$LFS setquota -p $TSTPRJID -b 0 -B ${BLIMIT}M -i 0 \
			-I $ILIMIT $DIR || error "set project quota failed"
	fi

	# make sure the system is clean
	local USED=$(getquota -u $TSTUSR global curinodes)
	[ $USED -ne 0 ] && error "Used inode($USED) for user $TSTUSR isn't 0."
	USED=$(getquota -g $TSTUSR global curinodes)
	[ $USED -ne 0 ] && error "Used inode($USED) for group $TSTUSR isn't 0."
	USED=$(getquota -u $TSTUSR global curspace)
	[ $USED -ne 0 ] && error "Used block($USED) for user $TSTUSR isn't 0."
	USED=$(getquota -g $TSTUSR global curspace)
	[ $USED -ne 0 ] && error "Used block($USED) for group $TSTUSR isn't 0."
	if is_project_quota_supported; then
		USED=$(getquota -p $TSTPRJID global curinodes)
		[ $USED -ne 0 ] &&
			error "Used inode($USED) for project $TSTPRJID isn't 0."
		USED=$(getquota -p $TSTPRJID global curspace)
		[ $USED -ne 0 ] &&
			error "Used block($USED) for project $TSTPRJID isn't 0."
	fi

	echo "Create more than $ILIMIT files and more than $BLIMIT MB ..."
	createmany -m $DIR/$tdir/$tfile-0_ $((ILIMIT + 1)) ||
		error "create failure, expect success"
	if is_project_quota_supported; then
		touch $DIR/$tdir/$tfile-0_1
		change_project -p $TSTPRJID $DIR/$tdir/$tfile-0_1
	fi
	$DD of=$DIR/$tdir/$tfile-0_1 count=$((BLIMIT+1)) ||
		error "write failure, expect success"

	echo "Chown files to $TSTUSR.$TSTUSR ..."
	for i in $(seq 0 $ILIMIT); do
		chown $TSTUSR.$TSTUSR $DIR/$tdir/$tfile-0_$i ||
			quota_error a $TSTUSR "chown failure, expect success"
	done

	# cleanup
	unlinkmany $DIR/$tdir/$tfile-0_ $((ILIMIT + 1)) ||
		error "unlinkmany $DIR/$tdir/$tfile-0_ failed"
}
run_test 5 "Chown & chgrp successfully even out of block/file quota"

# test dropping acquire request on master
test_6() {
	local LIMIT=3 # MB

	# Clear dmesg so watchdog is not triggered by previous
	# test output
	do_facet ost1 dmesg -c > /dev/null

	setup_quota_test || error "setup quota failed with $?"

	# make sure the system is clean
	local USED=$(getquota -u $TSTUSR global curspace)
	[ $USED -ne 0 ] && error "Used space($USED) for user $TSTUSR isn't 0."

	# make sure no granted quota on ost
	set_ost_qtype $QTYPE || error "enable ost quota failed"
	resetquota -u $TSTUSR

	# create file for $TSTUSR
	local TESTFILE=$DIR/$tdir/$tfile-$TSTUSR
	$LFS setstripe $TESTFILE -c 1 -i 0 || error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	# create file for $TSTUSR2
	local TESTFILE2=$DIR/$tdir/$tfile-$TSTUSR2
	$LFS setstripe $TESTFILE2 -c 1 -i 0 || error "setstripe $TESTFILE2 failed"
	chown $TSTUSR2.$TSTUSR2 $TESTFILE2 || error "chown $TESTFILE2 failed"

	# cache per-ID lock for $TSTUSR on slave
	$LFS setquota -u $TSTUSR -b 0 -B ${LIMIT}M -i 0 -I 0 $DIR ||
		error "set quota failed"
	$RUNAS $DD of=$TESTFILE count=1 ||
		error "write $TESTFILE failure, expect success"
	$RUNAS2 $DD of=$TESTFILE2 count=1 ||
		error "write $TESTFILE2 failure, expect success"

	if at_is_enabled; then
		at_max_saved=$(at_max_get ost1)
		at_max_set $TIMEOUT ost1

		# write to enforced ID ($TSTUSR) to exceed limit to make sure
		# DQACQ is sent, which makes at_max to take effect
		$RUNAS $DD of=$TESTFILE count=$LIMIT seek=1 oflag=sync \
								conv=notrunc
		rm -f $TESTFILE
		wait_delete_completed
	fi

	sync; sync
	sync_all_data || true

	#define QUOTA_DQACQ 601
	#define OBD_FAIL_PTLRPC_DROP_REQ_OPC 0x513
	lustre_fail mds 0x513 601

	do_facet ost1 $LCTL set_param \
			osd-*.$FSNAME-OST*.quota_slave.timeout=$((TIMEOUT / 2))

	# write to un-enforced ID ($TSTUSR2) should succeed
	$RUNAS2 $DD of=$TESTFILE2 count=$LIMIT seek=1 oflag=sync conv=notrunc ||
		error "write failure, expect success"

	# write to enforced ID ($TSTUSR) in background, exceeding limit
	# to make sure DQACQ is sent
	$RUNAS $DD of=$TESTFILE count=$LIMIT seek=1 oflag=sync conv=notrunc &
	DDPID=$!

	# watchdog timer uses a factor of 2
	echo "Sleep for $((TIMEOUT * 2 + 1)) seconds ..."
	sleep $((TIMEOUT * 2 + 1))

	[ $at_max_saved -ne 0 ] && at_max_set $at_max_saved ost1

	# write should be blocked and never finished
	if ! ps -p $DDPID  > /dev/null 2>&1; then
		lustre_fail mds 0 0
		error "write finished incorrectly!"
	fi

	lustre_fail mds 0 0

	# no watchdog is triggered
	do_facet ost1 dmesg > $TMP/lustre-log-${TESTNAME}.log
	watchdog=$(awk '/[Ss]ervice thread pid/ && /was inactive/ \
			{ print; }' $TMP/lustre-log-${TESTNAME}.log)
	[ -z "$watchdog" ] || error "$watchdog"

	rm -f $TMP/lustre-log-${TESTNAME}.log

	# write should continue then fail with EDQUOT
	local count=0
	local c_size
	while [ true ]; do
		if ! ps -p ${DDPID} > /dev/null 2>&1; then break; fi
		if [ $count -ge 240 ]; then
			quota_error u $TSTUSR "dd not finished in $count secs"
		fi
		count=$((count + 1))
		if [ $((count % 30)) -eq 0 ]; then
			c_size=$(stat -c %s $TESTFILE)
			echo "Waiting $count secs. $c_size"
			$SHOW_QUOTA_USER
		fi
		sleep 1
	done
}
run_test 6 "Test dropping acquire request on master"

# quota reintegration (global index)
test_7a() {
	local TESTFILE=$DIR/$tdir/$tfile
	local LIMIT=20 # MB

	[ "$SLOW" = "no" ] && LIMIT=5

	setup_quota_test || error "setup quota failed with $?"

	# make sure the system is clean
	local USED=$(getquota -u $TSTUSR global curspace)
	[ $USED -ne 0 ] && error "Used space($USED) for user $TSTUSR isn't 0."

	# make sure no granted quota on ost1
	set_ost_qtype $QTYPE || error "enable ost quota failed"
	resetquota -u $TSTUSR
	set_ost_qtype "none" || error "disable ost quota failed"

	local OSTUUID=$(ostname_from_index 0)
	USED=$(getquota -u $TSTUSR $OSTUUID bhardlimit)
	[ $USED -ne 0 ] &&
		error "limit($USED) on $OSTUUID for user $TSTUSR isn't 0"

	# create test file
	$LFS setstripe $TESTFILE -c 1 -i 0 || error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	echo "Stop ost1..."
	stop ost1

	echo "Enable quota & set quota limit for $TSTUSR"
	set_ost_qtype $QTYPE || error "enable ost quota failed"
	$LFS setquota -u $TSTUSR -b 0 -B ${LIMIT}M -i 0 -I 0 $DIR ||
		error "set quota failed"

	echo "Start ost1..."
	start ost1 $(ostdevname 1) $OST_MOUNT_OPTS || error "start ost1 failed"
	quota_init

	wait_ost_reint $QTYPE || error "reintegration failed"

	# hardlimit should have been fetched by slave during global
	# reintegration, write will exceed quota
	$RUNAS $DD of=$TESTFILE count=$((LIMIT + 1)) oflag=sync &&
		quota_error u $TSTUSR "write success, but expect EDQUOT"

	rm -f $TESTFILE
	wait_delete_completed
	sync_all_data || true
	sleep 3

	echo "Stop ost1..."
	stop ost1

	$LFS setquota -u $TSTUSR -b 0 -B 0 -i 0 -I 0 $DIR ||
		error "clear quota failed"

	echo "Start ost1..."
	start ost1 $(ostdevname 1) $OST_MOUNT_OPTS || error "start ost1 failed"
	quota_init

	wait_ost_reint $QTYPE || error "reintegration failed"

	# hardlimit should be cleared on slave during reintegration
	$RUNAS $DD of=$TESTFILE count=$((LIMIT + 1)) oflag=sync ||
		quota_error u $TSTUSR "write error, but expect success"
}
run_test 7a "Quota reintegration (global index)"

# quota reintegration (slave index)
test_7b() {
	local limit=100000 # MB
	local TESTFILE=$DIR/$tdir/$tfile

	setup_quota_test || error "setup quota failed with $?"

	# make sure the system is clean
	local USED=$(getquota -u $TSTUSR global curspace)
	[ $USED -ne 0 ] && error "Used space($USED) for user $TSTUSR isn't 0."

	# make sure no granted quota on ost1
	set_ost_qtype $QTYPE || error "enable ost quota failed"
	resetquota -u $TSTUSR
	set_ost_qtype "none" || error "disable ost quota failed"

	local OSTUUID=$(ostname_from_index 0)
	USED=$(getquota -u $TSTUSR $OSTUUID bhardlimit)
	[ $USED -ne 0 ] &&
		error "limit($USED) on $OSTUUID for user $TSTUSR isn't 0"

	# create test file
	$LFS setstripe $TESTFILE -c 1 -i 0 || error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	# consume some space to make sure the granted space will not
	# be released during reconciliation
	$RUNAS $DD of=$TESTFILE count=1 oflag=sync ||
		error "consume space failure, expect success"

	# define OBD_FAIL_QUOTA_EDQUOT 0xa02
	lustre_fail mds 0xa02

	set_ost_qtype $QTYPE || error "enable ost quota failed"
	$LFS setquota -u $TSTUSR -b 0 -B ${limit}M -i 0 -I 0 $DIR ||
		error "set quota failed"

	# ignore the write error
	$RUNAS $DD of=$TESTFILE count=1 seek=1 oflag=sync conv=notrunc

	local old_used=$(getquota -u $TSTUSR $OSTUUID bhardlimit)

	lustre_fail mds 0

	echo "Restart ost to trigger reintegration..."
	stop ost1
	start ost1 $(ostdevname 1) $OST_MOUNT_OPTS || error "start ost1 failed"
	quota_init

	wait_ost_reint $QTYPE || error "reintegration failed"

	USED=$(getquota -u $TSTUSR $OSTUUID bhardlimit)
	[ $USED -gt $old_used ] || error "limit on $OSTUUID $USED <= $old_used"

	cleanup_quota_test
	$SHOW_QUOTA_USER
}
run_test 7b "Quota reintegration (slave index)"

# quota reintegration (restart mds during reintegration)
test_7c() {
	local LIMIT=20 # MB
	local TESTFILE=$DIR/$tdir/$tfile

	[ "$SLOW" = "no" ] && LIMIT=5

	setup_quota_test || error "setup quota failed with $?"

	# make sure the system is clean
	local USED=$(getquota -u $TSTUSR global curspace)
	[ $USED -ne 0 ] && error "Used space($USED) for user $TSTUSR isn't 0."

	set_ost_qtype "none" || error "disable ost quota failed"
	$LFS setquota -u $TSTUSR -b 0 -B ${LIMIT}M -i 0 -I 0 $DIR ||
		error "set quota failed"

	# define OBD_FAIL_QUOTA_DELAY_REINT 0xa03
	lustre_fail ost 0xa03

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"
	# trigger reintegration
	local procf="osd-$ost1_FSTYPE.$FSNAME-OST*."
	procf=${procf}quota_slave.force_reint
	do_facet ost1 $LCTL set_param $procf=1 ||
		error "force reintegration failed"

	echo "Stop mds..."
	stop mds1

	lustre_fail ost 0

	echo "Start mds..."
	start mds1 $(mdsdevname 1) $MDS_MOUNT_OPTS
	quota_init

	# wait longer than usual to make sure the reintegration
	# is triggered by quota wb thread.
	wait_ost_reint $QTYPE 200 || error "reintegration failed"

	# hardlimit should have been fetched by slave during global
	# reintegration, write will exceed quota
	$RUNAS $DD of=$TESTFILE count=$((LIMIT + 1)) oflag=sync &&
		quota_error u $TSTUSR "write success, but expect EDQUOT"
	return 0
}
run_test 7c "Quota reintegration (restart mds during reintegration)"

# Quota reintegration (Transfer index in multiple bulks)
test_7d(){
	local TESTFILE=$DIR/$tdir/$tfile
	local TESTFILE1="$DIR/$tdir/$tfile"-1
	local limit=20 # MB

	setup_quota_test || error "setup quota failed with $?"

	set_ost_qtype "none" || error "disable ost quota failed"
	$LFS setquota -u $TSTUSR -B ${limit}M $DIR ||
		error "set quota for $TSTUSR failed"
	$LFS setquota -u $TSTUSR2 -B ${limit}M $DIR ||
		error "set quota for $TSTUSR2 failed"

	#define OBD_FAIL_OBD_IDX_READ_BREAK 0x608
	lustre_fail mds 0x608 0

	# enable quota to tirgger reintegration
	set_ost_qtype "u" || error "enable ost quota failed"
	wait_ost_reint "u" || error "reintegration failed"

	lustre_fail mds 0

	# hardlimit should have been fetched by slave during global
	# reintegration, write will exceed quota
	$RUNAS $DD of=$TESTFILE count=$((limit + 1)) oflag=sync &&
		quota_error u $TSTUSR "$TSTUSR write success, expect EDQUOT"

	$RUNAS2 $DD of=$TESTFILE1 count=$((limit + 1)) oflag=sync &&
		quota_error u $TSTUSR2 "$TSTUSR2 write success, expect EDQUOT"
	return 0
}
run_test 7d "Quota reintegration (Transfer index in multiple bulks)"

# quota reintegration (inode limits)
test_7e() {
	[ "$MDSCOUNT" -lt "2" ] && skip "needs >= 2 MDTs"

	# LU-2435: skip this quota test if underlying zfs version has not
	# supported native dnode accounting
	[ "$mds1_FSTYPE" == zfs ] && {
		local F="feature@userobj_accounting"
		local pool=$(zpool_name mds1)
		local feature=$(do_facet mds1 $ZPOOL get -H $F $pool)

		[[ "$feature" != *" active "* ]] &&
			skip "requires zpool with active userobj_accounting"
	}

	local ilimit=$((1024 * 2)) # inodes
	local TESTFILE=$DIR/${tdir}-1/$tfile

	setup_quota_test || error "setup quota failed with $?"

	# make sure the system is clean
	local USED=$(getquota -u $TSTUSR global curinodes)
	[ $USED -ne 0 ] && error "Used inode($USED) for user $TSTUSR isn't 0."

	# make sure no granted quota on mdt1
	set_mdt_qtype $QTYPE || error "enable mdt quota failed"
	resetquota -u $TSTUSR
	set_mdt_qtype "none" || error "disable mdt quota failed"

	local MDTUUID=$(mdtuuid_from_index $((MDSCOUNT - 1)))
	USED=$(getquota -u $TSTUSR $MDTUUID ihardlimit)
	[ $USED -ne 0 ] && error "limit($USED) on $MDTUUID for user" \
		"$TSTUSR isn't 0."

	echo "Stop mds${MDSCOUNT}..."
	stop mds${MDSCOUNT}

	echo "Enable quota & set quota limit for $TSTUSR"
	set_mdt_qtype $QTYPE || error "enable mdt quota failed"
	$LFS setquota -u $TSTUSR -b 0 -B 0 -i 0 -I $ilimit $DIR ||
		error "set quota failed"

	echo "Start mds${MDSCOUNT}..."
	start mds${MDSCOUNT} $(mdsdevname $MDSCOUNT) $MDS_MOUNT_OPTS
	quota_init

	wait_mdt_reint $QTYPE || error "reintegration failed"

	echo "create remote dir"
	$LFS mkdir -i $((MDSCOUNT - 1)) $DIR/${tdir}-1 ||
		error "create remote dir failed"
	chmod 0777 $DIR/${tdir}-1

	# hardlimit should have been fetched by slave during global
	# reintegration, create will exceed quota
	$RUNAS createmany -m $TESTFILE $((ilimit + 1)) &&
		quota_error u $TSTUSR "create succeeded, expect EDQUOT"

	$RUNAS unlinkmany $TESTFILE $ilimit || error "unlink files failed"
	wait_delete_completed
	sync_all_data || true

	echo "Stop mds${MDSCOUNT}..."
	stop mds${MDSCOUNT}

	$LFS setquota -u $TSTUSR -b 0 -B 0 -i 0 -I 0 $DIR ||
		error "clear quota failed"

	echo "Start mds${MDSCOUNT}..."
	start mds${MDSCOUNT} $(mdsdevname $MDSCOUNT) $MDS_MOUNT_OPTS
	quota_init

	wait_mdt_reint $QTYPE || error "reintegration failed"

	# hardlimit should be cleared on slave during reintegration
	$RUNAS createmany -m $TESTFILE $((ilimit + 1)) ||
		quota_error u $TSTUSR "create failed, expect success"

	$RUNAS unlinkmany $TESTFILE $((ilimit + 1)) || error "unlink failed"
	rmdir $DIR/${tdir}-1 || error "unlink remote dir failed"
}
run_test 7e "Quota reintegration (inode limits)"

# run dbench with quota enabled
test_8() {
	local BLK_LIMIT="100g" #100G
	local FILE_LIMIT=1000000

	setup_quota_test || error "setup quota failed with $?"

	set_mdt_qtype $QTYPE || error "enable mdt quota failed"
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	echo "Set enough high limit for user: $TSTUSR"
	$LFS setquota -u $TSTUSR -b 0 -B $BLK_LIMIT -i 0 -I $FILE_LIMIT $DIR ||
		error "set user quota failed"
	echo "Set enough high limit for group: $TSTUSR"
	$LFS setquota -g $TSTUSR -b 0 -B $BLK_LIMIT -i 0 -I $FILE_LIMIT $DIR ||
		error "set group quota failed"
	if is_project_quota_supported; then
		change_project -sp $TSTPRJID $DIR/$tdir
		echo "Set enough high limit for project: $TSTPRJID"
		$LFS setquota -p $TSTPRJID -b 0 \
			-B $BLK_LIMIT -i 0 -I $FILE_LIMIT $DIR ||
			error "set project quota failed"
	fi

	local duration=""
	[ "$SLOW" = "no" ] && duration=" -t 120"
	$RUNAS bash rundbench -D $DIR/$tdir 3 $duration ||
		quota_error a $TSTUSR "dbench failed!"

	is_project_quota_supported && change_project -C $DIR/$tdir
	return 0
}
run_test 8 "Run dbench with quota enabled"

# this check is just for test_9
OST0_MIN=4900000 #4.67G

check_whether_skip () {
	local OST0_SIZE=$($LFS df $DIR | awk '/\[OST:0\]/ {print $4}')
	log "OST0_SIZE: $OST0_SIZE  required: $OST0_MIN"
	if [ $OST0_SIZE -lt $OST0_MIN ]; then
		echo "WARN: OST0 has less than $OST0_MIN free, skip this test."
		return 0
	else
		return 1
	fi
}

# run for fixing bug10707, it needs a big room. test for 64bit
test_9() {
	local filesize=$((1024 * 9 / 2)) # 4.5G

	check_whether_skip && return 0

	setup_quota_test || error "setup quota failed with $?"

	set_ost_qtype "ug" || error "enable ost quota failed"

	local TESTFILE="$DIR/$tdir/$tfile-0"
	local BLK_LIMIT=100G #100G
	local FILE_LIMIT=1000000

	echo "Set block limit $BLK_LIMIT bytes to $TSTUSR.$TSTUSR"

	log "Set enough high limit(block:$BLK_LIMIT; file: $FILE_LIMIT)" \
		"for user: $TSTUSR"
	$LFS setquota -u $TSTUSR -b 0 -B $BLK_LIMIT -i 0 -I $FILE_LIMIT $DIR ||
		error "set user quota failed"

	log "Set enough high limit(block:$BLK_LIMIT; file: $FILE_LIMIT)" \
		"for group: $TSTUSR"
	$LFS setquota -g $TSTUSR -b 0 -B $BLK_LIMIT -i 0 -I $FILE_LIMIT $DIR ||
		error "set group quota failed"

	quota_show_check a u $TSTUSR
	quota_show_check a g $TSTUSR

	echo "Create test file"
	$LFS setstripe $TESTFILE -c 1 -i 0 || error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	log "Write the big file of 4.5G ..."
	$RUNAS $DD of=$TESTFILE count=$filesize ||
		quota_error a $TSTUSR "write 4.5G file failure, expect success"

	$SHOW_QUOTA_USER
	$SHOW_QUOTA_GROUP

	cleanup_quota_test

	$SHOW_QUOTA_USER
	$SHOW_QUOTA_GROUP
}
run_test 9 "Block limit larger than 4GB (b10707)"

test_10() {
	local TESTFILE=$DIR/$tdir/$tfile

	setup_quota_test || error "setup quota failed with $?"

	# set limit to root user should fail
	$LFS setquota -u root -b 100G -B 500G -i 1K -I 1M $DIR &&
		error "set limit for root user successfully, expect failure"
	$LFS setquota -g root -b 1T -B 10T -i 5K -I 100M $DIR &&
		error "set limit for root group successfully, expect failure"
	$LFS setquota -p 0 -b 1T -B 10T -i 5K -I 100M $DIR &&
		error "set limit for project 0 successfully, expect failure"

	# root user can overrun quota
	set_ost_qtype "ug" || error "enable ost quota failed"

	$LFS setquota -u $TSTUSR -b 0 -B 2M -i 0 -I 0 $DIR ||
		error "set quota failed"
	quota_show_check b u $TSTUSR

	$LFS setstripe $TESTFILE -c 1 || error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	runas -u 0 -g 0 $DD of=$TESTFILE count=3 oflag=sync ||
		error "write failure, expect success"
}
run_test 10 "Test quota for root user"

test_11() {
	local TESTFILE=$DIR/$tdir/$tfile
	setup_quota_test || error "setup quota failed with $?"

	set_mdt_qtype "ug" || error "enable mdt quota failed"
	$LFS setquota -u $TSTUSR -b 0 -B 0 -i 0 -I 1 $DIR ||
		error "set quota failed"

	touch "$TESTFILE"-0 || error "touch $TESTFILE-0 failed"
	touch "$TESTFILE"-1 || error "touch $TESTFILE-0 failed"

	chown $TSTUSR.$TSTUSR "$TESTFILE"-0 || error "chown $TESTFILE-0 failed"
	chown $TSTUSR.$TSTUSR "$TESTFILE"-1 || error "chown $TESTFILE-1 failed"

	$SHOW_QUOTA_USER
	local USED=$(getquota -u $TSTUSR global curinodes)
	[ $USED -ge 2 ] || error "Used inodes($USED) is less than 2"
}
run_test 11 "Chown/chgrp ignores quota"

test_12a() {
	[ "$OSTCOUNT" -lt "2" ] && skip "needs >= 2 OSTs"

	local blimit=22 # MB
	local blk_cnt=$((blimit - 5))
	local TESTFILE0="$DIR/$tdir/$tfile"-0
	local TESTFILE1="$DIR/$tdir/$tfile"-1

	setup_quota_test || error "setup quota failed with $?"

	set_ost_qtype "u" || error "enable ost quota failed"
	quota_show_check b u $TSTUSR

	$LFS setquota -u $TSTUSR -b 0 -B ${blimit}M -i 0 -I 0 $DIR ||
		error "set quota failed"

	$LFS setstripe $TESTFILE0 -c 1 -i 0 || error "setstripe $TESTFILE0 failed"
	$LFS setstripe $TESTFILE1 -c 1 -i 1 || error "setstripe $TESTFILE1 failed"
	chown $TSTUSR.$TSTUSR $TESTFILE0 || error "chown $TESTFILE0 failed"
	chown $TSTUSR.$TSTUSR $TESTFILE1 || error "chown $TESTFILE1 failed"

	echo "Write to ost0..."
	$RUNAS $DD of=$TESTFILE0 count=$blk_cnt oflag=sync ||
		quota_error a $TSTUSR "dd failed"

	echo "Write to ost1..."
	$RUNAS $DD of=$TESTFILE1 count=$blk_cnt oflag=sync &&
		quota_error a $TSTUSR "dd succeed, expect EDQUOT"

	echo "Free space from ost0..."
	rm -f $TESTFILE0
	wait_delete_completed
	sync_all_data || true

	echo "Write to ost1 after space freed from ost0..."
	$RUNAS $DD of=$TESTFILE1 count=$blk_cnt oflag=sync ||
		quota_error a $TSTUSR "rebalancing failed"
}
run_test 12a "Block quota rebalancing"

test_12b() {
	[ "$MDSCOUNT" -lt "2" ] && skip "needs >= 2 MDTs"

	local ilimit=$((1024 * 2)) # inodes
	local TESTFILE0=$DIR/$tdir/$tfile
	local TESTFILE1=$DIR/${tdir}-1/$tfile

	setup_quota_test || error "setup quota failed with $?"

	$LFS mkdir -i 1 $DIR/${tdir}-1 || error "create remote dir failed"
	chmod 0777 $DIR/${tdir}-1

	set_mdt_qtype "u" || error "enable mdt quota failed"
	quota_show_check f u $TSTUSR

	$LFS setquota -u $TSTUSR -b 0 -B 0 -i 0 -I $ilimit $DIR ||
		error "set quota failed"

	echo "Create $ilimit files on mdt0..."
	$RUNAS createmany -m $TESTFILE0 $ilimit || true

	echo "Create files on mdt1..."
	$RUNAS createmany -m $TESTFILE1 1 &&
		quota_error a $TSTUSR "create succeeded, expect EDQUOT"

	echo "Free space from mdt0..."
	$RUNAS unlinkmany $TESTFILE0 $ilimit || error "unlink mdt0 files failed"
	wait_delete_completed
	sync_all_data || true

	echo "Create files on mdt1 after space freed from mdt0..."
	$RUNAS createmany -m $TESTFILE1 $((ilimit / 2)) ||
		quota_error a $TSTUSR "rebalancing failed"

	$RUNAS unlinkmany $TESTFILE1 $((ilimit / 2)) ||
		error "unlink mdt1 files failed"
	rmdir $DIR/${tdir}-1 || error "unlink remote dir failed"
}
run_test 12b "Inode quota rebalancing"

test_13(){
	local TESTFILE=$DIR/$tdir/$tfile
	# the name of lwp on ost1 name is MDT0000-lwp-OST0000
	local procf="ldlm.namespaces.*MDT0000-lwp-OST0000.lru_size"

	setup_quota_test || error "setup quota failed with $?"

	set_ost_qtype "u" || error "enable ost quota failed"
	quota_show_check b u $TSTUSR

	$LFS setquota -u $TSTUSR -b 0 -B 10M -i 0 -I 0 $DIR ||
		error "set quota failed"
	$LFS setstripe $TESTFILE -c 1 -i 0 || error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	# clear the locks in cache first
	do_facet ost1 $LCTL set_param -n $procf=clear
	local init_nlock=$(do_facet ost1 $LCTL get_param -n $procf)

	# write to acquire the per-ID lock
	$RUNAS $DD of=$TESTFILE count=1 oflag=sync ||
		quota_error a $TSTUSR "dd failed"

	local nlock=$(do_facet ost1 $LCTL get_param -n $procf)
	[ $nlock -eq $((init_nlock + 1)) ] ||
		error "lock count($nlock) != $init_lock + 1"

	# clear quota doesn't trigger per-ID lock cancellation
	resetquota -u $TSTUSR
	nlock=$(do_facet ost1 $LCTL get_param -n $procf)
	[ $nlock -eq $((init_nlock + 1)) ] ||
		error "per-ID lock is lost on quota clear"

	# clear the per-ID lock
	do_facet ost1 $LCTL set_param -n $procf=clear
	nlock=$(do_facet ost1 $LCTL get_param -n $procf)
	[ $nlock -eq $init_nlock ] || error "per-ID lock isn't cleared"

	# spare quota should be released
	local OSTUUID=$(ostname_from_index 0)
	local limit=$(getquota -u $TSTUSR $OSTUUID bhardlimit)
	local space=$(getquota -u $TSTUSR $OSTUUID curspace)
	[ $limit -le $space ] ||
		error "spare quota isn't released, limit:$limit, space:$space"
}
run_test 13 "Cancel per-ID lock in the LRU list"

test_14()
{
	(( $MDS1_VERSION >= $(version_code 2.15.54.67) )) ||
		skip "Need MDS >= v2_15_54-67-gdfe7d for qmt_site_recalc_cb fix"

	local qpool="qpool1"
	local tfile1="$DIR/$tdir/$tfile-0"

	mds_supports_qp
	setup_quota_test || error "setup quota failed with $?"
	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	$LFS setquota -u $TSTUSR -b 0 -B 100M -i 0 -I 0 $DIR ||
		error "set user quota failed"
	pool_add $qpool || error "pool_add failed"
	pool_add_targets $qpool 0 ||
		error "pool_add_targets failed"
	$LFS setstripe -p $qpool $DIR/$tdir || error "cannot set stripe"
	$LFS setquota -u $TSTUSR -B 30M --pool $qpool $DIR ||
		error "set user quota failed"

	# don't care about returned value
	$RUNAS $DD of=$tfile1 count=10 oflag=direct

	echo "Stop ost1..."
	stop ost1
	$LFS setquota -u $TSTUSR -b 0 -B 0 -i 0 -I 0 $DIR ||
		error "set user quota failed"

	# no panic after removing OST0000 from the pool
	pool_remove_target $qpool 0
	start ost1 $(ostdevname 1) $OST_MOUNT_OPTS || error "start ost1 failed"
}
run_test 14 "check panic in qmt_site_recalc_cb"

test_15(){
	local LIMIT=$((24 * 1024 * 1024 * 1024 * 1024)) # 24 TB

	wait_delete_completed
	sync_all_data || true

	# test for user
	$LFS setquota -u $TSTUSR -b 0 -B $LIMIT -i 0 -I 0 $DIR ||
		error "set user quota failed"
	local TOTAL_LIMIT=$(getquota -u $TSTUSR global bhardlimit)
	[ $TOTAL_LIMIT -eq $LIMIT ] ||
		error "(user) limit:$TOTAL_LIMIT, expect:$LIMIT, failed!"
	resetquota -u $TSTUSR

	# test for group
	$LFS setquota -g $TSTUSR -b 0 -B $LIMIT -i 0 -I 0 $DIR ||
		error "set group quota failed"
	TOTAL_LIMIT=$(getquota -g $TSTUSR global bhardlimit)
	[ $TOTAL_LIMIT -eq $LIMIT ] ||
		error "(group) limits:$TOTAL_LIMIT, expect:$LIMIT, failed!"
	resetquota -g $TSTUSR
}
run_test 15 "Set over 4T block quota"

test_16a()
{
	(( $CLIENT_VERSION < $(version_code 2.14.55) )) &&
		skip "Not supported Lustre client before 2.14.55"

	setup_quota_test || error "setup quota failed with $?"

	$LFS setquota -u $TSTUSR -B 500M -I 10K $MOUNT ||
		error "failed to set quota for user $TSTUSR"
	$LFS setquota -g $TSTUSR -B 500M -I 10K $MOUNT ||
		error "failed to set quota for group $TSTUSR"

	$RUNAS $DD of=$DIR/$tdir/$tfile count=50 ||
		quota_error u $TSTUSR "write failure"

	$LFS quota -u $TSTUSR $MOUNT ||
		quota_error u $TSTUSR "failed to get quota"

	local OSC=$($LCTL dl | grep OST0000-osc-[^M] | awk '{print $4}')

	$LCTL --device %$OSC deactivate
	stack_trap "$LCTL --device %$OSC activate"

	$LFS quota -v -u $TSTUSR $MOUNT ||
		quota_error u $TSTUSR "failed to get quota after deactivate OSC"
	$LFS quota -v -g $TSTUSR $MOUNT ||
		quota_error g $TSTUSR "failed to get quota after deactivate OSC"

	(( $MDSCOUNT > 1 )) || return 0

	local MDC=$($LCTL dl | grep MDT0001-mdc-[^M] | awk '{print $4}')

	$LCTL --device %$MDC deactivate
	stack_trap "$LCTL --device %$MDC activate"

	$LFS quota -v -u $TSTUSR $MOUNT ||
		quota_error u $TSTUSR "failed to get quota after deactivate MDC"
	$LFS quota -v -g $TSTUSR $MOUNT ||
		quota_error g $TSTUSR "failed to get quota after deactivate OSC"
}
run_test 16a "lfs quota should skip the inactive MDT/OST"

cleanup_16b()
{
	stopall
	formatall
	setupall
}

test_16b()
{
	(( $CLIENT_VERSION < $(version_code 2.14.55) )) &&
		skip "Not supported Lustre client before 2.14.55"

	(( $MDSCOUNT >= 3 )) || skip "needs >= 3 MDTs"

	stopall
	if ! combined_mgs_mds ; then
		format_mgs
		start_mgs
	fi

	add mds1 $(mkfs_opts mds1 $(mdsdevname 1)) --index=0 --reformat \
		$(mdsdevname 1) $(mdsvdevname 1)
	add mds2 $(mkfs_opts mds2 $(mdsdevname 2)) --index=1 --reformat \
		$(mdsdevname 2) $(mdsvdevname 2)
	add mds3 $(mkfs_opts mds3 $(mdsdevname 3)) --index=100 --reformat \
		$(mdsdevname 3) $(mdsvdevname 3)

	add ost1 $(mkfs_opts ost1 $(ostdevname 1)) --index=0 --reformat \
		$(ostdevname 1) $(ostvdevname 1)
	add ost2 $(mkfs_opts ost2 $(ostdevname 2)) --index=100 --reformat \
		$(ostdevname 2) $(ostvdevname 2)

	stack_trap cleanup_16b

	start mds1 $(mdsdevname 1) $MDS_MOUNT_OPTS || error "MDT1 start failed"
	start mds2 $(mdsdevname 2) $MDS_MOUNT_OPTS || error "MDT2 start failed"
	start mds3 $(mdsdevname 3) $MDS_MOUNT_OPTS || error "MDT3 start failed"
	start ost1 $(ostdevname 1) $OST_MOUNT_OPTS || error "OST1 start failed"
	start ost2 $(ostdevname 2) $OST_MOUNT_OPTS || error "OST2 start failed"

	mount_client $MOUNT || error "Unable to mount client"

	setup_quota_test || error "setup quota failed with $?"

	$LFS setquota -u $TSTUSR -B 100M -I 10K $MOUNT ||
		error "failed to set quota for user $TSTUSR"
	$LFS setquota -g $TSTUSR -B 100M -I 10K $MOUNT ||
		error "failed to set quota for group $TSTUSR"

	$RUNAS $DD of=$DIR/$tdir/$tfile count=10 ||
		quota_error u $TSTUSR "write failure"

	cnt=$($LFS quota -v -u $TSTUSR $MOUNT | grep -ce "^$FSNAME-[MD|OS]T*")
	[ $cnt -le 5 ] || quota_error u $TSTUSR "failed to get user quota"
	cnt=$($LFS quota -v -g $TSTUSR $MOUNT | grep -ce "^$FSNAME-[MD|OS]T*")
	[ $cnt -le 5 ] || quota_error g $TSTUSR "failed to get group quota"
}
run_test 16b "lfs quota should skip the nonexistent MDT/OST"

test_17sub() {
	local err_code=$1
	local BLKS=1    # 1M less than limit
	local TESTFILE=$DIR/$tdir/$tfile

	setup_quota_test || error "setup quota failed with $?"

	# make sure the system is clean
	local USED=$(getquota -u $TSTUSR global curspace)
	[ $USED -ne 0 ] && error "Used space($USED) for user $TSTUSR isn't 0."

	set_ost_qtype "ug" || error "enable ost quota failed"
	# make sure no granted quota on ost
	resetquota -u $TSTUSR
	$LFS setquota -u $TSTUSR -b 0 -B 10M -i 0 -I 0 $DIR ||
		error "set quota failed"

	quota_show_check b u $TSTUSR

	#define OBD_FAIL_QUOTA_RECOVERABLE_ERR 0xa04
	lustre_fail mds 0xa04 $err_code

	# write in background
	$RUNAS $DD of=$TESTFILE count=$BLKS oflag=direct &
	local DDPID=$!

	sleep 2
	# write should be blocked and never finished
	if ! ps -p $DDPID  > /dev/null 2>&1; then
		lustre_fail mds 0 0
		quota_error u $TSTUSR "write finished incorrectly!"
	fi

	lustre_fail mds 0 0

	local count=0
	local timeout=30
	while [ true ]; do
		if ! ps -p ${DDPID} > /dev/null 2>&1; then break; fi
		count=$((count+1))
		if [ $count -gt $timeout ]; then
			quota_error u $TSTUSR "dd is not finished!"
		fi
		sleep 1
	done

	sync; sync_all_data || true

	USED=$(getquota -u $TSTUSR global curspace)
	[ $USED -ge $((BLKS * 1024)) ] || quota_error u $TSTUSR \
		"Used space(${USED}K) is less than ${BLKS}M"

	cleanup_quota_test
}

# DQACQ return recoverable error
test_17() {
	echo "DQACQ return -ENOLCK"
	#define ENOLCK  37
	test_17sub 37 || error "Handle -ENOLCK failed"

	echo "DQACQ return -EAGAIN"
	#define EAGAIN  11
	test_17sub 11 || error "Handle -EAGAIN failed"

	echo "DQACQ return -ETIMEDOUT"
	#define ETIMEDOUT 110
	test_17sub 110 || error "Handle -ETIMEDOUT failed"

	echo "DQACQ return -ENOTCONN"
	#define ENOTCONN 107
	test_17sub 107 || error "Handle -ENOTCONN failed"
}

run_test 17 "DQACQ return recoverable error"

test_18_sub () {
	local io_type=$1
	local blimit=200 # MB
	local TESTFILE="$DIR/$tdir/$tfile"

	setup_quota_test || error "setup quota failed with $?"

	set_ost_qtype "u" || error "enable ost quota failed"
	log "User quota (limit: $blimit)"
	$LFS setquota -u $TSTUSR -b 0 -B ${blimit}M -i 0 -I 0 $MOUNT ||
		error "set quota failed"
	quota_show_check b u $TSTUSR

	$LFS setstripe $TESTFILE -i 0 -c 1 || error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	local timeout=$($LCTL get_param -n timeout)

	if [ $io_type = "directio" ]; then
		log "Write 100M (directio) ..."
		$RUNAS $DD of=$TESTFILE count=100 oflag=direct &
	else
		log "Write 100M (buffered) ..."
		$RUNAS $DD of=$TESTFILE count=100 &
	fi
	local DDPID=$!

	replay_barrier $SINGLEMDS
	log "Fail mds for $((2 * timeout)) seconds"
	fail $SINGLEMDS $((2 * timeout))

	local count=0
	if at_is_enabled; then
		timeout=$(at_max_get mds)
	else
		timeout=$($LCTL get_param -n timeout)
	fi

	while [ true ]; do
		if ! ps -p ${DDPID} > /dev/null 2>&1; then break; fi
		if [ $((++count % (2 * timeout) )) -eq 0 ]; then
			log "it took $count second"
		fi
		sleep 1
	done

	log "(dd_pid=$DDPID, time=$count, timeout=$timeout)"
	sync
	cancel_lru_locks mdc
	cancel_lru_locks osc
	$SHOW_QUOTA_USER

	local testfile_size=$(stat -c %s $TESTFILE)
	if [ $testfile_size -ne $((BLK_SZ * 1024 * 100)) ] ; then
		quota_error u $TSTUSR "expect $((BLK_SZ * 1024 * 100))," \
			"got ${testfile_size}. Verifying file failed!"
	fi
	cleanup_quota_test
}

# test when mds does failover, the ost still could work well
# this test shouldn't trigger watchdog b=14840
test_18() {
	# Clear dmesg so watchdog is not triggered by previous
	# test output
	do_facet ost1 dmesg -c > /dev/null

	test_18_sub normal
	test_18_sub directio

	# check if watchdog is triggered
	do_facet ost1 dmesg > $TMP/lustre-log-${TESTNAME}.log
	local watchdog=$(awk '/[Ss]ervice thread pid/ && /was inactive/ \
			{ print; }' $TMP/lustre-log-${TESTNAME}.log)
	[ -z "$watchdog" ] || error "$watchdog"
	rm -f $TMP/lustre-log-${TESTNAME}.log
}
run_test 18 "MDS failover while writing, no watchdog triggered (b14840)"

test_19() {
	local blimit=5 # MB
	local TESTFILE=$DIR/$tdir/$tfile

	setup_quota_test || error "setup quota failed with $?"

	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# bind file to a single OST
	$LFS setstripe -c 1 $TESTFILE || error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	echo "Set user quota (limit: ${blimit}M)"
	$LFS setquota -u $TSTUSR -b 0 -B ${blimit}M -i 0 -I 0 $MOUNT ||
		error "set user quota failed"
	quota_show_check b u $TSTUSR
	echo "Update quota limits"
	$LFS setquota -u $TSTUSR -b 0 -B ${blimit}M -i 0 -I 0 $MOUNT ||
		error "set group quota failed"
	quota_show_check b u $TSTUSR

	# first wirte might be cached
	$RUNAS $DD of=$TESTFILE count=$((blimit + 1))
	cancel_lru_locks osc
	$SHOW_QUOTA_USER
	$RUNAS $DD of=$TESTFILE count=$((blimit + 1)) seek=$((blimit + 1)) &&
		quota_error u $TSTUSR "Write success, expect failure"
	$SHOW_QUOTA_USER
}
run_test 19 "Updating admin limits doesn't zero operational limits(b14790)"

test_20() { # b15754
	local LSTR=(2g 1t 4k 3m) # limits strings
	# limits values
	local LVAL=($((2*1024*1024)) $((1*1024*1024*1024)) $((4*1024)) \
		    $((3*1024*1024)))

	resetquota -u $TSTUSR

	$LFS setquota -u $TSTUSR --block-softlimit ${LSTR[0]} \
		$MOUNT || error "could not set quota limits"
	$LFS setquota -u $TSTUSR --block-hardlimit ${LSTR[1]} \
				--inode-softlimit ${LSTR[2]} \
				--inode-hardlimit ${LSTR[3]} \
				$MOUNT || error "could not set quota limits"

	[ "$(getquota -u $TSTUSR global bsoftlimit)" = "${LVAL[0]}" ] ||
		error "bsoftlimit was not set properly"
	[ "$(getquota -u $TSTUSR global bhardlimit)" = "${LVAL[1]}" ] ||
		error "bhardlimit was not set properly"
	[ "$(getquota -u $TSTUSR global isoftlimit)" = "${LVAL[2]}" ] ||
		error "isoftlimit was not set properly"
	[ "$(getquota -u $TSTUSR global ihardlimit)" = "${LVAL[3]}" ] ||
		error "ihardlimit was not set properly"

	resetquota -u $TSTUSR
}
run_test 20 "Test if setquota specifiers work properly (b15754)"

test_21_sub() {
	local testfile=$1
	local blk_number=$2
	local seconds=$3

	local time=$(($(date +%s) + seconds))
	while [ $(date +%s) -lt $time ]; do
		$RUNAS $DD of=$testfile count=$blk_number > /dev/null 2>&1
	done
}

# run for fixing bug16053, setquota shouldn't fail when writing and
# deleting are happening
test_21() {
	local TESTFILE="$DIR/$tdir/$tfile"
	local BLIMIT=10 # 10G
	local ILIMIT=1000000

	setup_quota_test || error "setup quota failed with $?"

	set_ost_qtype $QTYPE || error "Enable ost quota failed"

	log "Set limit(block:${BLIMIT}G; file:$ILIMIT) for user: $TSTUSR"
	$LFS setquota -u $TSTUSR -b 0 -B ${BLIMIT}G -i 0 -I $ILIMIT $MOUNT ||
		error "set user quota failed"
	log "Set limit(block:${BLIMIT}G; file:$ILIMIT) for group: $TSTUSR"
	$LFS setquota -g $TSTUSR -b 0 -B $BLIMIT -i 0 -I $ILIMIT $MOUNT ||
		error "set group quota failed"
	if is_project_quota_supported; then
		log "Set limit(block:${BLIMIT}G; file:$LIMIT) for " \
			"project: $TSTPRJID"
		$LFS setquota -p $TSTPRJID -b 0 -B $BLIMIT -i 0 -I $ILIMIT \
			 $MOUNT || error "set project quota failed"
	fi

	# repeat writing on a 1M file
	test_21_sub ${TESTFILE}_1 1 30 &
	local DDPID1=$!
	# repeat writing on a 128M file
	test_21_sub ${TESTFILE}_2 128 30 &
	local DDPID2=$!

	local time=$(($(date +%s) + 30))
	local i=1
	while [ $(date +%s) -lt $time ]; do
		log "Set quota for $i times"
		$LFS setquota -u $TSTUSR -b 0 -B "$((BLIMIT + i))G" -i 0 \
			-I $((ILIMIT + i)) $MOUNT ||
				error "Set user quota failed"
		$LFS setquota -g $TSTUSR -b 0 -B "$((BLIMIT + i))G" -i 0 \
			-I $((ILIMIT + i)) $MOUNT ||
				error "Set group quota failed"
		if is_project_quota_supported; then
			$LFS setquota -p $TSTPRJID -b 0 -B \
			"$((BLIMIT + i))G"  -i 0 -I $((ILIMIT + i)) $MOUNT ||
				error "Set project quota failed"
		fi
		i=$((i+1))
		sleep 1
	done

	local count=0
	while [ true ]; do
		if ! ps -p ${DDPID1} > /dev/null 2>&1; then break; fi
		count=$((count+1))
		if [ $count -gt 60 ]; then
			quota_error a $TSTUSR "dd should be finished!"
		fi
		sleep 1
	done
	echo "(dd_pid=$DDPID1, time=$count)successful"

	count=0
	while [ true ]; do
		if ! ps -p ${DDPID2} > /dev/null 2>&1; then break; fi
		count=$((count+1))
		if [ $count -gt 60 ]; then
			quota_error a $TSTUSR "dd should be finished!"
		fi
		sleep 1
	done
	echo "(dd_pid=$DDPID2, time=$count)successful"
}
run_test 21 "Setquota while writing & deleting (b16053)"

# enable/disable quota enforcement permanently
test_22() {
	echo "Set both mdt & ost quota type as ug"
	local qtype="ug"
	is_project_quota_supported && qtype=$QTYPE
	set_mdt_qtype $qtype || error "enable mdt quota failed"
	set_ost_qtype $qtype || error "enable ost quota failed"

	echo "Restart..."
	stopall || error "failed to stopall (1)"
	mount
	setupall

	echo "Verify if quota is enabled"
	local qtype1=$(mdt_quota_type)
	[ $qtype1 != $qtype ] && error "mdt quota setting is lost"
	qtype=$(ost_quota_type)
	[ $qtype1 != $qtype ] && error "ost quota setting is lost"

	echo "Set both mdt & ost quota type as none"
	set_mdt_qtype "none" || error "disable mdt quota failed"
	set_ost_qtype "none" || error "disable ost quota failed"

	echo "Restart..."
	stopall || error "failed to stopall (2)"
	mount
	setupall
	quota_init

	echo "Verify if quota is disabled"
	qtype=$(mdt_quota_type)
	[ $qtype != "none" ] && error "mdt quota setting is lost"
	qtype=$(ost_quota_type)
	[ $qtype != "none" ] && error "ost quota setting is lost"

	return 0
}
run_test 22 "enable/disable quota by 'lctl conf_param/set_param -P'"

test_23_sub() {
	local TESTFILE="$DIR/$tdir/$tfile"
	local LIMIT=$1

	setup_quota_test || error "setup quota failed with $?"

	set_ost_qtype $QTYPE || error "Enable ost quota failed"

	# test for user
	log "User quota (limit: $LIMIT MB)"
	$LFS setquota -u $TSTUSR -b 0 -B "$LIMIT"M -i 0 -I 0 $DIR ||
		error "set quota failed"
	quota_show_check b u $TSTUSR

	$LFS setstripe $TESTFILE -c 1 -i 0 || error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	log "Step1: trigger EDQUOT with O_DIRECT"
	log "Write half of file"
	$RUNAS $DD of=$TESTFILE count=$((LIMIT/2)) oflag=direct ||
		quota_error u $TSTUSR "(1) Write failure, expect success." \
			"limit=$LIMIT"
	log "Write out of block quota ..."
	$RUNAS $DD of=$TESTFILE count=$((LIMIT/2 + 1)) seek=$((LIMIT/2)) \
		oflag=direct conv=notrunc &&
		quota_error u $TSTUSR "(2) Write success, expect EDQUOT." \
			"limit=$LIMIT"
	log "Step1: done"

	log "Step2: rewrite should succeed"
	$RUNAS $DD of=$TESTFILE count=1 oflag=direct conv=notrunc||
		quota_error u $TSTUSR "(3) Write failure, expect success." \
			"limit=$LIMIT"
	log "Step2: done"

	cleanup_quota_test

	local OST0_UUID=$(ostname_from_index 0)
	local OST0_QUOTA_USED=$(getquota -u $TSTUSR $OST0_UUID curspace)
	[ $OST0_QUOTA_USED -ne 0 ] &&
		($SHOW_QUOTA_USER; \
		quota_error u $TSTUSR "quota isn't released")
	$SHOW_QUOTA_USER
}

test_23() {
	[ "$ost1_FSTYPE" == zfs ] &&
		skip "Overwrite in place is not guaranteed to be " \
		"space neutral on ZFS"

	local OST0_MIN=$((6 * 1024)) # 6MB, extra space for meta blocks.
	check_whether_skip && return 0
	log "run for 4MB test file"
	test_23_sub 4

	OST0_MIN=$((60 * 1024)) # 60MB, extra space for meta blocks.
	check_whether_skip && return 0
	log "run for 40MB test file"
	test_23_sub 40
}
run_test 23 "Quota should be honored with directIO (b16125)"

test_24() {
	local blimit=5 # MB
	local TESTFILE="$DIR/$tdir/$tfile"

	setup_quota_test || error "setup quota failed with $?"

	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# bind file to a single OST
	$LFS setstripe -c 1 $TESTFILE || error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	echo "Set user quota (limit: ${blimit}M)"
	$LFS setquota -u $TSTUSR -b 0 -B "$blimit"M -i 0 -I 0 $MOUNT ||
		error "set quota failed"

	# overrun quota by root user
	runas -u 0 -g 0 $DD of=$TESTFILE count=$((blimit + 1)) ||
		error "write failure, expect success"
	cancel_lru_locks osc
	sync_all_data || true

	$SHOW_QUOTA_USER | grep '*' || error "no matching *"
}
run_test 24 "lfs draws an asterix when limit is reached (b16646)"

test_25()
{
	(( $MDS1_VERSION >= $(version_code 2.15.55.145) )) ||
		skip "need MDS >= v2_15_55-145-g513b1cdbc for index version fix"

	local limit=10  # 10M
	local testfile="$DIR/$tdir/$tfile-0"
	local qpool="qpool1"

	mds_supports_qp
	setup_quota_test || error "setup quota failed with $?"

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	$LFS setquota -u $TSTUSR -b 0 -B 50T -i 0 -I 0 $DIR ||
		error "set user quota failed"

	pool_add $qpool || error "pool_add failed"
	pool_add_targets $qpool 0 $((OSTCOUNT - 1)) ||
		error "pool_add_targets failed"

	# increase ost index version to +200
	for i in {1..200}; do
		$LFS setquota -u $TSTUSR -B ${i}G --pool $qpool $DIR ||
			error "set user quota failed"
	done
	$LFS setquota -u $TSTUSR -b 0 -B 0 --pool $qpool $DIR ||
		error "set user quota failed"

	$LFS setquota -u $TSTUSR -B ${limit}M $DIR ||
		error "set user quota failed"

	local used=$(getquota -u $TSTUSR global curspace)
	(( used == 0)) || error "Used space($used) for user $TSTUSR isn't 0."

	$LFS setstripe $testfile -c 1 || error "setstripe $testfile failed"
	chown $TSTUSR.$TSTUSR $testfile || error "chown $testfile failed"

	test_1_check_write $testfile "user" $limit
	return 0
}
run_test 25 "check indexes versions"

test_27a() { # b19612
	$LFS quota $TSTUSR $DIR &&
		error "lfs succeeded with no type, but should have failed"
	$LFS setquota $TSTUSR $DIR &&
		error "lfs succeeded with no type, but should have failed"
	return 0
}
run_test 27a "lfs quota/setquota should handle wrong arguments (b19612)"

test_27b() { # b20200
	$LFS setquota -u $TSTID -b 1000 -B 1000 -i 1000 -I 1000 $DIR ||
		error "lfs setquota failed with uid argument"
	$LFS setquota -g $TSTID -b 1000 -B 1000 -i 1000 -I 1000 $DIR ||
		error "lfs stequota failed with gid argument"
	if is_project_quota_supported; then
		$LFS setquota -p $TSTPRJID -b 1000 -B 1000 -i 1000 -I \
			1000 $DIR || error \
				"lfs stequota failed with projid argument"
	fi
	$SHOW_QUOTA_USERID || error "lfs quota failed with uid argument"
	$SHOW_QUOTA_GROUPID || error "lfs quota failed with gid argument"
	if is_project_quota_supported; then
		$SHOW_QUOTA_PROJID ||
			error "lfs quota failed with projid argument"
		resetquota_one -p $TSTPRJID
	fi
	resetquota -u $TSTID
	resetquota -g $TSTID
	return 0
}
run_test 27b "lfs quota/setquota should handle user/group/project ID (b20200)"

test_27c() {
	local limit

	$LFS setquota -u $TSTID -b 30M -B 3T $DIR ||
		error "lfs setquota failed"

	limit=$($LFS quota -u $TSTID -v -h $DIR | grep $DIR | awk '{print $3}')
	[ $limit != "30M" ] && error "softlimit $limit isn't human-readable"
	limit=$($LFS quota -u $TSTID -v -h $DIR | grep $DIR | awk '{print $4}')
	[ $limit != "3T" ] && error "hardlimit $limit isn't human-readable"

	$LFS setquota -u $TSTID -b 1500M -B 18500G $DIR ||
		error "lfs setquota for $TSTID failed"

	limit=$($LFS quota -u $TSTID -v -h $DIR | grep $DIR | awk '{print $3}')
	[ $limit != "1.465G" ] && error "wrong softlimit $limit"
	limit=$($LFS quota -u $TSTID -v -h $DIR | grep $DIR | awk '{print $4}')
	[ $limit != "18.07T" ] && error "wrong hardlimit $limit"

	$LFS quota -u $TSTID -v -h $DIR | grep -q "Total allocated" ||
		error "total allocated inode/block limit not printed"

	resetquota -u $TSTUSR
}
run_test 27c "lfs quota should support human-readable output"

test_27d() {
	local softlimit=1.5
	local hardlimit=2.3
	local limit

	$LFS setquota -u $TSTID -b ${softlimit}p -B ${hardlimit}P $DIR ||
		error "set fraction block limit failed"
	limit=$($LFS quota -u $TSTID -h $DIR | grep $DIR | awk '{print $3}')
	[ $limit == ${softlimit}P ] || error "get fraction softlimit failed"
	limit=$($LFS quota -u $TSTID -h $DIR | grep $DIR | awk '{print $4}')
	[ $limit == ${hardlimit}P ] || error "get fraction hardlimit failed"

	resetquota -u $TSTUSR
}
run_test 27d "lfs setquota should support fraction block limit"

test_30()
{
	(( $MDS1_VERSION >= $(version_code 2.15.51.29) )) ||
		skip "need MDS >= v2_15_51-29-gd4978678b4 for grace time fix"

	local LIMIT=4 # MB
	local TESTFILE="$DIR/$tdir/$tfile"
	local GRACE=10

	setup_quota_test || error "setup quota failed with $?"

	set_ost_qtype "u" || error "enable ost quota failed"

	$LFS setstripe $TESTFILE -i 0 -c 1 || error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	$LFS setquota -t -u --block-grace $GRACE --inode-grace \
		$MAX_IQ_TIME $DIR || error "set grace time failed"
	$LFS setquota -u $TSTUSR -b ${LIMIT}M -B 0 -i 0 -I 0 $DIR ||
		error "set quota failed"
	$RUNAS $DD of=$TESTFILE count=$((LIMIT * 2)) || true
	cancel_lru_locks osc
	sleep $GRACE
	$LFS setquota -u $TSTUSR -B 0 $DIR || error "clear quota failed"
	# over-quota flag has not yet settled since we do not trigger async
	# events based on grace time period expiration
	$SHOW_QUOTA_USER
	$RUNAS $DD of=$TESTFILE conv=notrunc oflag=append count=4 || true
	cancel_lru_locks osc
	# now over-quota flag should be settled and further writes should fail
	$SHOW_QUOTA_USER
	$RUNAS $DD of=$TESTFILE conv=notrunc oflag=append count=4 &&
		error "grace times were reset"
	$LFS setquota -t -u --block-grace $MAX_DQ_TIME --inode-grace \
		$MAX_IQ_TIME $DIR || error "restore grace time failed"
}
run_test 30 "Hard limit updates should not reset grace times"

# basic usage tracking for user & group
test_33() {
	local INODES=10 # files
	local BLK_CNT=2 # MB each
	local TOTAL_BLKS=$((INODES * BLK_CNT * 1024))

	setup_quota_test || error "setup quota failed with $?"

	# make sure the system is clean
	local USED=$(getquota -u $TSTID global curspace)
	[ $USED -ne 0 ] &&
		error "Used space ($USED) for user $TSTID isn't 0."
	USED=$(getquota -g $TSTID global curspace)
	[ $USED -ne 0 ] &&
		error "Used space ($USED) for group $TSTID isn't 0."
	if is_project_quota_supported; then
		USED=$(getquota -p $TSTPRJID global curspace)
		[ $USED -ne 0 ] && error \
			"Used space ($USED) for project $TSTPRJID isn't 0."
	fi

	echo "Write files..."
	for i in $(seq 0 $INODES); do
		$RUNAS $DD of=$DIR/$tdir/$tfile-$i count=$BLK_CNT 2>/dev/null ||
			error "write failed"
			is_project_quota_supported &&
				change_project -p $TSTPRJID $DIR/$tdir/$tfile-$i
		echo "Iteration $i/$INODES completed"
	done
	cancel_lru_locks osc

	echo "Wait for setattr on objects finished..."
	wait_delete_completed

	sync; sync_all_data || true

	echo "Verify disk usage after write"
	USED=$(getquota -u $TSTID global curspace)
	[ $USED -lt $TOTAL_BLKS ] &&
		error "Used space for user $TSTID:$USED, expected:$TOTAL_BLKS"
	USED=$(getquota -g $TSTID global curspace)
	[ $USED -lt $TOTAL_BLKS ] &&
		error "Used space for group $TSTID:$USED, expected:$TOTAL_BLKS"
	if is_project_quota_supported; then
		USED=$(getquota -p $TSTPRJID global curspace)
		[ $USED -lt $TOTAL_BLKS ] && error \
			"Used space for project $TSTPRJID:$USED, expected:$TOTAL_BLKS"
	fi

	echo "Verify inode usage after write"
	USED=$(getquota -u $TSTID global curinodes)
	[ $USED -lt $INODES ] &&
		error "Used inode for user $TSTID is $USED, expected $INODES"
	USED=$(getquota -g $TSTID global curinodes)
	[ $USED -lt $INODES ] &&
		error "Used inode for group $TSTID is $USED, expected $INODES"
	if is_project_quota_supported; then
		USED=$(getquota -p $TSTPRJID global curinodes)
		[ $USED -lt $INODES ] && error \
			"Used inode for project $TSTPRJID is $USED, expected $INODES"
	fi

	cleanup_quota_test

	echo "Verify disk usage after delete"
	USED=$(getquota -u $TSTID global curspace)
	[ $USED -eq 0 ] || error "Used space for user $TSTID isn't 0. $USED"
	USED=$(getquota -u $TSTID global curinodes)
	[ $USED -eq 0 ] || error "Used inodes for user $TSTID isn't 0. $USED"
	USED=$(getquota -g $TSTID global curspace)
	[ $USED -eq 0 ] || error "Used space for group $TSTID isn't 0. $USED"
	USED=$(getquota -g $TSTID global curinodes)
	[ $USED -eq 0 ] || error "Used inodes for group $TSTID isn't 0. $USED"
	if is_project_quota_supported; then
		USED=$(getquota -p $TSTPRJID global curspace)
		[ $USED -eq 0 ] ||
			error "Used space for project $TSTPRJID isn't 0. $USED"
		USED=$(getquota -p $TSTPRJID global curinodes)
		[ $USED -eq 0 ] ||
			error "Used inodes for project $TSTPRJID isn't 0. $USED"
	fi
}
run_test 33 "Basic usage tracking for user & group & project"

# usage transfer test for user & group & project
test_34() {
	local BLK_CNT=2 # MB
	local project_supported="no"

	is_project_quota_supported && project_supported="yes"
	setup_quota_test || error "setup quota failed with $?"

	# make sure the system is clean
	local USED=$(getquota -u $TSTID global curspace)
	[ $USED -ne 0 ] && error "Used space ($USED) for user $TSTID isn't 0."
	USED=$(getquota -g $TSTID global curspace)
	[ $USED -ne 0 ] && error "Used space ($USED) for group $TSTID isn't 0."

	local USED=$(getquota -u $TSTID2 global curspace)
	[ $USED -ne 0 ] && error "Used space ($USED) for user $TSTID2 isn't 0."
	if [ $project_supported == "yes" ]; then
		USED=$(getquota -p $TSTPRJID global curspace)
		[ $USED -ne 0 ] && error \
			"Used space ($USED) for Project $TSTPRJID isn't 0."
	fi

	echo "Write file..."
	$DD of=$DIR/$tdir/$tfile count=$BLK_CNT 2>/dev/null ||
		error "write failed"
	cancel_lru_locks osc
	sync; sync_all_data || true

	echo "chown the file to user $TSTID"
	chown $TSTID $DIR/$tdir/$tfile || error "chown failed"

	echo "Wait for setattr on objects finished..."
	wait_delete_completed

	BLK_CNT=$((BLK_CNT * 1024))

	echo "Verify disk usage for user $TSTID"
	USED=$(getquota -u $TSTID global curspace)
	[ $USED -lt $BLK_CNT ] &&
		error "Used space for user $TSTID is ${USED}, expected $BLK_CNT"
	USED=$(getquota -u $TSTID global curinodes)
	[ $USED -ne 1 ] &&
		error "Used inodes for user $TSTID is $USED, expected 1"

	echo "chgrp the file to group $TSTID"
	chgrp $TSTID $DIR/$tdir/$tfile || error "chgrp failed"

	echo "Wait for setattr on objects finished..."
	wait_delete_completed

	echo "Verify disk usage for group $TSTID"
	USED=$(getquota -g $TSTID global curspace)
	[ $USED -ge $BLK_CNT ] ||
		error "Used space for group $TSTID is $USED, expected $BLK_CNT"
	USED=$(getquota -g $TSTID global curinodes)
	[ $USED -eq 1 ] ||
		error "Used inodes for group $TSTID is $USED, expected 1"

	# chown won't change the ost object group. LU-4345 */
	echo "chown the file to user $TSTID2"
	chown $TSTID2 $DIR/$tdir/$tfile || error "chown to $TSTID2 failed"

	echo "Wait for setattr on objects finished..."
	wait_delete_completed

	echo "change_project project id to $TSTPRJID"
	[ $project_supported == "yes" ] &&
		change_project -p $TSTPRJID $DIR/$tdir/$tfile
	echo "Wait for setattr on objects finished..."
	wait_delete_completed

	echo "Verify disk usage for user $TSTID2/$TSTID and group $TSTID"
	USED=$(getquota -u $TSTID2 global curspace)
	[ $USED -lt $BLK_CNT ] &&
		error "Used space for user $TSTID2 is $USED, expected $BLK_CNT"
	USED=$(getquota -u $TSTID global curspace)
	[ $USED -ne 0 ] &&
		error "Used space for user $TSTID is $USED, expected 0"
	USED=$(getquota -g $TSTID global curspace)
	[ $USED -lt $BLK_CNT ] &&
		error "Used space for group $TSTID is $USED, expected $BLK_CNT"
	if [ $project_supported == "yes" ]; then
		USED=$(getquota -p $TSTPRJID global curspace)
		[ $USED -lt $BLK_CNT ] && error \
			"Used space for group $TSTPRJID is $USED, expected $BLK_CNT"
	fi
	return 0
}
run_test 34 "Usage transfer for user & group & project"

# usage is still accessible across restart
test_35() {
	local BLK_CNT=2 # MB

	setup_quota_test || error "setup quota failed with $?"

	echo "Write file..."
	$RUNAS $DD of=$DIR/$tdir/$tfile count=$BLK_CNT 2>/dev/null ||
		error "write failed"
	is_project_quota_supported &&
		change_project -p $TSTPRJID $DIR/$tdir/$tfile
	cancel_lru_locks

	echo "Wait for setattr on objects finished..."
	wait_delete_completed

	sync; sync_all_data || true

	echo "Save disk usage before restart"
	local ORIG_USR_SPACE=$(getquota -u $TSTID global curspace)
	[ $ORIG_USR_SPACE -eq 0 ] &&
		error "Used space for user $TSTID is 0, expected ${BLK_CNT}M"
	local ORIG_USR_INODES=$(getquota -u $TSTID global curinodes)
	[ $ORIG_USR_INODES -eq 0 ] &&
		error "Used inodes for user $TSTID is 0, expected 1"
	echo "User $TSTID: ${ORIG_USR_SPACE}KB $ORIG_USR_INODES inodes"
	local ORIG_GRP_SPACE=$(getquota -g $TSTID global curspace)
	[ $ORIG_GRP_SPACE -eq 0 ] &&
		error "Used space for group $TSTID is 0, expected ${BLK_CNT}M"
	local ORIG_GRP_INODES=$(getquota -g $TSTID global curinodes)
	[ $ORIG_GRP_INODES -eq 0 ] &&
		error "Used inodes for group $TSTID is 0, expected 1"
	echo "Group $TSTID: ${ORIG_GRP_SPACE}KB $ORIG_GRP_INODES inodes"

	if is_project_quota_supported; then
		local ORIG_PRJ_SPACE=$(getquota -p $TSTPRJID global curspace)
		[ $ORIG_PRJ_SPACE -eq 0 ] && error \
			"Used space for project $TSTPRJID is 0, expected ${BLK_CNT}M"
		local ORIG_PRJ_INODES=$(getquota -p $TSTPRJID global curinodes)
		[ $ORIG_PRJ_INODES -eq 0 ] && error \
			"Used inodes for project $TSTPRJID is 0, expected 1"
		echo "Project $TSTPRJID: ${ORIG_PRJ_SPACE}KB $ORIG_PRJ_INODES inodes"
	fi

	log "Restart..."
	stopall
	setupall
	wait_recovery_complete
	quota_init

	echo "Verify disk usage after restart"
	local USED=$(getquota -u $TSTID global curspace)
	(( $USED == $ORIG_USR_SPACE )) || {
		ls -al $DIR/$tdir/$tfile
		$LFS quota -v -u $TSTID $DIR
		error "Used space for user $TSTID changed from " \
			"$ORIG_USR_SPACE to $USED"
	}
	USED=$(getquota -u $TSTID global curinodes)
	[ $USED -eq $ORIG_USR_INODES ] ||
		error "Used inodes for user $TSTID changed from " \
			"$ORIG_USR_INODES to $USED"
	USED=$(getquota -g $TSTID global curspace)
	[ $USED -eq $ORIG_GRP_SPACE ] ||
		error "Used space for group $TSTID changed from " \
			"$ORIG_GRP_SPACE to $USED"
	USED=$(getquota -g $TSTID global curinodes)
	[ $USED -eq $ORIG_GRP_INODES ] ||
		error "Used inodes for group $TSTID changed from " \
			"$ORIG_GRP_INODES to $USED"
	if [[ $project_supported == "yes" ]]; then
		USED=$(getquota -p $TSTPRJID global curinodes)
		(( $USED == $ORIG_PRJ_INODES )) ||
			error "Used inodes for project $TSTPRJID " \
				"changed from $ORIG_PRJ_INODES to $USED"
		USED=$(getquota -p $TSTPRJID global curspace)
		[ $USED -eq $ORIG_PRJ_SPACE ] ||
			error "Used space for project $TSTPRJID "\
				"changed from $ORIG_PRJ_SPACE to $USED"
	fi

	# check if the vfs_dq_init() is called before writing
	echo "Append to the same file..."
	$RUNAS $DD of=$DIR/$tdir/$tfile count=$BLK_CNT seek=1 2>/dev/null ||
		error "write failed"
	cancel_lru_locks osc
	sync; sync_all_data || true

	echo "Verify space usage is increased"
	USED=$(getquota -u $TSTID global curspace)
	[ $USED -gt $ORIG_USR_SPACE ] ||
		error "Used space for user $TSTID isn't increased" \
			"orig:$ORIG_USR_SPACE, now:$USED"
	USED=$(getquota -g $TSTID global curspace)
	[ $USED -gt $ORIG_GRP_SPACE ] ||
		error "Used space for group $TSTID isn't increased" \
			"orig:$ORIG_GRP_SPACE, now:$USED"
	if [[ $project_supported == "yes" ]]; then
		USED=$(getquota -p $TSTPRJID global curspace)
		(( $USED > $ORIG_PRJ_SPACE )) ||
			error "Used space for project $TSTPRJID isn't " \
				"increased orig:$ORIG_PRJ_SPACE, now:$USED"
	fi
}
run_test 35 "Usage is still accessible across reboot"

# chown/chgrp to the file created with MDS_OPEN_DELAY_CREATE
# LU-5006
test_37() {
	[ "$MDS1_VERSION" -lt $(version_code 2.6.93) ] &&
		skip "Old server doesn't have LU-5006 fix."

	setup_quota_test || error "setup quota failed with $?"

	# make sure the system is clean
	local USED=$(getquota -u $TSTID global curspace)
	[ $USED -ne 0 ] &&
		error "Used space ($USED) for user $TSTID isn't 0."

	# create file with MDS_OPEN_DELAY_CREATE flag
	$LFS setstripe -c 1 -i 0 $DIR/$tdir/$tfile ||
		error "Create file failed"
	# write to file
	$DD of=$DIR/$tdir/$tfile count=1 conv=notrunc \
		oflag=sync || error "Write file failed"
	# chown to the file
	chown $TSTID $DIR/$tdir/$tfile || error "Chown to file failed"

	# wait for setattr on objects finished..."
	wait_delete_completed

	USED=$(getquota -u $TSTID global curspace)
	[ $USED -ne 0 ] || quota_error u $TSTUSR "Used space is 0"
}
run_test 37 "Quota accounted properly for file created by 'lfs setstripe'"

# LU-8801
test_38() {
	[ "$MDS1_VERSION" -lt $(version_code 2.8.60) ] &&
		skip "Old server doesn't have LU-8801 fix."

	[ "$UID" != 0 ] && skip_env "must run as root" && return

	setup_quota_test || error "setup quota failed with $?"

	# make sure the system is clean
	local USED=$(getquota -u $TSTID global curspace)
	[ $USED -ne 0 ] &&
		error "Used space ($USED) for user $TSTID isn't 0."
	USED=$(getquota -u $TSTID2 global curspace)
	[ $USED -ne 0 ] &&
		error "Used space ($USED) for user $TSTID2 isn't 0."

	local TESTFILE="$DIR/$tdir/$tfile"
	local file_cnt=10000

	# Generate id entries in accounting file
	echo "Create $file_cnt files..."
	for i in `seq $file_cnt`; do
		touch $TESTFILE-$i
		chown $((file_cnt - i)):$((file_cnt - i)) $TESTFILE-$i ||
			error "failed to chown $TESTFILE-$i"
	done
	cancel_lru_locks osc
	sync; sync_all_data || true

	local procf="osd-$mds1_FSTYPE.$FSNAME-MDT0000"
	procf=${procf}.quota_slave.acct_user
	local acct_cnt

	acct_cnt=$(do_facet mds1 $LCTL get_param $procf | grep "id:" | \
		   awk '{if ($3 < 10000) {print $3}}' | wc -l)
	echo "Found $acct_cnt id entries"

	[ $file_cnt -eq $acct_cnt ] || {
		do_facet mds1 $LCTL get_param $procf
		error "skipped id entries"
	}
}
run_test 38 "Quota accounting iterator doesn't skip id entries"

test_39() {
	local TESTFILE="$DIR/$tdir/project"
	! is_project_quota_supported &&
		skip "Project quota is not supported"

	setup_quota_test || error "setup quota failed with $?"

	touch $TESTFILE
	projectid=$(lfs project $TESTFILE | awk '{print $1}')
	[ $projectid -ne 0 ] &&
		error "Project id should be 0 not $projectid"
	change_project -p 1024 $TESTFILE
	projectid=$(lfs project $TESTFILE | awk '{print $1}')
	[ $projectid -ne 1024 ] &&
		error "Project id should be 1024 not $projectid"

	stopall || error "failed to stopall (1)"
	mount
	setupall
	projectid=$(lfs project $TESTFILE | awk '{print $1}')
	[ $projectid -eq 1024 ] ||
		error "Project id should be 1024 not $projectid"
}
run_test 39 "Project ID interface works correctly"

test_40a() {
	! is_project_quota_supported &&
		skip "Project quota is not supported"
	local dir1="$DIR/$tdir/dir1"
	local dir2="$DIR/$tdir/dir2"

	setup_quota_test || error "setup quota failed with $?"

	mkdir -p $dir1 $dir2
	change_project -sp 1 $dir1 && touch $dir1/1
	change_project -sp 2 $dir2

	ln $dir1/1 $dir2/1_link &&
		error "Hard link across different project quota should fail"
	return 0
}
run_test 40a "Hard link across different project ID"

test_40b() {
	! is_project_quota_supported &&
		skip "Project quota is not supported"
	local dir1="$DIR/$tdir/dir1"
	local dir2="$DIR/$tdir/dir2"

	setup_quota_test || error "setup quota failed with $?"
	mkdir -p $dir1 $dir2
	change_project -sp 1 $dir1 && touch $dir1/1
	change_project -sp 2 $dir2

	mv $dir1/1 $dir2/2 || error "mv failed $?"
	local projid=$(lfs project $dir2/2 | awk '{print $1}')
	[ "$projid" -eq 2 ] || error "project id expected 2 not $projid"
}
run_test 40b "Mv across different project ID"

test_40c() {
	[ "$MDSCOUNT" -lt "2" ] && skip "needs >= 2 MDTs"
		! is_project_quota_supported &&
			skip "Project quota is not supported"

	setup_quota_test || error "setup quota failed with $?"
	local dir="$DIR/$tdir/dir"

	mkdir -p $dir && change_project -sp 1 $dir
	$LFS mkdir -i 1 $dir/remote_dir || error "create remote dir failed"
	local projid=$(lfs project -d $dir/remote_dir | awk '{print $1}')
	[ "$projid" != "1" ] && error "projid id expected 1 not $projid"
	touch $dir/remote_dir/file
	#verify inherit works file for remote dir.
	local projid=$(lfs project -d $dir/remote_dir/file | awk '{print $1}')
	[ "$projid" != "1" ] &&
		error "file under remote dir expected 1 not $projid"

	#Agent inode should be ignored for project quota
	local used=$(getquota -p 1 global curinodes)
	[ $used -eq 3 ] ||
		error "file count expected 3 got $used"
}
run_test 40c "Remote child Dir inherit project quota properly"

test_40d() {
	[ "$MDSCOUNT" -lt "2" ] && skip_env "needs >= 2 MDTs"
	is_project_quota_supported || skip "Project quota is not supported"

	setup_quota_test || error "setup quota failed with $?"
	local dir="$DIR/$tdir/dir"

	mkdir -p $dir
	$LFS setdirstripe -D -c 2 -i -1 $dir || error "setdirstripe failed"
	change_project -sp $TSTPRJID $dir ||
		error "change project on $dir failed"
	for i in $(seq 5); do
		mkdir -p $dir/d$i/d$i ||
			error "mkdir $dir/d$i/d$i failed"
		local projid=$($LFS project -d $dir/d$i/d$i |
			       awk '{print $1}')
		[ "$projid" == "$TSTPRJID" ] ||
			error "projid id expected $TSTPRJID not $projid"
		touch $dir/d$i/d$i/file
		#verify inherit works file for stripe dir.
		local projid=$($LFS project -d $dir/d$i/d$i/file | awk '{print $1}')
		[ "$projid" == "$TSTPRJID" ] ||
			error "file under remote dir expected 1 not $projid"
	done

	# account should be 1 + (2 + 1) *10 + 1 * 5
	local used=$(getquota -p $TSTPRJID global curinodes)
	[ $used -eq 36 ] ||
		error "file count expected 36 got $used"
}
run_test 40d "Stripe Directory inherit project quota properly"

test_41() {
	is_project_quota_supported ||
		skip "Project quota is not supported"
	setup_quota_test || error "setup quota failed with $?"
	local dir="$DIR/$tdir/dir"
	local blimit=102400
	local ilimit=4096
	local projid=$((testnum * 1000))

	quota_init

	# enable mdt/ost quota
	set_mdt_qtype ugp || error "enable mdt quota failed"
	set_ost_qtype ugp || error "enable ost quota failed"

	local statfs_prj_orig=$($LCTL get_param -n llite.*.statfs_project)
	(( statfs_prj_orig == 1 )) ||
		$LCTL set_param llite.*.statfs_project=1
	stack_trap "$LCTL set_param llite.*.statfs_project=$statfs_prj_orig"

	test_mkdir -p $dir && change_project -sp $projid $dir
	$LFS setquota -p $projid -b 0 -B ${blimit}K -i 0 -I $ilimit $dir ||
		error "set project quota failed"

	sync; sync_all_data
	sleep_maxage

	# check if df output works as expected
	echo "== global statfs: $MOUNT =="
	df -kP $MOUNT; df -iP $MOUNT; $LFS quota -p $projid $dir
	echo
	echo "== project statfs (prjid=$projid): $dir =="
	df -kP $dir; df -iP $dir
	local bused=$(getquota -p $projid global curspace)
	local iused=$(getquota -p $projid global curinodes)
	local expected="$ilimit$iused"

	wait_update $HOSTNAME \
		"df -iP $dir | awk \\\"/$FSNAME/\\\"'{print \\\$2 \\\$3}'" \
		"$expected" ||
		error "failed to get correct statfs for project quota"

	expected=$(df -kP $dir | awk "/$FSNAME/"' {print $2}')
	(( expected == blimit )) ||
		error "blimit mismatch: $expected != $blimit"

	# zfs block size is 4K, while quota is printed in 1K, df result may be
	# larger than quota result, but it's no more than 3K
	expected=$(df -kP $dir | awk "/$FSNAME/"' {print $3}')
	(( expected - bused < 4)) || error "bused mismatch: $expected != $bused"

	# disable statfs_project and check again
	$LCTL set_param llite.*.statfs_project=0

	expected=$({ df -kP $MOUNT; df -iP $MOUNT; } | \
		awk '/'$FSNAME'/ { printf "%d %d ", $2,$3 }')

	wait_update $HOSTNAME \
		"{ df -kP $dir; df -iP $dir; } |
		 awk '/$FSNAME/ { printf \\\"%d %d \\\", \\\$2,\\\$3 }'" \
		"$expected" ||
		error "failed to get correct statfs when statfs_project=0"
}
run_test 41 "df should return projid-specific values"

test_lfs_quota()
{
	local qdtype=$1
	local qtype=$2
	local bsl
	local bhl
	local isl
	local ihl

	eval $($LFS quota $qtype 2147483647 $MOUNT |
	    awk 'NR = 2 {printf("bsl=%d;bhl=%d;isl=%d;ihl=%d;", \
				$3, $4, $7, $8)}')

	(( $bsl != 0 || $bhl != 0 || $isl != 0 || $ihl != 0 )) &&
		skip "qid 2147483647 is already used"

	$LFS setquota $qdtype -b 100M -B 200M $MOUNT ||
		error "fail to set default quota"

	eval $($LFS quota $qtype 2147483647 $MOUNT |
	    awk 'NR = 2 {printf("bsl=%d;bhl=%d;isl=%d;ihl=%d;", \
				$3, $4, $7, $8)}')

	[ $bsl -ne 102400 -o $bhl -ne 204800 ] &&
		error "fail to include default block quota"

	$LFS setquota $qdtype -i 10K -I 20K $MOUNT ||
		error "fail to set default quota"

	eval $($LFS quota $qtype 2147483647 $MOUNT |
	    awk 'NR = 2 {printf("bsl=%d;bhl=%d;isl=%d;ihl=%d;", \
				$3, $4, $7, $8)}')

	[ $isl -ne 10240 -o $ihl -ne 20480 ] &&
		error "fail to include default file quota"
}

test_42()
{
	setup_quota_test || error "setup quota failed with $?"
	quota_init

	test_lfs_quota "-U" "-u"
	test_lfs_quota "-G" "-g"
	is_project_quota_supported && test_lfs_quota "-P" "-p"

	cleanup_quota_test
}
run_test 42 "lfs quota should include default quota info"

test_delete_qid()
{
	local qslv_file=$1
	local qtype_file=$2
	local qtype=$3
	local qid=$4
	local osd="osd-ldiskfs"

	[ "$ost1_FSTYPE" = zfs ] && osd="osd-zfs"

	rm -f $DIR/$tdir/$tfile
	$LFS setstripe -i 0 -c 1 $DIR/$tdir/$tfile
	chmod a+rw $DIR/$tdir/$tfile

	$LFS setquota $qtype $qid -B 300M $MOUNT
	$RUNAS $DD of=$DIR/$tdir/$tfile count=1 || error "failed to dd"

	do_facet $SINGLEMDS \
		"cat /proc/fs/lustre/qmt/$FSNAME-QMT0000/dt-0x0/$qtype_file |
		 grep -E 'id: *$qid'" || error "QMT: no qid $qid is found"
	echo $osd
	do_facet ost1 \
		"cat /proc/fs/lustre/$osd/$FSNAME-OST0000/$qslv_file |
		 grep -E 'id: *$qid'" || error "QSD: no qid $qid is found"

	$LFS setquota $qtype $qid --delete $MOUNT
	do_facet $SINGLEMDS \
		"cat /proc/fs/lustre/qmt/$FSNAME-QMT0000/dt-0x0/$qtype_file |
		 grep -E 'id: *$qid'" && error "QMT: qid $qid is not deleted"
	sleep 5
	do_facet ost1 \
		"cat /proc/fs/lustre/$osd/$FSNAME-OST0000/$qslv_file |
		 grep -E 'id: *$qid'" && error "QSD: qid $qid is not deleted"

	$LFS setquota $qtype $qid -B 500M $MOUNT
	$RUNAS $DD of=$DIR/$tdir/$tfile count=1 || error "failed to dd"
	do_facet $SINGLEMDS \
		"cat /proc/fs/lustre/qmt/$FSNAME-QMT0000/dt-0x0/$qtype_file |
		 grep -E 'id: *$qid'" || error "QMT: qid $pid is not recreated"
	cat /proc/fs/lustre/$osd/$FSNAME-OST0000/$qslv_file
	do_facet ost1 \
		"cat /proc/fs/lustre/$osd/$FSNAME-OST0000/$qslv_file |
		 grep -E 'id: *$qid'" || error "QSD: qid $qid is not recreated"
}

test_48()
{
	setup_quota_test || error "setup quota failed with $?"
	set_ost_qtype $QTYPE || error "enable ost quota failed"
	quota_init

	test_delete_qid "quota_slave/limit_user" "glb-usr" "-u" $TSTID
	test_delete_qid "quota_slave/limit_group" "glb-grp" "-g" $TSTID
	is_project_quota_supported &&
	    test_delete_qid "quota_slave/limit_project" "glb-prj" "-p" "10000"

	cleanup_quota_test
}
run_test 48 "lfs quota --delete should delete quota project ID"

test_get_allquota() {
	local file_cnt=$1
	local start_qid=$2
	local end_qid=$3
	local u_blimit=$4
	local u_ilimit=$5
	local g_blimit=$6
	local g_ilimit=$7
	local TFILE="$DIR/$tdir/$tfile-0"

	local u_blimits
	local u_ilimits
	local g_blimits
	local g_ilimits
	local u_busage
	local u_busage2
	local g_busage
	local g_busage2
	local u_iusage
	local u_iusage2
	local g_iusage
	local g_iusage2
	local start
	local total

	local qid_cnt=$file_cnt

	[ $end_qid -ne 0 ] && qid_cnt=$((end_qid - start_qid + 1))
	[ $end_qid -ge $file_cnt ] &&
		qid_cnt=$((qid_cnt - end_qid + file_cnt))
	[ $qid_cnt -le 0 ] && error "quota ID count is wrong"

	cnt=$($LFS quota -a -s $start_qid -e $end_qid -u $MOUNT | wc -l)
	[ $cnt -ge $((qid_cnt + 2)) ] || error "failed to get all usr quota"
	cnt=$($LFS quota -a -s $start_qid -e $end_qid -g $MOUNT | wc -l)
	[ $cnt -ge $((qid_cnt + 2)) ] || error "failed to get all grp quota"

	cancel_lru_locks osc
	sync; sync_all_data || true
	sleep 5

	eval $($LFS quota -a -s $start_qid -e $end_qid -u $MOUNT |
	    awk 'NR > 2 {printf("u_blimits[%d]=%d;u_ilimits[%d]=%d; \
		 u_busage[%d]=%d;u_iusage[%d]=%d;", \
		 NR, $5, NR, $9, NR, $3, NR, $7)}')
	eval $($LFS quota -a -s $start_qid -e $end_qid -g $MOUNT |
	    awk 'NR > 2 {printf("g_blimits[%d]=%d;g_ilimits[%d]=%d; \
		 g_busage[%d]=%d;g_iusage[%d]=%d;", \
		 NR, $5, NR, $9, NR, $3, NR, $7)}')

	for i in $(seq $qid_cnt); do
		[ $i -le 2 ] && continue

		[ ${u_ilimits[$i]} -eq $u_ilimit ] ||
		error "file limit for user ID $((start_qid + i - 3)) is wrong"
		[ ${u_blimits[$i]} -eq $u_blimit ] ||
		error "block limit for user ID $((start_qid + i - 3)) is wrong"
		[ ${g_ilimits[$i]} -eq $g_ilimit ] ||
		error "file limit for group ID $((start_qid + i - 3)) is wrong"
		[ ${g_blimits[$i]} -eq $g_blimit ] ||
		error "block limit for group ID $((start_qid + i - 3)) is wrong"
	done

	echo "Create $qid_cnt files..."
	createmany -S 4k -U $start_qid -G $start_qid -o ${TFILE} $qid_cnt ||
			error "failed to create many files"

	cancel_lru_locks osc
	sync; sync_all_data || true
	sleep 5

	start=$SECONDS
	$LFS quota -a -s $start_qid -e $end_qid -u $MOUNT | tail -n 50
	total=$((SECONDS - start))
	(( end - start > 0 )) &&
		echo "time=$total, rate=$((qid_cnt / total))/s" ||
		echo "time=0, rate=$qid_cnt/0"

	start=$SECONDS
	$LFS quota -a -s $start_qid -e $end_qid -g $MOUNT | tail -n 50
	total=$((SECONDS - start))
	(( end - start > 0 )) &&
		echo "time=$total, rate=$((qid_cnt / total))/s" ||
		echo "time=0, rate=$qid_cnt/0"

	cnt=$($LFS quota -a -s $start_qid -e $end_qid -u $MOUNT | wc -l)
	[ $cnt -ge $((qid_cnt + 2)) ] || error "failed to get all usr quota"
	cnt=$($LFS quota -a -s $start_qid -e $end_qid -g $MOUNT | wc -l)
	[ $cnt -ge $((qid_cnt + 2)) ] || error "failed to get all grp quota"

	eval $($LFS quota -a -s $start_qid -e $end_qid -u $MOUNT |
	    awk 'NR > 2 {printf("u_blimits[%d]=%d;u_ilimits[%d]=%d; \
		 u_busage2[%d]=%d;u_iusage2[%d]=%d;", \
		 NR, $5, NR, $9, NR, $3, NR, $7)}')
	eval $($LFS quota -a -s $start_qid -e $end_qid  -g $MOUNT |
	    awk 'NR > 2 {printf("g_blimits[%d]=%d;g_ilimits[%d]=%d; \
		 g_busage2[%d]=%d;g_iusage2[%d]=%d;", \
		 NR, $5, NR, $9, NR, $3, NR, $7)}')

	sz=$((sz / 1024))
	for i in $(seq $qid_cnt); do
		[ $i -le 2 ] && continue

		[ ${u_ilimits[$i]} -eq $u_ilimit ] ||
		error "file limit for user ID $((start_qid + i - 3)) is wrong"
		[ ${u_blimits[$i]} -eq $u_blimit ] ||
		error "block limit for user ID $((start_qid + i - 3)) is wrong"
		[ ${g_ilimits[$i]} -eq $g_ilimit ] ||
		error "file limit for group ID $((start_qid + i - 3)) is wrong"
		[ ${g_blimits[$i]} -eq $g_blimit ] ||
		error "block limit for group ID $((start_qid + i - 3)) is wrong"
		[ ${u_iusage2[$i]} -eq $((u_iusage[$i] + 1)) ] ||
		error "file usage for user ID $((start_qid + i - 3)) is wrong ${u_iusage[$i]}, ${u_iusage2[$i]}"
		[ ${u_busage2[$i]} -ge $((u_busage[$i] + 4)) ] ||
		error "block usage for user ID $((start_qid + i - 3)) is wrong ${u_busage[$i]}, ${u_busage2[$i]}"
		[ ${g_iusage2[$i]} -eq $((g_iusage[$i] + 1)) ] ||
		error "file usage for group ID $((start_qid + i - 3)) is wrong ${g_iusage[$i]}, ${g_iusage2[$i]}"
		[ ${g_busage2[$i]} -ge $((g_busage[$i] + 4)) ] ||
		error "block usage for group ID $((start_qid + i - 3)) is wrong ${g_busage[$i]}, ${g_busage2[$i]}"
	done

	unlinkmany ${TFILE} $qid_cnt
}

test_49()
{
	(( MDS1_VERSION >= $(version_code 2.15.60) )) ||
		skip "Need MDS version at least 2.15.60"

	local u_blimit=102400
	local u_ilimit=10240
	local g_blimit=204800
	local g_ilimit=20480
	local count=10

	setup_quota_test || error "setup quota failed with $?"
	stack_trap cleanup_quota_test EXIT

	[ "$SLOW" = "yes" ] && total_file_cnt=20000 || total_file_cnt=1000
	total_file_cnt=${NUM_QIDS:-$total_file_cnt}

	local start=$SECONDS

	echo "setquota for users and groups"
	#define OBD_FAIL_QUOTA_NOSYNC		0xA09
	do_facet mds1 $LCTL set_param fail_loc=0xa09
	for i in $(seq $total_file_cnt); do
		$LFS setquota -u $i -B ${u_blimit} -I ${u_ilimit} $MOUNT ||
				error "failed to setquota for usr $i"
		$LFS setquota -g $i -B ${g_blimit} -I ${g_ilimit} $MOUNT ||
				error "failed to setquota for grp $i"
		(( i % 1000 == 0)) &&
			echo "lfs setquota: $i / $((SECONDS - start)) seconds"
	done
	do_facet mds1 $LCTL set_param fail_loc=0

	start=$SECONDS
	$LFS quota -a -u $MOUNT | head -n 100
	echo "get all usr quota: $total_file_cnt / $((SECONDS - start)) seconds"

	start=$SECONDS
	$LFS quota -a -g $MOUNT | tail -n 100
	echo "get all grp quota: $total_file_cnt / $((SECONDS - start)) seconds"

	while true; do
		test_get_allquota $total_file_cnt $count $((count + 5000)) \
			$u_blimit $u_ilimit $g_blimit $g_ilimit
		test_get_allquota $total_file_cnt $count $((count + 5000)) \
			$u_blimit $u_ilimit $g_blimit $g_ilimit

		count=$((count + 5000))
		[ $count -gt $total_file_cnt ] && break
	done;

	do_facet mds1 $LCTL set_param fail_loc=0xa08
	for i in $(seq $total_file_cnt); do
		$LFS setquota -u $i --delete $MOUNT
		$LFS setquota -g $i --delete $MOUNT
	done
	do_facet mds1 $LCTL set_param fail_loc=0

	formatall
	setupall
}
run_test 49 "lfs quota -a prints the quota usage for all quota IDs"

test_50() {
	! is_project_quota_supported &&
		skip "Project quota is not supported"

	setup_quota_test || error "setup quota failed with $?"
	local dir1="$DIR/$tdir/dir1"
	local dir2="$DIR/$tdir/dir2"

	mkdir -p $dir1 && change_project -sp 1 $dir1
	mkdir -p $dir2 && change_project -sp 2 $dir2
	for num in $(seq 1 10); do
		touch $dir1/file_$num $dir2/file_$num
		ln -s $dir1/file_$num $dir1/file_$num"_link"
		ln -s $dir2/file_$num $dir2/file_$num"_link"
	done

	count=$($LFS find --projid 1 $DIR | wc -l)
	[ "$count" != 21 ] && error "expected 21 but got $count"

	# 1(projid 0 dir) + 1(projid 2 dir) + 20(projid 2 files)
	count=$($LFS find ! --projid 1 $DIR/$tdir | wc -l)
	[ $count -eq 22 ] || error "expected 22 but got $count"
}
run_test 50 "Test if lfs find --projid works"

test_51() {
	! is_project_quota_supported &&
		skip "Project quota is not supported"
	setup_quota_test || error "setup quota failed with $?"
	local dir="$DIR/$tdir/dir"

	mkdir $dir && change_project -sp 1 $dir
	local used=$(getquota -p 1 global curinodes)
	[ $used != "1" ] && error "expected 1 got $used"

	touch $dir/1
	touch $dir/2
	cp $dir/2 $dir/3
	used=$(getquota -p 1 global curinodes)
	[ $used != "4" ] && error "expected 4 got $used"

	$DD of=$DIR/$tdir/6 count=1
	#try cp to dir
	cp $DIR/$tdir/6 $dir/6
	used=$(getquota -p 1 global curinodes)
	[ $used != "5" ] && error "expected 5 got $used"

	#try mv to dir
	mv $DIR/$tdir/6 $dir/7
	used=$(getquota -p 1 global curinodes)
	[ $used -eq 6 ] || error "expected 6 got $used"
}
run_test 51 "Test project accounting with mv/cp"

test_52() {
	! is_project_quota_supported &&
		skip "Project quota is not supported"

	(( MDS1_VERSION >= $(version_code 2.14.55) )) ||
		skip "Need MDS version at least 2.14.55"

	setup_quota_test || error "setup quota failed with $?"

	local dir1=$DIR/$tdir/t52_dir1
	local dir2=$DIR/$tdir/t52_dir2

	mkdir $dir1 || error "failed to mkdir $dir1"
	mkdir $dir2 || error "failed to mkdir $dir2"

	$LFS project -sp 1000 $dir1 || error "fail to set project on $dir1"
	$LFS project -sp 1001 $dir2 || error "fail to set project on $dir2"

	$DD of=$dir1/$tfile count=100 ||
		error "failed to create and write $dir1/$tfile"

	cancel_lru_locks osc
	sync; sync_all_data || true

	local attrs=($(lsattr -p $dir1/$tfile))
	(( ${attrs[0]} == 1000 )) ||
		error "project ID on $dir1/$tfile is not inherited"

	$LFS quota -p 1000 $DIR
	$LFS quota -p 1001 $DIR

	local prev_used=$(getquota -p 1000 global curspace)
	local prev_used2=$(getquota -p 1001 global curspace)

	mrename $dir1 $dir2/tdir || log "rename directory return $?"

	local inum_before=$(ls -i $dir1/$tfile | awk '{print $1}')
	mrename $dir1/$tfile $dir2/$tfile || error "failed to rename file"
	local inum_after=$(ls -i $dir2/$tfile | awk '{print $1}')

	attrs=($(lsattr -p $dir2/$tfile))
	(( ${attrs[0]} == 1001 )) ||
		error "project ID is not updated after rename"

	(( $inum_before == $inum_after )) ||
		error "inode is changed after rename: $inum_before, $inum_after"

	sync_all_data || true

	$LFS quota -p 1000 $DIR
	$LFS quota -p 1001 $DIR

	local new_used=$(getquota -p 1000 global curspace)
	local new_used2=$(getquota -p 1001 global curspace)

	(( $prev_used >= $new_used + 102400 )) ||
		error "quota is not deducted from old project ID"
	(( $prev_used2 <= $new_used2 - 102400 )) ||
		error "quota is not added for the new project ID"
}
run_test 52 "Rename normal file across project ID"

test_53() {
	! is_project_quota_supported &&
		skip "Project quota is not supported"
	setup_quota_test || error "setup quota failed with $?"
	local dir="$DIR/$tdir/dir"
	mkdir $dir && change_project -s $dir
	[[ $($LFS project -d $dir) =~ " P " ]] ||
		error "inherit attribute should be set"

	change_project -C $dir
	[[ $($LFS project -d $dir) =~ " - " ]] ||
		error "inherit attribute should be cleared"
}
run_test 53 "Project inherit attribute could be cleared"

test_54() {
	! is_project_quota_supported &&
		skip "Project quota is not supported"
	setup_quota_test || error "setup quota failed with $?"
	local testfile="$DIR/$tdir/$tfile-0"

	#set project ID/inherit attribute
	change_project -sp $TSTPRJID $DIR/$tdir
	$RUNAS createmany -m ${testfile} 100 ||
		error "create many files failed"

	local proj_count=$(lfs project -r $DIR/$tdir | wc -l)
	# one more count for directory itself */
	((proj_count++))

	#check project
	local proj_count1=$(lfs project -rcp $TSTPRJID $DIR/$tdir | wc -l)
	[ $proj_count1 -eq 0 ] || error "c1: expected 0 got $proj_count1"

	proj_count1=$(lfs project -rcp $((TSTPRJID+1)) $DIR/$tdir | wc -l)
	[ $proj_count1 -eq $proj_count ] ||
			error "c2: expected $proj_count got $proj_count1"

	#clear project but with kept projid
	change_project -rCk $DIR/$tdir
	proj_count1=$(lfs project -rcp $TSTPRJID $DIR/$tdir | wc -l)
	[ $proj_count1 -eq 1 ] ||
			error "c3: expected 1 got $proj_count1"

	#verify projid untouched.
	proj_count1=$(lfs project -r $DIR/$tdir | grep -c $TSTPRJID)
	((proj_count1++))
	[ $proj_count1 -eq $proj_count ] ||
			error "c4: expected $proj_count got $proj_count1"

	# test -0 option
	lfs project $DIR/$tdir -cr -0 | xargs -0 lfs project -s
	proj_count1=$(lfs project -rcp $TSTPRJID $DIR/$tdir | wc -l)
	[ $proj_count1 -eq 0 ] || error "c5: expected 0 got $proj_count1"

	#this time clear all
	change_project -rC $DIR/$tdir
	proj_count1=$(lfs project -r $DIR/$tdir | grep -c $TSTPRJID)
	[ $proj_count1 -eq 0 ] ||
			error "c6: expected 0 got $proj_count1"
	#cleanup
	unlinkmany ${testfile} 100 ||
		error "unlink many files failed"
}
run_test 54 "basic lfs project interface test"

test_55() {
	[ "$MDS1_VERSION" -lt $(version_code 2.10.58) ] &&
		skip "Not supported before 2.10.58."
	setup_quota_test || error "setup quota failed with $?"

	set_ost_qtype $QTYPE || error "enable ost quota failed"
	quota_init

	#add second group to TSTUSR
	usermod -G $TSTUSR,$TSTUSR2 $TSTUSR

	#prepare test file
	$RUNAS dd if=/dev/zero of=$DIR/$tdir/$tfile bs=1024 count=100000 ||
	error "failed to dd"

	cancel_lru_locks osc
	sync; sync_all_data || true

	$LFS setquota -g $TSTUSR2 -b 0 -B 50M $DIR ||
	error "failed to setquota on group $TSTUSR2"

	$LFS quota -v -g $TSTUSR2 $DIR

	runas -u $TSTUSR -g $TSTUSR2 chgrp $TSTUSR2 $DIR/$tdir/$tfile &&
	error "chgrp should failed with -EDQUOT"

	USED=$(getquota -g $TSTUSR2 global curspace)
	echo "$USED"

	$LFS setquota -g $TSTUSR2 -b 0 -B 300M $DIR ||
	error "failed to setquota on group $TSTUSR2"

	$LFS quota -v -g $TSTUSR2 $DIR

	runas -u $TSTUSR -g $TSTUSR2 chgrp $TSTUSR2 $DIR/$tdir/$tfile ||
	error "chgrp should succeed"

	$LFS quota -v -g $TSTUSR2 $DIR
}
run_test 55 "Chgrp should be affected by group quota"

test_56() {
	setup_quota_test || error "setup quota failed with $?"

	set_ost_qtype $QTYPE || error "enable ost quota failed"
	quota_init

	$LFS setquota -t -u -b 10 -i 10 $DIR ||
		erro "failed to set grace time for usr quota"
	grace_time=$($LFS quota -t -u $DIR | grep "Block grace time:" |
		     awk '{print $4 $8}')
	if [ "x$grace_time" != "x10s;10s" ]; then
		$LFS quota -t -u $DIR
		error "expected grace time: 10s;10s, got:$grace_time"
	fi
}
run_test 56 "lfs quota -t should work well"

test_57() {
	setup_quota_test || error "setup quota failed with $?"

	local dir="$DIR/$tdir/dir"
	mkdir -p $dir
	mkfifo $dir/pipe
	#command can process further if it hit some errors
	$LFS project -sp 1 $dir/pipe
	touch $dir/aaa $dir/bbb
	mkdir $dir/subdir -p
	touch $dir/subdir/aaa $dir/subdir/bbb
	#create one invalid link file
	ln -s $dir/not_exist_file $dir/ccc
	local cnt=$(lfs project -r $dir 2>/dev/null | wc -l)
	[ $cnt -eq 7 ] || error "expected 7 got $cnt"
}
run_test 57 "lfs project could tolerate errors"

# LU-16988
test_mirror()
{
	local projid=$1
	local testfile=$2
	local mirrorfile=$3

	# create mirror
	$LFS mirror extend -N2 $mirrorfile || error "failed to create mirror"

	local mirrors=$($LFS getstripe -N $testfile)
	[[ $mirrors == 3 ]] || error "mirror count $mirrors is wrong"

	cancel_lru_locks osc
	cancel_lru_locks mdc
	sync; sync_all_data || true

	local prev_usage=$(getquota -p $projid global curspace)

	$RUNAS $DD of=$testfile count=50 conv=nocreat oflag=direct ||
			quota_error p $projid "write failed, expect succeed"

	cancel_lru_locks osc
	cancel_lru_locks mdc
	sync; sync_all_data || true

	$RUNAS $LFS mirror resync $testfile || error "failed to resync mirror"

	local usage=$(getquota -p $projid global curspace)
	(( usage >= prev_usage + 150*1024 )) ||
				error "project quota $usage is wrong"

	$RUNAS $DD of=$testfile count=30 conv=nocreat seek=50 oflag=direct ||
			quota_error p $projid "write failed, expect succeed"

	$RUNAS $LFS mirror resync $testfile &&
			error "resync mirror succeed, expect EDQUOT"

	$LFS mirror delete --mirror-id 2 $testfile ||
			error "failed to delete the second mirror"
	$LFS mirror delete --mirror-id 3 $testfile ||
			error "failed to delete the third mirror"
}

test_58() {
	(( $MDS1_VERSION >= $(version_code 2.15.56) )) ||
		skip "need MDS 2.15.56 or later"

	is_project_quota_supported || skip "Project quota is not supported"

	local testdir="$DIR/$tdir"
	local testfile="$DIR/$tdir/$tfile"
	local projid=1000
	local projid2=1001

	setup_quota_test || error "setup quota failed with $?"

	USED=$(getquota -p $projid global curspace)
	[ $USED -ne 0 ] && error "Used space ($USED) for proj $projid isn't 0"

	USED=$(getquota -p $projid2 global curspace)
	[ $USED -ne 0 ] && error "Used space ($USED) for proj $projid2 isn't 0"

	chown $TSTUSR.$TSTUSR $testdir || error "chown $testdir failed"
	quota_init
	set_ost_qtype ugp || error "enable ost quota failed"

	$LFS project -sp $projid $testdir || error "failed to set project ID"
	$LFS setquota -p $projid -B 200M $DIR ||
				error "failed to to set prj $projid quota"

	$RUNAS touch $testfile

	local id=$(lfs project -d $testfile | awk '{print $1}')
	[ "$id" != "$projid" ] && error "projid $projid is not inherited $id"

	echo "test by mirror created with normal file"
	test_mirror $projid $testfile $testfile

	$TRUNCATE $testfile 0
	wait_delete_completed || error "wait_delete_completed failed"
	sync_all_data || true

	$LFS project -sp $projid2 $testdir ||
				error "failed to set directory project ID"
	$LFS project -p $projid2 $testfile ||
				error "failed to set file project ID"
	$LFS setquota -p $projid -b 0 -B 0 $DIR ||
				error "failed to to reset prj quota"
	$LFS setquota -p $projid2 -B 200M $DIR ||
				error "failed to to set prj $projid2 quota"

	local fid=$($LFS path2fid $testfile)

	echo "test by mirror created with FID"
	test_mirror $projid2 $testfile $MOUNT/.lustre/fid/$fid
}
run_test 58 "project ID should be kept for new mirrors created by FID"

test_59() {
	[ "$mds1_FSTYPE" != ldiskfs ] &&
		skip "ldiskfs only test"
	disable_project_quota
	setup_quota_test || error "setup quota failed with $?"
	quota_init

	local testfile="$DIR/$tdir/$tfile-0"
	#make sure it did not crash kernel
	touch $testfile && lfs project -sp 1 $testfile

	enable_project_quota
}
run_test 59 "lfs project dosen't crash kernel with project disabled"

test_60() {
	[ $MDS1_VERSION -lt $(version_code 2.11.53) ] &&
		skip "Needs MDS version 2.11.53 or later."
	setup_quota_test || error "setup quota failed with $?"

	local testfile=$DIR/$tdir/$tfile
	local limit=100

	set_mdt_qtype "ug" || error "enable mdt quota failed"

	$LFS setquota -g $TSTUSR -b 0 -B 0 -i 0 -I $limit $DIR ||
		error "set quota failed"
	quota_show_check a g $TSTUSR

	chown $TSTUSR.$TSTUSR $DIR/$tdir || error "chown $DIR/$tdir failed"
	chmod g+s $DIR/$tdir || error "chmod g+s failed"
	$RUNAS createmany -m ${testfile} $((limit-1)) ||
		error "create many files failed"

	$RUNAS touch $DIR/$tdir/foo && error "regular user should fail"

	# root user can overrun quota
	runas -u 0 -g 0 touch $DIR/$tdir/foo ||
		error "root user should succeed"
}
run_test 60 "Test quota for root with setgid"

# test default quota
test_default_quota() {
	[ "$MDS1_VERSION" -lt $(version_code 2.11.51) ] &&
		skip "Not supported before 2.11.51."

	local qtype=$1
	local qres_type=$2
	local qid=$TSTUSR
	local qprjid=$TSTPRJID
	local qdtype="-U"
	local qs="-b"
	local qh="-B"
	local LIMIT=20480 #20M disk space
	local TESTFILE="$DIR/$tdir/$tfile-0"
	local $qpool_cmd

	[ $qtype == "-p" ] && ! is_project_quota_supported &&
		echo "Project quota is not supported" && return 0

	[ $qtype == "-u" ] && qdtype="-U"
	[ $qtype == "-g" ] && qdtype="-G"
	[ $qtype == "-p" ] && {
		qdtype="-P"
		qid=$qprjid
	}

	[ $qres_type == "meta" ] && {
		LIMIT=10240 #10K inodes
		qs="-i"
		qh="-I"
	}
	[ ! -z "$3" ] && {
		qpool_cmd="--pool $3"
		# pool quotas don't work properly without global limit
		$LFS setquota $qtype $qid -B1T -b1T $DIR ||
			error "set global limit failed"
	}

	setup_quota_test || error "setup quota failed with $?"

	quota_init

	# enable mdt/ost quota
	set_mdt_qtype $QTYPE || error "enable mdt quota failed"
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	log "set to use default quota"
	$LFS setquota $qtype $qid -d $qpool_cmd $DIR ||
		error "set $qid to use default quota failed"

	log "set default quota"
	$LFS setquota $qdtype $qpool_cmd $qs ${LIMIT} $qh ${LIMIT} $DIR ||
		error "set $qid default quota failed"

	log "get default quota"
	$LFS quota $qdtype $DIR || error "get default quota failed"

	if [ $qres_type == "data" ]; then
		local SLIMIT=$($LFS quota $qpool_cmd $qdtype $DIR | \
				grep "$MOUNT" | awk '{print $2}')
		[ $SLIMIT -eq $LIMIT ] ||
			error "the returned default quota is wrong"
	else
		local SLIMIT=$($LFS quota $qdtype $DIR | grep "$MOUNT" | \
							awk '{print $5}')
		[ $SLIMIT -eq $LIMIT ] ||
			error "the returned default quota is wrong"
	fi

	# make sure the system is clean
	local USED=$(getquota $qtype $qid global curspace)
	[ $USED -ne 0 ] && error "Used space for $qid isn't 0."

	$LFS setstripe $TESTFILE -c 1 $qpool_cmd ||
			error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	[ $qtype == "-p" ] && change_project -sp $TSTPRJID $DIR/$tdir

	log "Test not out of quota"
	if [ $qres_type == "data" ]; then
		$RUNAS $DD of=$TESTFILE count=$((LIMIT/2 >> 10)) oflag=sync ||
			quota_error $qtype $qid "write failed, expect succeed"
	else
		$RUNAS createmany -m $TESTFILE $((LIMIT/2)) ||
			quota_error $qtype $qid "create failed, expect succeed"

		unlinkmany $TESTFILE $((LIMIT/2))
	fi

	log "Test out of quota"
	# flush cache, ensure noquota flag is set on client
	cancel_lru_locks osc
	cancel_lru_locks mdc
	sync; sync_all_data || true
	if [ $qres_type == "data" ]; then
		$RUNAS $DD of=$TESTFILE count=$((LIMIT*2 >> 10)) oflag=sync &&
			quota_error $qtype $qid "write succeed, expect EDQUOT"
	else
		$RUNAS createmany -m $TESTFILE $((LIMIT*2)) &&
			quota_error $qtype $qid "create succeed, expect EDQUOT"

		unlinkmany $TESTFILE $((LIMIT*2))
	fi

	rm -f $TESTFILE
	$LFS setstripe $TESTFILE -c 1 $qpool_cmd ||
			error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	log "Increase default quota"

	# LU-4505: sleep 5 seconds to enable quota acquire
	sleep 5

	# increase default quota
	$LFS setquota $qdtype $qpool_cmd $qs $((LIMIT*3)) \
		$qh $((LIMIT*3)) $DIR || error "set default quota failed"

	cancel_lru_locks osc
	cancel_lru_locks mdc
	sync; sync_all_data || true
	if [ $qres_type == "data" ]; then
		$RUNAS $DD of=$TESTFILE count=$((LIMIT*2 >> 10)) oflag=sync ||
			quota_error $qtype $qid "write failed, expect succeed"
	else
		$RUNAS createmany -m $TESTFILE $((LIMIT*2)) ||
			quota_error $qtype $qid "create failed, expect succeed"

		unlinkmany $TESTFILE $((LIMIT*2))
	fi

	log "Set quota to override default quota"
	$LFS setquota $qtype $qid $qpool_cmd $qs ${LIMIT} $qh ${LIMIT} $DIR ||
		error "set $qid quota failed"

	cancel_lru_locks osc
	cancel_lru_locks mdc
	sync; sync_all_data || true
	if [ $qres_type == "data" ]; then
		$RUNAS $DD of=$TESTFILE count=$((LIMIT*2 >> 10)) oflag=sync &&
			quota_error $qtype $qid "write succeed, expect EQUOT"
	else
		$RUNAS createmany -m $TESTFILE $((LIMIT*2)) &&
			quota_error $qtype $qid "create succeed, expect EQUOT"

		unlinkmany $TESTFILE $((LIMIT*2))
	fi

	log "Set to use default quota again"

	# LU-4505: sleep 5 seconds to enable quota acquire
	sleep 5

	$LFS setquota $qtype $qid -d $qpool_cmd $DIR ||
		error "set $qid to use default quota failed"

	cancel_lru_locks osc
	cancel_lru_locks mdc
	sync; sync_all_data || true
	if [ $qres_type == "data" ]; then
		$RUNAS $DD of=$TESTFILE count=$((LIMIT*2 >> 10)) oflag=sync ||
			quota_error $qtype $qid "write failed, expect succeed"
	else
		$RUNAS createmany -m $TESTFILE $((LIMIT*2)) ||
			quota_error $qtype $qid "create failed, expect succeed"

		unlinkmany $TESTFILE $((LIMIT*2))
	fi

	log "Cleanup"
	rm -f $TESTFILE
	wait_delete_completed || error "wait_delete_completed failed"
	sync_all_data || true

	$LFS setquota $qdtype $qpool_cmd $qs 0 $qh 0 $DIR ||
		error "reset default quota failed"
	$LFS setquota $qtype $qid $qpool_cmd $qs 0 $qh 0 $DIR ||
		error "reset quota failed"
	cleanup_quota_test
}

test_61() {
	test_default_quota "-u" "data"
	test_default_quota "-u" "meta"
	test_default_quota "-g" "data"
	test_default_quota "-g" "meta"
	test_default_quota "-p" "data"
	test_default_quota "-p" "meta"
}
run_test 61 "default quota tests"

test_62() {
	! is_project_quota_supported &&
		skip "Project quota is not supported"
	[[ "$(chattr -h 2>&1)" =~ "project" ||
	   "$(chattr -h 2>&1)" =~ "pRVf" ]] ||
		skip "chattr did not support project quota"
	setup_quota_test || error "setup quota failed with $?"
	local testdir=$DIR/$tdir/

	$RUNAS mkdir -p $testdir || error "failed to mkdir"
	change_project -s $testdir
	[[ $($LFS project -d $testdir) =~ "P" ]] ||
		error "inherit attribute should be set"
	# chattr used FS_IOC_SETFLAGS ioctl
	$RUNAS chattr -P $testdir &&
		error "regular user clear inherit should fail"
	[[ $($LFS project -d $testdir) =~ "P" ]] ||
		error "inherit attribute should still be set"
	chattr -P $testdir || error "root failed to clear inherit"
	[[ $($LFS project -d $testdir) =~ "P" ]] &&
		error "inherit attribute should be cleared"
	return 0
}
run_test 62 "Project inherit should be only changed by root"

test_dom() {
	[ "$MDS1_VERSION" -lt $(version_code 2.11.55) ] &&
		skip "Not supported before 2.11.55"

	local qtype=$1
	local qid=$TSTUSR
	local dd_failed=false
	local tdir_dom=${tdir}_dom
	local LIMIT=20480 #20M

	[ $qtype == "p" ] && ! is_project_quota_supported &&
		echo "Project quota is not supported" && return 0

	[ $qtype == "p" ] && qid=$TSTPRJID

	setup_quota_test || error "setup quota failed with $?"

	quota_init

	# enable mdt/ost quota
	set_mdt_qtype $QTYPE || error "enable mdt quota failed"
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# make sure the system is clean
	local USED=$(getquota -$qtype $qid global curspace)
	[ $USED -ne 0 ] && error "Used space for $qid isn't 0."

	chown $TSTUSR.$TSTUSR $DIR/$tdir || error "chown $tdir failed"

	mkdir $DIR/$tdir_dom || error "mkdir $tdir_dom failed"
	$LFS setstripe -E 1M -L mdt $DIR/$tdir_dom ||
		error "setstripe $tdir_dom failed"
	chown $TSTUSR.$TSTUSR $DIR/$tdir_dom || error "chown $tdir_dom failed"

	[ $qtype == "p" ] && {
		change_project -sp $TSTPRJID $DIR/$tdir
		change_project -sp $TSTPRJID $DIR/$tdir_dom
	}

	$LFS setquota -$qtype $qid -b $LIMIT -B $LIMIT $DIR ||
		error "set $qid quota failed"

	for ((i = 0; i < $((LIMIT/2048)); i++)); do
		$RUNAS $DD of=$DIR/$tdir_dom/$tfile-$i count=1 oflag=sync ||
								dd_failed=true
	done

	$dd_failed && quota_error $qtype $qid "write failed, expect succeed"

	for ((i = $((LIMIT/2048)); i < $((LIMIT/1024 + 10)); i++)); do
		$RUNAS $DD of=$DIR/$tdir_dom/$tfile-$i count=1 oflag=sync ||
								dd_failed=true
	done

	$dd_failed || quota_error $qtype $qid "write succeed, expect EDQUOT"

	rm -f $DIR/$tdir_dom/*

	# flush cache, ensure noquota flag is set on client
	cancel_lru_locks osc
	cancel_lru_locks mdc
	sync; sync_all_data || true

	dd_failed=false

	$RUNAS $DD of=$DIR/$tdir/file count=$((LIMIT/2048)) oflag=sync ||
		quota_error $qtype $qid "write failed, expect succeed"

	for ((i = 0; i < $((LIMIT/2048 + 10)); i++)); do
		$RUNAS $DD of=$DIR/$tdir_dom/$tfile-$i count=1 oflag=sync ||
								dd_failed=true
	done

	$dd_failed || quota_error $qtype $TSTID "write succeed, expect EDQUOT"

	rm -f $DIR/$tdir/*
	rm -f $DIR/$tdir_dom/*

	# flush cache, ensure noquota flag is set on client
	cancel_lru_locks osc
	cancel_lru_locks mdc
	sync; sync_all_data || true

	dd_failed=false

	for ((i = 0; i < $((LIMIT/2048)); i++)); do
		$RUNAS $DD of=$DIR/$tdir_dom/$tfile-$i count=1 oflag=sync ||
								dd_failed=true
	done

	$dd_failed && quota_error $qtype $qid "write failed, expect succeed"

	$RUNAS $DD of=$DIR/$tdir/file count=$((LIMIT/2048 + 10)) oflag=sync &&
		quota_error $qtype $qid "write succeed, expect EDQUOT"

	rm -fr $DIR/$tdir
	rm -fr $DIR/$tdir_dom

	$LFS setquota -u $TSTUSR -b 0 -B 0 -i 0 -I 0 $DIR ||
		error "reset usr quota failed"
}

test_63() {
	test_dom "u"
	test_dom "g"
	test_dom "p"
}
run_test 63 "quota on DoM tests"

test_64() {
	! is_project_quota_supported &&
		skip "Project quota is not supported"
	setup_quota_test || error "setup quota failed with $?"
	local dir1="$DIR/$tdir/"

	touch $dir1/file
	ln -s $dir1/file $dir1/file_link
	mkfifo $dir1/fifo

	$LFS project -srp $TSTPRJID $dir1 >&/dev/null ||
		error "set project should succeed"

	used=$(getquota -p $TSTPRJID global curinodes)
	[ $used -eq 4 ] || error "expected 4 got $used"
	$LFS project -rC $dir1 >&/dev/null ||
		error "clear project should succeed"

	used=$(getquota -p $TSTPRJID global curinodes)
	[ $used -eq 0 ] || error "expected 0 got $used"
}
run_test 64 "lfs project on non dir/files should succeed"

test_65() {
	local SIZE=10 # MB
	local TESTFILE="$DIR/$tdir/$tfile-0"

	setup_quota_test || error "setup quota failed with $?"
	set_ost_qtype $QTYPE || error "enable ost quota failed"
	quota_init

	echo "Write..."
	$RUNAS $DD of=$TESTFILE count=$SIZE ||
		error "failed to write"
	# flush cache, ensure noquota flag is set on client
	cancel_lru_locks osc
	sync; sync_all_data || true

	local quota_u=$($LFS quota -u $TSTUSR $DIR)
	local quota_g=$($LFS quota -g $TSTUSR $DIR)
	local quota_all=$($RUNAS $LFS quota $DIR)

	[ "$(echo "$quota_all" | head -n3)" == "$quota_u" ] ||
		error "usr quota not match"
	[ "$(echo "$quota_all" | tail -n3)" == "$quota_g" ] ||
		error "grp quota not match"
}
run_test 65 "Check lfs quota result"

test_66() {
	! is_project_quota_supported &&
		skip "Project quota is not supported"
	[ "$MDS1_VERSION" -lt $(version_code 2.12.4) ] &&
		skip "Not supported before 2.12.4"
	setup_quota_test || error "setup quota failed with $?"
	local old=$(do_facet mds1 $LCTL get_param -n \
		    mdt.*.enable_chprojid_gid | head -1)
	local testdir=$DIR/$tdir/foo

	do_facet mds1 $LCTL set_param mdt.*.enable_chprojid_gid=0
	stack_trap "do_facet mds1 $LCTL \
		set_param mdt.*.enable_chprojid_gid=$old" EXIT

	mkdir_on_mdt0 $testdir || error "failed to mkdir"
	chown -R $TSTID:$TSTID $testdir
	change_project -sp $TSTPRJID $testdir
	$RUNAS mkdir $testdir/foo || error "failed to mkdir foo"

	$RUNAS lfs project -p 0 $testdir/foo &&
		error "nonroot user should fail to set projid"

	$RUNAS lfs project -C $testdir/foo &&
		error "nonroot user should fail to clear projid"

	change_project -C $testdir/foo || error "failed to clear project"

	do_facet mds1 $LCTL set_param mdt.*.enable_chprojid_gid=-1
	$RUNAS lfs project -p $TSTPRJID $testdir/foo || error \
	"failed to set projid with normal user when enable_chprojid_gid=-1"

	$RUNAS lfs project -rC $testdir/ || error \
"failed to clear project state with normal user when enable_chprojid_gid=-1"

	touch $testdir/bar || error "failed touch $testdir/bar"
	$RUNAS lfs project -p $TSTPRJID $testdir/bar && error \
	"normal user should not be able to set projid on root owned file"

	change_project -p $TSTPRJID $testdir/bar || error \
		"root should be able to change its own file's projid"
}
run_test 66 "nonroot user can not change project state in default"

test_67_write() {
	local file="$1"
	local qtype="$2"
	local size=$3
	local _runas=""
	local short_qtype=${qtype:0:1}

	echo "file "$file
	echo "0 $0 1 $1 2 $2 3 $3 4 $4"
	case "$4" in
		$TSTUSR)  _runas=$RUNAS;;
		$TSTUSR2) _runas=$RUNAS2;;
		*)          error "unknown quota parameter $4";;
	esac

	log "Write..."
	date
	$_runas $DD of=$file count=$size ||
		quota_error $short_qtype $TSTUSR \
			"$qtype write failure, but expect success"
	date
	cancel_lru_locks osc
	date
	sync; sync_all_data || true
	date
}

getgranted() {
	local pool=$1
	local ptype=$2
	local userid=$3
	local qtype=$4
	local param=qmt.$FSNAME-QMT0000.$ptype-$pool.glb-$qtype

	do_facet mds1 $LCTL get_param $param |
		grep -A2 $userid | awk -F'[, ]*' 'NR==2{print $9}'
}

test_67() {
	local limit=20 # MB
	local testfile="$DIR/$tdir/$tfile-0"
	local testfile2="$DIR/$tdir/$tfile-1"
	local testfile3="$DIR/$tdir/$tfile-2"
	local qpool="qpool1"
	local used
	local granted
	local granted_mb

	mds_supports_qp
	[ "$ost1_FSTYPE" == zfs ] &&
		skip "ZFS grants some block space together with inode"

	setup_quota_test || error "setup quota failed with $?"

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# test for user
	log "User quota (block hardlimit:$limit MB)"
	$LFS setquota -u $TSTUSR -b 0 -B ${limit}M -i 0 -I 0 $DIR ||
		error "set user quota failed"

	# make sure the system is clean
	used=$(getquota -u $TSTUSR global curspace)
	[ $used -ne 0 ] && error "Used space($used) for user $TSTUSR isn't 0."

	granted=$(getgranted "0x0" "dt" $TSTID "usr")
	echo "granted 0x0 before write $granted"

	# trigger reintegration
	local procf="osd-$(facet_fstype ost1).$FSNAME-OST*."
	procf=${procf}quota_slave.force_reint
	do_facet ost1 $LCTL set_param $procf=1 ||
		error "force reintegration failed"
	wait_ost_reint "u" || error "reintegration failed"
	granted=$(getgranted "0x0" "dt" $TSTID "usr")
	[ $granted -ne 0 ] &&
		error "Granted($granted) for $TSTUSR in $qpool isn't 0."

	$LFS setstripe $testfile -c 1 -i 0 || error "setstripe $testfile failed"
	chown $TSTUSR.$TSTUSR $testfile || error "chown $testfile failed"

	# write 10 MB to testfile
	test_67_write "$testfile" "user" 10 "$TSTUSR"

	# create qpool and add OST1
	pool_add $qpool || error "pool_add failed"
	pool_add_targets $qpool 1 1 || error "pool_add_targets failed"
	# as $TSTUSR hasn't limits, lqe may absent. But it should be
	# created after the 1st direct qmt_get.
	used=$(getquota -u $TSTUSR global bhardlimit $qpool)

	# check granted - should be 0, as testfile is located only on OST0
	granted=$(getgranted "0x0" "dt" $TSTID "usr")
	echo "global granted $granted"
	granted=$(getgranted $qpool "dt" $TSTID "usr")
	echo "$qpool granted $granted"
	[ $granted -ne 0 ] &&
		error "Granted($granted) for $TSTUSR in $qpool isn't 0."

	# add OST0 to qpool and check granted space
	pool_add_targets $qpool 0 1 ||
		error "pool_add_targets failed"
	granted_mb=$(($(getgranted $qpool "dt" $TSTID "usr")/1024))
	echo "Granted $granted_mb MB"
	#should be 10M + qunit for each OST
	[ $granted_mb -ge 10 -a $granted_mb -lt $limit ] ||
		error "Granted($granted_mb) for $TSTUSR in $qpool is wrong."

	$LFS setstripe $testfile2 -c 1 -i 1 ||
		error "setstripe $testfile2 failed"
	chown $TSTUSR2.$TSTUSR2 $testfile2 || error "chown $testfile2 failed"
	# Write from another user and check that qpool1
	# shows correct granted, despite $TSTUSR2 hasn't limits in qpool1.
	test_67_write "$testfile2" "user" 10 "$TSTUSR2"
	used=$(getquota -u $TSTUSR2 global curspace $qpool)
	granted=$(getgranted $qpool "dt" $TSTID2 "usr")
	[ $granted -ne 0 ] &&
		error "Granted($granted) for $TSTUSR2 in $qpool isn't 0."

	# Granted space for $TSTUSR2 in qpool1 should appear only
	# when global lqe for this user becomes enforced.
	$LFS setquota -u $TSTUSR2 -B ${limit}M $DIR ||
		error "set user quota failed"
	granted_mb=$(($(getgranted $qpool "dt" $TSTID2 "usr")/1024))
	echo "granted_mb $granted_mb"
	[ $granted_mb -ge 10 -a $granted_mb -lt $limit ] ||
		error "Granted($granted) for $TSTUSR in $qpool is wrong."

	$LFS setstripe $testfile3 -c 1 -i 0 ||
		error "setstripe $testfile3 failed"
	chown $TSTUSR2.$TSTUSR2 $testfile3 || error "chown $testfile3 failed"
	test_67_write "$testfile3" "user" 10 "$TSTUSR2"
	granted_mb=$(($(getgranted $qpool "dt" $TSTID2 "usr")/1024))
	echo "$testfile3 granted_mb $granted_mb"
	[ $granted_mb -eq $limit ] ||
		error "Granted($granted_mb) for $TSTUSR2 is not equal to 20M"

	# remove OST1 from the qpool1 and check granted space
	# should be 0 for TSTUSR and 10M for TSTUSR2
	pool_remove_target $qpool 0
	granted_mb=$(($(getgranted $qpool "dt" $TSTID "usr")/1024))
	[ $granted_mb -eq 0 ] ||
		error "Granted($granted_mb) for $TSTUSR in $qpool != 0."
	granted_mb=$(($(getgranted $qpool "dt" $TSTID2 "usr")/1024))
	[ $granted_mb -eq 10 ] ||
		error "Granted($granted_mb) for $TSTUSR2 is not equal to 10M"

	rm -f $testfile
	wait_delete_completed || error "wait_delete_completed failed"
	sync_all_data || true
	used=$(getquota -u $TSTUSR global curspace)
	[ $used -eq 0 ] || quota_error u $TSTUSR \
		"user quota isn't released after deletion"
}
run_test 67 "quota pools recalculation"

get_slave_nr() {
	local pool=$1
	local qtype=$2
	local nr

	wait_update_facet "--quiet" mds1 \
		"$LCTL get_param -n qmt.$FSNAME-QMT0000.dt-$pool.info \
			>/dev/null 2>&1 || echo foo" "">/dev/null ||
		error "mds1: failed to create quota pool $pool"

	do_facet mds1 $LCTL get_param -n qmt.$FSNAME-QMT0000.dt-$pool.info |
		awk '/usr/ {getline; print $2}'
}

test_68()
{
	local qpool="qpool1"

	mds_supports_qp
	setup_quota_test || error "setup quota failed with $?"

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# check slave number for glbal pool
	local nr=$(get_slave_nr "0x0" "usr")
	echo "nr result $nr"
	[[ $nr != $((OSTCOUNT + MDSCOUNT)) ]] &&
		error "Slave_nr $nr for global pool != ($OSTCOUNT + $MDSCOUNT)"

	# create qpool and add OST1
	pool_add $qpool || error "pool_add failed"
	nr=$(get_slave_nr $qpool "usr")
	[[ $nr != 0 ]] && error "Slave number $nr for $qpool != 0"

	# add OST1 to qpool
	pool_add_targets $qpool 1 1 || error "pool_add_targets failed"
	nr=$(get_slave_nr $qpool "usr")
	[[ $nr != 1 ]] && error "Slave number $nr for $qpool != 1"

	# add OST0 to qpool
	pool_add_targets $qpool 0 1 || error "pool_add_targets failed"
	nr=$(get_slave_nr $qpool "usr")
	[[ $nr != 2 ]] && error "Slave number $nr for $qpool != 2"

	# remove OST0
	pool_remove_target $qpool 0
	nr=$(get_slave_nr $qpool "usr")
	[[ $nr != 1 ]] && error "Slave number $nr for $qpool != 1"

	# remove OST1
	pool_remove_target $qpool 1
	nr=$(get_slave_nr $qpool "usr")
	[[ $nr != 0 ]] && error "Slave number $nr for $qpool != 0"

	# Check again that all is fine with global pool
	nr=$(get_slave_nr "0x0" "usr")
	[[ $nr == $((OSTCOUNT + MDSCOUNT)) ]] ||
		error "Slave_nr $nr for global pool != ($OSTCOUNT + $MDSCOUNT)"
}
run_test 68 "slave number in quota pool changed after each add/remove OST"

test_69()
{
	local global_limit=200 # MB
	local limit=10 # MB
	local testfile="$DIR/$tdir/$tfile-0"
	local dom0="$DIR/$tdir/dom0"
	local qpool="qpool1"

	mds_supports_qp
	setup_quota_test || error "setup quota failed with $?"

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"
	set_mdt_qtype $QTYPE || error "enable mdt quota failed"

	# Save DOM only at MDT0
	$LFS setdirstripe -c 1 -i 0 $dom0 || error "cannot create $dom0"
	$LFS setstripe -E 1M $dom0 -L mdt || error "setstripe to $dom0 failed"
	chmod 0777 $dom0
	$LFS setstripe -c 1 -i 0 "$DIR/$tdir/"

	# create qpool and add OST0
	pool_add $qpool || error "pool_add failed"
	pool_add_targets $qpool 0 0 || error "pool_add_targets failed"

	log "User quota (block hardlimit:$global_limit MB)"
	$LFS setquota -u $TSTUSR -b 0 -B ${global_limit}M -i 0 -I 0 $DIR ||
		error "set user quota failed"

	log "User quota (block hardlimit:$limit MB)"
	$LFS setquota -u $TSTUSR -B ${limit}M --pool $qpool $DIR ||
		error "set user quota failed"

	$RUNAS dd if=/dev/zero of="$dom0/f1" bs=1K count=512 oflag=sync ||
		quota_error u $TSTUSR "write failed"

	$RUNAS dd if=/dev/zero of="$dom0/f1" bs=1K count=512 seek=512 \
		oflag=sync || quota_error u $TSTUSR "write failed"

	$RUNAS $DD of=$testfile count=$limit || true

	# flush cache, ensure noquota flag is set on client
	cancel_lru_locks osc
	sync; sync_all_data || true

	# MDT0 shouldn't get EDQUOT with glimpse.
	$RUNAS $DD of=$testfile count=$limit seek=$limit &&
		quota_error u $TSTUSR \
			"user write success, but expect EDQUOT"

	# Now all members of qpool1 should get EDQUOT. Expect success
	# when write to DOM on MDT0, as it belongs to global pool.
	$RUNAS dd if=/dev/zero of="$dom0/f1" bs=1K count=512 \
		oflag=sync || quota_error u $TSTUSR "write failed"

	$RUNAS dd if=/dev/zero of="$dom0/f1" bs=1K count=512 seek=512 \
		oflag=sync || quota_error u $TSTUSR "write failed"
}
run_test 69 "EDQUOT at one of pools shouldn't affect DOM"

test_70a()
{
	local qpool="qpool1"
	local limit=20 # MB
	local err=0
	local bhard

	[[ CLIENT_VERSION -lt $(version_code $VERSION_WITH_QP) ]] &&
		skip "Needs a client >= $VERSION_WITH_QP"

	setup_quota_test || error "setup quota failed with $?"

	# MDS returns EFAULT for unsupported quotactl command
	[[ $MDS1_VERSION -lt $(version_code $VERSION_WITH_QP) ]] && err=14

	# create qpool and add OST0
	pool_add $qpool || error "pool_add failed"
	pool_add_targets $qpool 0 0 || error "pool_add_targets failed"

	$LFS setquota -u $TSTUSR -B ${limit}M --pool $qpool $DIR
	rc=$?
	[ $rc -eq $err ] || error "setquota res $rc != $err"

	# If MDS supports QP, check that limit was set properly.
	if [[ $MDS1_VERSION -ge $(version_code $VERSION_WITH_QP) ]]; then
		bhard=$(getquota -u $TSTUSR global bhardlimit $qpool)
		echo "hard limit $bhard limit $limit"
		[ $bhard -ne $((limit*1024)) ] &&
			error "bhard:$bhard for $qpool!=$((limit*1024))"
	fi

	$LFS quota -u $TSTUSR --pool $qpool $DIR
	rc=$?
	[ $rc -eq $err ] || error "quota res $rc != $err"
}
run_test 70a "check lfs setquota/quota with a pool option"

test_70b()
{
	local glbl_hard=200 # 200M
	local glbl_soft=100 # 100M
	local pool_hard=10 # 10M
	local qpool="qpool1"

	pool_add $qpool || error "pool_add failed"
	pool_add_targets $qpool 0 1 || error "pool_add_targets failed"

	$LFS setquota -u $TSTUSR -b ${glbl_soft}M -B ${glbl_hard}M $DIR ||
		error "set user quota failed"
	$LFS setquota -u $TSTUSR -B ${pool_hard}M --pool $qpool $DIR ||
		error "set user quota failed"

	local tmp=$(getquota -u $TSTUSR global bhardlimit $qpool)
	[ $tmp -eq $((pool_hard * 1024)) ] ||
		error "wrong block hard limit $tmp for $qpool"
	local tmp=$(getquota -u $TSTUSR global bsoftlimit $qpool)
	# soft limit hasn't been set and should be zero
	[ $tmp -eq 0 ] || error "wrong soft block limit $tmp for $qpool"
}
run_test 70b "lfs setquota pool works properly"

test_71a()
{
	local limit=10 # MB
	local global_limit=100 # MB
	local testfile="$DIR/$tdir/$tfile-0"
	local qpool="qpool1"
	local qpool2="qpool2"

	[ "$ost1_FSTYPE" == zfs ] &&
		skip "ZFS grants some block space together with inode"
	[[ $OSTCOUNT -lt 2 ]] && skip "need >= 2 OSTs"
	mds_supports_qp
	setup_quota_test || error "setup quota failed with $?"

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# test for user
	log "User quota (block hardlimit:$global_limit MB)"
	$LFS setquota -u $TSTUSR -b 0 -B ${global_limit}M -i 0 -I 0 $DIR ||
		error "set user quota failed"

	pool_add $qpool || error "pool_add failed"
	pool_add_targets $qpool 0 1 ||
		error "pool_add_targets failed"

	$LFS setquota -u $TSTUSR -B ${limit}M --pool $qpool $DIR ||
		error "set user quota failed"

	pool_add $qpool2 || error "pool_add failed"
	pool_add_targets $qpool2 1 1 ||
		error "pool_add_targets failed"

	$LFS setquota -u $TSTUSR -B ${limit}M --pool $qpool2 $DIR ||
		error "set user quota failed"

	# make sure the system is clean
	local used=$(getquota -u $TSTUSR global curspace)

	echo "used $used"
	[ $used -ne 0 ] && error "Used space($used) for user $TSTUSR isn't 0."

	# create 1st component 1-10M
	$LFS setstripe -E 10M -S 1M -c 1 -i 0 $testfile
	#create 2nd component 10-30M
	$LFS setstripe --component-add -E 30M -c 1 -i 1 $testfile
	chown $TSTUSR.$TSTUSR $testfile || error "chown $testfile failed"

	# сheck normal use and out of quota with PFL
	# 1st element is in qppol1(OST0), 2nd in qpool2(OST2).
	test_1_check_write $testfile "user" $((limit*2))
	rm -f $testfile
	wait_delete_completed || error "wait_delete_completed failed"
	sync_all_data || true
	used=$(getquota -u $TSTUSR global curspace)
	[ $used -ne 0 ] && quota_error u $TSTUSR \
		"user quota isn't released after deletion"

	# create 1st component 1-10M
	$LFS setstripe -E 10M -S 1M -c 1 -i 0 $testfile
	# create 2nd component 10-30M
	$LFS setstripe --component-add -E 30M -c 1 -i 1 $testfile
	chown $TSTUSR.$TSTUSR $testfile || error "chown $testfile failed"

	# write to the 2nd component
	$RUNAS $DD of=$testfile count=$limit seek=10 ||
		quota_error u $TSTUSR \
			"write failure, but expect success"
	# this time maybe cache write,  ignore it's failure
	$RUNAS $DD of=$testfile count=$((2*limit)) seek=10 || true
	cancel_lru_locks osc
	sync; sync_all_data || true
	# write over limit in qpool2(2nd component 10-30M)
	$RUNAS $DD of=$testfile count=1 seek=$((10 + 2*limit)) &&
		quota_error u $TSTUSR "user write success, but expect EDQUOT"
	# write to the 1st component - OST0 is empty
	$RUNAS $DD of=$testfile count=$limit seek=0 ||
		quota_error u $TSTUSR "write failed"
}
run_test 71a "Check PFL with quota pools"

test_71b()
{
	local global_limit=1000 # MB
	local limit1=160 # MB
	local limit2=10 # MB
	local testfile="$DIR/$tdir/$tfile-0"
	local qpool="qpool1"
	local qpool2="qpool2"

	[ "$ost1_FSTYPE" == zfs ] &&
		skip "ZFS grants some block space together with inode"
	[[ $OSTCOUNT -lt 2 ]] && skip "need >= 2 OSTs" && return
	mds_supports_qp
	setup_quota_test || error "setup quota failed with $?"

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# test for user
	log "User quota (block hardlimit:$global_limit MB)"
	$LFS setquota -u $TSTUSR -b 0 -B ${global_limit}M -i 0 -I 0 $DIR ||
		error "set user quota failed"

	pool_add $qpool || error "pool_add failed"
	pool_add_targets $qpool 0 1 ||
		error "pool_add_targets failed"

	$LFS setquota -u $TSTUSR -B ${limit1}M --pool $qpool $DIR ||
		error "set user quota failed"

	pool_add $qpool2 || error "pool_add failed"
	pool_add_targets $qpool2 1 1 ||
		error "pool_add_targets failed"

	$LFS setquota -u $TSTUSR -B ${limit2}M --pool $qpool2 $DIR ||
		error "set user quota failed"

	# make sure the system is clean
	local used=$(getquota -u $TSTUSR global curspace)

	echo "used $used"
	[ $used -ne 0 ] && error "Used space($used) for user $TSTUSR isn't 0."

	# First component is on OST0, 2nd on OST1
	$LFS setstripe -E 128M -i 0 -z 64M -E -1 -i 1 -z 64M $testfile
	chown $TSTUSR.$TSTUSR $testfile || error "chown $testfile failed"

	# fill the 1st component on OST0
	$RUNAS $DD of=$testfile count=128 ||
		quota_error u $TSTUSR "write failed"
	# write to the 2nd cmpnt on OST1
	$RUNAS $DD of=$testfile count=$((limit2/2)) seek=128 ||
		quota_error u $TSTUSR "write failed"
	# this time maybe cache write,  ignore it's failure
	$RUNAS $DD of=$testfile count=$((limit2/2)) seek=$((128 + limit2/2)) ||
		true
	cancel_lru_locks osc
	sync; sync_all_data || true
	# write over limit in qpool2
	$RUNAS $DD of=$testfile count=2 seek=$((128 + limit2)) &&
		quota_error u $TSTUSR "user write success, but expect EDQUOT"
	return 0
}
run_test 71b "Check SEL with quota pools"

test_72()
{
	local limit=10 # MB
	local global_limit=50 # MB
	local testfile="$DIR/$tdir/$tfile-0"
	local qpool="qpool1"

	mds_supports_qp
	setup_quota_test || error "setup quota failed with $?"

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# test for user
	log "User quota (block hardlimit:$global_limit MB)"
	$LFS setquota -u $TSTUSR -b 0 -B ${global_limit}M -i 0 -I 0 $DIR ||
		error "set user quota failed"

	pool_add $qpool || error "pool_add failed"
	pool_add_targets $qpool 1 1 || error "pool_add_targets failed"

	$LFS setquota -u $TSTUSR -B ${limit}M --pool $qpool $DIR ||
		error "set user quota failed"

	# make sure the system is clean
	local used=$(getquota -u $TSTUSR global curspace)
	echo "used $used"
	[ $used -ne 0 ] && error "Used space($used) for user $TSTUSR isn't 0."

	used=$(getquota -u $TSTUSR global bhardlimit $qpool)

	$LFS setstripe $testfile -c 1 -i 1 || error "setstripe $testfile failed"
	chown $TSTUSR.$TSTUSR $testfile || error "chown $testfile failed"
	test_1_check_write $testfile "user" $limit
	used=$(getquota -u $TSTUSR global bhardlimit $qpool)
	echo "used $used"
	[ $used -ge $limit ] || error "used($used) is less than limit($limit)"
	# check that lfs quota -v -u --pool prints only OST that
	# was added in a pool
	lfs quota -v -u $TSTUSR --pool $qpool $DIR | grep -v "OST0001" |
		grep "OST\|MDT" && error "$qpool consists wrong targets"
	return 0
}
run_test 72 "lfs quota --pool prints only pool's OSTs"

test_73a()
{
	(( $MDS1_VERSION >= $(version_code 2.14.51.158) )) ||
		skip "need MDS >= v2_14_51-158-g25a70a88 for default pool quota"

	local qpool="qpool1"

	mds_supports_qp

	pool_add $qpool || error "pool_add failed"
	pool_add_targets $qpool 0 $((OSTCOUNT - 1)) ||
		error "pool_add_targets failed"

	test_default_quota "-u" "data" "qpool1"
}
run_test 73a "default limits at OST Pool Quotas"

test_73b()
{
	(( $MDS1_VERSION >= $(version_code 2.14.52.91) )) ||
		skip "need MDS >= v2_14_52-91-g188112fc8 for nested lqe fix"

	local TESTFILE1="$DIR/$tdir/$tfile-1"
	local limit=20 #20M
	local qpool="qpool1"

	mds_supports_qp

	setup_quota_test || error "setup quota failed with $?"
	quota_init
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# pool quotas don't work properly without global limit
	$LFS setquota -u $TSTUSR -b 0 -B ${limit}M -i 0 -I 0 $DIR ||
		error "set global limit failed"

	pool_add $qpool || error "pool_add failed"
	pool_add_targets $qpool 0 $((OSTCOUNT - 1)) ||
		error "pool_add_targets failed"

	log "set default quota for $qpool"
	$LFS setquota -U --pool $qpool -b ${limit}M -B ${limit}M $DIR ||
		error "set default quota failed"

	log "Write from user that hasn't lqe"
	# Check that it doesn't cause a panic or a deadlock
	# due to nested lqe lookups that rewrite 1st lqe in qti_lqes array.
	# Have to use RUNAS_ID as resetquota creates lqes in
	# the beginning for TSTUSR/TSTUSR2 when sets limits to 0.
	runas -u $RUNAS_ID -g $RUNAS_GID $DD of=$TESTFILE1 count=10

	cancel_lru_locks osc
	sync; sync_all_data || true
}
run_test 73b "default OST Pool Quotas limit for new user"

test_74()
{
	(( $MDS1_VERSION >= $(version_code 2.14.52.6) )) ||
		skip "need MDS >= v2_14_52-6-g8c19365416 for pool per-user fix"

	local global_limit=200 # 200M
	local limit=10 # 10M
	local limit2=50 # 50M
	local qpool="qpool1"
	local qpool2="qpool2"
	local tmp=0

	mds_supports_qp
	setup_quota_test || error "setup quota failed with $?"

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	$LFS setquota -u $TSTUSR -b 0 -B ${global_limit}M -i 0 -I 0 $DIR ||
		error "set user quota failed"

	pool_add $qpool || error "pool_add failed"
	pool_add_targets $qpool 0 1 ||
		error "pool_add_targets failed"

	$LFS setquota -u $TSTUSR -B ${limit}M --pool $qpool $DIR ||
		error "set user quota failed"

	pool_add $qpool2 || error "pool_add failed"
	pool_add_targets $qpool2 1 1 ||
		error "pool_add_targets failed"

	$LFS setquota -u $TSTUSR -B ${limit2}M --pool $qpool2 $DIR ||
		error "set user quota failed"

	tmp=$(getquota -u $TSTUSR global bhardlimit)
	[ $tmp -eq $((global_limit * 1024)) ] ||
		error "wrong global limit $global_limit"

	tmp=$(getquota -u $TSTUSR global bhardlimit $qpool)
	[ $tmp -eq $((limit * 1024)) ] || error "wrong limit $tmp for $qpool"

	tmp=$(getquota -u $TSTUSR global bhardlimit $qpool2)
	[ $tmp -eq $((limit2 * 1024)) ] || error "wrong limit $tmp for $qpool2"

	# check limits in pools
	$LFS quota -u $TSTUSR --pool $DIR
	tmp=$($LFS quota -u $TSTUSR --pool $DIR | \
	      grep -A4 $qpool | awk 'NR == 2{print $4}')
	echo "pool limit for $qpool $tmp"
	[ $tmp -eq $((limit * 1024)) ] || error "wrong limit:$tmp for $qpool"
	tmp=$($LFS quota -u $TSTUSR --pool $DIR | \
	      grep -A4 $qpool2 | awk 'NR == 2{print $4}')
	echo "pool limit for $qpool2 $tmp"
	[ $tmp -eq $((limit2 * 1024)) ] || error "wrong limit:$tmp for $qpool2"
}
run_test 74 "check quota pools per user"

function cleanup_quota_test_75()
{
	do_facet mgs $LCTL nodemap_modify --name default \
		--property admin --value 1
	do_facet mgs $LCTL nodemap_modify --name default \
		--property trusted --value 1
	do_facet mgs $LCTL nodemap_modify --name default \
		--property squash_uid --value 99
	do_facet mgs $LCTL nodemap_modify --name default \
		--property squash_gid --value 99

	wait_nm_sync default admin_nodemap
	wait_nm_sync default trusted_nodemap

	do_facet mgs $LCTL nodemap_activate 0
	wait_nm_sync active

	resetquota -u $TSTUSR
}

test_dom_75() {
	local dd_failed=false
	local LIMIT=20480 #20M
	local qid=$TSTID

	for ((i = 0; i < $((LIMIT/2048-1)); i++)); do
		$DD of=$DIR/$tdir_dom/$tfile-$i count=1 \
			conv=fsync || dd_failed=true
	done

	$dd_failed && quota_error u $qid "write failed, expect succeed (1)"

	for ((i = $((LIMIT/2048-1)); i < $((LIMIT/1024 + 10)); i++)); do
		$DD of=$DIR/$tdir_dom/$tfile-$i count=1 \
			conv=fsync || dd_failed=true
	done

	$dd_failed || quota_error u $qid "write succeed, expect EDQUOT (1)"

	rm -f $DIR/$tdir_dom/*

	# flush cache, ensure noquota flag is set on client
	cancel_lru_locks
	sync; sync_all_data || true

	dd_failed=false

	$DD of=$DIR/$tdir/file count=$((LIMIT/2048-1)) conv=fsync ||
		quota_error u $qid "write failed, expect succeed (2)"

	for ((i = 0; i < $((LIMIT/2048 + 10)); i++)); do
		$DD of=$DIR/$tdir_dom/$tfile-$i count=1 \
			conv=fsync || dd_failed=true
	done

	$dd_failed || quota_error u $TSTID "write succeed, expect EDQUOT (2)"

	rm -f $DIR/$tdir/*
	rm -f $DIR/$tdir_dom/*

	# flush cache, ensure noquota flag is set on client
	cancel_lru_locks
	sync; sync_all_data || true

	dd_failed=false

	for ((i = 0; i < $((LIMIT/2048-1)); i++)); do
		$DD of=$DIR/$tdir_dom/$tfile-$i count=1 \
			conv=fsync || dd_failed=true
	done

	$dd_failed && quota_error u $qid "write failed, expect succeed (3)"

	$DD of=$DIR/$tdir/file count=$((LIMIT/2048 + 10)) oflag=direct &&
		quota_error u $qid "write succeed, expect EDQUOT (3)"
	true
}

test_75()
{
	(( $MDS1_VERSION >= $(version_code 2.14.52.68) )) ||
		skip "need MDS >= v2_14_52-68-ga4fbe7341b for squash root fix"

	local soft_limit=10 # MB
	local hard_limit=20 # MB
	local limit=$soft_limit
	local testfile="$DIR/$tdir/$tfile-0"
	local grace=20 # seconds
	local tdir_dom=${tdir}_dom

	if [ $(facet_fstype $SINGLEMDS) = "zfs" ]; then
	    grace=60
	fi

	setup_quota_test || error "setup quota failed with $?"
	stack_trap cleanup_quota_test_75 EXIT

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"
	set_mdt_qtype $QTYPE || error "enable mdt quota failed"

	local used=$(getquota -u $TSTID global curspace)
	$LFS setquota -t -u --block-grace $grace --inode-grace \
		$MAX_IQ_TIME $DIR || error "set user grace time failed"
	$LFS setquota -u $TSTUSR -b $((soft_limit+used/1024))M \
			-B $((hard_limit+used/1024))M -i 0 -I 0 $DIR ||
		error "set user quota failed"

	chmod 777 $DIR/$tdir || error "chmod 777 $DIR/$tdir failed"
	mkdir $DIR/$tdir_dom
	chmod 777 $DIR/$tdir_dom
	$LFS setstripe -E 1M -L mdt $DIR/$tdir_dom ||
		error "setstripe $tdir_dom failed"

	do_facet mgs $LCTL nodemap_activate 1
	wait_nm_sync active
	do_facet mgs $LCTL nodemap_modify --name default \
		--property admin --value 0
	do_facet mgs $LCTL nodemap_modify --name default \
		--property trusted --value 0
	do_facet mgs $LCTL nodemap_modify --name default \
		--property deny_unknown --value 0
	do_facet mgs $LCTL nodemap_modify --name default \
		--property squash_uid --value $TSTID
	do_facet mgs $LCTL nodemap_modify --name default \
		--property squash_gid --value $TSTID
	cancel_lru_locks mdc
	wait_nm_sync default admin_nodemap
	wait_nm_sync default trusted_nodemap
	wait_nm_sync default squash_uid

	# mmap write when over soft limit
	limit=$soft_limit
	$DD of=$testfile count=${limit} || quota_error a $TSTUSR \
			"root write failure, but expect success (1)"
	OFFSET=$((limit * 1024))
	cancel_lru_locks osc

	echo "Write to exceed soft limit"
	dd if=/dev/zero of=$testfile bs=1K count=10 seek=$OFFSET ||
	      quota_error a $TSTUSR "root write failure, but expect success (2)"
	OFFSET=$((OFFSET + 1024)) # make sure we don't write to same block
	cancel_lru_locks osc

	echo "mmap write when over soft limit"
	$MULTIOP $testfile.mmap OT40960SMW ||
		quota_error a $TSTUSR "mmap write failure, but expect success"
	cancel_lru_locks osc
	rm -f $testfile*
	wait_delete_completed || error "wait_delete_completed failed (1)"
	sync_all_data || true

	# test for user hard limit
	limit=$hard_limit
	log "Write..."
	$DD of=$testfile count=$((limit/2)) ||
		quota_error u $TSTID \
			"root write failure, but expect success (3)"

	log "Write out of block quota ..."
	# possibly a cache write, ignore failure
	$DD of=$testfile count=$((limit/2)) seek=$((limit/2)) || true
	# flush cache, ensure noquota flag is set on client
	cancel_lru_locks osc
	sync; sync_all_data || true
	# sync forced cache flush, but did not guarantee that slave
	# got new edquot through glimpse, so wait to make sure
	sleep 5
	$DD of=$testfile count=1 seek=$limit conv=fsync &&
		quota_error u $TSTID \
			"user write success, but expect EDQUOT"
	rm -f $testfile
	wait_delete_completed || error "wait_delete_completed failed (2)"
	sync_all_data || true
	[ $(getquota -u $TSTUSR global curspace) -eq $used ] ||
		quota_error u $TSTID "user quota not released after deletion"

	test_dom_75
}
run_test 75 "nodemap squashed root respects quota enforcement"

test_76() {
	(( $MDS1_VERSION >= $(version_code 2.14.52.109) )) ||
		skip "need MDS >= v2_14_52-109-g3ffa5d680f for bad PRJID fix"
	! is_project_quota_supported &&
		skip "skip project quota unsupported"

	setup_quota_test || error "setup quota failed with $?"
	quota_init

	local testfile="$DIR/$tdir/$tfile-0"

	touch $testfile
	$LFS project -p 4294967295 $testfile &&
		error "set project ID should fail"
	return 0
}
run_test 76 "project ID 4294967295 should be not allowed"

test_77()
{
	(( $MDS1_VERSION >= $(version_code 2.14.54.33) )) ||
		skip "need MDS >= v2_14_54-33-g29e00cecc6 for readonly fix"

	mount_client $MOUNT2 "ro"
	lfs setquota -u $TSTUSR -b 100M -B 100M -i 10K -I 10K $MOUNT2 &&
		error "lfs setquota should fail in read-only Lustre mount"
	umount $MOUNT2
}
run_test 77 "lfs setquota should fail in Lustre mount with 'ro'"

test_78A()
{
	(( $OST1_VERSION >= $(version_code 2.14.55.173) )) ||
		skip "need OST >= v2_14_55-173-g789038c97a for fallocate fix"
	check_set_fallocate_or_skip

	setup_quota_test || error "setup quota failed with $?"

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	mkdir -p $DIR/$tdir || error "failed to create $tdir"
	chown $TSTUSR $DIR/$tdir || error "failed to chown $tdir"

	# setup quota limit
	$LFS setquota -u $TSTUSR -b25M -B25M $DIR/$tdir ||
		error "lfs setquota failed"

	# call fallocate
	runas -u $TSTUSR -g $TSTUSR fallocate -l 204800 $DIR/$tdir/$tfile

	kbytes=$(lfs quota -u $TSTUSR $DIR |
		awk -v pattern=$DIR 'match($0, pattern) {printf $2}')
	echo "kbytes returned:$kbytes"

	# For file size of 204800. We should be having roughly 200 kbytes
	# returned. Anything alarmingly low (50 taken as arbitrary value)
	# would bail out this TC. Also this also avoids $kbytes of 0
	# to be used in calculation below.
	(( $kbytes > 50 )) ||
		error "fallocate did not use quota. kbytes returned:$kbytes"

	local expect_lo=$(($kbytes * 95 / 100)) # 5% below
	local expect_hi=$(($kbytes * 105 / 100)) # 5% above

	# Verify kbytes is 200 (204800/1024). With a permited  5% drift
	(( $kbytes >= $expect_lo && $kbytes <= $expect_hi )) ||
		error "fallocate did not use quota correctly"
}
run_test 78A "Check fallocate increase quota usage"

test_78a()
{
	(( $CLIENT_VERSION >= $(version_code 2.15.0.37) )) ||
		skip "need client >= v2_15_50-37-g5fc934eb for falloc proj fix"
	(( $OST1_VERSION >= $(version_code 2.15.0.37) )) ||
		skip "need OST >= v2_15_50-37-g5fc934ebbb for falloc proj fix"
	check_set_fallocate_or_skip

	setup_quota_test || error "setup quota failed with $?"

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	mkdir -p $DIR/$tdir || error "failed to create $tdir"

	local projectid=5200 # Random project id to test

	change_project -sp $projectid $DIR/$tdir

	# setup quota limit
	$LFS setquota -p $projectid -b25M -B25M $DIR/$tdir ||
		error "lfs setquota project failed"

	# call fallocate
	fallocate -l 204800 $DIR/$tdir/$tfile

	# Get curspace (kbytes) for $projectid
	local kbytes=$(getquota -p $projectid global curspace)

	echo "kbytes returned:$kbytes"

	# For file size of 204800. We should be having roughly 200 kbytes
	# returned. Anything alarmingly low (50 taken as arbitrary value)
	# would bail out this TC. Also this also avoids $kbytes of 0
	# to be used in calculation below.
	(( $kbytes > 50 )) ||
		error "fallocate did not use projectid. kbytes returned:$kbytes"

	local expect_lo=$(($kbytes * 95 / 100)) # 5% below
	local expect_hi=$(($kbytes * 105 / 100)) # 5% above

	# Verify kbytes is 200 (204800/1024). With a permited  5% drift
	(( $kbytes >= $expect_lo && $kbytes <= $expect_hi )) ||
		error "fallocate did not use quota projectid correctly"
}
run_test 78a "Check fallocate increase projectid usage"

test_79()
{
	(( $MDS1_VERSION >= $(version_code 2.14.56.37) )) ||
		skip "need MDS >= v2_14_56-37-gc9901b68b4 for pool panic fix"

	local qpool="qpool1"
	local cmd="$LCTL get_param -n qmt.$FSNAME-QMT0000.dt-$qpool.info"
	local stopf=$TMP/$tfile

	do_facet mds1 "touch $stopf" || error "can't create $stopf"
	do_facet mds1 "ls $stopf" || error "can't find $stopf"
	stack_trap "do_facet mds1 'rm -f $stopf'"
	do_facet mds1 "while [ -e $stopf ]; do $cmd &>/dev/null; done"&
	local pid=$!
	pool_add $qpool || error "pool_add failed"
	do_facet mds1 "rm $stopf"
	wait $pid
}
run_test 79 "access to non-existed dt-pool/info doesn't cause a panic"

test_80()
{
	(( $MDS1_VERSION >= $(version_code 2.14.56.51) )) ||
		skip "need MDS >= v2_14_56-51-g61ec1e0f2c for EDQUOT failover"

	local dir1="$DIR/$tdir/dir1"
	local dir2="$DIR/$tdir/dir2"
	local TESTFILE0="$dir1/$tfile-0"
	local TESTFILE1="$dir1/$tfile-1"
	local TESTFILE2="$dir1/$tfile-2"
	local TESTFILE3="$dir2/$tfile-0"
	local global_limit=100 # 100M
	local limit=10 # 10M
	local qpool="qpool1"

	[ "$OSTCOUNT" -lt "2" ] && skip "needs >= 2 OSTs"
	mds_supports_qp
	[ "$ost1_FSTYPE" == zfs ] &&
		skip "ZFS grants some block space together with inode"
	setup_quota_test || error "setup quota failed with $?"
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# make sure the system is clean
	local used=$(getquota -u $TSTUSR global curspace)
	[ $used -ne 0 ] && error "Used space($used) for user $TSTUSR is not 0."

	pool_add $qpool || error "pool_add failed"
	pool_add_targets $qpool 0 1 ||
		error "pool_add_targets failed"

	$LFS setquota -u $TSTUSR -b 0 -B ${global_limit}M -i 0 -I 0 $DIR ||
		error "set user quota failed"

	$LFS setquota -u $TSTUSR -B ${global_limit}M --pool $qpool $DIR ||
		error "set user quota failed"
	$LFS setquota -u $TSTUSR -B ${limit}M --pool $qpool $DIR ||
		error "set user quota failed"

	mkdir -p $dir1 || error "failed to mkdir"
	chown $TSTUSR.$TSTUSR $dir1 || error "chown $dir1 failed"
	mkdir -p $dir2 || error "failed to mkdir"
	chown $TSTUSR.$TSTUSR $dir2 || error "chown $dir2 failed"

	$LFS setstripe $dir1 -i 1 -c 1|| error "setstripe $testfile failed"
	$LFS setstripe $dir2 -i 0 -c 1|| error "setstripe $testfile failed"
	lfs getstripe $dir1
	lfs getstripe $dir2
	sleep 3

	$LFS quota -v -u $TSTUSR $DIR
	#define OBD_FAIL_QUOTA_PREACQ            0xA06
	do_facet mds1 $LCTL set_param fail_loc=0xa06
	$RUNAS $DD of=$TESTFILE3 count=3 ||
		quota_error u $TSTUSR "write failed"
	$RUNAS $DD of=$TESTFILE2 count=7 ||
		quota_error u $TSTUSR "write failed"
	$RUNAS $DD of=$TESTFILE1 count=1 oflag=direct ||
		quota_error u $TSTUSR "write failed"
	sync
	sleep 3
	$LFS quota -v -u --pool $qpool $TSTUSR $DIR

	rm -f $TESTFILE2
	stop ost2
	do_facet mds1 $LCTL set_param fail_loc=0
	start ost2 $(ostdevname 2) $OST_MOUNT_OPTS || error "start ost2 failed"
	$LFS quota -v -u $TSTUSR --pool $qpool $DIR
	# OST0 needs some time to update quota usage after removing TESTFILE2
	sleep 4
	$LFS quota -v -u $TSTUSR --pool $qpool $DIR
	$RUNAS $DD of=$TESTFILE0 count=2 oflag=direct ||
		quota_error u $TSTUSR "write failure, but expect success"
}
run_test 80 "check for EDQUOT after OST failover"

test_81()
{
	(( $MDS1_VERSION >= $(version_code 2.14.56.52) )) ||
		skip "need MDS >= v2_14_56-52-g862f0baa7c for qmt_pool_free fix"

	local global_limit=20  # 100M
	local testfile="$DIR/$tdir/$tfile-0"
	local qpool="qpool1"

	mds_supports_qp
	setup_quota_test || error "setup quota failed with $?"

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# test for user
	log "User quota (block hardlimit:$global_limit MB)"
	$LFS setquota -u $TSTUSR -B 1G $DIR || error "set user quota failed"

	pool_add $qpool || error "pool_add failed"
	#define OBD_FAIL_QUOTA_RECALC	0xA07
	do_facet mds1 $LCTL set_param fail_loc=0x80000A07 fail_val=10
	# added OST casues to start pool recalculation
	pool_add_targets $qpool 0 0 1
	stop mds1 -f || error "MDS umount failed"

	#start mds1 back to destroy created pool
	start mds1 $(mdsdevname 1) $MDS_MOUNT_OPTS
	clients_up || true
}
run_test 81 "Race qmt_start_pool_recalc with qmt_pool_free"

test_82()
{
	(( $MDS1_VERSION >= $(version_code 2.15.50.72) )) ||
		skip "need MDS >= v2_15_50-72-g61481796ac for over 8 QIDs fix"

	is_project_quota_supported || skip "skip project quota unsupported"

	setup_quota_test || error "setup quota failed with $?"
	quota_init

	local parent_dir="$DIR/$tdir.parent"
	local child_dir="$parent_dir/child"

	mkdir -p $child_dir
	stack_trap "chown -R 0:0 $parent_dir"

	chown $TSTUSR:$TSTUSR $parent_dir ||
		error "failed to chown on $parent_dir"
	chown $TSTUSR2:$TSTUSRS2 $child_dir ||
		error "failed to chown on $parent_dir"

	$LFS project -p 1000 $parent_dir ||
		error "failed to set project id on $parent_dir"
	$LFS project -p 1001 $child_dir ||
		error "failed to set project id on $child_dir"

	rmdir $child_dir || error "cannot remove child dir, test failed"
}
run_test 82 "verify more than 8 qids for single operation"

test_grace_with_default_quota()
{
	local qtype=$1
	local qdtype=$2
	local bgrace
	local igrace
	local bgrace2
	local igrace2
	echo "ttt1"
	$LFS setquota $qdtype -b 0 -B 0 -i 0 -I 0 $DIR ||
		error "clear default quota [$qdtype] failed"
	echo "ttt2"
	$LFS setquota -t $qtype --block-grace 1w --inode-grace 1w $DIR ||
		error "reset quota [$qdtype] grace failed"
	echo "ttt3"

	eval $($LFS quota -t $qtype $DIR | awk -F "[; ]" \
			'{printf("bgrace=%s;igrace=%s;", $4, $9)}')
	echo "ttt4"

	$LFS setquota $qdtype -B 10G -i 10k $DIR
	echo "ttt5"

	eval $($LFS quota -t $qtype $DIR | awk -F "[; ]" \
			'{printf("bgrace2=%s;igrace2=%s;", $4, $9)}')

	[ "$bgrace" == "$bgrace2" ] ||
			error "set default quota shouldn't affect block grace"
	[ "$igrace" == "$igrace2" ] ||
			error "set default quota shouldn't affect inode grace"

}

test_83()
{
	(( $MDS1_VERSION >= $(version_code 2.15.51.29) )) ||
		skip "need MDS >= v2_15_51-29-gd4978678b4 for grace time fix"

	setup_quota_test || error "setup quota failed with $?"
	test_grace_with_default_quota "-u" "-U"
	test_grace_with_default_quota "-g" "-G"

	is_project_quota_supported || return 0
	test_grace_with_default_quota "-p" "-P"
}
run_test 83 "Setting default quota shouldn't affect grace time"

test_84()
{
	(( $MDS1_VERSION >= $(version_code 2.15.53.115) )) ||
		skip "need MDS >= v2_15_53-115-ga2fd4d3aee for insane quota fix"
	(( $OST1_VERSION >= $(version_code 2.15.53.115) )) ||
		skip "need OSS >= v2_15_53-115-ga2fd4d3aee for insane quota fix"

	local dir1="$DIR/$tdir/dir1"
	local TESTFILE1="$dir1/$tfile-1"
	local waited=0
	local grant=0
	local grant2=0
	local qp="qpool1"

	mds_supports_qp

	setup_quota_test || error "setup quota failed with $?"
	quota_init
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	pool_add $qp || error "pool_add failed"
	pool_add_targets $qp 0 $(($OSTCOUNT - 1)) ||
		error "pool_add_targets failed"

	$LFS setquota -g $TSTUSR -B 10G $DIR ||
		error "failed to set group quota for $TSTUSR"
	$LFS setquota -g $TSTUSR -B 5G --pool $qp $DIR ||
                error "set user quota failed"
	$LFS quota -gv $TSTUSR $DIR

	wait_quota_synced "ost1" "OST0000" "grp" $TSTID "hardlimit" "10485760"

	mkdir -p $dir1 || error "failed to mkdir"
	chown $TSTUSR.$TSTUSR $dir1 || error "chown $dir1 failed"

	$LFS setstripe -c 1 -i 0 $TESTFILE1
	$LFS getstripe $TESTFILE1
	chown $TSTUSR.$TSTUSR $TESTFILE1

	$RUNAS $DD of=$TESTFILE1 count=60 conv=nocreat oflag=direct ||
		quota_error g $TSTUSR "write failed"

	sync_all_data || true
	sleep 3
	$LFS quota -gv $TSTUSR $DIR
	$LFS quota -gv --pool $qp $TSTUSR $DIR

	# the grant quota should be larger than 0
	waited=0
	while (( $waited < 60 )); do
		grant=$(getquota -g $TSTUSR lustre-OST0000 bhardlimit $qp)
		grant2=$(getquota -g $TSTUSR lustre-OST0000 bhardlimit)
		(( ${grant} > 0 && ${grant2} > 0 )) && break

		do_facet ost1 $LCTL set_param \
				osd-*.*-OST0000.quota_slave.force_reint=1
		sleep 1
		waited=$((waited + 1))
	done

	(( $waited >= 60)) && {
		$LFS quota -gv $TSTUSR $DIR
		$LFS quota -gv --pool $qp $TSTUSR $DIR
	}

	(( ${grant} > 0 )) || error "pool grant is not increased after dd"
	(( ${grant2} > 0 )) || error "grant is not increased after dd"

#define OBD_FAIL_QUOTA_GRANT 0xA08
	lustre_fail mds 0xa08
	lustre_fail ost 0xa08
	sleep 1

	# clear quota limits to trigger updating grant quota
	$LFS setquota -g $TSTUSR -b 0 -B 0 $DIR ||
		error "failed to clear the group quota for $TSTUSR"
	$LFS quota -gv $TSTUSR $DIR
	$LFS quota -gv --pool $qp $TSTUSR $DIR

	# the grant quota should be set as insane value
	waited=0
	while (( $waited < 60 )); do
		grant=$(getquota -g $TSTUSR lustre-OST0000 bhardlimit $qp)
		grant2=$(getquota -g $TSTUSR lustre-OST0000 bhardlimit)
		(( ${#grant} == 20 && ${#grant2} == 20 )) && break

		sleep 1
		waited=$((waited + 1))
	done

	(( $waited >= 60)) && {
		$LFS quota -gv $TSTUSR $DIR
		$LFS quota -gv --pool $qp $TSTUSR $DIR
	}

	(( ${#grant} == 20 )) || error "pool grant is not set as insane value"
	(( ${#grant2} == 20 )) || error "grant is not set as insane value"

	lustre_fail mds_ost 0
	sleep 1

	# reset the quota
	$LFS setquota -g $TSTUSR -r $DIR ||
		error "failed to reset group quota for $TSTUSR"

	sleep 3
	$LFS quota -gv $TSTUSR $DIR
	$LFS quota -gv --pool $qp $TSTUSR $DIR

	# the grant quota should be reset
	grant=$(getquota -g $TSTUSR lustre-OST0000 bhardlimit)
	(( ${#grant} == 20 )) && error "grant is not cleared"
	grant=$(getquota -g $TSTUSR lustre-OST0000 bhardlimit $qp)
	(( ${#grant} == 20 )) && error "pool grant is not cleared"

	$LFS quota -gv $TSTUSR --pool $qp $DIR
	$LFS quota -gv --pool $qp $TSTUSR $DIR
	local hlimit=$(getquota -g $TSTUSR global bhardlimit $qp)
	 [ $hlimit -eq 5242880 ] || error "pool limit is changed"

	# test whether the quota still works
	$LFS setquota -g $TSTUSR -B 100M $DIR ||
		error "failed to set group quota for $TSTUSR"
	$LFS quota -gv $TSTUSR $DIR

	$RUNAS $DD of=$TESTFILE1 count=200 conv=nocreat oflag=direct &&
		quota_error g $TSTUSR "dd succeed, expect EDQUOT"

	$LFS setquota -g $TSTUSR -B 300M $DIR ||
		error "failed to set group quota for $TSTUSR"
	$LFS quota -gv $TSTUSR $DIR

	$RUNAS $DD of=$TESTFILE1 count=200 conv=nocreat oflag=direct ||
		quota_error g $TSTUSR "dd failed, expect succeed"
}
run_test 84 "Reset quota should fix the insane granted quota"

test_85()
{
	(( $MDS1_VERSION >= $(version_code 2.15.55.5) )) ||
		skip "need MDS >= v2_15_55-5-g6c0b4329d0 for least_qunit fix"
	(( $OST1_VERSION >= $(version_code 2.15.55.5) )) ||
		skip "need OSS >= v2_15_55-5-g6c0b4329d0 for least_qunit fix"

	local limit=3 # 3M
	local qpool="qpool1"
	local qpool2="qpool2"
	local tfile1="$DIR/$tdir/$tfile-0"

	(( OSTCOUNT >= 2 )) || skip "needs >= 2 OSTs"
	mds_supports_qp
	setup_quota_test || error "setup quota failed with $?"

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	$LFS setquota -u $TSTUSR -b 0 -B 50T -i 0 -I 0 $DIR ||
		error "set user quota failed"

	pool_add $qpool || error "pool_add failed"
	pool_add_targets $qpool 0 1 ||
		error "pool_add_targets failed"

	pool_add $qpool2 || error "pool_add failed"
	pool_add_targets $qpool2 0 1 ||
		error "pool_add_targets failed"

	$LFS setstripe -p $qpool $DIR/$tdir || error "cannot set stripe"
	$LFS setquota -u $TSTUSR -B 30M --pool $qpool $DIR ||
		error "set user quota failed"
	$LFS setquota -u $TSTUSR -B ${limit}M --pool $qpool $DIR ||
		error "set user quota failed"

	# don't care about returned value. Just check we don't hung on write.
	$RUNAS $DD of=$tfile1 count=10
	return 0
}
run_test 85 "do not hung at write with the least_qunit"

test_preacquired_quota()
{
	local test_dir=$1
	local qtype=$2
	local qtype_name=$3
	local qid=$4

	[[ "$qtype" == "-p" ]] && change_project -sp $qid $DIR/$tdir

	$LFS setquota $qtype $qid -i 100K -I 100K $DIR ||
		error "failed to set file [$qtype] quota"

	$RUNAS createmany -m $test_dir/tfile- 5000 ||
		error "failed to create files, expect succeed"

	wait_zfs_commit $SINGLEMDS
	$LFS setquota $qtype $qid -i 2K -I 2K $DIR ||
		error "failed to decrease file [$qtype] quota"

	wait_quota_synced "mds1" "MDT0000" $qtype_name $qid "hardlimit" "2048"

	# make sure the lqe->lqe_edquot is set
	$RUNAS createmany -m $test_dir/tfile2- 10
	sleep 5

	$RUNAS createmany -m $test_dir/tfile3- 30 &&
		error "succeed to create files, expect failed"

	rm -f $test_dir/tfile*
	$LFS setquota $qtype $qid -i 0 -I 0 $DIR ||
		error "failed to reset file user quota"
}

test_86()
{
	(( $MDS1_VERSION >= $(version_code 2.15.57.41) )) ||
		skip "need MDS >= 2.15.57.41 for quota over limit release fix"

	local test_dir="$DIR/$tdir/test_dir"

	setup_quota_test || error "setup quota failed with $?"
	set_mdt_qtype $QTYPE || error "enable mdt quota failed"

	$LFS setdirstripe -c 1 -i 0 $test_dir || error "setdirstripe failed"
	chmod 777 $test_dir

	test_preacquired_quota "$test_dir" "-u" "usr" "$TSTID"
	test_preacquired_quota "$test_dir" "-g" "grp" "$TSTID"

	is_project_quota_supported || return 0
	test_preacquired_quota "$test_dir" "-p" "prj" "1000"
}
run_test 86 "Pre-acquired quota should be released if quota is over limit"

check_quota_no_mount()
{
	local opts="$1"
	local id="$2"

	echo "cmd: $LFS quota $opts $id"
	local expected=$($LFS quota $opts $id $MOUNT)
	local actual=$($LFS quota $opts $id)

	[[ "$actual" == "$expected" ]] ||
		error "quota info not $expected, found: $actual"
}

check_quota_two_mounts()
{
	local opts="$1"
	local id="$2"

	local cmd="$LFS quota -q $opts $id $MOUNT $MOUNT2"
	echo "cmd: $cmd"
#	remove the header for comparison
	local actual
	local full=$($cmd)
	local head=$($LFS quota -q $opts $id $MOUNT)
	local tail=$($LFS quota -q $opts $id $MOUNT2)

	actual=$(echo "$full" | head -n$(echo "$head" | wc -l))
	[[ "$actual" == "$head" ]] ||
	# re-fetch head if it failed
	[[ "$actual" == "$($LFS quota -q $opts $id $MOUNT)" ]] ||
		error "quota info from $MOUNT not '$head', found '$actual'"

	actual=$(echo "$full" | tail -n$(echo "$tail" | wc -l))
	[[ "$actual" == "$tail" ]] ||
	# re-fetch tail if it failed
	[[ "$actual" == "$($LFS quota -q $opts $id $MOUNT2)" ]] ||
		error "quota info from $MOUNT2 not '$tail', found '$actual'"
}

test_90a()
{
	(( MDS1_VERSION >= $(version_code 2.15.60) )) ||
		skip "Need MDS version at least 2.15.60"

	setup_quota_test || error "setup quota failed with $?"

	stack_trap cleanup_quota_test

	check_quota_no_mount
	check_quota_no_mount -u $TSTUSR
	check_quota_no_mount "-a -u"
	check_quota_no_mount "-t -u"
	check_quota_no_mount -U
	check_quota_no_mount -g $TSTUSR
	check_quota_no_mount "-a -g"
	check_quota_no_mount "-t -g"
	check_quota_no_mount -G

	! is_project_quota_supported &&
		skip "Project quota is not supported"
	check_quota_no_mount -p 100
	check_quota_no_mount "-a -p"
	check_quota_no_mount "-t -p"
	check_quota_no_mount -P
}
run_test 90a "lfs quota should work without mount point"

test_90b()
{
	(( MDS1_VERSION >= $(version_code 2.15.60) )) ||
		skip "Need MDS version at least 2.15.60"

	setup_quota_test || error "setup quota failed with $?"
	mount_client $MOUNT2

	stack_trap "umount $MOUNT2"
	stack_trap cleanup_quota_test

	check_quota_two_mounts -u $TSTUSR
	check_quota_two_mounts "-a -u"
	check_quota_two_mounts "-t -u"
	check_quota_two_mounts -U
	check_quota_two_mounts -g $TSTUSR
	check_quota_two_mounts "-a -g"
	check_quota_two_mounts "-t -g"
	check_quota_two_mounts -G

	! is_project_quota_supported &&
		skip "Project quota is not supported"
	check_quota_two_mounts -p 1000
	check_quota_two_mounts "-a -p"
	check_quota_two_mounts "-t -p"
	check_quota_two_mounts -P
}
run_test 90b "lfs quota should work with multiple mount points"


quota_fini()
{
	do_nodes $(comma_list $(nodes_list)) \
		"lctl set_param -n debug=-quota-trace"
	if $PQ_CLEANUP; then
		disable_project_quota
	fi
}
reset_quota_settings
quota_fini

cd $ORIG_PWD
complete_test $SECONDS
check_and_cleanup_lustre
export QUOTA_AUTO=$QUOTA_AUTO_OLD
exit_status
