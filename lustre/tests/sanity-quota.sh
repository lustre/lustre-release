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
# Bug number for skipped test:  LU-5152
ALWAYS_EXCEPT+="                55"
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
TSTID=${TSTID:-60000}
TSTID2=${TSTID2:-60001}
TSTUSR=${TSTUSR:-"quota_usr"}
TSTUSR2=${TSTUSR2:-"quota_2usr"}
TSTPRJID=${TSTPRJID:-1000}
BLK_SZ=1024
MAX_DQ_TIME=604800
MAX_IQ_TIME=604800
QTYPE="ugp"
# QP exists since this version. Should be finally set before landing.
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

change_project()
{
	echo "lfs project $*"
	lfs project $* || error "lfs project $* failed"
}

RUNAS="runas -u $TSTID -g $TSTID"
RUNAS2="runas -u $TSTID2 -g $TSTID2"
DD="dd if=/dev/zero bs=1M"

FAIL_ON_ERROR=false

# clear quota limits for a user or a group
# usage: resetquota -u username
#        resetquota -g groupname
#	 resetquota -p projid

resetquota() {
	[ "$#" != 2 ] && error "resetquota: wrong number of arguments: $#"
	[ "$1" != "-u" -a "$1" != "-g" -a "$1" != "-p" ] &&
		error "resetquota: wrong specifier $1 passed"

	if [ $1 == "-p" ]; then
		is_project_quota_supported || return 0
	fi

	$LFS setquota "$1" "$2" -b 0 -B 0 -i 0 -I 0 $MOUNT ||
		error "clear quota for [type:$1 name:$2] failed"
	# give a chance to slave to release space
	sleep 1
}

quota_scan() {
	local local_ugp=$1
	local local_id=$2

	if [ "$local_ugp" == "a" -o "$local_ugp" == "u" ]; then
		$LFS quota -v -u $local_id $DIR
		log "Files for user ($local_id):"
		($LFS find --user $local_id $DIR | head -n 4 |
			xargs stat 2>/dev/null)
	fi

	if [ "$local_ugp" == "a" -o "$local_ugp" == "g" ]; then
		$LFS quota -v -g $local_id $DIR
		log "Files for group ($local_id):"
		($LFS find --group $local_id $DIR | head -n 4 |
			xargs stat 2>/dev/null)
	fi

	is_project_quota_supported || return 0
	if [ "$local_ugp" == "a" -o "$local_ugp" == "p" ]; then
		$LFS quota -v -p $TSTPRJID $DIR
		log "Files for project ($TSTPRJID):"
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

	$LFS quota -v "$1" "$2" $pool_arg $DIR |
		awk 'BEGIN { num='$spec' } { if ($1 == "'$uuid'") \
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
			osd-*.$FSNAME-MDT*.quota_slave.enable=$qtype
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
			osd-*.$FSNAME-OST*.quota_slave.enable=$qtype
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
	if [ "$orig_time" == "none" ]; then
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
	mkdir $DIR/$tdir || return 1
	chmod 0777 $DIR/$tdir || return 2
	# always clear fail_loc in case of fail_loc isn't cleared
	# properly when previous test failed
	lustre_fail mds_ost 0
}

cleanup_quota_test() {
	echo "Delete files..."
	rm -rf $DIR/$tdir
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
	resetquota -u $TSTUSR
	resetquota -u $TSTID
	resetquota -g $TSTUSR
	resetquota -g $TSTID
	resetquota -u $TSTUSR2
	resetquota -u $TSTID2
	resetquota -g $TSTUSR2
	resetquota -g $TSTID2
	resetquota -p $TSTPRJID
}

# enable quota debug
quota_init() {
	do_nodes $(comma_list $(nodes_list)) "lctl set_param debug=+quota+trace"
}
quota_init
reset_quota_settings

check_runas_id_ret $TSTUSR $TSTUSR $RUNAS ||
	error "Please create user $TSTUSR($TSTID) and group $TSTUSR($TSTID)"
check_runas_id_ret $TSTUSR2 $TSTUSR2 $RUNAS2 ||
	error "Please create user $TSTUSR2($TSTID2) and group $TSTUSR2($TSTID2)"

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
	trap cleanup_quota_test EXIT

	set_ost_qtype "none" || error "disable ost quota failed"
	test_quota_performance $MB

	set_ost_qtype $QTYPE || error "enable ost quota failed"
	$LFS setquota -u $TSTUSR -b 0 -B 10G -i 0 -I 0 $DIR ||
		error "set quota failed"
	test_quota_performance $MB

	cleanup_quota_test
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
	# this time maybe cache write,  ignore it's failure
	$RUNAS $DD of=$testfile count=$((limit/2)) seek=$((limit/2)) || true
	# flush cache, ensure noquota flag is set on client
	cancel_lru_locks osc
	sync; sync_all_data || true
	# sync means client wrote all it's cache, but id doesn't
	# garantee that slave got new edquot trough glimpse.
	# so wait a little to be sure slave got it.
	sleep 5
	$RUNAS $DD of=$testfile count=1 seek=$limit &&
		quota_error $short_qtype $TSTUSR \
			"user write success, but expect EDQUOT"
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
	trap cleanup_quota_test EXIT

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# test for user
	log "User quota (block hardlimit:$limit MB)"
	$LFS setquota -u $TSTUSR -b 0 -B ${limit}M -i 0 -I 0 $DIR ||
		error "set user quota failed"

	# make sure the system is clean
	local used=$(getquota -u $TSTUSR global curspace)
	[ $used -ne 0 ] && error "Used space($used) for user $TSTUSR isn't 0."

	$LFS setstripe $testfile -c 1 || error "setstripe $testfile failed"
	chown $TSTUSR.$TSTUSR $testfile || error "chown $testfile failed"

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

	$LFS setstripe $testfile -c 1 || error "setstripe $testfile failed"
	chown $TSTUSR.$TSTUSR $testfile || error "chown $testfile failed"

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
		cleanup_quota_test
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

	$LFS setstripe $testfile -c 1 || error "setstripe $testfile failed"
	chown $TSTUSR:$TSTUSR $testfile || error "chown $testfile failed"
	change_project -p $TSTPRJID $testfile

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
	local limit=10 # MB
	local global_limit=20 # MB
	local testfile="$DIR/$tdir/$tfile-0"
	local qpool="qpool1"

	mds_supports_qp
	setup_quota_test || error "setup quota failed with $?"
	stack_trap cleanup_quota_test EXIT

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

	used=$(getquota -u $TSTUSR global bhardlimit $qpool)

	$LFS setstripe $testfile -c 1 || error "setstripe $testfile failed"
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

	testfile="$DIR/$tdir/$tfile-1"
	# make sure the system is clean
	used=$(getquota -g $TSTUSR global curspace $qpool)
	[ $used -ne 0 ] && error "Used space ($used) for group $TSTUSR isn't 0"

	$LFS setstripe $testfile -c 1 || error "setstripe $testfile failed"
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
		cleanup_quota_test
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


	$LFS setstripe $testfile -c 1 || error "setstripe $testfile failed"
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
	stack_trap cleanup_quota_test EXIT

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

	test_1_check_write $testfile "user" $global_limit

	used=$(getquota -u $TSTUSR global curspace $qpool1)
	echo "qpool1 used $used"
	used=$(getquota -u $TSTUSR global curspace $qpool2)
	echo "qpool2 used $used"

	rm -f $testfile
	wait_delete_completed || error "wait_delete_completed failed"
	sync_all_data || true

	used=$(getquota -u $TSTUSR global curspace $qpool1)
	[ $used -ne 0 ] && quota_error u $TSTUSR \
		"user quota isn't released after deletion"
	resetquota -u $TSTUSR

	# cleanup
	cleanup_quota_test
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
	stack_trap cleanup_quota_test EXIT

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
	[ $used -ne 0 ] && quota_error u $TSTUSR \
		"user quota isn't released after deletion"
	resetquota -u $TSTUSR

	# cleanup
	cleanup_quota_test
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
	stack_trap cleanup_quota_test EXIT

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
	[ $used -ne 0 ] && quota_error u $TSTUSR \
		"user quota isn't released after deletion"
	resetquota -u $TSTUSR

	# cleanup
	cleanup_quota_test
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
	stack_trap cleanup_quota_test EXIT

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

	# cleanup
	cleanup_quota_test
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
	stack_trap cleanup_quota_test EXIT
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
	$RUNAS $DD of=$testfile count=$OSTCOUNT seek=$limit &&
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
	trap cleanup_quota_test EXIT

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# test for user
	log "User quota (block hardlimit:$limit MB)"
	$LFS setquota -u $TSTUSR -b 0 -B ${limit}M -i 0 -I 0 $DIR ||
		error "set user quota failed"

	# make sure the system is clean
	local used=$(getquota -u $TSTUSR global curspace)
	[ $used -ne 0 ] && error "Used space($used) for user $TSTUSR isn't 0."

	$LFS setstripe $testfile -c 1 || error "setstripe $testfile failed"
	chown $TSTUSR.$TSTUSR $testfile || error "chown $testfile failed"

	check_write_fallocate $testfile "user" $limit

	rm -f $testfile
	wait_delete_completed || error "wait_delete_completed failed"
	sync_all_data || true
	used=$(getquota -u $TSTUSR global curspace)
	[ $used -ne 0 ] && quota_error u $TSTUSR \
		"user quota isn't released after deletion"
	resetquota -u $TSTUSR
}
run_test 1h "Block hard limit test using fallocate"

# test inode hardlimit
test_2() {
	local TESTFILE="$DIR/$tdir/$tfile-0"
	local LIMIT=$(do_facet mds1 $LCTL get_param -n \
		qmt.$FSNAME-QMT0000.md-0x0.info |
		awk '/least qunit/{ print $3 }')
	local L2=$(do_facet mds1 $LCTL get_param -n \
		qmt.$FSNAME-QMT0000.md-0x0.soft_least_qunit)

	[ $L2 -le $LIMIT ] || LIMIT=$L2

	[ "$SLOW" = "no" ] || LIMIT=$((LIMIT * 1024))

	local FREE_INODES=$(mdt_free_inodes 0)
	echo "$FREE_INODES free inodes on master MDT"
	[ $FREE_INODES -lt $LIMIT ] &&
		skip "not enough free inodes $FREE_INODES required $LIMIT"

	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

	# enable mdt quota
	set_mdt_qtype $QTYPE || error "enable mdt quota failed"

	# test for user
	log "User quota (inode hardlimit:$LIMIT files)"
	$LFS setquota -u $TSTUSR -b 0 -B 0 -i 0 -I $LIMIT $DIR ||
		error "set user quota failed"

	# make sure the system is clean
	local USED=$(getquota -u $TSTUSR global curinodes)
	[ $USED -ne 0 ] && error "Used inodes($USED) for user $TSTUSR isn't 0."

	log "Create $LIMIT files ..."
	$RUNAS createmany -m ${TESTFILE} $LIMIT ||
		quota_error u $TSTUSR "user create failure, but expect success"
	log "Create out of file quota ..."
	$RUNAS touch ${TESTFILE}_xxx &&
		quota_error u $TSTUSR "user create success, but expect EDQUOT"

	# cleanup
	unlinkmany ${TESTFILE} $LIMIT || error "unlinkmany $TESTFILE failed"
	rm -f ${TESTFILE}_xxx
	wait_delete_completed

	USED=$(getquota -u $TSTUSR global curinodes)
	[ $USED -ne 0 ] && quota_error u $TSTUSR \
		"user quota isn't released after deletion"
	resetquota -u $TSTUSR

	# test for group
	log "--------------------------------------"
	log "Group quota (inode hardlimit:$LIMIT files)"
	$LFS setquota -g $TSTUSR -b 0 -B 0 -i 0 -I $LIMIT $DIR ||
		error "set group quota failed"

	TESTFILE=$DIR/$tdir/$tfile-1
	# make sure the system is clean
	USED=$(getquota -g $TSTUSR global curinodes)
	[ $USED -ne 0 ] && error "Used inodes($USED) for group $TSTUSR isn't 0."

	log "Create $LIMIT files ..."
	$RUNAS createmany -m ${TESTFILE} $LIMIT ||
		quota_error g $TSTUSR "group create failure, but expect success"
	log "Create out of file quota ..."
	$RUNAS touch ${TESTFILE}_xxx &&
		quota_error g $TSTUSR "group create success, but expect EDQUOT"

	# cleanup
	unlinkmany ${TESTFILE} $LIMIT || error "unlinkmany $TESTFILE failed"
	rm -f ${TESTFILE}_xxx
	wait_delete_completed

	USED=$(getquota -g $TSTUSR global curinodes)
	[ $USED -ne 0 ] && quota_error g $TSTUSR \
		"user quota isn't released after deletion"

	resetquota -g $TSTUSR
	! is_project_quota_supported && cleanup_quota_test &&
		echo "Skip project quota is not supported" && return 0

	# test for project
	log "--------------------------------------"
	log "Project quota (inode hardlimit:$LIMIT files)"
	$LFS setquota -p $TSTPRJID -b 0 -B 0 -i 0 -I $LIMIT $DIR ||
		error "set project quota failed"

	TESTFILE=$DIR/$tdir/$tfile-1
	# make sure the system is clean
	USED=$(getquota -p $TSTPRJID global curinodes)
	[ $USED -ne 0 ] &&
		error "Used inodes($USED) for project $TSTPRJID isn't 0"

	change_project -sp $TSTPRJID $DIR/$tdir
	log "Create $LIMIT files ..."
	$RUNAS createmany -m ${TESTFILE} $((LIMIT-1)) || quota_error p \
		$TSTPRJID "project create fail, but expect success"
	log "Create out of file quota ..."
	$RUNAS touch ${TESTFILE}_xxx && quota_error p $TSTPRJID \
		"project create success, but expect EDQUOT"
	change_project -C $DIR/$tdir

	cleanup_quota_test
	USED=$(getquota -p $TSTPRJID global curinodes)
	[ $USED -eq 0 ] || quota_error p $TSTPRJID \
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
	stack_trap cleanup_quota_test EXIT

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
	# qpool has minimum soft limit, but it's grace is grater than
	# grace period of qpool2. Thus write shouldn't fail when
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
	trap cleanup_quota_test EXIT
	is_project_quota_supported && change_project -sp $TSTPRJID $DIR/$tdir

	echo "Create files to exceed soft limit"
	$RUNAS createmany -m ${TESTFILE}_ $((LIMIT + 1)) ||
		quota_error a $TSTUSR "create failure, but expect success"
	local trigger_time=$(date +%s)

	sync_all_data || true

	local cur_time=$(date +%s)
	[ $(($cur_time - $trigger_time)) -ge $grace ] &&
		error "Passed grace time $grace, $trigger_time, $cur_time"

	echo "Create file before timer goes off"
	$RUNAS touch ${TESTFILE}_before ||
		quota_error a $TSTUSR "failed create before timer expired," \
			"but expect success. $trigger_time, $cur_time"
	sync_all_data || true

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
	sync_all_data || true

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
	sync_all_data || true

	# cleanup
	cleanup_quota_test
}

# file soft limit
test_4a() {
	local LIMIT=$(do_facet $SINGLEMDS $LCTL get_param -n \
		qmt.$FSNAME-QMT0000.md-0x0.soft_least_qunit)
	local TESTFILE=$DIR/$tdir/$tfile-0
	local GRACE=12

	set_mdt_qtype $QTYPE || error "enable mdt quota failed"

	echo "User quota (soft limit:$LIMIT files  grace:$GRACE seconds)"
	# make sure the system is clean
	local USED=$(getquota -u $TSTUSR global curinodes)
	[ $USED -ne 0 ] && error "Used space($USED) for user $TSTUSR isn't 0."

	$LFS setquota -t -u --block-grace $MAX_DQ_TIME --inode-grace \
		$GRACE $DIR || error "set user grace time failed"
	$LFS setquota -u $TSTUSR -b 0 -B 0 -i $LIMIT -I 0 $DIR ||
		error "set user quota failed"

	[ "$mds1_FSTYPE" = zfs ] && GRACE=20

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
	trap cleanup_quota_test EXIT

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
	cleanup_quota_test
}
run_test 5 "Chown & chgrp successfully even out of block/file quota"

# test dropping acquire request on master
test_6() {
	local LIMIT=3 # MB

	# Clear dmesg so watchdog is not triggered by previous
	# test output
	do_facet ost1 dmesg -c > /dev/null

	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

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

	cleanup_quota_test
}
run_test 6 "Test dropping acquire request on master"

# quota reintegration (global index)
test_7a() {
	local TESTFILE=$DIR/$tdir/$tfile
	local LIMIT=20 # MB

	[ "$SLOW" = "no" ] && LIMIT=5

	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

	# make sure the system is clean
	local USED=$(getquota -u $TSTUSR global curspace)
	[ $USED -ne 0 ] && error "Used space($USED) for user $TSTUSR isn't 0."

	# make sure no granted quota on ost1
	set_ost_qtype $QTYPE || error "enable ost quota failed"
	resetquota -u $TSTUSR
	set_ost_qtype "none" || error "disable ost quota failed"

	local OSTUUID=$(ostuuid_from_index 0)
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

	cleanup_quota_test
}
run_test 7a "Quota reintegration (global index)"

# quota reintegration (slave index)
test_7b() {
	local limit=100000 # MB
	local TESTFILE=$DIR/$tdir/$tfile

	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

	# make sure the system is clean
	local USED=$(getquota -u $TSTUSR global curspace)
	[ $USED -ne 0 ] && error "Used space($USED) for user $TSTUSR isn't 0."

	# make sure no granted quota on ost1
	set_ost_qtype $QTYPE || error "enable ost quota failed"
	resetquota -u $TSTUSR
	set_ost_qtype "none" || error "disable ost quota failed"

	local OSTUUID=$(ostuuid_from_index 0)
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
	trap cleanup_quota_test EXIT

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

	cleanup_quota_test
}
run_test 7c "Quota reintegration (restart mds during reintegration)"

# Quota reintegration (Transfer index in multiple bulks)
test_7d(){
	local TESTFILE=$DIR/$tdir/$tfile
	local TESTFILE1="$DIR/$tdir/$tfile"-1
	local limit=20 # MB

	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

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

	cleanup_quota_test
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
	trap cleanup_quota_test EXIT

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

	cleanup_quota_test
}
run_test 7e "Quota reintegration (inode limits)"

# run dbench with quota enabled
test_8() {
	local BLK_LIMIT="100g" #100G
	local FILE_LIMIT=1000000

	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

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
	cleanup_quota_test
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
	trap cleanup_quota_test EXIT

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
	trap cleanup_quota_test EXIT

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

	cleanup_quota_test
}
run_test 10 "Test quota for root user"

test_11() {
	local TESTFILE=$DIR/$tdir/$tfile
	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

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

	cleanup_quota_test
}
run_test 11 "Chown/chgrp ignores quota"

test_12a() {
	[ "$OSTCOUNT" -lt "2" ] && skip "needs >= 2 OSTs"

	local blimit=22 # MB
	local blk_cnt=$((blimit - 5))
	local TESTFILE0="$DIR/$tdir/$tfile"-0
	local TESTFILE1="$DIR/$tdir/$tfile"-1

	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

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

	cleanup_quota_test
}
run_test 12a "Block quota rebalancing"

test_12b() {
	[ "$MDSCOUNT" -lt "2" ] && skip "needs >= 2 MDTs"

	local ilimit=$((1024 * 2)) # inodes
	local TESTFILE0=$DIR/$tdir/$tfile
	local TESTFILE1=$DIR/${tdir}-1/$tfile

	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

	$LFS mkdir -i 1 $DIR/${tdir}-1 || error "create remote dir failed"
	chmod 0777 $DIR/${tdir}-1

	set_mdt_qtype "u" || error "enable mdt quota failed"
	quota_show_check f u $TSTUSR

	$LFS setquota -u $TSTUSR -b 0 -B 0 -i 0 -I $ilimit $DIR ||
		error "set quota failed"

	echo "Create $ilimit files on mdt0..."
	$RUNAS createmany -m $TESTFILE0 $ilimit ||
		quota_error u $TSTUSR "create failed, but expect success"

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

	cleanup_quota_test
}
run_test 12b "Inode quota rebalancing"

test_13(){
	local TESTFILE=$DIR/$tdir/$tfile
	# the name of lwp on ost1 name is MDT0000-lwp-OST0000
	local procf="ldlm.namespaces.*MDT0000-lwp-OST0000.lru_size"

	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

	set_ost_qtype "u" || error "enable ost quota failed"
	quota_show_check b u $TSTUSR

	$LFS setquota -u $TSTUSR -b 0 -B 10M -i 0 -I 0 $DIR ||
		error "set quota failed"
	$LFS setstripe $TESTFILE -c 1 -i 0 || error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	# clear the locks in cache first
	do_facet ost1 $LCTL set_param -n $procf=clear
	local nlock=$(do_facet ost1 $LCTL get_param -n $procf)
	[ $nlock -eq 0 ] || error "$nlock cached locks"

	# write to acquire the per-ID lock
	$RUNAS $DD of=$TESTFILE count=1 oflag=sync ||
		quota_error a $TSTUSR "dd failed"

	nlock=$(do_facet ost1 $LCTL get_param -n $procf)
	[ $nlock -eq 1 ] || error "lock count($nlock) isn't 1"

	# clear quota doesn't trigger per-ID lock cancellation
	resetquota -u $TSTUSR
	nlock=$(do_facet ost1 $LCTL get_param -n $procf)
	[ $nlock -eq 1 ] || error "per-ID lock is lost on quota clear"

	# clear the per-ID lock
	do_facet ost1 $LCTL set_param -n $procf=clear
	nlock=$(do_facet ost1 $LCTL get_param -n $procf)
	[ $nlock -eq 0 ] || error "per-ID lock isn't cleared"

	# spare quota should be released
	local OSTUUID=$(ostuuid_from_index 0)
	local limit=$(getquota -u $TSTUSR $OSTUUID bhardlimit)
	local space=$(getquota -u $TSTUSR $OSTUUID curspace)
	[ $limit -le $space ] ||
		error "spare quota isn't released, limit:$limit, space:$space"

	cleanup_quota_test
}
run_test 13 "Cancel per-ID lock in the LRU list"

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

test_17sub() {
	local err_code=$1
	local BLKS=1    # 1M less than limit
	local TESTFILE=$DIR/$tdir/$tfile

	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

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
	trap cleanup_quota_test EXIT

	set_ost_qtype "u" || error "enable ost quota failed"
	log "User quota (limit: $blimit)"
	$LFS setquota -u $TSTUSR -b 0 -B ${blimit}M -i 0 -I 0 $MOUNT ||
		error "set quota failed"
	quota_show_check b u $TSTUSR

	$LFS setstripe $TESTFILE -i 0 -c 1 || error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	local timeout=$(sysctl -n lustre.timeout)

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
		timeout=$(lctl get_param -n timeout)
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
	trap cleanup_quota_test EXIT

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

	cleanup_quota_test
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
	trap cleanup_quota_test EXIT

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

	cleanup_quota_test
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
	trap cleanup_quota_test EXIT

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

	local OST0_UUID=$(ostuuid_from_index 0)
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
	trap cleanup_quota_test EXIT

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

	cleanup_quota_test
}
run_test 24 "lfs draws an asterix when limit is reached (b16646)"

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
	fi
	resetquota -u $TSTID
	resetquota -g $TSTID
	resetquota -p $TSTPRJID
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

test_30() {
	local LIMIT=4 # MB
	local TESTFILE="$DIR/$tdir/$tfile"
	local GRACE=10

	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

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
	# cleanup
	cleanup_quota_test
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
	trap cleanup_quota_test EXIT

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
	trap cleanup_quota_test EXIT

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

	cleanup_quota_test
}
run_test 34 "Usage transfer for user & group & project"

# usage is still accessible across restart
test_35() {
	local BLK_CNT=2 # MB

	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

	echo "Write file..."
	$RUNAS $DD of=$DIR/$tdir/$tfile count=$BLK_CNT 2>/dev/null ||
		error "write failed"
	is_project_quota_supported &&
		change_project -p $TSTPRJID $DIR/$tdir/$tfile
	cancel_lru_locks osc

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
	quota_init

	echo "Verify disk usage after restart"
	local USED=$(getquota -u $TSTID global curspace)
	[ $USED -eq $ORIG_USR_SPACE ] ||
		error "Used space for user $TSTID changed from " \
			"$ORIG_USR_SPACE to $USED"
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
	if [ $project_supported == "yes" ]; then
		USED=$(getquota -p $TSTPRJID global curinodes)
		[ $USED -eq $ORIG_PRJ_INODES ] ||
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
	if [ $project_supported == "yes" ]; then
		USED=$(getquota -p $TSTPRJID global curspace)
		[ $USED -gt $ORIG_PRJ_SPACE ] ||
			error "Used space for project $TSTPRJID isn't " \
				"increased orig:$ORIG_PRJ_SPACE, now:$USED"
	fi

	cleanup_quota_test
}
run_test 35 "Usage is still accessible across reboot"

# chown/chgrp to the file created with MDS_OPEN_DELAY_CREATE
# LU-5006
test_37() {
	[ "$MDS1_VERSION" -lt $(version_code 2.6.93) ] &&
		skip "Old server doesn't have LU-5006 fix."

	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

	# make sure the system is clean
	local USED=$(getquota -u $TSTID global curspace)
	[ $USED -ne 0 ] &&
		error "Used space ($USED) for user $TSTID isn't 0."

	# create file with MDS_OPEN_DELAY_CREATE flag
	$LFS setstripe -c 1 -i 0 $DIR/$tdir/$tfile ||
		error "Create file failed"
	# write to file
	dd if=/dev/zero of=$DIR/$tdir/$tfile bs=1M count=1 conv=notrunc \
		oflag=sync || error "Write file failed"
	# chown to the file
	chown $TSTID $DIR/$tdir/$tfile || error "Chown to file failed"

	# wait for setattr on objects finished..."
	wait_delete_completed

	USED=$(getquota -u $TSTID global curspace)
	[ $USED -ne 0 ] || quota_error u $TSTUSR "Used space is 0"

	cleanup_quota_test
}
run_test 37 "Quota accounted properly for file created by 'lfs setstripe'"

# LU-8801
test_38() {
	[ "$MDS1_VERSION" -lt $(version_code 2.8.60) ] &&
		skip "Old server doesn't have LU-8801 fix."

	[ "$UID" != 0 ] && skip_env "must run as root" && return

	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

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
	local accnt_cnt

	acct_cnt=$(do_facet mds1 $LCTL get_param $procf | grep "id:" | \
		   awk '{if ($3 < 10000) {print $3}}' | wc -l)
	echo "Found $acct_cnt id entries"

	[ $file_cnt -eq $acct_cnt ] || {
		do_facet mds1 $LCTL get_param $procf
		error "skipped id entries"
	}

	cleanup_quota_test
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
	[ $projectid -ne 1024 ] &&
		error "Project id should be 1024 not $projectid"

	cleanup_quota_test
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
	rm -rf $dir1 $dir2

	cleanup_quota_test
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
	if [ "$projid" != "2" ]; then
		error "project id expected 2 not $projid"
	fi
	rm -rf $dir1 $dir2
	cleanup_quota_test
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
	USED=$(getquota -p 1 global curinodes)
	[ "$USED" != "3" ] &&
		error "file count expected 3 got $USED"

	rm -rf $dir
	cleanup_quota_test
	return 0
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
	USED=$(getquota -p $TSTPRJID global curinodes)
	[ "$USED" == "36" ] ||
		error "file count expected 36 got $USED"

	rm -rf $dir
	cleanup_quota_test
}
run_test 40d "Stripe Directory inherit project quota properly"

test_41() {
	is_project_quota_supported ||
		skip "Project quota is not supported"
	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT
	local dir="$DIR/$tdir/dir"
	local blimit=102400
	local ilimit=4096
	local projid=$((testnum * 1000))

	quota_init

	# enable mdt/ost quota
	set_mdt_qtype ugp || error "enable mdt quota failed"
	set_ost_qtype ugp || error "enable ost quota failed"

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
	# note trailing space to match double printf from awk
	local expected="$blimit $bused $ilimit $iused "

	wait_update $HOSTNAME \
		"{ df -kP $dir; df -iP $dir; } |
		 awk '/$FSNAME/ { printf \\\"%d %d \\\", \\\$2,\\\$3 }'" \
		"$expected" ||
		error "failed to get correct statfs for project quota"

	cleanup_quota_test
}
run_test 41 "df should return projid-specific values"

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
	[ "$count" != 22 ] && error "expected 22 but got $count"

	rm -rf $dir1 $dir2
	cleanup_quota_test
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

	$DD if=/dev/zero of=$DIR/$tdir/6 bs=1M count=1
	#try cp to dir
	cp $DIR/$tdir/6 $dir/6
	used=$(getquota -p 1 global curinodes)
	[ $used != "5" ] && error "expected 5 got $used"

	#try mv to dir
	mv $DIR/$tdir/6 $dir/7
	used=$(getquota -p 1 global curinodes)
	[ $used != "6" ] && error "expected 6 got $used"

	rm -rf $dir
	cleanup_quota_test
}
run_test 51 "Test project accounting with mv/cp"

test_52() {
	! is_project_quota_supported &&
		skip "Project quota is not supported"
	setup_quota_test || error "setup quota failed with $?"
	local dir="$DIR/$tdir/dir"
	mkdir $dir && change_project -sp 1 $dir

	touch $DIR/$tdir/file
	#Try renaming a file into the project.  This should fail.
	for num in $(seq 1 2000); do
		mrename $DIR/$tdir/file $dir/file >&/dev/null &&
			error "rename should fail"
	done
	rm -rf $dir
	cleanup_quota_test
}
run_test 52 "Rename across different project ID"

test_53() {
	! is_project_quota_supported &&
		skip "Project quota is not supported"
	setup_quota_test || error "setup quota failed with $?"
	local dir="$DIR/$tdir/dir"
	mkdir $dir && change_project -s $dir
	lfs project -d $dir | grep P || error "inherit attribute should be set"

	change_project -C $dir
	lfs project -d $dir | grep P &&
		error "inherit attribute should be cleared"

	rm -rf $dir
	cleanup_quota_test
}
run_test 53 "Project inherit attribute could be cleared"

test_54() {
	! is_project_quota_supported &&
		skip "Project quota is not supported"
	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT
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

	cleanup_quota_test
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

	cleanup_quota_test
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

	cleanup_quota_test
}
run_test 56 "lfs quota -t should work well"

test_57() {
	setup_quota_test || error "setup quota failed with $?"

	local dir="$DIR/$tdir/dir"
	mkdir -p $dir
	mkfifo $dir/pipe
	#try to change pipe file should not hang and return failure
	wait_update_facet client "$LFS project -sp 1 $dir/pipe 2>&1 |
		awk -F ':' '{ print \\\$2 }'" \
			" unable to get xattr for fifo '$dir/pipe'" || return 1
	#command can process further if it hit some errors
	touch $dir/aaa $dir/bbb
	mkdir $dir/subdir -p
	touch $dir/subdir/aaa $dir/subdir/bbb
	#create one invalid link file
	ln -s $dir/not_exist_file $dir/ccc
	local cnt=$(lfs project -r $dir 2>/dev/null | wc -l)
	[ $cnt -eq 5 ] || error "expected 5 got $cnt"

	cleanup_quota_test
}
run_test 57 "lfs project could tolerate errors"

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
	cleanup_quota_test
}
run_test 59 "lfs project dosen't crash kernel with project disabled"

test_60() {
	[ $MDS1_VERSION -lt $(version_code 2.11.53) ] &&
		skip "Needs MDS version 2.11.53 or later."
	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

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

	cleanup_quota_test
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
	stack_trap cleanup_quota_test EXIT

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
	 [[ "$(chattr -h 2>&1)" =~ "project" ]] ||
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
	cleanup_quota_test
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
	trap cleanup_quota_test EXIT

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

	rm -f $DIR/$tdir/*
	rm -fr $DIR/$tdir_dom

	$LFS setquota -u $TSTUSR -b 0 -B 0 -i 0 -I 0 $DIR ||
		error "reset usr quota failed"

	cleanup_quota_test
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

	$LFS project -sp $TSTPRJID $dir1/file_link >&/dev/null &&
		error "set symlink file's project should fail"

	$LFS project $TSTPRJID $dir1/file_link >&/dev/null &&
		error "get symlink file's project should fail"

	cleanup_quota_test
}
run_test 64 "lfs project on symlink files should fail"

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

	[ "$(echo "$quota_all" | head -n3)" != "$quota_u" ] &&
		error "usr quota not match"
	[ "$(echo "$quota_all" | tail -n3)" != "$quota_g" ] &&
		error "grp quota not match"

	rm -f $TESTFILE
	# cleanup
	cleanup_quota_test
}
run_test 65 "Check lfs quota result"

test_66() {
	! is_project_quota_supported &&
		skip "Project quota is not supported"
	[ "$MDS1_VERSION" -lt $(version_code 2.12.4) ] &&
		skip "Not supported before 2.12.4"
	setup_quota_test || error "setup quota failed with $?"
	stack_trap cleanup_quota_test EXIT
	local old=$(do_facet mds1 $LCTL get_param -n \
		    mdt.*.enable_chprojid_gid | head -1)
	local testdir=$DIR/$tdir/foo

	do_facet mds1 $LCTL set_param mdt.*.enable_chprojid_gid=0
	stack_trap "do_facet mds1 $LCTL set_param mdt.*.enable_chprojid_gid=0" \
		EXIT

	test_mkdir -i 0 -c 1 $testdir || error "failed to mkdir"
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

	cleanup_quota_test
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
		quota_usr)  _runas=$RUNAS;;
		quota_2usr) _runas=$RUNAS2;;
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
	trap cleanup_quota_test EXIT

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
	test_67_write "$testfile" "user" 10 "quota_usr"

	# create qpool and add OST1
	pool_add $qpool || error "pool_add failed"
	pool_add_targets $qpool 1 1 || error "pool_add_targets failed"
	# as quota_usr hasn't limits, lqe may absent. But it should be
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
	# shows correct granted, despite quota_2usr hasn't limits in qpool1.
	test_67_write "$testfile2" "user" 10 "quota_2usr"
	used=$(getquota -u $TSTUSR2 global curspace $qpool)
	granted=$(getgranted $qpool "dt" $TSTID2 "usr")
	[ $granted -ne 0 ] &&
		error "Granted($granted) for $TSTUSR2 in $qpool isn't 0."

	# Granted space for quota_2usr in qpool1 should appear only
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
	test_67_write "$testfile3" "user" 10 "quota_2usr"
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
	[ $used -ne 0 ] && quota_error u $TSTUSR \
		"user quota isn't released after deletion"
	resetquota -u $TSTUSR

	cleanup_quota_test
}
run_test 67 "quota pools recalculation"

get_slave_nr() {
	local pool=$1
	local qtype=$2
	local nr

	do_facet mds1 $LCTL get_param -n qmt.$FSNAME-QMT0000.dt-$pool.info |
		awk '/usr/ {getline; print $2}'
}

test_68()
{
	local qpool="qpool1"

	mds_supports_qp
	setup_quota_test || error "setup quota failed with $?"
	stack_trap cleanup_quota_test EXIT

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
	[[ $nr != $((OSTCOUNT + MDSCOUNT)) ]] &&
		error "Slave_nr $nr for global pool != ($OSTCOUNT + $MDSCOUNT)"

	cleanup_quota_test
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
	stack_trap cleanup_quota_test EXIT

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

	cleanup_quota_test
}
run_test 69 "EDQUOT at one of pools shouldn't affect DOM"

test_70()
{
	local qpool="qpool1"
	local limit=20 # MB
	local err=0
	local bhard

	[[ CLIENT_VERSION -lt $(version_code $VERSION_WITH_QP) ]] &&
		skip "Needs a client >= $VERSION_WITH_QP"

	setup_quota_test || error "setup quota failed with $?"
	stack_trap cleanup_quota_test EXIT

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

	cleanup_quota_test
}
run_test 70 "check lfs setquota/quota with a pool option"

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
	stack_trap cleanup_quota_test EXIT

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

	cleanup_quota_test
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
	stack_trap cleanup_quota_test EXIT

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

	cleanup_quota_test
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
	stack_trap cleanup_quota_test EXIT

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
	# check that lfs quota -uv --pool prints only OST that
	# was added in a pool
	lfs quota -v -u quota_usr --pool $qpool $DIR | grep -v "OST0001" |
		grep "OST\|MDT" && error "$qpool consists wrong targets"

	cleanup_quota_test
}
run_test 72 "lfs quota --pool prints only pool's OSTs"

test_73()
{
	local qpool="qpool1"

	mds_supports_qp

	pool_add $qpool || error "pool_add failed"
	pool_add_targets $qpool 0 $((OSTCOUNT - 1)) ||
		error "pool_add_targets failed"

	test_default_quota "-u" "data" "qpool1"
}
run_test 73 "default limits at OST Pool Quotas"

quota_fini()
{
	do_nodes $(comma_list $(nodes_list)) "lctl set_param debug=-quota"
	if $PQ_CLEANUP; then
		disable_project_quota
	fi
}
reset_quota_settings
quota_fini

cd $ORIG_PWD
complete $SECONDS
check_and_cleanup_lustre
export QUOTA_AUTO=$QUOTA_AUTO_OLD
exit_status
