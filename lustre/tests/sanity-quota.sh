#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# Run test by setting NOSETUP=true when ltest has setup env for us
set -e

SRCDIR=$(dirname $0)
export PATH=$PWD/$SRCDIR:$SRCDIR:$PWD/$SRCDIR/../utils:$PATH:/sbin

ONLY=${ONLY:-"$*"}
# Bug number for skipped test:
ALWAYS_EXCEPT="$SANITY_QUOTA_EXCEPT"
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

[ "$ALWAYS_EXCEPT$EXCEPT" ] &&
	echo "Skipping tests: $ALWAYS_EXCEPT $EXCEPT"

TMP=${TMP:-/tmp}

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

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging
DIRECTIO=${DIRECTIO:-$LUSTRE/tests/directio}

require_dsh_mds || exit 0
require_dsh_ost || exit 0

# Does e2fsprogs support quota feature?
if [ $(facet_fstype $SINGLEMDS) == ldiskfs ] &&
	do_facet $SINGLEMDS "! $DEBUGFS -c -R supported_features |
		grep -q 'quota'"; then
	skip_env "e2fsprogs doesn't support quota" && exit 0
fi

if [ $(facet_fstype $SINGLEMDS) = "zfs" ]; then
# bug number for skipped test:        LU-2836 LU-6836 LU-2836
	ALWAYS_EXCEPT="$ALWAYS_EXCEPT 3       4a      6"
# bug number for skipped test:        LU-5638
	ALWAYS_EXCEPT="$ALWAYS_EXCEPT 11 33 34 35"
# bug number:     LU-2887
	#         21  9	  (min)"
	ZFS_SLOW="12a 9"
fi

[ "$SLOW" = "no" ] && EXCEPT_SLOW="$ZFS_SLOW"

QUOTALOG=${TESTSUITELOG:-$TMP/$(basename $0 .sh).log}

[ "$QUOTALOG" ] && rm -f $QUOTALOG || true

DIR=${DIR:-$MOUNT}
DIR2=${DIR2:-$MOUNT2}

QUOTA_AUTO_OLD=$QUOTA_AUTO
export QUOTA_AUTO=0

check_and_setup_lustre

is_project_quota_supported() {
	lsattr -dp > /dev/null 2>&1 || return 1

	[ "$(facet_fstype $SINGLEMDS)" == "ldiskfs" ] &&
		[ $(lustre_version_code $SINGLEMDS) -gt \
		$(version_code 2.9.55) ] &&
		egrep -q "7." /etc/redhat-release && return 0

	if [ "$(facet_fstype $SINGLEMDS)" == "zfs" ]; then
		[ $(lustre_version_code $SINGLEMDS) -le \
			$(version_code 2.10.53) ] && return 1

		$ZPOOL upgrade -v | grep project_quota && return 0
	fi

	return 1
}

SHOW_QUOTA_USER="$LFS quota -v -u $TSTUSR $DIR"
SHOW_QUOTA_USERID="$LFS quota -v -u $TSTID $DIR"
SHOW_QUOTA_GROUP="$LFS quota -v -g $TSTUSR $DIR"
SHOW_QUOTA_GROUPID="$LFS quota -v -g $TSTID $DIR"
SHOW_QUOTA_PROJID="eval is_project_quota_supported && $LFS quota -v -p $TSTPRJID $DIR"
SHOW_QUOTA_INFO_USER="$LFS quota -t -u $DIR"
SHOW_QUOTA_INFO_GROUP="$LFS quota -t -g $DIR"
SHOW_QUOTA_INFO_PROJID="eval is_project_quota_supported && $LFS quota -t -p $DIR"

build_test_filter

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
	echo "chattr $*"
	chattr $* || error "chattr $* failed"
}

RUNAS="runas -u $TSTID -g $TSTID"
RUNAS2="runas -u $TSTID2 -g $TSTID2"
DD="dd if=/dev/zero bs=1M"

FAIL_ON_ERROR=false

check_runas_id_ret $TSTUSR $TSTUSR $RUNAS ||
	error "Please create user $TSTUSR($TSTID) and group $TSTUSR($TSTID)"
check_runas_id_ret $TSTUSR2 $TSTUSR2 $RUNAS2 ||
	error "Please create user $TSTUSR2($TSTID2) and group $TSTUSR2($TSTID2)"

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
#		  bhardlimit|bsoftlimit|bgrace|ihardlimit|isoftlimit|igrace
getquota() {
	local spec
	local uuid

	sync_all_data > /dev/null 2>&1 || true

	[ "$#" != 4 ] && error "getquota: wrong number of arguments: $#"
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

	[ "$uuid" = "global" ] && uuid=$DIR

	$LFS quota -v "$1" "$2" $DIR |
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
	do_facet mgs $LCTL conf_param $FSNAME.quota.mdt=$qtype
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
	do_facet mgs $LCTL conf_param $FSNAME.quota.ost=$qtype
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

disable_project_quota() {
	is_project_quota_supported || return 0
	[ "$(facet_fstype $SINGLEMDS)" != "ldiskfs" ] && return 0
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
	trap 0
	echo "Delete files..."
	rm -rf $DIR/$tdir
	echo "Wait for unlink objects finished..."
	wait_delete_completed
	sync_all_data || true
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

enable_project_quota() {
	is_project_quota_supported || return 0
	[ "$(facet_fstype $SINGLEMDS)" != "ldiskfs" ] && return 0
	stopall || error "failed to stopall (1)"

	for num in $(seq $MDSCOUNT); do
		do_facet mds$num $TUNE2FS -O project $(mdsdevname $num) ||
			error "tune2fs $(mdsdevname $num) failed"
	done

	for num in $(seq $OSTCOUNT); do
		do_facet ost$num $TUNE2FS -O project $(ostdevname $num) ||
			error "tune2fs $(ostdevname $num) failed"
	done

	mount
	setupall
}
enable_project_quota

# enable quota debug
quota_init() {
	do_nodes $(comma_list $(nodes_list)) "lctl set_param debug=+quota"
}
quota_init

resetquota -u $TSTUSR
resetquota -g $TSTUSR
resetquota -u $TSTUSR2
resetquota -g $TSTUSR2
resetquota -p $TSTPRJID

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
	    if [ $(facet_fstype $SINGLEMDS) = "zfs" ]; then
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
	local MB=100 # 100M
	[ "$SLOW" = "no" ] && MB=10

	local free_space=$(lfs_df | grep "summary" | awk '{print $4}')
	[ $free_space -le $((MB * 1024)) ] &&
		skip "not enough space ${free_space} KB, " \
			"required $((MB * 1024)) KB" && return
	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

	set_ost_qtype "none" || error "disable ost quota failed"
	test_quota_performance $MB

	set_ost_qtype $QTYPE || error "enable ost quota failed"
	$LFS setquota -u $TSTUSR -b 0 -B 10G -i 0 -I 0 $DIR ||
		error "set quota failed"
	test_quota_performance $MB

	cleanup_quota_test
	resetquota -u $TSTUSR
}
run_test 0 "Test basic quota performance"

# test block hardlimit
test_1() {
	local LIMIT=10  # 10M
	local TESTFILE="$DIR/$tdir/$tfile-0"

	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

	# enable ost quota
	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# test for user
	log "User quota (block hardlimit:$LIMIT MB)"
	$LFS setquota -u $TSTUSR -b 0 -B ${LIMIT}M -i 0 -I 0 $DIR ||
		error "set user quota failed"

	# make sure the system is clean
	local USED=$(getquota -u $TSTUSR global curspace)
	[ $USED -ne 0 ] && error "Used space($USED) for user $TSTUSR isn't 0."

	$SETSTRIPE $TESTFILE -c 1 || error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	log "Write..."
	$RUNAS $DD of=$TESTFILE count=$((LIMIT/2)) ||
		quota_error u $TSTUSR "user write failure, but expect success"
	log "Write out of block quota ..."
	# this time maybe cache write,  ignore it's failure
	$RUNAS $DD of=$TESTFILE count=$((LIMIT/2)) seek=$((LIMIT/2)) || true
	# flush cache, ensure noquota flag is set on client
	cancel_lru_locks osc
	sync; sync_all_data || true
	$RUNAS $DD of=$TESTFILE count=1 seek=$LIMIT &&
		quota_error u $TSTUSR "user write success, but expect EDQUOT"

	rm -f $TESTFILE
	wait_delete_completed || error "wait_delete_completed failed"
	sync_all_data || true
	USED=$(getquota -u $TSTUSR global curspace)
	[ $USED -ne 0 ] && quota_error u $TSTUSR \
		"user quota isn't released after deletion"
	resetquota -u $TSTUSR

	# test for group
	log "--------------------------------------"
	log "Group quota (block hardlimit:$LIMIT MB)"
	$LFS setquota -g $TSTUSR -b 0 -B ${LIMIT}M -i 0 -I 0 $DIR ||
		error "set group quota failed"

	TESTFILE="$DIR/$tdir/$tfile-1"
	# make sure the system is clean
	USED=$(getquota -g $TSTUSR global curspace)
	[ $USED -ne 0 ] && error "Used space ($USED) for group $TSTUSR isn't 0"

	$SETSTRIPE $TESTFILE -c 1 || error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	log "Write ..."
	$RUNAS $DD of=$TESTFILE count=$((LIMIT/2)) ||
		quota_error g $TSTUSR "Group write failure, but expect success"
	log "Write out of block quota ..."
	# this time maybe cache write, ignore it's failure
	$RUNAS $DD of=$TESTFILE count=$((LIMIT/2)) seek=$((LIMIT/2)) || true
	cancel_lru_locks osc
	sync; sync_all_data || true
	$RUNAS $DD of=$TESTFILE count=10 seek=$LIMIT &&
		quota_error g $TSTUSR "Group write success, but expect EDQUOT"
	rm -f $TESTFILE
	wait_delete_completed || error "wait_delete_completed failed"
	sync_all_data || true
	USED=$(getquota -g $TSTUSR global curspace)
	[ $USED -ne 0 ] && quota_error g $TSTUSR \
				"Group quota isn't released after deletion"
	resetquota -g $TSTUSR

	if ! is_project_quota_supported; then
		echo "Project quota is not supported"
		cleanup_quota_test
		return 0
	fi

	TESTFILE="$DIR/$tdir/$tfile-2"
	# make sure the system is clean
	USED=$(getquota -p $TSTPRJID global curspace)
	[ $USED -ne 0 ] &&
		error "used space($USED) for project $TSTPRJID isn't 0"

	# test for Project
	log "--------------------------------------"
	log "Project quota (block hardlimit:$LIMIT mb)"
	$LFS setquota -p $TSTPRJID -b 0 -B ${LIMIT}M -i 0 -I 0 $DIR ||
		error "set project quota failed"

	$SETSTRIPE $TESTFILE -c 1 || error "setstripe $TESTFILE failed"
	chown $TSTUSR:$TSTUSR $TESTFILE || error "chown $TESTFILE failed"
	change_project -p $TSTPRJID $TESTFILE

	log "write ..."
	$RUNAS $DD of=$TESTFILE count=$((LIMIT/2)) || quota_error p $TSTPRJID \
		"project write failure, but expect success"
	log "write out of block quota ..."
	# this time maybe cache write, ignore it's failure
	$RUNAS $DD of=$TESTFILE count=$((LIMIT/2)) seek=$((LIMIT/2)) || true
	cancel_lru_locks osc
	sync; sync_all_data || true
	$RUNAS $DD of=$TESTFILE count=10 seek=$LIMIT && quota_error p \
		$TSTPRJID "project write success, but expect EDQUOT"

	# cleanup
	cleanup_quota_test

	USED=$(getquota -p $TSTPRJID global curspace)
	[ $USED -ne 0 ] && quota_error p $TSTPRJID \
		"project quota isn't released after deletion"

	resetquota -p $TSTPRJID
}
run_test 1 "Block hard limit (normal use and out of quota)"

# test inode hardlimit
test_2() {
	local LIMIT=$((1024 * 1024)) # 1M inodes
	local TESTFILE="$DIR/$tdir/$tfile-0"

	[ "$SLOW" = "no" ] && LIMIT=1024 # 1k inodes

	local FREE_INODES=$(mdt_free_inodes 0)
	echo "$FREE_INODES free inodes on master MDT"
	[ $FREE_INODES -lt $LIMIT ] &&
		skip "not enough free inodes $FREE_INODES required $LIMIT" &&
		return

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

	change_project +P $DIR/$tdir/
	change_project -p $TSTPRJID -d $DIR/$tdir
	log "Create $LIMIT files ..."
	$RUNAS createmany -m ${TESTFILE} $((LIMIT-1)) || quota_error p \
		$TSTPRJID "project create fail, but expect success"
	log "Create out of file quota ..."
	$RUNAS touch ${TESTFILE}_xxx && quota_error p $TSTPRJID \
		"project create success, but expect EDQUOT"
	change_project -P $DIR/$tdir
	change_project -p 0 -d $DIR/$tdir

	cleanup_quota_test
	USED=$(getquota -p $TSTPRJID global curinodes)
	[ $USED -ne 0 ] && quota_error p $TSTPRJID \
		"project quota isn't released after deletion"

	resetquota -p $TSTPRJID

}
run_test 2 "File hard limit (normal use and out of quota)"

test_block_soft() {
	local TESTFILE=$1
	local TIMER=$(($2 * 3 / 2))
	local LIMIT=$3
	local OFFSET=0
	local qtype=$4

	setup_quota_test
	trap cleanup_quota_test EXIT

	$SETSTRIPE $TESTFILE -c 1 -i 0
	chown $TSTUSR.$TSTUSR $TESTFILE
	[ "$qtype" == "p" ] && is_project_quota_supported &&
		change_project -p $TSTPRJID $TESTFILE

	echo "Write up to soft limit"
	$RUNAS $DD of=$TESTFILE count=$LIMIT ||
		quota_error a $TSTUSR "write failure, but expect success"
	OFFSET=$((LIMIT * 1024))
	cancel_lru_locks osc

	echo "Write to exceed soft limit"
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=1K count=10 seek=$OFFSET ||
		quota_error a $TSTUSR "write failure, but expect success"
	OFFSET=$((OFFSET + 1024)) # make sure we don't write to same block
	cancel_lru_locks osc

	$SHOW_QUOTA_USER
	$SHOW_QUOTA_GROUP
	$SHOW_QUOTA_PROJID
	$SHOW_QUOTA_INFO_USER
	$SHOW_QUOTA_INFO_GROUP
	$SHOW_QUOTA_INFO_PROJID

	echo "Write before timer goes off"
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=1K count=10 seek=$OFFSET ||
		quota_error a $TSTUSR "write failure, but expect success"
	OFFSET=$((OFFSET + 1024))
	cancel_lru_locks osc

	echo "Sleep $TIMER seconds ..."
	sleep $TIMER

	$SHOW_QUOTA_USER
	$SHOW_QUOTA_GROUP
	$SHOW_QUOTA_PROJID
	$SHOW_QUOTA_INFO_USER
	$SHOW_QUOTA_INFO_GROUP
	$SHOW_QUOTA_INFO_PROJID

	echo "Write after timer goes off"
	# maybe cache write, ignore.
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=1K count=10 seek=$OFFSET || true
	OFFSET=$((OFFSET + 1024))
	cancel_lru_locks osc
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=1K count=10 seek=$OFFSET &&
		quota_error a $TSTUSR "write success, but expect EDQUOT"

	$SHOW_QUOTA_USER
	$SHOW_QUOTA_GROUP
	$SHOW_QUOTA_PROJID
	$SHOW_QUOTA_INFO_USER
	$SHOW_QUOTA_INFO_GROUP
	$SHOW_QUOTA_INFO_PROJID

	echo "Unlink file to stop timer"
	rm -f $TESTFILE
	wait_delete_completed
	sync_all_data || true

	$SHOW_QUOTA_USER
	$SHOW_QUOTA_GROUP
	$SHOW_QUOTA_PROJID
	$SHOW_QUOTA_INFO_USER
	$SHOW_QUOTA_INFO_GROUP
	$SHOW_QUOTA_INFO_PROJID

	$SETSTRIPE $TESTFILE -c 1 -i 0
	chown $TSTUSR.$TSTUSR $TESTFILE
	[ "$qtype" == "p" ] && change_project -p $TSTPRJID $TESTFILE

	echo "Write ..."
	$RUNAS $DD of=$TESTFILE count=$LIMIT ||
		quota_error a $TSTUSR "write failure, but expect success"
	# cleanup
	cleanup_quota_test
}

# block soft limit
test_3() {
	local LIMIT=1  # 1MB
	local GRACE=20 # 20s
	local TESTFILE=$DIR/$tdir/$tfile-0

	set_ost_qtype $QTYPE || error "enable ost quota failed"

	echo "User quota (soft limit:$LIMIT MB  grace:$GRACE seconds)"
	# make sure the system is clean
	local USED=$(getquota -u $TSTUSR global curspace)
	[ $USED -ne 0 ] && error "Used space($USED) for user $TSTUSR isn't 0."

	$LFS setquota -t -u --block-grace $GRACE --inode-grace \
		$MAX_IQ_TIME $DIR || error "set user grace time failed"
	$LFS setquota -u $TSTUSR -b ${LIMIT}M -B 0 -i 0 -I 0 $DIR ||
		error "set user quota failed"

	test_block_soft $TESTFILE $GRACE $LIMIT "u"
	resetquota -u $TSTUSR

	echo "Group quota (soft limit:$LIMIT MB  grace:$GRACE seconds)"
	TESTFILE=$DIR/$tdir/$tfile-1
	# make sure the system is clean
	USED=$(getquota -g $TSTUSR global curspace)
	[ $USED -ne 0 ] && error "Used space($USED) for group $TSTUSR isn't 0."

	$LFS setquota -t -g --block-grace $GRACE --inode-grace \
		$MAX_IQ_TIME $DIR || error "set group grace time failed"
	$LFS setquota -g $TSTUSR -b ${LIMIT}M -B 0 -i 0 -I 0 $DIR ||
		error "set group quota failed"

	test_block_soft $TESTFILE $GRACE $LIMIT "g"
	resetquota -g $TSTUSR

	if is_project_quota_supported; then
		echo "Project quota (soft limit:$LIMIT MB  grace:$GRACE sec)"
		TESTFILE=$DIR/$tdir/$tfile-2
		# make sure the system is clean
		USED=$(getquota -p $TSTPRJID global curspace)
		[ $USED -ne 0 ] && error \
			"Used space($USED) for project $TSTPROJID isn't 0."

		$LFS setquota -t -p --block-grace $GRACE --inode-grace \
			$MAX_IQ_TIME $DIR ||
				error "set project grace time failed"
		$LFS setquota -p $TSTPRJID -b ${LIMIT}M -B 0 -i 0 -I 0 \
			$DIR || error "set project quota failed"

		test_block_soft $TESTFILE $GRACE $LIMIT "p"
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
run_test 3 "Block soft limit (start timer, timer goes off, stop timer)"

test_file_soft() {
	local TESTFILE=$1
	local LIMIT=$2
	local grace=$3
	local TIMER=$(($grace * 3 / 2))

	setup_quota_test
	trap cleanup_quota_test EXIT
	is_project_quota_supported && change_project +P $DIR/$tdir/ &&
		change_project -p $TSTPRJID -d $DIR/$tdir

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

	echo "Sleep $TIMER seconds ..."
	sleep $TIMER

	$SHOW_QUOTA_USER
	$SHOW_QUOTA_GROUP
	$SHOW_QUOTA_PROJID
	$SHOW_QUOTA_INFO_USER
	$SHOW_QUOTA_INFO_GROUP
	$SHOW_QUOTA_INFO_PROJID

	echo "Create file after timer goes off"
	# There is a window that space is accounted in the quota usage but
	# hasn't been decreased from the pending write, if we acquire quota
	# in this window, we'll acquire more than we needed.
	$RUNAS touch ${TESTFILE}_after_1 ${TESTFILE}_after_2 || true
	sync_all_data || true
	$RUNAS touch ${TESTFILE}_after_3 &&
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
	local LIMIT=10 # inodes
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

	test_file_soft $TESTFILE $LIMIT $GRACE
	resetquota -u $TSTUSR

	echo "Group quota (soft limit:$LIMIT files  grace:$GRACE seconds)"
	# make sure the system is clean
	USED=$(getquota -g $TSTUSR global curinodes)
	[ $USED -ne 0 ] && error "Used space($USED) for group $TSTUSR isn't 0."

	$LFS setquota -t -g --block-grace $MAX_DQ_TIME --inode-grace \
		$GRACE $DIR || error "set group grace time failed"
	$LFS setquota -g $TSTUSR -b 0 -B 0 -i $LIMIT -I 0 $DIR ||
		error "set group quota failed"
	TESTFILE=$DIR/$tdir/$tfile-1

	test_file_soft $TESTFILE $LIMIT $GRACE
	resetquota -g $TSTUSR

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
		test_file_soft $TESTFILE $((LIMIT-1)) $GRACE
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
	local BLIMIT=10 # 10M
	local ILIMIT=10 # 10 inodes

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

	resetquota -u $TSTUSR
	resetquota -g $TSTUSR
	resetquota -p $TSTPRJID
}
run_test 5 "Chown & chgrp successfully even out of block/file quota"

# test dropping acquire request on master
test_6() {
	local LIMIT=3 # 3M

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
	$SETSTRIPE $TESTFILE -c 1 -i 0 || error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	# create file for $TSTUSR2
	local TESTFILE2=$DIR/$tdir/$tfile-$TSTUSR2
	$SETSTRIPE $TESTFILE2 -c 1 -i 0 || error "setstripe $TESTFILE2 failed"
	chown $TSTUSR2.$TSTUSR2 $TESTFILE2 || error "chown $TESTFILE2 failed"

	# cache per-ID lock for $TSTUSR on slave
	$LFS setquota -u $TSTUSR -b 0 -B ${LIMIT}M -i 0 -I 0 $DIR ||
		error "set quota failed"
	$RUNAS $DD of=$TESTFILE count=1 ||
		error "write $TESTFILE failure, expect success"
	$RUNAS2 $DD of=$TESTFILE2 count=1 ||
		error "write $TESTFILE2 failure, expect success"
	sync; sync
	sync_all_data || true

	#define QUOTA_DQACQ 601
	#define OBD_FAIL_PTLRPC_DROP_REQ_OPC 0x513
	lustre_fail mds 0x513 601

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

	# write should be blocked and never finished
	if ! ps -p $DDPID  > /dev/null 2>&1; then
		lustre_fail mds 0 0
		error "write finished incorrectly!"
	fi

	lustre_fail mds 0 0

	# no watchdog is triggered
	do_facet ost1 dmesg > $TMP/lustre-log-${TESTNAME}.log
	watchdog=$(awk '/Service thread pid/ && /was inactive/ \
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
	resetquota -u $TSTUSR
}
run_test 6 "Test dropping acquire request on master"

# quota reintegration (global index)
test_7a() {
	local TESTFILE=$DIR/$tdir/$tfile
	local LIMIT=20 # 20M

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
	$SETSTRIPE $TESTFILE -c 1 -i 0 || error "setstripe $TESTFILE failed"
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
	resetquota -u $TSTUSR
}
run_test 7a "Quota reintegration (global index)"

# quota reintegration (slave index)
test_7b() {
	local LIMIT="100G"
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
	$SETSTRIPE $TESTFILE -c 1 -i 0 || error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	# consume some space to make sure the granted space will not
	# be released during reconciliation
	$RUNAS $DD of=$TESTFILE count=1 oflag=sync ||
		error "consume space failure, expect success"

	# define OBD_FAIL_QUOTA_EDQUOT 0xa02
	lustre_fail mds 0xa02

	set_ost_qtype $QTYPE || error "enable ost quota failed"
	$LFS setquota -u $TSTUSR -b 0 -B $LIMIT -i 0 -I 0 $DIR ||
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
	resetquota -u $TSTUSR
	$SHOW_QUOTA_USER
}
run_test 7b "Quota reintegration (slave index)"

# quota reintegration (restart mds during reintegration)
test_7c() {
	local LIMIT=20 # 20M
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
	local procf="osd-$(facet_fstype ost1).$FSNAME-OST*."
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
	resetquota -u $TSTUSR
}
run_test 7c "Quota reintegration (restart mds during reintegration)"

# Quota reintegration (Transfer index in multiple bulks)
test_7d(){
	local TESTFILE=$DIR/$tdir/$tfile
	local TESTFILE1="$DIR/$tdir/$tfile"-1
	local limit=20 #20M

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
	resetquota -u $TSTUSR
	resetquota -u $TSTUSR2
}
run_test 7d "Quota reintegration (Transfer index in multiple bulks)"

# quota reintegration (inode limits)
test_7e() {
	[ "$MDSCOUNT" -lt "2" ] && skip "needs >= 2 MDTs" && return

	# LU-2435: skip this quota test if underlying zfs version has not
	# supported native dnode accounting
	[ "$(facet_fstype mds1)" == "zfs" ] && {
		local F="feature@userobj_accounting"
		local pool=$(zpool_name mds1)
		local feature=$(do_facet mds1 $ZPOOL get -H $F $pool)

		[[ "$feature" != *" active "* ]] &&
			skip "requires zpool with active userobj_accounting" &&
			return
	}

	local ilimit=$((1024 * 2)) # 2k inodes
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
		quota_error -u $TSTUSR "create failed, expect success"

	$RUNAS unlinkmany $TESTFILE $((ilimit + 1)) || error "unlink failed"
	rmdir $DIR/${tdir}-1 || error "unlink remote dir failed"

	cleanup_quota_test
	resetquota -u $TSTUSR
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
		change_project +P $DIR/$tdir && change_project -p \
			$TSTPRJID -d $DIR/$tdir
		echo "Set enough high limit for project: $TSTPRJID"
		$LFS setquota -p $TSTPRJID -b 0 \
			-B $BLK_LIMIT -i 0 -I $FILE_LIMIT $DIR ||
			error "set project quota failed"
	fi

	local duration=""
	[ "$SLOW" = "no" ] && duration=" -t 120"
	$RUNAS bash rundbench -D $DIR/$tdir 3 $duration ||
		quota_error a $TSTUSR "dbench failed!"

	is_project_quota_supported && change_project -P $DIR/$tdir &&
	change_project -dp 0 $DIR/$tdir
	cleanup_quota_test
	resetquota -u $TSTUSR
	resetquota -g $TSTUSR
	resetquota -p $TSTPRJID
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
	$SETSTRIPE $TESTFILE -c 1 -i 0 || error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	log "Write the big file of 4.5G ..."
	$RUNAS $DD of=$TESTFILE count=$filesize ||
		quota_error a $TSTUSR "write 4.5G file failure, expect success"

	$SHOW_QUOTA_USER
	$SHOW_QUOTA_GROUP

	cleanup_quota_test
	resetquota -u $TSTUSR
	resetquota -g $TSTUSR

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

	$SETSTRIPE $TESTFILE -c 1 || error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	runas -u 0 -g 0 $DD of=$TESTFILE count=3 oflag=sync ||
		error "write failure, expect success"

	cleanup_quota_test
	resetquota -u $TSTUSR
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
	resetquota -u $TSTUSR
}
run_test 11 "Chown/chgrp ignores quota"

test_12a() {
	[ "$OSTCOUNT" -lt "2" ] && skip "needs >= 2 OSTs" && return

	local blimit=22 # 22M
	local blk_cnt=$((blimit - 5))
	local TESTFILE0="$DIR/$tdir/$tfile"-0
	local TESTFILE1="$DIR/$tdir/$tfile"-1

	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

	set_ost_qtype "u" || error "enable ost quota failed"
	quota_show_check b u $TSTUSR

	$LFS setquota -u $TSTUSR -b 0 -B "$blimit"M -i 0 -I 0 $DIR ||
		error "set quota failed"

	$SETSTRIPE $TESTFILE0 -c 1 -i 0 || error "setstripe $TESTFILE0 failed"
	$SETSTRIPE $TESTFILE1 -c 1 -i 1 || error "setstripe $TESTFILE1 failed"
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
	resetquota -u $TSTUSR
}
run_test 12a "Block quota rebalancing"

test_12b() {
	[ "$MDSCOUNT" -lt "2" ] && skip "needs >= 2 MDTs" && return

	local ilimit=$((1024 * 2)) # 2k inodes
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
	resetquota -u $TSTUSR
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
	$SETSTRIPE $TESTFILE -c 1 -i 0 || error "setstripe $TESTFILE failed"
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
	resetquota -u $TSTUSR
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
	local blimit="200m" # 200M
	local TESTFILE="$DIR/$tdir/$tfile"

	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

	set_ost_qtype "u" || error "enable ost quota failed"
	log "User quota (limit: $blimit)"
	$LFS setquota -u $TSTUSR -b 0 -B $blimit -i 0 -I 0 $MOUNT ||
		error "set quota failed"
	quota_show_check b u $TSTUSR

	$SETSTRIPE $TESTFILE -i 0 -c 1 || error "setstripe $TESTFILE failed"
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
	resetquota -u $TSTUSR
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
	local watchdog=$(awk '/Service thread pid/ && /was inactive/ \
			{ print; }' $TMP/lustre-log-${TESTNAME}.log)
	[ -z "$watchdog" ] || error "$watchdog"
	rm -f $TMP/lustre-log-${TESTNAME}.log
}
run_test 18 "MDS failover while writing, no watchdog triggered (b14840)"

test_19() {
	local blimit=5 # 5M
	local TESTFILE=$DIR/$tdir/$tfile

	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# bind file to a single OST
	$SETSTRIPE -c 1 $TESTFILE || error "setstripe $TESTFILE failed"
	chown $TSTUSR.$TSTUSR $TESTFILE || error "chown $TESTFILE failed"

	echo "Set user quota (limit: ${blimit}M)"
	$LFS setquota -u $TSTUSR -b 0 -B "$blimit"M -i 0 -I 0 $MOUNT ||
		error "set user quota failed"
	quota_show_check b u $TSTUSR
	echo "Update quota limits"
	$LFS setquota -u $TSTUSR -b 0 -B "$blimit"M -i 0 -I 0 $MOUNT ||
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
	resetquota -u $TSTUSR
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
	resetquota -u $TSTUSR
	resetquota -g $TSTUSR
	resetquota -p $TSTPRJID
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
	[ $qtype1 != $qtype] && error "mdt quota setting is lost"
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
run_test 22 "enable/disable quota by 'lctl conf_param'"

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

	$SETSTRIPE $TESTFILE -c 1 -i 0 || error "setstripe $TESTFILE failed"
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
	resetquota -u $TSTUSR
}

test_23() {
	[ $(facet_fstype ost1) == "zfs" ] &&
		skip "Overwrite in place is not guaranteed to be " \
		"space neutral on ZFS" && return

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
	local blimit=5 # 5M
	local TESTFILE="$DIR/$tdir/$tfile"

	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

	set_ost_qtype $QTYPE || error "enable ost quota failed"

	# bind file to a single OST
	$SETSTRIPE -c 1 $TESTFILE || error "setstripe $TESTFILE failed"
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
	resetquota -u $TSTUSR
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
	resetquota -u $TSTUSR
	resetquota -g $TSTUSR
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
	local LIMIT=4 # 4MB
	local TESTFILE="$DIR/$tdir/$tfile"
	local GRACE=10

	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

	set_ost_qtype "u" || error "enable ost quota failed"

	$SETSTRIPE $TESTFILE -i 0 -c 1 || error "setstripe $TESTFILE failed"
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
	resetquota -u $TSTUSR
	$LFS setquota -t -u --block-grace $MAX_DQ_TIME --inode-grace \
		$MAX_IQ_TIME $DIR || error "restore grace time failed"
}
run_test 30 "Hard limit updates should not reset grace times"

# basic usage tracking for user & group
test_33() {
	local INODES=10 # 10 files
	local BLK_CNT=2 # of 2M each
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
	local BLK_CNT=2 # 2MB
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
	local BLK_CNT=2 # 2 MB

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
	local ORIG_REFORMAT=$REFORMAT
	REFORMAT=""
	cleanup_and_setup_lustre
	REFORMAT=$ORIG_REFORMAT
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
	[ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.6.93) ] &&
		skip "Old server doesn't have LU-5006 fix." && return

	setup_quota_test || error "setup quota failed with $?"
	trap cleanup_quota_test EXIT

	# make sure the system is clean
	local USED=$(getquota -u $TSTID global curspace)
	[ $USED -ne 0 ] &&
		error "Used space ($USED) for user $TSTID isn't 0."

	# create file with MDS_OPEN_DELAY_CREATE flag
	$SETSTRIPE -c 1 -i 0 $DIR/$tdir/$tfile ||
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
	[ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.8.60) ] &&
		skip "Old server doesn't have LU-8801 fix." && return

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

	local procf="osd-$(facet_fstype $SINGLEMDS).$FSNAME-MDT0000"
	procf=${procf}.quota_slave.acct_user
	local accnt_cnt

	acct_cnt=$(do_facet mds1 $LCTL get_param $procf | grep "id:" | wc -l)
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
		skip "Project quota is not supported" && return 0

	setup_quota_test || error "setup quota failed with $?"

	touch $TESTFILE
	projectid=$(lsattr -p $TESTFILE | awk '{print $1}')
	[ $projectid -ne 0 ] &&
		error "Project id should be 0 not $projectid"
	change_project -p 1024 $TESTFILE
	projectid=$(lsattr -p $TESTFILE | awk '{print $1}')
	[ $projectid -ne 1024 ] &&
		error "Project id should be 1024 not $projectid"

	stopall || error "failed to stopall (1)"
	mount
	setupall
	projectid=$(lsattr -p $TESTFILE | awk '{print $1}')
	[ $projectid -ne 1024 ] &&
		error "Project id should be 1024 not $projectid"

	cleanup_quota_test
}
run_test 39 "Project ID interface works correctly"

test_40a() {
	! is_project_quota_supported &&
		skip "Project quota is not supported" && return 0
	local dir1="$DIR/$tdir/dir1"
	local dir2="$DIR/$tdir/dir2"

	setup_quota_test || error "setup quota failed with $?"

	mkdir -p $dir1 $dir2
	change_project +P $dir1 && change_project -p 1 -d $dir1 && touch $dir1/1
	change_project +P $dir2 && change_project -p 2 -d $dir2

	ln $dir1/1 $dir2/1_link &&
		error "Hard link across different project quota should fail"
	rm -rf $dir1 $dir2

	cleanup_quota_test
}
run_test 40a "Hard link across different project ID"

test_40b() {
	! is_project_quota_supported &&
		skip "Project quota is not supported" && return 0
	local dir1="$DIR/$tdir/dir1"
	local dir2="$DIR/$tdir/dir2"

	setup_quota_test || error "setup quota failed with $?"
	mkdir -p $dir1 $dir2
	change_project +P $dir1 && change_project -p 1 -d $dir1 && touch $dir1/1
	change_project +P $dir2 && change_project -p 2 -d $dir2

	mv $dir1/1 $dir2/2 || error "mv failed $?"
	local projid=$(lsattr -p $dir2/2 | awk '{print $1}')
	if [ "$projid" != "2" ]; then
		error "project id expected 2 not $projid"
	fi
	rm -rf $dir1 $dir2
	cleanup_quota_test
}
run_test 40b "Mv across different project ID"

test_40c() {
	[ "$MDSCOUNT" -lt "2" ] && skip "needs >= 2 MDTs" && return
		! is_project_quota_supported &&
			skip "Project quota is not supported" && return 0

	setup_quota_test || error "setup quota failed with $?"
	local dir="$DIR/$tdir/dir"

	mkdir -p $dir && change_project +P $dir && change_project -dp 1 $dir
	$LFS mkdir -i 1 $dir/remote_dir || error "create remote dir failed"
	local projid=$(lsattr -dp $dir/remote_dir | awk '{print $1}')
	[ "$projid" != "1" ] && error "projid id expected 1 not $projid"
	touch $dir/remote_dir/file
	#verify inherit works file for remote dir.
	local projid=$(lsattr -dp $dir/remote_dir/file | awk '{print $1}')
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

test_50() {
	! is_project_quota_supported &&
		skip "Project quota is not supported" && return 0

	setup_quota_test || error "setup quota failed with $?"
	local dir="$DIR/$tdir/dir"

	mkdir $dir && change_project -dp 1 $dir
	count=$($LFS find --projid 1 $DIR | wc -l)
	[ "$count" != 1 ] && error "expected 1 but got $count"

	rm -rf $dir
	cleanup_quota_test
}
run_test 50 "Test if lfs find --projid works"

test_51() {
	! is_project_quota_supported &&
		skip "Project quota is not supported" && return 0
	setup_quota_test || error "setup quota failed with $?"
	local dir="$DIR/$tdir/dir"

	mkdir $dir && change_project -dp 1 $dir && change_project +P $dir
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
		skip "Project quota is not supported" && return 0
	setup_quota_test || error "setup quota failed with $?"
	local dir="$DIR/$tdir/dir"
	mkdir $dir && change_project -dp 1 $dir && change_project +P $dir

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
		skip "Project quota is not supported" && return 0
	setup_quota_test || error "setup quota failed with $?"
	local dir="$DIR/$tdir/dir"
	mkdir $dir && change_project +P $dir
	lsattr -pd $dir | grep P || error "inherit attribute should be set"

	change_project -Pd $dir
	lsattr -pd $dir | grep P && error "inherit attribute should be cleared"

	rm -rf $dir
	cleanup_quota_test
}
run_test 53 "Project inherit attribute could be cleared"

quota_fini()
{
	do_nodes $(comma_list $(nodes_list)) "lctl set_param debug=-quota"
	disable_project_quota
}
quota_fini

cd $ORIG_PWD
complete $SECONDS
check_and_cleanup_lustre
export QUOTA_AUTO=$QUOTA_AUTO_OLD
exit_status
