#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# exit on error
set -e
set +o monitor

ONLY=${ONLY:-"$*"}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
init_logging

ALWAYS_EXCEPT="$SANITY_HSM_EXCEPT "
if $SHARED_KEY; then
# bug number for skipped tests: LU-9795
	ALWAYS_EXCEPT+="	402b "
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!
fi

# Skip tests for PPC that fail frequently
if [[ $(uname -m) = ppc64 ]]; then
	# bug number:    LU-12251 LU-12251 LU-12251 LU-12251 LU-12251 LU-12251
	ALWAYS_EXCEPT+=" 1a       1b       1d       1e       12c      12f "
	# bug number:    LU-12251 LU-12251 LU-12251 LU-12251 LU-12251 LU-12251
	ALWAYS_EXCEPT+=" 12g      12h      12m      12n      12o      12p "
	# bug number:    LU-12251 LU-12251 LU-12251 LU-12251 LU-12251 LU-12251
	ALWAYS_EXCEPT+=" 12q      21       22       23       24a      24b "
	# bug number:    LU-12251 LU-12251 LU-12251 LU-12251 LU-12251 LU-12251
	ALWAYS_EXCEPT+=" 24d      24e      24f      25b      30c      37 "
	# bug number:    LU-12251 LU-12251 LU-12251 LU-12251 LU-12251 LU-12251
	ALWAYS_EXCEPT+=" 57       58       90       110b     111b     113 "
	# bug number:    LU-12251 LU-12251 LU-12251 LU-12251 LU-12251 LU-12251
	ALWAYS_EXCEPT+=" 222b     222d     228      260a     260b     260c "
	# bug number:    LU-12252 LU-12252 LU-12252 LU-12252 LU-12252 LU-12252
	ALWAYS_EXCEPT+=" 220A     220a     221      222a     222c     223a "
	# bug number:    LU-12252 LU-12252 LU-12252 LU-12252 LU-12252 LU-12252
	ALWAYS_EXCEPT+=" 223b     224A     224a     226      227      600"
	# bug number:    LU-12252 LU-12252 LU-12252 LU-12252 LU-12252 LU-12252
	ALWAYS_EXCEPT+=" 601      602      603      604      605 "
fi

build_test_filter

[ -n "$FILESET" ] && skip "Not functional for FILESET set"

OPENFILE=${OPENFILE:-openfile}
MOUNT_2=${MOUNT_2:-"yes"}
FAIL_ON_ERROR=false

# script only handles up to 10 MDTs (because of MDT_PREFIX)
[ $MDSCOUNT -gt 9 ] &&
	error "script cannot handle more than 9 MDTs, please fix"

check_and_setup_lustre

if [[ $MDS1_VERSION -lt $(version_code 2.4.53) ]]; then
	skip_env "Need MDS version at least 2.4.53"
fi

# $RUNAS_ID may get set incorrectly somewhere else
if [[ $UID -eq 0 && $RUNAS_ID -eq 0 ]]; then
	skip_env "\$RUNAS_ID set to 0, but \$UID is also 0!"
fi
check_runas_id $RUNAS_ID $RUNAS_GID $RUNAS
if getent group nobody; then
	GROUP=nobody
elif getent group nogroup; then
	GROUP=nogroup
else
	error "No generic nobody group"
fi

# if there is no CLIENT1 defined, some tests can be ran on localhost
CLIENT1=${CLIENT1:-$HOSTNAME}
# if CLIENT2 doesn't exist then use CLIENT1 instead
# All tests should use CLIENT2 with MOUNT2 only therefore it will work if
# $CLIENT2 == CLIENT1
# Exception is the test which need two separate nodes
CLIENT2=${CLIENT2:-$CLIENT1}

search_copytools() {
	local hosts=${1:-$(facet_active_host $SINGLEAGT)}
	do_nodesv $hosts "pgrep --pidfile=$HSMTOOL_PID_FILE hsmtool"
}

wait_copytools() {
	local hosts=${1:-$(facet_active_host $SINGLEAGT)}
	local wait_timeout=200
	local wait_start=$SECONDS
	local wait_end=$((wait_start + wait_timeout))
	local sleep_time=1

	while ((SECONDS < wait_end)); do
		if ! search_copytools $hosts; then
			echo "copytools stopped in $((SECONDS - wait_start))s"
			return 0
		fi

		echo "copytools still running on $hosts"
		sleep $sleep_time
		[ $sleep_time -lt 5 ] && sleep_time=$((sleep_time + 1))
	done

	# try to dump Copytool's stack
	do_nodesv $hosts "echo 1 >/proc/sys/kernel/sysrq ; " \
			 "echo t >/proc/sysrq-trigger"

	echo "copytools failed to stop in ${wait_timeout}s"

	return 1
}

copytool_monitor_setup() {
	local facet=${1:-$SINGLEAGT}
	local agent=$(facet_active_host $facet)

	local cmd="mktemp --tmpdir=/tmp -d ${TESTSUITE}.${TESTNAME}.XXXX"
	local test_dir=$(do_node $agent "$cmd") ||
		error "Failed to create tempdir on $agent"
	export HSMTOOL_MONITOR_DIR=$test_dir

	# Create the fifo and a monitor (cat dies when copytool dies)
	do_node $agent "mkfifo -m 0644 $test_dir/fifo" ||
		error "failed to create copytool fifo on $agent"
	cmd="cat $test_dir/fifo > $test_dir/events &"
	cmd+=" echo \\\$! > $test_dir/monitor_pid"

	# This background subshell nonsense is required when pdsh/ssh decides
	# to wait for the cat process to exit on the remote client
	(do_node $agent "$cmd") &
	export HSMTOOL_MONITOR_PDSH=$!

	# Slightly racy, but just making a best-effort to catch obvious
	# problems.
	sleep 1
	do_node $agent "stat $HSMTOOL_MONITOR_DIR/monitor_pid 2>&1 > /dev/null"
	if [ $? != 0 ]; then
		error "Failed to start copytool monitor on $agent"
	fi
}

fid2archive()
{
	local fid="$1"

	case "$HSMTOOL_ARCHIVE_FORMAT" in
		v1)
			printf "%s" "$(hsm_root)/*/*/*/*/*/*/$fid"
			;;
		v2)
			printf "%s" "$(hsm_root)/*/$fid"
			;;
	esac
}

get_copytool_event_log() {
	local facet=${1:-$SINGLEAGT}
	local agent=$(facet_active_host $facet)

	[ -z "$HSMTOOL_MONITOR_DIR" ] &&
		error "Can't get event log: No monitor directory!"

	do_node $agent "cat $HSMTOOL_MONITOR_DIR/events" ||
		error "Could not collect event log from $agent"
}

copytool_suspend() {
	local agents=${1:-$(facet_active_host $SINGLEAGT)}

	stack_trap "pkill_copytools $agents CONT || true" EXIT
	pkill_copytools $agents STOP || return 0
	echo "Copytool is suspended on $agents"
}

copytool_remove_backend() {
	local fid=$1
	local be=$(do_facet $SINGLEAGT find "$(hsm_root)" -name $fid)
	echo "Remove from backend: $fid = $be"
	do_facet $SINGLEAGT rm -f $be
}

file_creation_failure() {
	local cmd=$1
	local file=$2
	local err=$3

	case $err in
	28)
		df $MOUNT $MOUNT2 >&2
		error "Not enough space to create $file with $cmd"
		;;
	*)
		error "cannot create $file with $cmd, status=$err"
		;;
	esac
}

# Creates a file using dd
create_file() {
	local file=$1
	local bs=$2
	local count=$3
	local conv=$4
	local source=${5:-/dev/zero}
	local args=""
	local err

	if [ -n "$conv" ]; then
		args+=" conv=$conv"
	fi

	# Create the directory in case it does not exist
	mkdir -p "$(dirname "$file")"
	# Delete the file in case it already exist
	rm -f "$file"

	if dd if="$source" of="$file" count="$count" bs="$bs" $args; then
		path2fid "$file" || error "cannot get FID of '$file'"
	else
		err=$?
		echo "cannot create file '$file'" >&2;
		# Let the caller decide what to do on error
		return $err;
	fi
}

create_empty_file() {
	create_file "${1/$DIR/$DIR2}" 1M 0 ||
		file_creation_failure dd "${1/$DIR/$DIR2}" $?
}

create_small_file() {
	local source_file=/dev/urandom
	local count=1
	local bs=1M
	local conv=${2:-fsync}

	create_file "${1/$DIR/$DIR2}" $bs $count $conv $source_file ||
		file_creation_failure dd "${1/$DIR/$DIR2}" $?
}

create_small_sync_file() {
	create_small_file "$1" sync
}

create_archive_file() {
	local file="$(hsm_root)/$1"
	local count=${2:-39}
	local source=/dev/urandom

	# Create the counterpart directory of the archive
	do_facet "$SINGLEAGT" mkdir -p "$(dirname "$file")" ||
		error "cannot create archive directory '$(dirname "$file")'"

	do_facet "$SINGLEAGT" dd if=$source of="$file" bs=1M count=$count ||
		error "cannot create archive file '$file'"
}

copy2archive() {
	local hsm_root="$(hsm_root)"
	local file="$hsm_root/$2"

	stack_trap "do_facet $SINGLEAGT rm -rf '$hsm_root'" EXIT
	do_facet $SINGLEAGT mkdir -p "$(dirname "$file")" ||
	    error "mkdir '$(dirname "$file")' failed"
	do_facet $SINGLEAGT cp -p "$1" "$file" ||
		error "cannot copy '$1' to '$file'"
}

get_hsm_param() {
	local param=$1
	local val=$(do_facet $SINGLEMDS $LCTL get_param -n $HSM_PARAM.$param)
	echo $val
}

set_test_state() {
	local cmd=$1
	local target=$2
	mdts_set_param "" hsm_control "$cmd"
	mdts_check_param hsm_control "$target" 10
}


cdt_set_no_retry() {
	mdts_set_param "" hsm.policy "+NRA"
	CDT_POLICY_HAD_CHANGED=true
}

cdt_clear_no_retry() {
	mdts_set_param "" hsm.policy "-NRA"
	CDT_POLICY_HAD_CHANGED=true
}

cdt_set_non_blocking_restore() {
	mdts_set_param "" hsm.policy "+NBR"
	CDT_POLICY_HAD_CHANGED=true
}

cdt_clear_non_blocking_restore() {
	mdts_set_param "" hsm.policy "-NBR"
	CDT_POLICY_HAD_CHANGED=true
}

cdt_clear_mount_state() {
	mdts_set_param "-P -d" hsm_control ""
}

cdt_disable() {
	set_test_state disabled disabled
}

cdt_enable() {
	set_test_state enabled enabled
}

cdt_shutdown() {
	set_test_state shutdown stopped
}

cdt_purge() {
	set_test_state purge enabled
}

cdt_restart() {
	cdt_shutdown
	cdt_enable
	cdt_set_sanity_policy
}


get_hsm_archive_id() {
	local f=$1
	local st
	st=$($LFS hsm_state $f)
	[[ $? == 0 ]] || error "$LFS hsm_state $f failed"

	local ar=$(echo $st | grep -oP '(?<=archive_id:).*')
	echo $ar
}

check_hsm_flags_user() {
	local f=$1
	local fl=$2

	local st=$(get_hsm_flags $f user)
	[[ $st == $fl ]] || error "hsm flags on $f are $st != $fl"
}

copy_file() {
	local f=

	if [[ -d $2 ]]; then
		f=$2/$(basename $1)
	else
		f=$2
	fi

	if [[ "$3" != 1 ]]; then
		f=${f/$DIR/$DIR2}
	fi
	rm -f $f
	cp $1 $f || file_creation_failure cp $f $?

	path2fid $f || error "cannot get fid on $f"
}

# Delete any file bigger than 10M under $MOUNT and wait for deletes to complete
#
# Note that this might lead to surprising behaviours such as deleting an
# important file for the currently running test
delete_large_files() {
	printf "Deleting large files...\n" >&2
	find $MOUNT -size +10M -delete
	wait_delete_completed
}

get_request_state() {
	local fid=$1
	local request=$2

	do_facet $SINGLEMDS "$LCTL get_param -n $HSM_PARAM.actions |"\
		"awk '/'$fid'.*action='$request'/ {print \\\$13}' | cut -f2 -d="
}

get_request_count() {
	local fid=$1
	local request=$2

	do_facet $SINGLEMDS "$LCTL get_param -n $HSM_PARAM.actions |"\
		"awk -vn=0 '/'$fid'.*action='$request'/ {n++}; END {print n}'"
}

# Ensure the number of HSM request for a given FID is correct
# assert_request_count FID REQUEST_TYPE COUNT [ERROR_MSG]
assert_request_count() {
	local request_count=$(get_request_count $1 $2)
	local default_error_msg=("expected $3 '$2' request(s) for '$1', found "
				"'$request_count'")
	[ $request_count -eq $3 ] || error "${4:-"${default_error_msg[@]}"}"
}

wait_all_done() {
	local timeout=$1
	local fid=$2

	local cmd="$LCTL get_param -n $HSM_PARAM.actions"
	[[ -n $fid ]] && cmd+=" | grep '$fid'"
	cmd+=" | egrep 'WAITING|STARTED'"

	wait_update_facet --verbose mds1 "$cmd" "" $timeout ||
		error "requests did not complete"
}

wait_for_grace_delay() {
	local val=$(get_hsm_param grace_delay)
	sleep $val
}

wait_for_loop_period() {
	local val=$(get_hsm_param loop_period)
	sleep $val
}

parse_json_event() {
	local raw_event=$1

	# python2.6 in EL6 includes an internal json module
	local json_parser='import json; import fileinput;'
	json_parser+=' print "\n".join(["local %s=\"%s\"" % tuple for tuple in '
	json_parser+='json.loads([line for line in '
	json_parser+='fileinput.input()][0]).items()])'

	echo $raw_event | python -c "$json_parser"
}

get_agent_by_uuid_mdt() {
	local uuid=$1
	local mdtidx=$2
	local mds=mds$(($mdtidx + 1))
	do_facet $mds "$LCTL get_param -n ${MDT_PREFIX}${mdtidx}.hsm.agents |\
		 grep $uuid"
}

check_agent_registered_by_mdt() {
	local uuid=$1
	local mdtidx=$2
	local mds=mds$(($mdtidx + 1))
	local agent=$(get_agent_by_uuid_mdt $uuid $mdtidx)
	if [[ ! -z "$agent" ]]; then
		echo "found agent $agent on $mds"
	else
		error "uuid $uuid not found in agent list on $mds"
	fi
}

check_agent_unregistered_by_mdt() {
	local uuid=$1
	local mdtidx=$2
	local mds=mds$(($mdtidx + 1))
	local agent=$(get_agent_by_uuid_mdt $uuid $mdtidx)
	if [[ -z "$agent" ]]; then
		echo "uuid not found in agent list on $mds"
	else
		error "uuid found in agent list on $mds: $agent"
	fi
}

check_agent_registered() {
	local uuid=$1
	local mdsno
	for mdsno in $(seq 1 $MDSCOUNT); do
		check_agent_registered_by_mdt $uuid $((mdsno - 1))
	done
}

check_agent_unregistered() {
	local uuid=$1
	local mdsno
	for mdsno in $(seq 1 $MDSCOUNT); do
		check_agent_unregistered_by_mdt $uuid $((mdsno - 1))
	done
}

get_agent_uuid() {
	local agent=${1:-$(facet_active_host $SINGLEAGT)}

	# Lustre mount-point is mandatory and last parameter on
	# copytool cmd-line.
	local mntpnt=$(do_rpc_nodes $agent \
			pgrep --pidfile=$HSMTOOL_PID_FILE --list-full hsmtool |
		       awk '{print $NF}')
	[ -n "$mntpnt" ] || error "Found no Agent or with no mount-point "\
				  "parameter"
	do_rpc_nodes $agent get_client_uuid $mntpnt | cut -d' ' -f2
}

# initiate variables
init_agt_vars

# populate MDT device array
get_mdt_devices

# cleanup from previous bad setup
kill_copytools

# for recovery tests, coordinator needs to be started at mount
# so force it
# the lustre conf must be without hsm on (like for sanity.sh)
echo "Set HSM on and start"
cdt_set_mount_state enabled
cdt_check_state enabled

echo "Set sanity-hsm HSM policy"
cdt_set_sanity_policy

# finished requests are quickly removed from list
set_hsm_param grace_delay 10

CLIENT_NIDS=( $($LCTL list_nids all) )

test_1A() { # was test_1
	mkdir -p $DIR/$tdir
	chmod 777 $DIR/$tdir

	local f=$DIR/$tdir/$tfile
	$RUNAS touch $f

	# User flags
	check_hsm_flags_user $f "0x00000000"

	$RUNAS $LFS hsm_set --norelease $f ||
		error "user could not change hsm flags"
	check_hsm_flags_user $f "0x00000010"

	$RUNAS $LFS hsm_clear --norelease $f ||
		error "user could not clear hsm flags"
	check_hsm_flags_user $f "0x00000000"

	# User could not change those flags...
	$RUNAS $LFS hsm_set --exists $f &&
		error "user should not set this flag"
	check_hsm_flags_user $f "0x00000000"

	# ...but root can
	$LFS hsm_set --exists $f ||
		error "root could not change hsm flags"
	check_hsm_flags_user $f "0x00000001"

	$LFS hsm_clear --exists $f ||
		error "root could not clear hsm state"
	check_hsm_flags_user $f "0x00000000"

}
run_test 1A "lfs hsm flags root/non-root access"

test_1a() {
	local f=$DIR/$tdir/$tfile
	local fid=$(create_small_file $f)

	copytool setup

	$LFS hsm_archive $f || error "could not archive file"
	wait_request_state $fid ARCHIVE SUCCEED

	# Release and check states
	$LFS hsm_release $f || error "could not release file"
	echo -n "Verifying released state: "
	check_hsm_flags $f "0x0000000d"

	$MMAP_CAT $f > /dev/null || error "failed mmap & cat release file"
}
run_test 1a "mmap & cat a HSM released file"

test_1bde_base() {
	local f=$1
	rm -f $f

	dd if=/dev/urandom of=$f bs=1M count=1 conv=sync ||
		error "failed to create file"
	local fid=$(path2fid $f)

	copytool setup

	echo "archive $f"
	$LFS hsm_archive $f || error "could not archive file"
	wait_request_state $fid ARCHIVE SUCCEED

	echo "release $f"
	$LFS hsm_release $f || error "could not release file"
	echo "verify released state: "
	check_hsm_flags $f "0x0000000d" && echo "pass"

	echo "restore $f"
	$LFS hsm_restore $f || error "could not restore file"
	wait_request_state $fid RESTORE SUCCEED
	echo "verify restored state: "
	check_hsm_flags $f "0x00000009" && echo "pass"
}

test_1b() {
	mkdir -p $DIR/$tdir
	$LFS setstripe -E 1M -S 1M -E 64M -c 2 -E -1 -c 4 $DIR/$tdir ||
		error "failed to set default stripe"
	local f=$DIR/$tdir/$tfile

	test_1bde_base $f
}
run_test 1b "Archive, Release and Restore composite file"

test_1c() {
	mkdir -p $DIR/$tdir
	chmod 777 $DIR/$tdir

	local f=$DIR/$tdir/$tfile
	$RUNAS touch $f

	# Test whether we can set the maximum archive number.
	local LOCAL_HSM_ARCHIVE_NUMBER=32
	$LFS hsm_set --exists --archive-id $LOCAL_HSM_ARCHIVE_NUMBER $f ||
		error "root could not change hsm flags"
	check_hsm_flags_user $f "0x00000001"
	echo "verifying archive number is $LOCAL_HSM_ARCHIVE_NUMBER"
	local st=$(get_hsm_archive_id $f)
	[[ $st == $LOCAL_HSM_ARCHIVE_NUMBER ]] ||
		error "wrong archive number, $st != $LOCAL_HSM_ARCHIVE_NUMBER"

	# Test whether setting archive number 0 results in no change.
	$LFS hsm_set --exists --archive-id 0 $f ||
		error "root could not change hsm flags"
	check_hsm_flags_user $f "0x00000001"
	echo "verifying archive number is still $LOCAL_HSM_ARCHIVE_NUMBER"
	st=$(get_hsm_archive_id $f)
	[[ $st == $LOCAL_HSM_ARCHIVE_NUMBER ]] ||
		error "wrong archive number, $st != $LOCAL_HSM_ARCHIVE_NUMBER"

	LOCAL_HSM_ARCHIVE_NUMBER=33
	if [ "$CLIENT_VERSION" -ge $(version_code 2.11.56) ] &&
	   [ "$MDS1_VERSION" -ge $(version_code 2.11.56) ]; then
		# lustre in the new version supports unlimited archiveID.
		# Test whether setting archive number > 32 is supported
		$LFS hsm_set --exists --archive-id $LOCAL_HSM_ARCHIVE_NUMBER $f ||
			error "archive ID $LOCAL_HSM_ARCHIVE_NUMBER too large?"
		check_hsm_flags_user $f "0x00000001"

		echo "verifying archive number is $LOCAL_HSM_ARCHIVE_NUMBER"
		st=$(get_hsm_archive_id $f)
		[[ $st == $LOCAL_HSM_ARCHIVE_NUMBER ]] ||
			error "wrong archive number, $st != $LOCAL_HSM_ARCHIVE_NUMBER"
	else
		# old client or old mds can only support at most 32 archiveID
		# test whether setting archive number > 32 results in error.
		$LFS hsm_set --exists --archive-id $LOCAL_HSM_ARCHIVE_NUMBER $f &&
			error "bitmap archive number is larger than 32"
		check_hsm_flags_user $f "0x00000001"
	fi

	# Test whether setting archive number 16 and archived flag.
	LOCAL_HSM_ARCHIVE_NUMBER=16
	$LFS hsm_set --exists --archived \
	     --archive-id $LOCAL_HSM_ARCHIVE_NUMBER $f ||
	    error "root could not change hsm flags"
	check_hsm_flags_user $f "0x00000009"
	echo "verifying archive number is $LOCAL_HSM_ARCHIVE_NUMBER"
	st=$(get_hsm_archive_id $f)
	[[ $st == $LOCAL_HSM_ARCHIVE_NUMBER ]] ||
		error "wrong archive number, $st != $LOCAL_HSM_ARCHIVE_NUMBER"
}
run_test 1c "Check setting archive-id in lfs hsm_set"

test_1d() {
	[ $MDS1_VERSION -lt $(version_code 2.10.59) ] &&
		skip "need MDS version at least 2.10.59"

	mkdir -p $DIR/$tdir
	$LFS setstripe -E 1M -L mdt -E -1 -c 2 $DIR/$tdir ||
		error "failed to set default stripe"
	local f=$DIR/$tdir/$tfile

	test_1bde_base $f
}
run_test 1d "Archive, Release and Restore DoM file"

test_1e() {
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	mkdir -p $DIR/$tdir
	$LFS setstripe -E 1G -z 64M -E 10G -z 512M -E -1 -z 1G $DIR/$tdir ||
		error "failed to set default stripe"
	local comp_file=$DIR/$tdir/$tfile

	test_1bde_base $comp_file

	local flg_opts="--comp-start 0 -E 64M --comp-flags init"
	local found=$($LFS find $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "1st component not found"

	flg_opts="--comp-start 64M -E 1G --comp-flags extension"
	found=$($LFS find $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "2nd component not found"

	flg_opts="--comp-start 1G -E 1G --comp-flags ^init"
	found=$($LFS find $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "3rd component not found"

	flg_opts="--comp-start 1G -E 10G --comp-flags extension"
	found=$($LFS find $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "4th component not found"

	flg_opts="--comp-start 10G -E 10G --comp-flags ^init"
	found=$($LFS find $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "5th component not found"

	flg_opts="--comp-start 10G -E EOF --comp-flags extension"
	found=$($LFS find $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "6th component not found"

	sel_layout_sanity $comp_file 6
}
run_test 1e "Archive, Release and Restore SEL file"

test_2() {
	local f=$DIR/$tdir/$tfile

	create_empty_file "$f"
	# New files are not dirty
	check_hsm_flags $f "0x00000000"

	# For test, we simulate an archived file.
	$LFS hsm_set --exists $f || error "user could not change hsm flags"
	check_hsm_flags $f "0x00000001"

	# chmod do not put the file dirty
	chmod 600 $f || error "could not chmod test file"
	check_hsm_flags $f "0x00000001"

	# chown do not put the file dirty
	chown $RUNAS_ID $f || error "could not chown test file"
	check_hsm_flags $f "0x00000001"

	# truncate put the file dirty
	$TRUNCATE $f 1 || error "could not truncate test file"
	check_hsm_flags $f "0x00000003"

	$LFS hsm_clear --dirty $f || error "could not clear hsm flags"
	check_hsm_flags $f "0x00000001"
}
run_test 2 "Check file dirtyness when doing setattr"

test_3() {
	mkdir -p $DIR/$tdir
	f=$DIR/$tdir/$tfile

	# New files are not dirty
	cp -p /etc/passwd $f
	check_hsm_flags $f "0x00000000"

	# For test, we simulate an archived file.
	$LFS hsm_set --exists $f ||
		error "user could not change hsm flags"
	check_hsm_flags $f "0x00000001"

	# Reading a file, does not set dirty
	cat $f > /dev/null || error "could not read file"
	check_hsm_flags $f "0x00000001"

	# Open for write without modifying data, does not set dirty
	openfile -f O_WRONLY $f || error "could not open test file"
	check_hsm_flags $f "0x00000001"

	# Append to a file sets it dirty
	cp -p /etc/passwd $f.append || error "could not create file"
	$LFS hsm_set --exists $f.append ||
		error "user could not change hsm flags"
	dd if=/etc/passwd of=$f.append bs=1 count=3\
	   conv=notrunc oflag=append status=noxfer ||
		file_creation_failure dd $f.append $?
	check_hsm_flags $f.append "0x00000003"

	# Modify a file sets it dirty
	cp -p /etc/passwd $f.modify || error "could not create file"
	$LFS hsm_set --exists $f.modify ||
		error "user could not change hsm flags"
	dd if=/dev/zero of=$f.modify bs=1 count=3\
	   conv=notrunc status=noxfer ||
		file_creation_failure dd $f.modify $?
	check_hsm_flags $f.modify "0x00000003"

	# Open O_TRUNC sets dirty
	cp -p /etc/passwd $f.trunc || error "could not create file"
	$LFS hsm_set --exists $f.trunc ||
		error "user could not change hsm flags"
	cp /etc/group $f.trunc || error "could not override a file"
	check_hsm_flags $f.trunc "0x00000003"

	# Mmapped a file sets dirty
	cp -p /etc/passwd $f.mmap || error "could not create file"
	$LFS hsm_set --exists $f.mmap ||
		error "user could not change hsm flags"
	multiop $f.mmap OSMWUc || error "could not mmap a file"
	check_hsm_flags $f.mmap "0x00000003"
}
run_test 3 "Check file dirtyness when opening for write"

test_4() {
	local f=$DIR/$tdir/$tfile
	local fid=$(create_small_file $f)

	$LFS hsm_cancel $f
	local st=$(get_request_state $fid CANCEL)
	[[ -z "$st" ]] || error "hsm_cancel must not be registered (state=$st)"
}
run_test 4 "Useless cancel must not be registered"

test_8() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/passwd $f)
	$LFS hsm_archive $f
	wait_request_state $fid ARCHIVE SUCCEED

	check_hsm_flags $f "0x00000009"
}
run_test 8 "Test default archive number"

test_9A() { # was test_9
	# we do not use the default one to be sure
	local archive_id=$((HSM_ARCHIVE_NUMBER + 1))
	copytool setup --archive-id $archive_id

	# give time for CT to register with MDTs
	sleep $(($MDSCOUNT*2))
	local uuid=$(get_agent_uuid $(facet_active_host $SINGLEAGT))
	check_agent_registered $uuid

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/passwd $f)
	$LFS hsm_archive --archive $archive_id $f
	wait_request_state $fid ARCHIVE SUCCEED

	check_hsm_flags $f "0x00000009"
}
run_test 9A "Use of explicit archive number, with dedicated copytool"

test_9a() {
	needclients 3 || return 0

	local n
	local file
	local fid

	# start all of the copytools
	for n in $(seq $AGTCOUNT); do
		copytool setup --facet agt$n
	done

	# archive files
	for n in $(seq $AGTCOUNT); do
		file=$DIR/$tdir/$tfile.$n
		fid=$(create_small_file $file)

		$LFS hsm_archive $file || error "could not archive file $file"
		wait_request_state $fid ARCHIVE SUCCEED
		check_hsm_flags $file "0x00000009"
	done
}
run_test 9a "Multiple remote agents"

test_10a() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir/d1
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/hosts $f)
	$LFS hsm_archive -a $HSM_ARCHIVE_NUMBER $f ||
		error "hsm_archive failed"
	wait_request_state $fid ARCHIVE SUCCEED

	local hsm_root="$(copytool_device $SINGLEAGT)"
	local archive="$(do_facet $SINGLEAGT \
			 find "$hsm_root" -name "$fid" -print0)"
	[ -n "$archive" ] || error "fid '$fid' not in archive '$hsm_root'"

	echo "Verifying content"
	do_facet $SINGLEAGT diff $f $archive || error "archived file differs"
	echo "Verifying hsm state "
	check_hsm_flags $f "0x00000009"

	echo "Verifying archive number is $HSM_ARCHIVE_NUMBER"
	local st=$(get_hsm_archive_id $f)
	[[ $st == $HSM_ARCHIVE_NUMBER ]] ||
		error "Wrong archive number, $st != $HSM_ARCHIVE_NUMBER"
}
run_test 10a "Archive a file"

test_10b() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/hosts $f)
	$LFS hsm_archive $f || error "archive request failed"
	wait_request_state $fid ARCHIVE SUCCEED

	$LFS hsm_archive $f || error "archive of non dirty file failed"
	local cnt=$(get_request_count $fid ARCHIVE)
	[[ "$cnt" == "1" ]] ||
		error "archive of non dirty file must not make a request"
}
run_test 10b "Archive of non dirty file must work without doing request"

test_10c() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/hosts $f)
	$LFS hsm_set --noarchive $f
	$LFS hsm_archive $f && error "archive a noarchive file must fail"
	return 0
}
run_test 10c "Check forbidden archive"

test_10d() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/hosts $f)
	$LFS hsm_archive $f || error "cannot archive $f"
	wait_request_state $fid ARCHIVE SUCCEED

	local ar=$(get_hsm_archive_id $f)
	local dflt=$(get_hsm_param default_archive_id)
	[[ $ar == $dflt ]] ||
		error "archived file is not on default archive: $ar != $dflt"
}
run_test 10d "Archive a file on the default archive id"

test_11a() {
	mkdir -p $DIR/$tdir
	copy2archive /etc/hosts $tdir/$tfile
	local f=$DIR/$tdir/$tfile

	copytool import $tdir/$tfile $f
	echo -n "Verifying released state: "
	check_hsm_flags $f "0x0000000d"

	local LSZ=$(stat -c "%s" $f)
	local ASZ=$(do_facet $SINGLEAGT stat -c "%s" "$(hsm_root)/$tdir/$tfile")

	echo "Verifying imported size $LSZ=$ASZ"
	[[ $LSZ -eq $ASZ ]] || error "Incorrect size $LSZ != $ASZ"
	echo -n "Verifying released pattern: "
	local PTRN=$($LFS getstripe -L $f)
	echo $PTRN
	[[ $PTRN == released ]] || error "Is not released"
	local fid=$(path2fid $f)
	echo "Verifying new fid $fid in archive"

	do_facet $SINGLEAGT "[ -f \"$(fid2archive "$fid")\" ]" ||
		error "No archive for fid $fid"
}
run_test 11a "Import a file"

test_11b() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/hosts $f)
	$LFS hsm_archive -a $HSM_ARCHIVE_NUMBER $f ||
		error "hsm_archive failed"
	wait_request_state $fid ARCHIVE SUCCEED

	local FILE_HASH=$(md5sum $f)
	rm -f $f

	copytool import $fid $f

	echo "$FILE_HASH" | md5sum -c

	[[ $? -eq 0 ]] || error "Restored file differs"
}
run_test 11b "Import a deleted file using its FID"

test_11c() {
	pool_add $TESTNAME || error "Pool creation failed"
	pool_add_targets $TESTNAME 1 1 || error "pool_add_targets failed"

	mkdir -p $DIR/$tdir
	$LFS setstripe -p "$TESTNAME" $DIR/$tdir

	copy2archive /etc/hosts $tdir/$tfile
	copytool import $tdir/$tfile $DIR/$tdir/$tfile
}
run_test 11c "Import a file to a directory with a pool"

test_12a() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	copy2archive /etc/hosts $tdir/$tfile

	local f=$DIR/$tdir/$tfile
	copytool import $tdir/$tfile $f
	local f2=$DIR2/$tdir/$tfile
	echo "Verifying released state: "
	check_hsm_flags $f2 "0x0000000d"

	local fid=$(path2fid $f2)
	$LFS hsm_restore $f2
	wait_request_state $fid RESTORE SUCCEED

	echo "Verifying file state: "
	check_hsm_flags $f2 "0x00000009"

	do_facet $SINGLEAGT diff -q $(hsm_root)/$tdir/$tfile $f

	[[ $? -eq 0 ]] || error "Restored file differs"
}
run_test 12a "Restore an imported file explicitly"

test_12b() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	copy2archive /etc/hosts $tdir/$tfile

	local f=$DIR/$tdir/$tfile
	copytool import $tdir/$tfile $f
	echo "Verifying released state: "
	check_hsm_flags $f "0x0000000d"

	cat $f > /dev/null || error "File read failed"

	echo "Verifying file state after restore: "
	check_hsm_flags $f "0x00000009"

	do_facet $SINGLEAGT diff -q $(hsm_root)/$tdir/$tfile $f

	[[ $? -eq 0 ]] || error "Restored file differs"
}
run_test 12b "Restore an imported file implicitly"

test_12c() {
	[ "$OSTCOUNT" -lt "2" ] && skip_env "needs >= 2 OSTs" && return

	# test needs a running copytool
	copytool setup

	local f=$DIR/$tdir/$tfile
	mkdir -p $DIR/$tdir
	$LFS setstripe -c 2 "$f"
	local fid=$(create_file "$f" 1M 5)

	local FILE_CRC=$(md5sum $f)

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f || error "release $f failed"

	echo "$FILE_CRC" | md5sum -c

	[[ $? -eq 0 ]] || error "Restored file differs"
}
run_test 12c "Restore a file with stripe of 2"

test_12d() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir

	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/hosts $f)
	$LFS hsm_restore $f || error "restore of non archived file failed"
	local cnt=$(get_request_count $fid RESTORE)
	[[ "$cnt" == "0" ]] ||
		error "restore non archived must not make a request"
	$LFS hsm_archive $f ||
		error "archive request failed"
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_restore $f ||
		error "restore of non released file failed"
	local cnt=$(get_request_count $fid RESTORE)
	[[ "$cnt" == "0" ]] ||
		error "restore a non dirty file must not make a request"
}
run_test 12d "Restore of a non archived, non released file must work"\
		" without doing request"

test_12e() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/hosts $f)
	$LFS hsm_archive $f || error "archive request failed"
	wait_request_state $fid ARCHIVE SUCCEED

	# make file dirty
	cat /etc/hosts >> $f
	sync
	$LFS hsm_state $f

	$LFS hsm_restore $f && error "restore a dirty file must fail"
	return 0
}
run_test 12e "Check forbidden restore"

test_12f() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/hosts $f)

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f || error "release of $f failed"
	$LFS hsm_restore $f
	wait_request_state $fid RESTORE SUCCEED

	echo -n "Verifying file state: "
	check_hsm_flags $f "0x00000009"

	diff -q /etc/hosts $f

	[[ $? -eq 0 ]] || error "Restored file differs"
}
run_test 12f "Restore a released file explicitly"

test_12g() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/hosts $f)

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f || error "release of $f failed"

	diff -q /etc/hosts $f
	local st=$?

	# we check we had a restore done
	wait_request_state $fid RESTORE SUCCEED

	[[ $st -eq 0 ]] || error "Restored file differs"
}
run_test 12g "Restore a released file implicitly"

test_12h() {
	needclients 2 || return 0

	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/hosts $f)

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f || error "release of $f failed"

	do_node $CLIENT2 diff -q /etc/hosts $f
	local st=$?

	# we check we had a restore done
	wait_request_state $fid RESTORE SUCCEED

	[[ $st -eq 0 ]] || error "Restored file differs"
}
run_test 12h "Restore a released file implicitly from a second node"

test_12m() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/passwd $f)
	$LFS hsm_archive $f || error "archive of $f failed"
	wait_request_state $fid ARCHIVE SUCCEED

	$LFS hsm_release $f || error "release of $f failed"

	cmp /etc/passwd $f

	[[ $? -eq 0 ]] || error "Restored file differs"
}
run_test 12m "Archive/release/implicit restore"

test_12n() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	copy2archive /etc/hosts $tdir/$tfile

	local f=$DIR/$tdir/$tfile
	copytool import $tdir/$tfile $f

	do_facet $SINGLEAGT cmp /etc/hosts $f ||
		error "Restored file differs"

	$LFS hsm_release $f || error "release of $f failed"
}
run_test 12n "Import/implicit restore/release"

test_12o() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/hosts $f)

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f || error "release of $f failed"

#define OBD_FAIL_MDS_HSM_SWAP_LAYOUTS		0x152
	do_facet $SINGLEMDS lctl set_param fail_loc=0x152

	# set no retry action mode
	cdt_set_no_retry

	diff -q /etc/hosts $f
	local st=$?

	# we check we had a restore failure
	wait_request_state $fid RESTORE FAILED

	[[ $st -eq 0 ]] && error "Restore must fail"

	# remove no retry action mode
	cdt_clear_no_retry

	# check file is still released
	check_hsm_flags $f "0x0000000d"

	# retry w/o failure injection
	do_facet $SINGLEMDS lctl set_param fail_loc=0

	# to be sure previous RESTORE result is gone
	cdt_purge
	wait_for_grace_delay

	diff -q /etc/hosts $f
	st=$?

	# we check we had a restore done
	wait_request_state $fid RESTORE SUCCEED

	[[ $st -eq 0 ]] || error "Restored file differs"
}
run_test 12o "Layout-swap failure during Restore leaves file released"

test_12p() {
	# test needs a running copytool
	copytool setup

	mkdir $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/hosts $f)

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	do_facet $SINGLEAGT cat $f > /dev/null || error "cannot cat $f"
	$LFS hsm_release $f || error "cannot release $f"
	do_facet $SINGLEAGT cat $f > /dev/null || error "cannot cat $f"
	$LFS hsm_release $f || error "cannot release $f"
	do_facet $SINGLEAGT cat $f > /dev/null || error "cannot cat $f"
}
run_test 12p "implicit restore of a file on copytool mount point"

test_12q() {
	[ $MDS1_VERSION -lt $(version_code 2.7.58) ] &&
		skip "need MDS version at least 2.7.58"

	stack_trap "zconf_umount \"$(facet_host $SINGLEAGT)\" \"$MOUNT3\"" EXIT
	zconf_mount $(facet_host $SINGLEAGT) $MOUNT3 ||
		error "cannot mount $MOUNT3 on $SINGLEAGT"

	# test needs a running copytool
	copytool setup -m "$MOUNT3"

	local f=$DIR/$tdir/$tfile
	local f2=$DIR2/$tdir/$tfile
	local fid=$(create_small_file $f)
	local orig_size=$(stat -c "%s" $f)

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED

	$LFS hsm_release $f || error "could not release file"
	check_hsm_flags $f "0x0000000d"

	kill_copytools
	wait_copytools || error "copytool failed to stop"

	cat $f > /dev/null &

	# wait a bit to allow implicit restore request to be handled.
	# if not, next stat would also block on layout-lock.
	sleep 5

	local size=$(stat -c "%s" $f2)
	[ $size -eq $orig_size ] ||
		error "$f2: wrong size after archive: $size != $orig_size"

	copytool setup -m "$MOUNT3"

	wait

	size=$(stat -c "%s" $f)
	[ $size -eq $orig_size ] ||
		error "$f: wrong size after restore: $size != $orig_size"

	size=$(stat -c "%s" $f2)
	[ $size -eq $orig_size ] ||
		error "$f2: wrong size after restore: $size != $orig_size"

	:>$f

	size=$(stat -c "%s" $f)
	[ $size -eq 0 ] ||
		error "$f: wrong size after overwrite: $size != 0"

	size=$(stat -c "%s" $f2)
	[ $size -eq 0 ] ||
		error "$f2: wrong size after overwrite: $size != 0"
}
run_test 12q "file attributes are refreshed after restore"

test_12r() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/hosts $f)

	$LFS hsm_archive $f || error "archive of $f failed"
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f || error "release of $f failed"

	offset=$(lseek_test -d 7 $f)

	# we check we had a restore done
	wait_request_state $fid RESTORE SUCCEED
	[[ $offset == 7 ]] || error "offset $offset != 7"
}
run_test 12r "lseek restores released file"

test_13() {
	local -i i j k=0
	for i in {1..10}; do
		local archive_dir="$(hsm_root)"/subdir/dir.$i

		do_facet $SINGLEAGT mkdir -p "$archive_dir"
		for j in {1..10}; do
			local archive_file="$archive_dir"/file.$j

			do_facet $SINGLEAGT "echo $k > \"$archive_dir\"/file.$j"
			k+=1
		done
	done

	# import to Lustre
	copytool import "subdir" "$DIR/$tdir"

	# To check the import, the test uses diff with the -r flag
	# This is nice, but diff only checks files one by one, and triggering
	# an implicit restore for one file at a time will consume as many
	# seconds as there are files to compare. To speed this up, a restore
	# operation is triggered manually first.
	copytool setup
	find "$DIR/$tdir"/subdir -type f -exec $LFS hsm_restore {} \;

	# Compare the imported data
	do_facet $SINGLEAGT \
		diff -r "$(hsm_root)"/subdir "$DIR/$tdir"/subdir ||
		error "imported files differ from archived data"
}
run_test 13 "Recursively import and restore a directory"

test_14() {
	# test needs a running copytool
	copytool setup

	# archive a file
	local f=$DIR/$tdir/$tfile
	local fid=$(create_small_file $f)
	local sum=$(md5sum $f | awk '{print $1}')
	$LFS hsm_archive $f || error "could not archive file"
	wait_request_state $fid ARCHIVE SUCCEED

	# create released file (simulate llapi_hsm_import call)
	local fid2=$(create_empty_file "$f")
	$LFS hsm_set --archived --exists $f || error "could not force hsm flags"
	$LFS hsm_release $f || error "could not release file"

	# rebind the archive to the newly created file
	echo "rebind $fid to $fid2"

	copytool rebind $fid $fid2

	# restore file and compare md5sum
	local sum2=$(md5sum $f | awk '{print $1}')

	[[ $sum == $sum2 ]] || error "md5sum mismatch after restore"
}
run_test 14 "Rebind archived file to a new fid"

test_15() {
	# test needs a running copytool
	copytool setup

	# archive files
	local f=$DIR/$tdir/$tfile
	local count=5
	local tmpfile=$SHARED_DIRECTORY/tmp.$$

	local fids=()
	local sums=()
	for i in $(seq 1 $count); do
		fids[$i]=$(create_small_file $f.$i)
		sums[$i]=$(md5sum $f.$i | awk '{print $1}')
		$LFS hsm_archive $f.$i || error "could not archive file"
	done
	wait_all_done $(($count*60))

	stack_trap "rm -f $tmpfile" EXIT
	:>$tmpfile
	# delete the files
	for i in $(seq 1 $count); do
		local fid2=$(create_empty_file "${f}.${i}")
		# add the rebind operation to the list
		echo ${fids[$i]} $fid2 >> $tmpfile

		# set it released (simulate llapi_hsm_import call)
		$LFS hsm_set --archived --exists $f.$i ||
			error "could not force hsm flags"
		$LFS hsm_release $f.$i || error "could not release file"
	done
	nl=$(wc -l < $tmpfile)
	[[ $nl == $count ]] || error "$nl files in list, $count expected"

	echo "rebind list of files"
	copytool rebind "$tmpfile"

	# restore files and compare md5sum
	for i in $(seq 1 $count); do
		local sum2=$(md5sum $f.$i | awk '{print $1}')
		[[ $sum2 == ${sums[$i]} ]] ||
		    error "md5sum mismatch after restore ($sum2 != ${sums[$i]})"
	done
}
run_test 15 "Rebind a list of files"

test_16() {
	# test needs a running copytool
	copytool setup -b 1

	local ref=/tmp/ref
	# create a known size file so we can verify transfer speed
	# 20 MB <-> 20s
	local goal=20
	dd if=/dev/zero of=$ref bs=1M count=20

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file $ref $f)
	rm $ref
	local start=$(date +%s)
	$LFS hsm_archive $f
	wait_request_state $fid ARCHIVE SUCCEED
	local end=$(date +%s)
	# Add 1 to account for rounding errors between start and end (LU-8155)
	local duration=$((end - start + 1))

	[[ $duration -ge $((goal - 1)) ]] ||
		error "Transfer is too fast $duration < $goal"
}
run_test 16 "Test CT bandwith control option"

test_20() {
	local f=$DIR/$tdir/$tfile
	create_empty_file "$f"

	# Could not release a non-archived file
	$LFS hsm_release $f && error "release should not succeed"

	# For following tests, we must test them with HS_ARCHIVED set
	$LFS hsm_set --exists --archived $f || error "could not add flag"

	# Could not release a file if no-release is set
	$LFS hsm_set --norelease $f || error "could not add flag"
	$LFS hsm_release $f && error "release should not succeed"
	$LFS hsm_clear --norelease $f || error "could not remove flag"

	# Could not release a file if lost
	$LFS hsm_set --lost $f || error "could not add flag"
	$LFS hsm_release $f && error "release should not succeed"
	$LFS hsm_clear --lost $f || error "could not remove flag"

	# Could not release a file if dirty
	$LFS hsm_set --dirty $f || error "could not add flag"
	$LFS hsm_release $f && error "release should not succeed"
	$LFS hsm_clear --dirty $f || error "could not remove flag"
}
run_test 20 "Release is not permitted"

test_21() {
	# test needs a running copytool
	copytool setup

	local f=$DIR/$tdir/test_release

	# Create a file and check its states
	local fid=$(create_small_file $f)
	check_hsm_flags $f "0x00000000"

	# LU-4388/LU-4389 - ZFS does not report full number of blocks
	# used until file is flushed to disk
	if [ "$ost1_FSTYPE" == "zfs" ]; then
	    # this causes an OST_SYNC rpc to be sent
	    dd if=/dev/zero of=$f bs=512 count=1 oflag=sync conv=notrunc,fsync
	    # clear locks to reread file data
	    cancel_lru_locks osc
	fi

	local orig_size=$(stat -c "%s" $f)
	local orig_blocks=$(stat -c "%b" $f)

	start_full_debug_logging

	$LFS hsm_archive $f || error "could not archive file"
	wait_request_state $fid ARCHIVE SUCCEED

	local blocks=$(stat -c "%b" $f)
	[ $blocks -eq $orig_blocks ] ||
		error "$f: wrong block number after archive: " \
		      "$blocks != $orig_blocks"
	local size=$(stat -c "%s" $f)
	[ $size -eq $orig_size ] ||
		error "$f: wrong size after archive: $size != $orig_size"

	# Release and check states
	$LFS hsm_release $f || error "could not release file"
	check_hsm_flags $f "0x0000000d"

	blocks=$(stat -c "%b" $f)
	[ $blocks -gt 5 ] &&
		error "$f: too many blocks after release: $blocks > 5"
	size=$(stat -c "%s" $f)
	[ $size -ne $orig_size ] &&
		error "$f: wrong size after release: $size != $orig_size"

	# Check we can release an file without stripe info
	f=$f.nolov
	$MCREATE $f
	fid=$(path2fid $f)
	check_hsm_flags $f "0x00000000"
	$LFS hsm_archive $f || error "could not archive file"
	wait_request_state $fid ARCHIVE SUCCEED

	# Release and check states
	$LFS hsm_release $f || error "could not release file"
	check_hsm_flags $f "0x0000000d"

	# Release again a file that is already released is OK
	$LFS hsm_release $f || fail "second release should succeed"
	check_hsm_flags $f "0x0000000d"

	stop_full_debug_logging
}
run_test 21 "Simple release tests"

test_22() {
	# test needs a running copytool
	copytool setup

	local f=$DIR/$tdir/test_release
	local swap=$DIR/$tdir/test_swap

	# Create a file and check its states
	local fid=$(create_small_file $f)
	check_hsm_flags $f "0x00000000"

	$LFS hsm_archive $f || error "could not archive file"
	wait_request_state $fid ARCHIVE SUCCEED

	# Release and check states
	$LFS hsm_release $f || error "could not release file"
	check_hsm_flags $f "0x0000000d"

	create_small_file $swap
	$LFS swap_layouts $swap $f && error "swap_layouts should failed"

	return 0
}
run_test 22 "Could not swap a release file"

test_23() {
	# test needs a running copytool
	copytool setup

	local f=$DIR/$tdir/test_mtime

	# Create a file and check its states
	local fid=$(create_small_file $f)
	check_hsm_flags $f "0x00000000"

	$LFS hsm_archive $f || error "could not archive file"
	wait_request_state $fid ARCHIVE SUCCEED

	# Set modification time in the past
	touch -m -a -d @978261179 $f

	# Release and check states
	$LFS hsm_release $f || error "could not release file"
	check_hsm_flags $f "0x0000000d"

	local MTIME=$(stat -c "%Y" $f)
	local ATIME=$(stat -c "%X" $f)
	[ $MTIME -eq "978261179" ] || fail "bad mtime: $MTIME"
	[ $ATIME -eq "978261179" ] || fail "bad atime: $ATIME"
}
run_test 23 "Release does not change a/mtime (utime)"

test_24a() {
	local file=$DIR/$tdir/$tfile
	local fid
	local atime0
	local atime1
	local mtime0
	local mtime1
	local ctime0
	local ctime1

	# test needs a running copytool
	copytool setup

	fid=$(create_small_file $file)

	# Create a file and check its states
	check_hsm_flags $file "0x00000000"

	# Ensure atime is less than mtime and ctime.
	sleep 1
	echo >> $file

	atime0=$(stat -c "%X" $file)
	mtime0=$(stat -c "%Y" $file)
	ctime0=$(stat -c "%Z" $file)

	[ $atime0 -lt $mtime0 ] ||
		error "atime $atime0 is not less than mtime $mtime0"

	[ $atime0 -lt $ctime0 ] ||
		error "atime $atime0 is not less than ctime $ctime0"

	# Archive should not change any timestamps.
	$LFS hsm_archive $file || error "cannot archive '$file'"
	wait_request_state $fid ARCHIVE SUCCEED

	atime1=$(stat -c "%X" $file)
	mtime1=$(stat -c "%Y" $file)
	ctime1=$(stat -c "%Z" $file)

	[ $atime0 -eq $atime1 ] ||
		error "archive changed atime from $atime0 to $atime1"

	[ $mtime0 -eq $mtime1 ] ||
		error "archive changed mtime from $mtime0 to $mtime1"

	[ $ctime0 -eq $ctime1 ] ||
		error "archive changed ctime from $ctime0 to $ctime1"

	# Release should not change any timestamps.
	$LFS hsm_release $file || error "cannot release '$file'"
	check_hsm_flags $file "0x0000000d"

	atime1=$(stat -c "%X" $file)
	mtime1=$(stat -c "%Y" $file)
	ctime1=$(stat -c "%Z" $file)

	[ $atime0 -eq $atime1 ] ||
		error "release changed atime from $atime0 to $atime1"

	[ $mtime0 -eq $mtime1 ] ||
		error "release changed mtime from $mtime0 to $mtime1"

	[ $ctime0 -eq $ctime1 ] ||
		error "release changed ctime from $ctime0 to $ctime1"

	# Restore should not change any timestamps.
	$LFS hsm_restore $file
	wait_request_state $fid RESTORE SUCCEED

	atime1=$(stat -c "%X" $file)
	mtime1=$(stat -c "%Y" $file)
	ctime1=$(stat -c "%Z" $file)

	[ $atime0 -eq $atime1 ] ||
		error "restore changed atime from $atime0 to $atime1"

	[ $mtime0 -eq $mtime1 ] ||
		error "restore changed mtime from $mtime0 to $mtime1"

	[ $ctime0 -eq $ctime1 ] ||
		error "restore changed ctime from $ctime0 to $ctime1"

	kill_copytools
	wait_copytools || error "Copytools failed to stop"

	# Once more, after unmount and mount.
	umount_client $MOUNT || error "cannot unmount '$MOUNT'"
	mount_client $MOUNT || error "cannot mount '$MOUNT'"

	atime1=$(stat -c "%X" $file)
	mtime1=$(stat -c "%Y" $file)
	ctime1=$(stat -c "%Z" $file)

	[ $atime0 -eq $atime1 ] ||
		error "remount changed atime from $atime0 to $atime1"

	[ $mtime0 -eq $mtime1 ] ||
		error "remount changed mtime from $mtime0 to $mtime1"

	[ $ctime0 -eq $ctime1 ] ||
		error "remount changed ctime from $ctime0 to $ctime1"
}
run_test 24a "Archive, release, and restore does not change a/mtime (i/o)"

test_24b() {
	local file=$DIR/$tdir/$tfile
	local fid
	local sum0
	local sum1
	# LU-3811

	# Test needs a running copytool.
	copytool setup

	# Check that root can do HSM actions on a regular user's file.
	fid=$(create_small_file $file)
	sum0=$(md5sum $file)

	chown $RUNAS_ID:$RUNAS_GID $file ||
		error "cannot chown '$file' to '$RUNAS_ID'"

	chmod ugo-w $DIR/$tdir ||
		error "cannot chmod '$DIR/$tdir'"

	$LFS hsm_archive $file
	wait_request_state $fid ARCHIVE SUCCEED

	$LFS hsm_release $file
	check_hsm_flags $file "0x0000000d"

	$LFS hsm_restore $file
	wait_request_state $fid RESTORE SUCCEED

	# Check that ordinary user can get HSM state.
	$RUNAS $LFS hsm_state $file ||
		error "user '$RUNAS_ID' cannot get HSM state of '$file'"

	$LFS hsm_release $file
	check_hsm_flags $file "0x0000000d"

	# Check that ordinary user can accessed released file.
	sum1=$($RUNAS md5sum $file) ||
		error "user '$RUNAS_ID' cannot read '$file'"

	[ "$sum0" == "$sum1" ] ||
		error "md5sum mismatch for '$file'"
}
run_test 24b "root can archive, release, and restore user files"

test_24c() {
	local file=$DIR/$tdir/$tfile
	local action=archive
	local user_save
	local group_save
	local other_save

	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir

	# Save the default masks and check that cleanup_24c will
	# restore the request masks correctly.
	user_save=$(get_hsm_param user_request_mask)
	stack_trap "set_hsm_param user_request_mask $user_save" EXIT
	group_save=$(get_hsm_param group_request_mask)
	stack_trap "set_hsm_param user_request_mask $group_save" EXIT
	other_save=$(get_hsm_param other_request_mask)
	stack_trap "set_hsm_param user_request_mask $other_save" EXIT

	[ "$user_save" == RESTORE ] ||
		error "user_request_mask is '$user_save' expected 'RESTORE'"
	[ "$group_save" == RESTORE ] ||
		error "group_request_mask is '$group_save' expected 'RESTORE'"
	[ "$other_save" == RESTORE ] ||
		error "other_request_mask is '$other_save' expected 'RESTORE'"

	# User.
	create_small_file $file
	chown $RUNAS_ID:$GROUP $file ||
		error "cannot chown '$file' to '$RUNAS_ID:$GROUP'"

	$RUNAS $LFS hsm_$action $file &&
		error "$action by user should fail"

	set_hsm_param user_request_mask $action
	$RUNAS $LFS hsm_$action $file ||
		error "$action by user should succeed"

	# Group.
	create_small_file $file
	chown nobody:$RUNAS_GID $file ||
		error "cannot chown '$file' to 'nobody:$RUNAS_GID'"

	$RUNAS $LFS hsm_$action $file &&
		error "$action by group should fail"

	set_hsm_param group_request_mask $action
	$RUNAS $LFS hsm_$action $file ||
		error "$action by group should succeed"

	# Other.
	create_small_file $file
	chown nobody:$GROUP $file ||
		error "cannot chown '$file' to 'nobody:$GROUP'"

	$RUNAS $LFS hsm_$action $file &&
		error "$action by other should fail"

	set_hsm_param other_request_mask $action
	$RUNAS $LFS hsm_$action $file ||
		error "$action by other should succeed"
}
run_test 24c "check that user,group,other request masks work"

test_24d() {
	local file1=$DIR/$tdir/$tfile
	local file2=$DIR2/$tdir/$tfile
	local fid1
	local fid2

	fid1=$(create_small_file $file1)

	echo $fid1
	$LFS getstripe $file1

	stack_trap "zconf_umount \"$(facet_host $SINGLEAGT)\" \"$MOUNT3\"" EXIT
	zconf_mount "$(facet_host $SINGLEAGT)" "$MOUNT3" ||
		error "cannot mount '$MOUNT3' on '$SINGLEAGT'"

	copytool setup -m  "$MOUNT3"

	stack_trap "mount -o remount,rw \"$MOUNT2\"" EXIT
	mount -o remount,ro $MOUNT2

	do_nodes $(comma_list $(nodes_list)) $LCTL clear

	fid2=$(path2fid $file2)
	[ "$fid1" == "$fid2" ] ||
		error "FID mismatch '$fid1' != '$fid2'"

	$LFS hsm_archive $file2 &&
		error "archive should fail on read-only mount"
	check_hsm_flags $file1 "0x00000000"

	$LFS hsm_archive $file1 || error "Fail to archive $file1"
	wait_request_state $fid1 ARCHIVE SUCCEED

	$LFS hsm_release $file1
	$LFS hsm_restore $file2
	wait_request_state $fid1 RESTORE SUCCEED

	$LFS hsm_release $file1 || error "cannot release '$file1'"
	dd if=$file2 of=/dev/null bs=1M || error "cannot read '$file2'"

	$LFS hsm_release $file2 &&
		error "release should fail on read-only mount"

	return 0
}
run_test 24d "check that read-only mounts are respected"

test_24e() {
	copytool setup

	local f=$DIR/$tdir/$tfile
	local fid

	fid=$(create_small_file $f) || error "cannot create $f"
	$LFS hsm_archive $f || error "cannot archive $f"
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f || error "cannot release $f"
	while ! $LFS hsm_state $f | grep released; do
		sleep 1
	done

	tar -cf $TMP/$tfile.tar $DIR/$tdir || error "cannot tar $DIR/$tdir"
}
run_test 24e "tar succeeds on HSM released files" # LU-6213

test_24f() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir/d1
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/hosts $f)
	sum0=$(md5sum $f)
	echo $sum0
	$LFS hsm_archive $f ||
		error "hsm_archive failed"
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f || error "cannot release $f"
	tar --xattrs -cvf $f.tar -C $DIR/$tdir $tfile
	rm -f $f
	sync
	tar --xattrs -xvf $f.tar -C $DIR/$tdir ||
		error "Can not recover the tar contents"
	sum1=$(md5sum $f)
	echo "Sum0 = $sum0, sum1 = $sum1"
	[ "$sum0" == "$sum1" ] || error "md5sum mismatch for '$tfile'"
}
run_test 24f "root can archive, release, and restore tar files"

test_24g() {
	[ $MDS1_VERSION -lt $(version_code 2.11.56) ] &&
		skip "need MDS version 2.11.56 or later"

	local file=$DIR/$tdir/$tfile
	local fid

	echo "RUNAS = '$RUNAS'"

	copytool setup

	mkdir -p $DIR/$tdir
	chmod ugo+rwx $DIR/$tdir

	echo "Please listen carefully as our options have changed." | tee $file
	fid=$(path2fid $file)
	chmod ugo+rw $file

	$LFS hsm_archive $file
	wait_request_state $fid ARCHIVE SUCCEED
	check_hsm_flags $file 0x00000009 # exists archived

	echo "To be electrocuted by your telephone, press #." | $RUNAS tee $file
	check_hsm_flags $file 0x0000000b # exists dirty archived
}
run_test 24g "write by non-owner still sets dirty" # LU-11369

test_25a() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	copy2archive /etc/hosts $tdir/$tfile

	local f=$DIR/$tdir/$tfile

	copytool import $tdir/$tfile $f

	$LFS hsm_set --lost $f

	md5sum $f
	local st=$?

	[[ $st == 1 ]] || error "lost file access should failed (returns $st)"
}
run_test 25a "Restore lost file (HS_LOST flag) from import"\
	     " (Operation not permitted)"

test_25b() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir

	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/passwd $f)

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED

	$LFS hsm_release $f
	$LFS hsm_set --lost $f
	md5sum $f
	st=$?

	[[ $st == 1 ]] || error "lost file access should failed (returns $st)"
}
run_test 25b "Restore lost file (HS_LOST flag) after release"\
	     " (Operation not permitted)"

test_26A() { # was test_26
	# test needs a running copytool
	copytool setup

	local f=$DIR/$tdir/$tfile
	local fid=$(create_empty_file "$f")

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED

	$LFS hsm_remove $f
	wait_request_state $fid REMOVE SUCCEED

	check_hsm_flags $f "0x00000000"
}
run_test 26A "Remove the archive of a valid file"

test_26a() {
	local raolu=$(get_hsm_param remove_archive_on_last_unlink)
	[[ $raolu -eq 0 ]] || error "RAoLU policy should be off"

	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/passwd $f)

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED

	local f2=$DIR/$tdir/${tfile}_2
	local fid2=$(copy_file /etc/passwd $f2)

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f2
	wait_request_state $fid2 ARCHIVE SUCCEED

	local f3=$DIR/$tdir/${tfile}_3
	local fid3=$(copy_file /etc/passwd $f3)

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f3
	wait_request_state $fid3 ARCHIVE SUCCEED

	# set a long grace_delay vs short loop_period
	local orig_loop_period=$(get_hsm_param loop_period)
	local orig_grace_delay=$(get_hsm_param grace_delay)
	stack_trap "set_hsm_param loop_period $orig_loop_period" EXIT
	set_hsm_param loop_period 10
	stack_trap "set_hsm_param grace_delay $orig_grace_delay" EXIT
	set_hsm_param grace_delay 100

	rm -f $f

	stack_trap "set_hsm_param remove_archive_on_last_unlink 0" EXIT
	set_hsm_param remove_archive_on_last_unlink 1

	ln "$f3" "$f3"_bis || error "Unable to create hard-link"
	rm -f $f3

	rm -f $f2

	wait_request_state $fid2 REMOVE SUCCEED

	assert_request_count $fid REMOVE 0 \
		"Unexpected archived data remove request for $f"
	assert_request_count $fid3 REMOVE 0 \
		"Unexpected archived data remove request for $f3"
}
run_test 26a "Remove Archive On Last Unlink (RAoLU) policy"

test_26b() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/passwd $f)

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED

	stack_trap "set_hsm_param remove_archive_on_last_unlink 0" EXIT
	set_hsm_param remove_archive_on_last_unlink 1

	cdt_shutdown
	cdt_check_state stopped

	rm -f $f

	wait_request_state $fid REMOVE WAITING

	cdt_enable

	# copytool must re-register
	kill_copytools
	wait_copytools || error "copytool failed to stop"
	copytool setup

	wait_request_state $fid REMOVE SUCCEED
}
run_test 26b "RAoLU policy when CDT off"

test_26c() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/passwd $f)

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED

	local f2=$DIR/$tdir/${tfile}_2
	local fid2=$(copy_file /etc/passwd $f2)

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f2
	wait_request_state $fid2 ARCHIVE SUCCEED

	# set a long grace_delay vs short loop_period
	local orig_loop_period=$(get_hsm_param loop_period)
	local orig_grace_delay=$(get_hsm_param grace_delay)
	stack_trap "set_hsm_param loop_period $orig_loop_period" EXIT
	set_hsm_param loop_period 10
	stack_trap "set_hsm_param grace_delay $orig_grace_delay" EXIT
	set_hsm_param grace_delay 100

	stack_trap "set_hsm_param remove_archive_on_last_unlink 0" EXIT
	set_hsm_param remove_archive_on_last_unlink 1

	multiop_bg_pause $f O_c || error "open $f failed"
	local pid=$!

	rm -f $f
	rm -f $f2

	wait_request_state $fid2 REMOVE SUCCEED
	assert_request_count $fid REMOVE 0 \
		"Unexpected archived data remove request for $f"

	kill -USR1 $pid || error "multiop early exit"
	# should reach autotest timeout if multiop fails to trap
	# signal, close file, and exit ...
	wait $pid || error "wait PID $PID failed"

	wait_request_state $fid REMOVE SUCCEED
}
run_test 26c "RAoLU effective when file closed"

test_26d() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(create_small_file $f)

	$LFS hsm_archive $f || error "could not archive file"
	wait_request_state $fid ARCHIVE SUCCEED

	# set a long grace_delay vs short loop_period
	local orig_loop_period=$(get_hsm_param loop_period)
	local orig_grace_delay=$(get_hsm_param grace_delay)
	stack_trap "set_hsm_param loop_period $orig_loop_period" EXIT
	set_hsm_param loop_period 10
	stack_trap "set_hsm_param grace_delay $orig_grace_delay" EXIT
	set_hsm_param grace_delay 100

	stack_trap "set_hsm_param remove_archive_on_last_unlink 0" EXIT
	set_hsm_param remove_archive_on_last_unlink 1

	multiop_bg_pause $f O_c || error "multiop failed"
	local MULTIPID=$!

	rm -f $f

	mds_evict_client

	wait_request_state $fid REMOVE SUCCEED

	client_up || client_up || true

	kill -USR1 $MULTIPID
	wait $MULTIPID || error "multiop close failed"
}
run_test 26d "RAoLU when Client eviction"

test_27a() {
	# test needs a running copytool
	copytool setup

	create_archive_file $tdir/$tfile
	local f=$DIR/$tdir/$tfile
	copytool import $tdir/$tfile $f
	local fid=$(path2fid $f)

	$LFS hsm_remove $f

	[[ $? != 0 ]] || error "Remove of a released file should fail"
}
run_test 27a "Remove the archive of an imported file (Operation not permitted)"

test_27b() {
	# test needs a running copytool
	copytool setup

	local f=$DIR/$tdir/$tfile
	local fid=$(create_empty_file "$f")

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f

	$LFS hsm_remove $f

	[[ $? != 0 ]] || error "Remove of a released file should fail"
}
run_test 27b "Remove the archive of a relased file (Operation not permitted)"

test_28() {
	# test needs a running copytool
	copytool setup

	local f=$DIR/$tdir/$tfile
	local fid=$(create_empty_file "$f")

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED

	cdt_disable
	$LFS hsm_remove $f

	rm -f $f

	cdt_enable

	wait_request_state $fid REMOVE SUCCEED
}
run_test 28 "Concurrent archive/file remove"

test_29a() {
	# Tests --mntpath and --archive options

	local archive_id=7
	copytool setup -m "$MOUNT" -a $archive_id

	# Bad archive number
	$LFS hsm_remove -m "$MOUNT" -a 33 0x857765760:0x8:0x2 2>&1 |
		grep "Invalid argument" ||
		error "unexpected hsm_remove failure (1)"

	# mntpath is present but file is given
	$LFS hsm_remove --mntpath "$MOUNT" --archive 30 /qwerty/uyt 2>&1 |
		grep "hsm: '/qwerty/uyt' is not a valid FID" ||
		error "unexpected hsm_remove failure (2)"
}
run_test 29a "Tests --mntpath and --archive options"

test_29b() {
	# test needs a running copytool
	copytool setup

	local f=$DIR/$tdir/$tfile
	local fid=$(create_small_file $f)

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED

	rm -f $f

	$LFS hsm_remove -m $MOUNT -a $HSM_ARCHIVE_NUMBER $fid
	wait_request_state $fid REMOVE SUCCEED
}
run_test 29b "Archive/delete/remove by FID from the archive."

test_29c() {
	# test needs a running copytool
	copytool setup

	local fid1=$(create_small_file $DIR/$tdir/$tfile-1)
	local fid2=$(create_small_file $DIR/$tdir/$tfile-2)
	local fid3=$(create_small_file $DIR/$tdir/$tfile-3)

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $DIR/$tdir/$tfile-[1-3]
	wait_request_state $fid1 ARCHIVE SUCCEED
	wait_request_state $fid2 ARCHIVE SUCCEED
	wait_request_state $fid3 ARCHIVE SUCCEED

	rm -f $DIR/$tdir/$tfile-[1-3]

	echo $fid1 > $DIR/$tdir/list
	echo $fid2 >> $DIR/$tdir/list
	echo $fid3 >> $DIR/$tdir/list

	$LFS hsm_remove -m $MOUNT -a $HSM_ARCHIVE_NUMBER \
		--filelist $DIR/$tdir/list
	wait_request_state $fid1 REMOVE SUCCEED
	wait_request_state $fid2 REMOVE SUCCEED
	wait_request_state $fid3 REMOVE SUCCEED
}
run_test 29c "Archive/delete/remove by FID, using a file list."

test_29d() {
	# test needs more than one CT
	needclients 3 || return 0

	local n
	local file
	local fid

	# start all of the copytools
	for n in $(seq $AGTCOUNT); do
		copytool setup -f agt$n -a $n
	done

	# archive files
	file=$DIR/$tdir/$tfile
	fid=$(create_small_file $file)

	$LFS hsm_archive $file
	wait_request_state $fid ARCHIVE SUCCEED
	check_hsm_flags $file "0x00000009"

	rm -f $file

	$LFS hsm_remove --mntpath "$MOUNT" -a 0 $fid ||
		error "cannot hsm_remove '$fid'"

	# give time for CDT to handle remove request and create broadcasted
	sleep 2

	# remove request has been broadcasted ?
	local cnt=$(get_request_count $fid REMOVE)
	# broadcasted requests + original
	[[ $cnt -eq $((AGTCOUNT + 1)) ]] ||
		error "remove not broadcasted to all CTs"

	# give time for CDT and CTs to handle broadcasted
	wait_for_loop_period

	# each agent serves one different archive_id, so broadcasted
	# hsm_remove request should only succeed once and fail at all others
	local res
	local scnt=0
	local fcnt=0
	for n in $(seq $AGTCOUNT); do
		res=$(do_facet $SINGLEMDS "$LCTL get_param -n \
			       $HSM_PARAM.actions | awk \
			       '/'$fid'.*action=REMOVE archive#='$n'/ \
			       {print \\\$13}' | cut -f2 -d=")
		if [[ "$res" == "SUCCEED" ]]; then
			scnt=$((scnt + 1))
		elif [[ "$res" == "FAILED" ]]; then
			fcnt=$((fcnt + 1))
		fi
	done

	[[ $scnt -eq 1 ]] ||
		error "one and only CT should have removed successfully"

	[[ $AGTCOUNT -eq $((scnt + fcnt)) ]] ||
		error "all but one CT should have failed to remove"
}
run_test 29d "hsm_remove by FID with archive_id 0 for unlinked file cause "\
	     "request to be sent once for each registered archive_id"

test_30a() {
	# restore at exec cannot work on agent node (because of Linux kernel
	# protection of executables)
	needclients 2 || return 0

	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	copy2archive /bin/true $tdir/$tfile

	local f=$DIR/$tdir/true
	copytool import $tdir/$tfile $f

	local fid=$(path2fid $f)

	stack_trap "cdt_clear_no_retry" EXIT
	# set no retry action mode
	cdt_set_no_retry
	do_node $CLIENT2 $f
	local st=$?

	$LFS hsm_state $f

	[[ $st == 0 ]] || error "Failed to exec a released file"
}
run_test 30a "Restore at exec (import case)"

test_30b() {
	# restore at exec cannot work on agent node (because of Linux kernel
	# protection of executables)
	needclients 2 || return 0

	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/true
	local fid=$(copy_file /bin/true $f)
	chmod 755 $f
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f
	$LFS hsm_state $f

	stack_trap cdt_clear_no_retry EXIT
	# set no retry action mode
	cdt_set_no_retry

	do_node $CLIENT2 $f
	local st=$?

	$LFS hsm_state $f

	[[ $st == 0 ]] || error "Failed to exec a released file"
}
run_test 30b "Restore at exec (release case)"

test_30c() {
	needclients 2 || return 0

	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/SLEEP
	local slp_sum1=$(md5sum /bin/sleep)
	local fid=$(copy_file /bin/sleep $f)
	chmod 755 $f
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f
	check_hsm_flags $f "0x0000000d"

	stack_trap cdt_clear_no_retry EXIT
	# set no retry action mode
	cdt_set_no_retry

	do_node $CLIENT2 "$f 10" &
	local pid=$!
	sleep 3
	echo 'Hi!' > $f
	[[ $? == 0 ]] && error "Update during exec of released file must fail"
	wait $pid
	[[ $? == 0 ]] || error "Execution failed during run"
	cmp /bin/sleep $f
	if [[ $? != 0 ]]; then
		local slp_sum2=$(md5sum /bin/sleep)
		# in case sleep file is modified during the test
		[[ $slp_sum1 == $slp_sum2 ]] &&
			error "Binary overwritten during exec"
	fi

	check_hsm_flags $f "0x00000009"
}
run_test 30c "Update during exec of released file must fail"

restore_and_check_size() {
	local f=$1
	local fid=$2
	local s=$(stat -c "%s" $f)
	local n=$s
	local st=$(get_hsm_flags $f)
	local err=0
	local cpt=0
	$LFS hsm_restore $f
	while [[ "$st" != "0x00000009" && $cpt -le 10 ]]
	do
		n=$(stat -c "%s" $f)
		# we echo in both cases to show stat is not hang
		if [[ $n != $s ]]; then
			echo "size seen is $n != $s"
			err=1
		else
			echo "size seen is right: $n == $s"
		fi
		sleep 10
		cpt=$((cpt + 1))
		st=$(get_hsm_flags $f)
	done
	if [[ "$st" = "0x00000009" ]]; then
		echo " "done
	else
		echo " restore is too long"
		wait_request_state $fid RESTORE SUCCEED
	fi
	return $err
}

test_31a() {
	# test needs a running copytool
	copytool setup

	create_archive_file $tdir/$tfile
	local f=$DIR/$tdir/$tfile
	copytool import $tdir/$tfile $f
	local fid=$($LFS path2fid $f)
	copytool setup

	restore_and_check_size $f $fid
	local err=$?

	[[ $err -eq 0 ]] || error "File size changed during restore"
}
run_test 31a "Import a large file and check size during restore"


test_31b() {
	# test needs a running copytool
	copytool setup

	local f=$DIR/$tdir/$tfile
	local fid=$(create_file "$f" 1MB 39)

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f

	restore_and_check_size $f $fid
	local err=$?

	[[ $err -eq 0 ]] || error "File size changed during restore"
}
run_test 31b "Restore a large unaligned file and check size during restore"

test_31c() {
	# test needs a running copytool
	copytool setup

	local f=$DIR/$tdir/$tfile
	local fid=$(create_file "$f" 1M 39)

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f

	restore_and_check_size $f $fid
	local err=$?

	[[ $err -eq 0 ]] || error "File size changed during restore"
}
run_test 31c "Restore a large aligned file and check size during restore"

test_33() {
	local f=$DIR/$tdir/$tfile
	local fid=$(create_empty_file "$f")

	copytool setup

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f

	# Prevent restore from completing
	copytool_suspend

	# Implicit restore
	md5sum $f >/dev/null &
	local pid=$!

	wait_request_state $fid RESTORE STARTED
	kill -15 $pid

	copytool_continue

	# Check restore trigger process was killed
	wait $pid
	[ $? -eq 143 ] || error "md5sum was not 'Terminated'"
}
run_test 33 "Kill a restore waiting process"

test_34() {
	# test needs a running copytool
	copytool setup -b 1

	local f=$DIR/$tdir/$tfile
	local fid=$(create_empty_file "$f")

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f

	# Prevent restore from completing
	copytool_suspend

	md5sum $f >/dev/null &
	local pid=$!

	wait_request_state $fid RESTORE STARTED

	# rm must not block during restore
	timeout --signal=KILL 1 rm "$f" || error "rm $f failed"

	copytool_continue
	wait_request_state $fid RESTORE SUCCEED

	# Check md5sum pgm finished
	kill -0 $pid && error "Restore initiatior still running"
	wait $pid || error "Restore initiator failed with $?"

	# Check the file was actually deleted
	[ ! -f "$f" ] || error "$f was not deleted"
}
run_test 34 "Remove file during restore"

test_35() {
	# test needs a running copytool
	copytool setup -b 1

	local f=$DIR/$tdir/$tfile
	local f1=$DIR/$tdir/$tfile-1
	local fid=$(create_empty_file "$f")
	local fid1=$(copy_file /etc/passwd $f1)

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f

	# Prevent restore from completing
	copytool_suspend

	md5sum $f >/dev/null &
	local pid=$!

	wait_request_state $fid RESTORE STARTED

	# mv must not block during restore
	timeout --signal=KILL 1 mv "$f1" "$f" || error "mv $f1 $f failed"

	copytool_continue
	wait_request_state $fid RESTORE SUCCEED

	# Check md5sum pgm finished
	kill -0 $pid && error "Restore initiatior still running"
	wait $pid || error "Restore initiator failed with $?"

	local fid2=$(path2fid $f)
	[[ $fid2 == $fid1 ]] || error "Wrong fid after mv $fid2 != $fid1"
}
run_test 35 "Overwrite file during restore"

test_36() {
	# test needs a running copytool
	copytool setup -b 1

	local f=$DIR/$tdir/$tfile
	local fid=$(create_empty_file "$f")

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f

	# Prevent restore from completing
	copytool_suspend

	md5sum $f >/dev/null &
	local pid=$!

	wait_request_state $fid RESTORE STARTED

	# mv must not block during restore
	timeout --signal=KILL 10 mv "$f" "$f.new" ||
		error "mv '$f' '$f.new' failed with rc=$?"

	copytool_continue
	wait_request_state $fid RESTORE SUCCEED

	# Check md5sum pgm finished
	kill -0 $pid && error "Restore initiator is still running"
	wait $pid || error "Restore initiator failed with $?"
}
run_test 36 "Move file during restore"

test_37() {
	# LU-5683: check that an archived dirty file can be rearchived.
	copytool setup

	local f=$DIR/$tdir/$tfile
	local fid

	fid=$(create_small_file $f) || error "cannot create small file"

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f || error "cannot release $f"

	# Allow previous archive request to expire from the actions log.
	wait_for_grace_delay

	# Dirty file.
	dd if=/dev/urandom of=$f bs=1M count=1 || error "cannot dirty file"

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
}
run_test 37 "re-archive a dirty file"

multi_archive() {
	local prefix=$1
	local count=$2
	local n=""

	for n in $(seq 1 $count); do
		$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $prefix.$n
	done
	echo "$count archive requests submitted"
}

test_40() {
	local stream_count=4
	local file_count=100
	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local i=""
	local p=""
	local fid=""
	local max_requests=$(get_hsm_param max_requests)

	stack_trap "set_hsm_param max_requests $max_requests" EXIT
	# Increase the number of HSM request that can be performed in
	# parallel. With the coordinator running once per second, this
	# also limits the number of requests per seconds that can be
	# performed, so we pick a decent number. But we also need to keep
	# that number low because the copytool has no rate limit and will
	# fail some requests if if gets too many at once.
	set_hsm_param max_requests 300

	for i in $(seq 1 $file_count); do
		for p in $(seq 1 $stream_count); do
			fid=$(copy_file /etc/hosts $f.$p.$i)
		done
	done

	copytool setup

	# to be sure wait_all_done will not be mislead by previous tests
	cdt_purge
	wait_for_grace_delay
	typeset -a pids
	# start archive streams in background (archive files in parallel)
	for p in $(seq 1 $stream_count); do
		multi_archive $f.$p $file_count &
		pids[$p]=$!
	done
	echo -n  "Wait for all requests being enqueued..."
	wait ${pids[*]}
	echo OK
	wait_all_done 100
}
run_test 40 "Parallel archive requests"

test_52() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(create_small_file $f)

	$LFS hsm_archive $f || error "could not archive file"
	wait_request_state $fid ARCHIVE SUCCEED
	check_hsm_flags $f "0x00000009"

	multiop_bg_pause $f O_c || error "multiop failed"
	local MULTIPID=$!

	mds_evict_client
	client_up || client_up || true

	kill -USR1 $MULTIPID
	wait $MULTIPID || error "multiop close failed"

	check_hsm_flags $f "0x0000000b"
}
run_test 52 "Opened for write file on an evicted client should be set dirty"

test_53() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(create_small_file $f)

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f ||
		error "could not archive file"
	wait_request_state $fid ARCHIVE SUCCEED
	check_hsm_flags $f "0x00000009"

	multiop_bg_pause $f o_c || error "multiop failed"
	MULTIPID=$!

	mds_evict_client
	client_up || client_up || true

	kill -USR1 $MULTIPID
	wait $MULTIPID || error "multiop close failed"

	check_hsm_flags $f "0x00000009"
}
run_test 53 "Opened for read file on an evicted client should not be set dirty"

test_54() {
	local f=$DIR/$tdir/$tfile
	local fid=$(create_file "$f" 1MB 39)

	copytool setup -b 1

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f ||
		error "could not archive file"
	wait_request_state $fid ARCHIVE STARTED

	check_hsm_flags $f "0x00000001"

	stack_trap "cdt_clear_no_retry" EXIT
	# Avoid coordinator resending this request as soon it has failed.
	cdt_set_no_retry

	echo "foo" >> $f
	sync
	wait_request_state $fid ARCHIVE FAILED

	check_hsm_flags $f "0x00000003"
}
run_test 54 "Write during an archive cancels it"

test_55() {
	local f=$DIR/$tdir/$tfile
	local fid=$(create_file "$f" 1MB 39)

	copytool setup -b 1

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f ||
		error "could not archive file"
	wait_request_state $fid ARCHIVE STARTED

	check_hsm_flags $f "0x00000001"

	stack_trap "cdt_clear_no_retry" EXIT
	# Avoid coordinator resending this request as soon it has failed.
	cdt_set_no_retry

	$TRUNCATE $f 1024 || error "truncate failed"
	sync
	wait_request_state $fid ARCHIVE FAILED

	check_hsm_flags $f "0x00000003"
}
run_test 55 "Truncate during an archive cancels it"

test_56() {
	local f=$DIR/$tdir/$tfile
	local fid=$(create_file "$f" 1MB 39)

	copytool setup -b 1

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f ||
		error "could not archive file"
	wait_request_state $fid ARCHIVE STARTED

	check_hsm_flags $f "0x00000001"

	# Change metadata and sync to be sure we are not changing only
	# in memory.
	chmod 644 $f
	chgrp sys $f
	sync
	wait_request_state $fid ARCHIVE SUCCEED

	check_hsm_flags $f "0x00000009"
}
run_test 56 "Setattr during an archive is ok"

test_57() {
	# Need one client for I/O, one for request
	needclients 2 || return 0

	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/test_archive_remote
	# Create a file on a remote node
	do_node $CLIENT2 "dd if=/dev/urandom of=$f bs=1M "\
		"count=2 conv=fsync"

	# And archive it
	do_node $CLIENT2 "$LFS hsm_archive -a $HSM_ARCHIVE_NUMBER $f" ||
		error "hsm_archive failed"
	local fid=$(path2fid $f)
	wait_request_state $fid ARCHIVE SUCCEED

	# Release and implicit restore it
	do_node $CLIENT2 "$LFS hsm_release $f" ||
		error "hsm_release failed"
	do_node $CLIENT2 "md5sum $f" ||
		error "hsm_restore failed"

	wait_request_state $fid RESTORE SUCCEED
}
run_test 57 "Archive a file with dirty cache on another node"

truncate_released_file() {
	local src_file=$1
	local trunc_to=$2

	local sz=$(stat -c %s $src_file)
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file $1 $f)
	local ref=$f-ref
	cp $f $f-ref

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f ||
		error "could not archive file"
	wait_request_state $fid ARCHIVE SUCCEED

	$LFS hsm_release $f || error "could not release file"

	$TRUNCATE $f $trunc_to || error "truncate failed"
	sync

	local sz1=$(stat -c %s $f)
	[[ $sz1 == $trunc_to ]] ||
		error "size after trunc: $sz1 expect $trunc_to, original $sz"

	$LFS hsm_state $f
	check_hsm_flags $f "0x0000000b"

	local state=$(get_request_state $fid RESTORE)
	[[ "$state" == "SUCCEED" ]] ||
		error "truncate $sz does not trig restore, state = $state"

	$TRUNCATE $ref $trunc_to
	cmp $ref $f || error "file data wrong after truncate"

	rm -f $f $f-ref
}

test_58() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir

	local sz=$(stat -c %s /etc/passwd)

	echo "truncate up from $sz to $((sz*2))"
	truncate_released_file /etc/passwd $((sz*2))

	echo "truncate down from $sz to $((sz/2))"
	truncate_released_file /etc/passwd $((sz/2))

	echo "truncate to 0"
	truncate_released_file /etc/passwd 0
}
run_test 58 "Truncate a released file will trigger restore"

test_59() {
	local fid
	[[ $MDS1_VERSION -lt $(version_code 2.7.63) ]] &&
		skip "Need MDS version at least 2.7.63"

	copytool setup
	$MCREATE $DIR/$tfile || error "mcreate failed"
	$TRUNCATE $DIR/$tfile 42 || error "truncate failed"
	$LFS hsm_archive $DIR/$tfile || error "archive request failed"
	fid=$(path2fid $DIR/$tfile)
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $DIR/$tfile || error "release failed"
}
run_test 59 "Release stripeless file with non-zero size"

test_60() {
	# This test validates the fix for LU-4512. Ensure that the -u
	# option changes the progress reporting interval from the
	# default (30 seconds) to the user-specified interval.
	local f=$DIR/$tdir/$tfile
	local fid=$(create_file "$f" 1M 10)

	local interval=5
	local progress_timeout=$((interval * 4))
	copytool setup -b 1 --update-interval $interval

	local mdtidx=0
	local mdt=${MDT_PREFIX}${mdtidx}
	local mds=mds$((mdtidx + 1))

	# Wait for copytool to register
	wait_update_facet $mds \
		"$LCTL get_param -n ${mdt}.hsm.agents | grep -o ^uuid" \
		uuid 100 || error "coyptool failed to register with $mdt"

	local start_at=$(date +%s)
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f ||
		error "could not archive file"

	local agent=$(facet_active_host $SINGLEAGT)
	local logfile=$(copytool_logfile $SINGLEAGT)

	wait_update $agent \
	    "grep -o start.copy \"$logfile\"" "start copy" 100 ||
		error "copytool failed to start"

	local cmd="$LCTL get_param -n ${mdt}.hsm.active_requests"
	cmd+=" | awk '/'$fid'.*action=ARCHIVE/ {print \\\$12}' | cut -f2 -d="

	local RESULT
	local WAIT=0
	local sleep=1

	echo -n "Expecting a progress update within $progress_timeout seconds... "
	while [ true ]; do
		RESULT=$(do_node $(facet_active_host $mds) "$cmd")
		if [ -n "$RESULT" ] && [ "$RESULT" -gt 0 ]; then
			echo "$RESULT bytes copied in $WAIT seconds."
			break
		elif [ $WAIT -ge $progress_timeout ]; then
			error "Timed out waiting for progress update!"
			break
		fi
		WAIT=$((WAIT + sleep))
		sleep $sleep
	done

	local finish_at=$(date +%s)
	local elapsed=$((finish_at - start_at))

	# Ensure that the progress update occurred within the expected window.
	if [ $elapsed -lt $((interval - 1)) ]; then
		error "Expected progress update after at least $interval seconds"
	fi

	echo "Wait for on going archive hsm action to complete"
	wait_update $agent "grep -o copied \"$logfile\"" "copied" 10 ||
		echo "File archiving not completed even after 10 secs"
}
run_test 60 "Changing progress update interval from default"

test_61() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/passwd $f)
	cdt_disable
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	rm -f $f
	cdt_enable
	wait_request_state $fid ARCHIVE FAILED
}
run_test 61 "Waiting archive of a removed file should fail"

test_70() {
	# test needs a new running copytool
	stack_trap copytool_monitor_cleanup EXIT
	copytool_monitor_setup
	copytool setup --event-fifo "$HSMTOOL_MONITOR_DIR/fifo"

	# Wait for the copytool to register.
	wait_update --verbose $(facet_active_host mds1) \
		"$LCTL get_param -n ${MDT_PREFIX}0.hsm.agents | grep -o ^uuid" \
		uuid 100 ||
		error "copytool failed to register with MDT0000"

	kill_copytools
	wait_copytools || error "Copytools failed to stop"

	local REGISTER_EVENT
	local UNREGISTER_EVENT
	while read event; do
		local parsed=$(parse_json_event "$event")
		if [ -z "$parsed" ]; then
			error "Copytool sent malformed event: $event"
		fi
		eval $parsed

		if [ $event_type == "REGISTER" ]; then
			REGISTER_EVENT=$event
		elif [ $event_type == "UNREGISTER" ]; then
			UNREGISTER_EVENT=$event
		fi
	done < <(echo $"$(get_copytool_event_log)")

	if [ -z "$REGISTER_EVENT" ]; then
		error "Copytool failed to send register event to FIFO"
	fi

	if [ -z "$UNREGISTER_EVENT" ]; then
		error "Copytool failed to send unregister event to FIFO"
	fi

	echo "Register/Unregister events look OK."
}
run_test 70 "Copytool logs JSON register/unregister events to FIFO"

test_71() {
	# Bump progress interval for livelier events.
	local interval=5

	# test needs a new running copytool
	stack_trap copytool_monitor_cleanup EXIT
	copytool_monitor_setup
	copytool setup --update-interval $interval --event-fifo \
		"$HSMTOOL_MONITOR_DIR/fifo"

	stack_trap "cdt_clear_no_retry" EXIT
	# Just start and stop the copytool to generate events.
	cdt_clear_no_retry

	local f=$DIR/$tdir/$tfile
	local fid=$(create_small_file "$f")

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f ||
		error "could not archive file"
	wait_request_state $fid ARCHIVE SUCCEED

	local expected_fields="event_time data_fid source_fid"
	expected_fields+=" total_bytes current_bytes"

	local -A events=(
		[ARCHIVE_START]=false
		[ARCHIVE_FINISH]=false
		[ARCHIVE_RUNNING]=false
		)
	while read event; do
		# Make sure we're not getting anything from previous events.
		for field in $expected_fields; do
			unset $field
		done

		local parsed=$(parse_json_event "$event")
		if [ -z "$parsed" ]; then
			error "Copytool sent malformed event: $event"
		fi
		eval $parsed

		events["$event_type"]=true

		[ "$event_type" != ARCHIVE_RUNNING ] && continue

		# Do some simple checking of the progress update events.
		for expected_field in $expected_fields; do
			if [ -z ${!expected_field+x} ]; then
				error "Missing $expected_field field in event"
			fi
		done

		[ $total_bytes -gt 0 ] || error "Expected total_bytes to be > 0"

		# These should be identical throughout an archive operation
		[ $source_fid == $data_fid ] ||
			error "Expected source_fid to equal data_fid"
	done < <(echo $"$(get_copytool_event_log)")

	# Check we received every type of events we were expecting
	for event in "${!events[@]}"; do
		${events["$event"]} ||
			error "Copytool failed to send '$event' event to FIFO"
	done

	echo "Archive events look OK."
}
run_test 71 "Copytool logs JSON archive events to FIFO"

test_72() {
	# Bump progress interval for livelier events.
	local interval=5

	# test needs a new running copytool
	stack_trap copytool_monitor_cleanup EXIT
	copytool_monitor_setup
	copytool setup --update-interval $interval --event-fifo \
		"$HSMTOOL_MONITOR_DIR/fifo"
	local test_file=$HSMTOOL_MONITOR_DIR/file

	local cmd="dd if=/dev/urandom of=$test_file count=16 bs=1000000 "
	cmd+="conv=fsync"
	do_facet $SINGLEAGT "$cmd" ||
		error "cannot create $test_file on $SINGLEAGT"
	copy2archive $test_file $tdir/$tfile

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	copytool import $tdir/$tfile $f
	f=$DIR2/$tdir/$tfile
	echo "Verifying released state: "
	check_hsm_flags $f "0x0000000d"

	local fid=$(path2fid $f)
	$LFS hsm_restore $f
	wait_request_state $fid RESTORE SUCCEED

	local expected_fields="event_time data_fid source_fid"
	expected_fields+=" total_bytes current_bytes"

	local START_EVENT
	local FINISH_EVENT
	while read event; do
		# Make sure we're not getting anything from previous events.
		for field in $expected_fields; do
			unset $field
		done

		local parsed=$(parse_json_event "$event")
		if [ -z "$parsed" ]; then
			error "Copytool sent malformed event: $event"
		fi
		eval $parsed

		if [ $event_type == "RESTORE_START" ]; then
			START_EVENT=$event
			if [ $source_fid != $data_fid ]; then
				error "source_fid should == data_fid at start"
			fi
			continue
		elif [ $event_type == "RESTORE_FINISH" ]; then
			FINISH_EVENT=$event
			if [ $source_fid != $data_fid ]; then
				error "source_fid should == data_fid at finish"
			fi
			continue
		elif [ $event_type != "RESTORE_RUNNING" ]; then
			continue
		fi

		# Do some simple checking of the progress update events.
		for expected_field in $expected_fields; do
			if [ -z ${!expected_field+x} ]; then
				error "Missing $expected_field field in event"
			fi
		done

		if [ $total_bytes -eq 0 ]; then
			error "Expected total_bytes to be > 0"
		fi

		# When a restore starts out, the data fid is the same as the
		# source fid. After the restore has gotten going, we learn
		# the new data fid. Once the restore has finished, the source
		# fid is set to the new data fid.
		#
		# We test this because some monitoring software may depend on
		# this behavior. If it changes, then the consumers of these
		# events may need to be modified.
		if [ $source_fid == $data_fid ]; then
			error "source_fid should != data_fid during restore"
		fi
	done < <(echo $"$(get_copytool_event_log)")

	if [ -z "$START_EVENT" ]; then
		error "Copytool failed to send restore start event to FIFO"
	fi

	if [ -z "$FINISH_EVENT" ]; then
		error "Copytool failed to send restore finish event to FIFO"
	fi

	echo "Restore events look OK."
}
run_test 72 "Copytool logs JSON restore events to FIFO"

test_90() {
	file_count=51 # Max number of files constrained by LNET message size
	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	local f=$DIR/$tdir/$tfile
	local FILELIST=/tmp/filelist.txt
	local i=""

	rm -f $FILELIST
	for i in $(seq 1 $file_count); do
		fid=$(copy_file /etc/hosts $f.$i)
		echo $f.$i >> $FILELIST
	done

	copytool setup
	# to be sure wait_all_done will not be mislead by previous tests
	cdt_purge
	wait_for_grace_delay
	$LFS hsm_archive --filelist $FILELIST ||
		error "cannot archive a file list"
	wait_all_done 200
	$LFS hsm_release --filelist $FILELIST ||
		error "cannot release a file list"
	$LFS hsm_restore --filelist $FILELIST ||
		error "cannot restore a file list"
	wait_all_done 200
}
run_test 90 "Archive/restore a file list"

double_verify_reset_hsm_param() {
	local p=$1
	echo "Testing $HSM_PARAM.$p"
	local val=$(get_hsm_param $p)
	local save=$val
	local val2=$(($val * 2))
	set_hsm_param $p $val2
	val=$(get_hsm_param $p)
	[[ $val == $val2 ]] ||
		error "$HSM_PARAM.$p: $val != $val2 should be (2 * $save)"
	echo "Set $p to 0 must failed"
	set_hsm_param $p 0
	local rc=$?
	# restore value
	set_hsm_param $p $save

	if [[ $rc == 0 ]]; then
		error "we must not be able to set $HSM_PARAM.$p to 0"
	fi
}

test_100() {
	double_verify_reset_hsm_param loop_period
	double_verify_reset_hsm_param grace_delay
	double_verify_reset_hsm_param active_request_timeout
	double_verify_reset_hsm_param max_requests
	double_verify_reset_hsm_param default_archive_id
}
run_test 100 "Set coordinator /proc tunables"

test_102() {
	cdt_disable
	cdt_enable
	cdt_restart
}
run_test 102 "Verify coordinator control"

test_103() {
	# test needs a running copytool
	copytool setup

	local i=""
	local fid=""

	mkdir -p $DIR/$tdir
	for i in $(seq 1 20); do
		fid=$(copy_file /etc/passwd $DIR/$tdir/$i)
	done
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $DIR/$tdir/*

	cdt_purge

	echo "Current requests"
	local res=$(do_facet $SINGLEMDS "$LCTL get_param -n\
			$HSM_PARAM.actions |\
			grep -v CANCELED | grep -v SUCCEED | grep -v FAILED")

	[[ -z "$res" ]] || error "Some request have not been canceled"
}
run_test 103 "Purge all requests"

DATA=CEA
DATAHEX='[434541]'
test_104() {
	local f=$DIR/$tdir/$tfile
	local fid=$(create_empty_file "$f")

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER --data $DATA $f
	local data1=$(do_facet $SINGLEMDS "$LCTL get_param -n\
			$HSM_PARAM.actions |\
			grep $fid | cut -f16 -d=")

	[[ "$data1" == "$DATAHEX" ]] ||
		error "Data field in records is ($data1) and not ($DATAHEX)"

	cdt_purge
}
run_test 104 "Copy tool data field"

test_105() {
	local max_requests=$(get_hsm_param max_requests)
	mkdir -p $DIR/$tdir
	local i=""

	stack_trap "set_hsm_param max_requests $max_requests" EXIT
	set_hsm_param max_requests 300

	cdt_disable
	for i in $(seq -w 1 10); do
		cp /etc/passwd $DIR/$tdir/$i
		$LFS hsm_archive $DIR/$tdir/$i
	done
	local reqcnt1=$(do_facet $SINGLEMDS "$LCTL get_param -n\
			$HSM_PARAM.actions |\
			grep WAITING | wc -l")
	cdt_restart

	cdt_disable
	local reqcnt2=$(do_facet $SINGLEMDS "$LCTL get_param -n\
			$HSM_PARAM.actions |\
			grep WAITING | wc -l")
	cdt_enable
	cdt_purge
	[[ "$reqcnt1" == "$reqcnt2" ]] ||
		error "Requests count after shutdown $reqcnt2 != "\
		      "before shutdown $reqcnt1"
}
run_test 105 "Restart of coordinator"

test_106() {
	# test needs a running copytool
	copytool setup

	local uuid=$(get_agent_uuid $(facet_active_host $SINGLEAGT))

	check_agent_registered $uuid

	search_copytools || error "No copytool found"

	kill_copytools
	wait_copytools || error "Copytool failed to stop"

	check_agent_unregistered $uuid

	copytool setup
	uuid=$(get_agent_uuid $(facet_active_host $SINGLEAGT))
	check_agent_registered $uuid
}
run_test 106 "Copytool register/unregister"

test_107() {
	[ "$CLIENTONLY" ] && skip "CLIENTONLY mode" && return

	# test needs a running copytool
	copytool setup
	# create and archive file
	mkdir -p $DIR/$tdir
	local f1=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/passwd $f1)
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f1
	wait_request_state $fid ARCHIVE SUCCEED
	# shutdown and restart MDS
	fail $SINGLEMDS
	# check the copytool still gets messages from MDT
	local f2=$DIR/$tdir/2
	local fid=$(copy_file /etc/passwd $f2)
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f2
	# main check of this sanity: this request MUST succeed
	wait_request_state $fid ARCHIVE SUCCEED
}
run_test 107 "Copytool re-register after MDS restart"

policy_set_and_test()
{
	local change="$1"
	local target="$2"
	do_facet $SINGLEMDS $LCTL set_param "$HSM_PARAM.policy=\\\"$change\\\""
	local policy=$(do_facet $SINGLEMDS $LCTL get_param -n $HSM_PARAM.policy)
	[[ "$policy" == "$target" ]] ||
		error "Wrong policy after '$change': '$policy' != '$target'"
}

test_109() {
	# to force default policy setting if error
	CDT_POLICY_HAD_CHANGED=true

	local policy=$(do_facet $SINGLEMDS $LCTL get_param -n $HSM_PARAM.policy)
	local default="NonBlockingRestore [NoRetryAction]"
	[[ "$policy" == "$default" ]] ||
		error "default policy has changed,"\
		      " '$policy' != '$default' update the test"
	policy_set_and_test "+NBR" "[NonBlockingRestore] [NoRetryAction]"
	policy_set_and_test "+NRA" "[NonBlockingRestore] [NoRetryAction]"
	policy_set_and_test "-NBR" "NonBlockingRestore [NoRetryAction]"
	policy_set_and_test "-NRA" "NonBlockingRestore NoRetryAction"
	policy_set_and_test "NRA NBR" "[NonBlockingRestore] [NoRetryAction]"
	# useless bacause we know but safer for futur changes to use real value
	local policy=$(do_facet $SINGLEMDS $LCTL get_param -n $HSM_PARAM.policy)
	echo "Next set_param must failed"
	policy_set_and_test "wrong" "$policy"

	# return to default
	echo "Back to default policy"
	cdt_set_sanity_policy
}
run_test 109 "Policy display/change"

test_110a() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir

	copy2archive /etc/passwd $tdir/$tfile

	local f=$DIR/$tdir/$tfile
	copytool import $tdir/$tfile $f
	local fid=$(path2fid $f)

	cdt_set_non_blocking_restore
	md5sum $f
	local st=$?

	# cleanup
	wait_request_state $fid RESTORE SUCCEED
	cdt_clear_non_blocking_restore

	# Test result
	[[ $st == 1 ]] ||
		error "md5sum returns $st != 1, "\
			"should also perror ENODATA (No data available)"
}
run_test 110a "Non blocking restore policy (import case)"

test_110b() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/passwd $f)
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f

	cdt_set_non_blocking_restore
	md5sum $f
	local st=$?

	# cleanup
	wait_request_state $fid RESTORE SUCCEED
	cdt_clear_non_blocking_restore

	# Test result
	[[ $st == 1 ]] ||
		error "md5sum returns $st != 1, "\
			"should also perror ENODATA (No data available)"
}
run_test 110b "Non blocking restore policy (release case)"

test_111a() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	copy2archive /etc/passwd $tdir/$tfile

	local f=$DIR/$tdir/$tfile

	copytool import $tdir/$tfile $f
	local fid=$(path2fid $f)

	cdt_set_no_retry

	copytool_remove_backend $fid

	$LFS hsm_restore $f
	wait_request_state $fid RESTORE FAILED
	local st=$?

	# cleanup
	cdt_clear_no_retry

	# Test result
	[[ $st == 0 ]] || error "Restore does not failed"
}
run_test 111a "No retry policy (import case), restore will error"\
	      " (No such file or directory)"

test_111b() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/passwd $f)
	stack_trap cdt_clear_no_retry EXIT
	cdt_set_no_retry
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f

	copytool_remove_backend $fid

	$LFS hsm_restore $f
	wait_request_state $fid RESTORE FAILED
	local st=$?

	# Test result
	[[ $st == 0 ]] || error "Restore does not failed"
}
run_test 111b "No retry policy (release case), restore will error"\
	      " (No such file or directory)"

test_112() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/passwd $f)
	cdt_disable
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	local l=$($LFS hsm_action $f)
	echo $l
	local res=$(echo $l | cut -f 2- -d" " | grep ARCHIVE)

	cdt_enable
	wait_request_state $fid ARCHIVE SUCCEED

	# Test result
	[[ ! -z "$res" ]] || error "action is $l which is not an ARCHIVE"
}
run_test 112 "State of recorded request"

test_113() {
	local file1=$DIR/$tdir/$tfile
	local file2=$DIR2/$tdir/$tfile

	local fid=$(create_small_sync_file $file1)

	stack_trap "zconf_umount \"$(facet_host $SINGLEAGT)\" \"$MOUNT3\"" EXIT
	zconf_mount "$(facet_host $SINGLEAGT)" "$MOUNT3" ||
		error "cannot mount '$MOUNT3' on '$SINGLEAGT'"

	copytool setup -m  "$MOUNT3"

	do_nodes $(comma_list $(nodes_list)) $LCTL clear

	$LFS hsm_archive $file1 || error "Fail to archive $file1"
	wait_request_state $fid ARCHIVE SUCCEED

	$LFS hsm_release $file1
	echo "Verifying released state: "
	check_hsm_flags $file1 "0x0000000d"

	multiop_bg_pause $file1 oO_WRONLY:O_APPEND:_w4c || error "multiop failed"
	MULTIPID=$!
	stat $file2 &
	kill -USR1 $MULTIPID

	wait
	sync

	local size1=$(stat -c "%s" $file1)
	local size2=$(stat -c "%s" $file2)

	[ $size1 -eq $size2 ] || error "sizes are different $size1 $size2"
}
run_test 113 "wrong stat after restore"

test_200() {
	local f=$DIR/$tdir/$tfile
	local fid=$(create_empty_file "$f")

	copytool setup

	# Prevent archive from completing
	copytool_suspend

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	# wait archive to register at CDT
	wait_request_state $fid ARCHIVE STARTED

	# Cancel the archive
	$LFS hsm_cancel "$f"

	wait_request_state $fid ARCHIVE CANCELED

	copytool_continue
	wait_request_state $fid CANCEL SUCCEED
}
run_test 200 "Register/Cancel archive"

test_201() {
	# test needs a running copytool
	copytool setup

	local f=$DIR/$tdir/$tfile
	create_archive_file $tdir/$tfile
	copytool import $tdir/$tfile $f
	local fid=$(path2fid $f)

	# test with cdt on is made in test_222
	cdt_disable
	$LFS hsm_restore $f
	# wait restore to register at CDT
	wait_request_state $fid RESTORE WAITING
	$LFS hsm_cancel $f
	cdt_enable
	wait_request_state $fid RESTORE CANCELED
	wait_request_state $fid CANCEL SUCCEED
}
run_test 201 "Register/Cancel restore"

test_202() {
	local f=$DIR/$tdir/$tfile
	local fid=$(create_empty_file "$f")

	# test needs a running copytool
	copytool setup

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED

	copytool_suspend
	$LFS hsm_remove $f
	# wait remove to register at CDT
	wait_request_state $fid REMOVE STARTED
	$LFS hsm_cancel $f

	wait_request_state $fid REMOVE CANCELED
}
run_test 202 "Register/Cancel remove"

test_220A() { # was test_220
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir

	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/passwd $f)

	changelog_register

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED

	changelog_find -type HSM -target-fid $fid -flags 0x0 ||
		error "The expected changelog was not emitted"
}
run_test 220A "Changelog for archive"

test_220a() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir

	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/passwd $f)

	changelog_register

	# block copytool operations to allow for HSM request to be
	# submitted and file be unlinked (CDT will find object removed)
	copytool_suspend

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f

	# wait request to reach CT
	wait_request_state $fid ARCHIVE STARTED

	rm -f $f

	copytool_continue

	wait_request_state $fid ARCHIVE FAILED

	# HE_ARCHIVE|ENOENT
	changelog_find -type HSM -target-fid $fid -flags 0x2 ||
		error "The expected changelog was not emitted"
}
run_test 220a "Changelog for failed archive"

test_221() {
	local f=$DIR/$tdir/$tfile
	local fid=$(create_empty_file "$f")

	copytool setup -b 1
	changelog_register

	# Prevent archive from completing
	copytool_suspend
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE STARTED

	$LFS hsm_cancel $f
	wait_request_state $fid ARCHIVE CANCELED

	copytool_continue
	wait_request_state $fid CANCEL SUCCEED

	changelog_find -type HSM -target-fid $fid -flags 0x7d ||
		error "The expected changelog was not emitted"
}
run_test 221 "Changelog for archive canceled"

test_222a() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	copy2archive /etc/passwd $tdir/$tfile

	local f=$DIR/$tdir/$tfile
	copytool import $tdir/$tfile $f
	local fid=$(path2fid $f)

	changelog_register

	$LFS hsm_restore $f
	wait_request_state $fid RESTORE SUCCEED

	changelog_find -type HSM -target-fid $fid -flags 0x80 ||
		error "The expected changelog was not emitted"
}
run_test 222a "Changelog for explicit restore"

test_222b() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/passwd $f)

	changelog_register
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f

	md5sum $f

	wait_request_state $fid RESTORE SUCCEED

	changelog_find -type HSM -target-fid $fid -flags 0x80 ||
		error "The expected changelog was not emitted"
}
run_test 222b "Changelog for implicit restore"

test_222c() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	copy2archive /etc/passwd $tdir/$tfile

	local f=$DIR/$tdir/$tfile
	copytool import $tdir/$tfile $f
	local fid=$(path2fid $f)

	changelog_register

	# block copytool operations to allow for HSM request to be
	# submitted and file be unlinked (CDT will find object removed)
	copytool_suspend

	$LFS hsm_restore $f

	# wait request to reach CT
	wait_request_state $fid RESTORE STARTED

	rm -f $f

	copytool_continue

	wait_request_state $fid RESTORE FAILED

	# HE_RESTORE|ENOENT
	changelog_find -type HSM -target-fid $fid -flags 0x82 ||
		error "The expected changelog was not emitted"
}
run_test 222c "Changelog for failed explicit restore"

test_222d() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/passwd $f)

	changelog_register
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f

	copytool_remove_backend $fid
	md5sum $f

	wait_request_state $fid RESTORE FAILED

	# HE_RESTORE|ENOENT
	changelog_find -type HSM -target-fid $fid -flags 0x82 ||
		error "The expected changelog was not emitted"
}
run_test 222d "Changelog for failed implicit restore"

test_223a() {
	# test needs a running copytool
	copytool setup -b 1

	local f=$DIR/$tdir/$tfile
	create_archive_file $tdir/$tfile

	changelog_register

	copytool import $tdir/$tfile $f
	local fid=$(path2fid $f)

	$LFS hsm_restore $f
	wait_request_state $fid RESTORE STARTED
	$LFS hsm_cancel $f
	wait_request_state $fid RESTORE CANCELED
	wait_request_state $fid CANCEL SUCCEED

	changelog_find -type HSM -target-fid $fid -flags 0xfd ||
		error "The expected changelog was not emitted"
}
run_test 223a "Changelog for restore canceled (import case)"

test_223b() {
	local f=$DIR/$tdir/$tfile
	local fid=$(create_empty_file "$f")

	copytool setup -b 1
	changelog_register

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f

	# Prevent restore from completing
	copytool_suspend
	$LFS hsm_restore $f
	wait_request_state $fid RESTORE STARTED

	$LFS hsm_cancel $f
	wait_request_state $fid RESTORE CANCELED

	copytool_continue
	wait_request_state $fid CANCEL SUCCEED

	changelog_find -type HSM -target-fid $fid -flags 0xfd ||
		error "The expected changelog was not emitted"
}
run_test 223b "Changelog for restore canceled (release case)"

test_224A() { # was test_224
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir

	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/passwd $f)

	changelog_register
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED

	$LFS hsm_remove $f
	wait_request_state $fid REMOVE SUCCEED

	changelog_find -type HSM -target-fid $fid -flags 0x200 ||
		error "The expected changelog was not emitted"
}
run_test 224A "Changelog for remove"

test_224a() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir

	local f=$DIR/$tdir/$tfile
	local fid=$(copy_file /etc/passwd $f)

	changelog_register
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED

	copytool_remove_backend $fid

	# block copytool operations to allow for HSM request to be
	# submitted and file be unlinked (CDT will find object removed)
	copytool_suspend

	$LFS hsm_remove $f

	# wait for request to reach CT
	wait_request_state $fid REMOVE STARTED

	rm -f $f

	copytool_continue

	wait_request_state $fid REMOVE FAILED

	# HE_REMOVE|ENOENT=0x202
	changelog_find -type HSM -target-fid $fid -flags 0x202 ||
		error "The expected changelog was not emitted"
}
run_test 224a "Changelog for failed remove"

test_225() {
	# test is not usable because remove request is too fast
	# so it is always finished before cancel can be done ...
	echo "Test disabled"
	return 0

	# test needs a running copytool
	copytool setup

	local f=$DIR/$tdir/$tfile
	local fid=$(create_empty_file "$f")

	changelog_register
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED

	# Prevent restore from completing
	copytool_suspend
	$LFS hsm_remove $f

	$LFS hsm_cancel $f
	wait_request_state $fid REMOVE CANCELED

	copytool_continue
	wait_request_state $fid CANCEL SUCCEED

	changelog_find -type HSM -target-fid $fid -flags 0x27d
		error "The expected changelog was not emitted"
}
run_test 225 "Changelog for remove canceled"

test_226() {
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir

	local f1=$DIR/$tdir/$tfile-1
	local f2=$DIR/$tdir/$tfile-2
	local f3=$DIR/$tdir/$tfile-3
	local fid1=$(copy_file /etc/passwd $f1)
	local fid2=$(copy_file /etc/passwd $f2)
	copy_file /etc/passwd $f3

	changelog_register
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f1
	wait_request_state $fid1 ARCHIVE SUCCEED

	$LFS hsm_archive $f2
	wait_request_state $fid2 ARCHIVE SUCCEED

	rm $f1 || error "rm $f1 failed"

	changelog_dump
	changelog_find -type UNLNK -target-fid $fid1 -flags 0x3 ||
		error "The expected changelog was not emitted"

	mv $f3 $f2 || error "mv $f3 $f2 failed"

	changelog_find -type RENME -target-fid $fid2 -flags 0x3 ||
		error "The expected changelog was not emitted"
}
run_test 226 "changelog for last rm/mv with exiting archive"

# This is just a utility function to clarify what test_227 does
__test_227()
{
	local target=0x280

	"$LFS" "$action" --$flag "$file" ||
		error "Cannot ${action#hsm_} $flag on '$file'"

	# Only one changelog should be produced
	local entries="$(changelog_find -type HSM -target-fid $fid)"
	[ $(wc -l <<< "$entries") -eq $((++count)) ] ||
		error "lfs $action --$flag '$file' produced more than one" \
		      "changelog record"

	# Parse the last changelog record
	local entry="$(tail -n 1 <<< "$entries")"
	eval local -A changelog=$(changelog2array $entry)

	# Also check the flags match what is expected
	[[ ${changelog[flags]} == $target ]] ||
		error "Changelog flag is '${changelog[flags]}', not $target"
}

test_227() {
	local file="$DIR/$tdir/$tfile"
	local fid=$(create_empty_file "$file")
	local count=0

	changelog_register

	for flag in norelease noarchive exists archived lost; do
		if [ "$flag" == lost ]; then
			# The flag "lost" only works on an archived file
			"$LFS" hsm_set --archived "$file"
			((count++))
		fi

		action="hsm_set" __test_227
		action="hsm_clear" __test_227
	done
}
run_test 227 "changelog when explicit setting of HSM flags"

test_228() {
	# test needs a running copytool
	copytool setup

	local fid=$(create_small_sync_file $DIR/$tfile)
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $DIR/$tfile
	wait_request_state $fid ARCHIVE SUCCEED

	$LFS hsm_release $DIR/$tfile
	check_hsm_flags $DIR/$tfile "0x0000000d"

	filefrag $DIR/$tfile | grep " 1 extent found" ||
		error "filefrag on released file must return only one extent"

	# only newer versions of cp detect sparse files by stat/FIEMAP
	# (LU-2580)
	cp --sparse=auto $DIR/$tfile $DIR/$tfile.2 ||
		error "copying $DIR/$tfile"
	cmp $DIR/$tfile $DIR/$tfile.2 || error "comparing copied $DIR/$tfile"

	$LFS hsm_release $DIR/$tfile
	check_hsm_flags $DIR/$tfile "0x0000000d"

	mkdir -p $DIR/$tdir || error "mkdir $tdir failed"

	tar cf - --sparse $DIR/$tfile | tar xvf - -C $DIR/$tdir ||
		error "tar failed"
	cmp $DIR/$tfile $DIR/$tdir/$DIR/$tfile ||
		error "comparing untarred $DIR/$tfile"

	rm -f $DIR/$tfile $DIR/$tfile.2 ||
		error "rm $DIR/$tfile or $DIR/$tfile.2 failed"
}
run_test 228 "On released file, return extend to FIEMAP. For [cp,tar] --sparse"

test_250() {
	local file="$DIR/$tdir/$tfile"

	# set max_requests to allow one request of each type to be started (3)
	stack_trap \
		"set_hsm_param max_requests $(get_hsm_param max_requests)" EXIT
	set_hsm_param max_requests 3
	# speed up test
	stack_trap \
		"set_hsm_param loop_period $(get_hsm_param loop_period)" EXIT
	set_hsm_param loop_period 1

	# send 1 requests of each kind twice
	copytool setup
	# setup the files
	for action in archive restore remove; do
		local filepath="$file"-to-$action
		local fid=$(create_empty_file "$filepath")
		local fid2=$(create_empty_file "$filepath".bis)

		if [ "$action" != archive ]; then
			"$LFS" hsm_archive "$filepath"
			wait_request_state $fid ARCHIVE SUCCEED
			"$LFS" hsm_archive "$filepath".bis
			wait_request_state $fid2 ARCHIVE SUCCEED
		fi
		if [ "$action" == restore ]; then
			"$LFS" hsm_release "$filepath"
			"$LFS" hsm_release "$filepath".bis
		fi
	done

	# suspend the copytool to prevent requests from completing
	stack_trap "copytool_continue" EXIT
	copytool_suspend

	# send `max_requests' requests (one of each kind)
	for action in archive restore remove; do
		filepath="$file"-to-$action
		"$LFS" hsm_${action} "$filepath"
		wait_request_state $(path2fid "$filepath") "${action^^}" STARTED
	done

	# send another batch of requests
	for action in archive restore remove; do
		"$LFS" hsm_${action} "$file-to-$action".bis
	done
	# wait for `loop_period' seconds to make sure the coordinator has time
	# to register those, even though it should not
	sleep 1

	# only the first batch of request should be started
	local -i count
	count=$(do_facet $SINGLEMDS "$LCTL" get_param -n $HSM_PARAM.actions |
		grep -c STARTED)

	((count == 3)) ||
		error "expected 3 STARTED requests, found $count"
}
run_test 250 "Coordinator max request"

test_251() {
	local f=$DIR/$tdir/$tfile
	local fid=$(create_empty_file "$f")

	cdt_disable
	# to have a short test
	local old_to=$(get_hsm_param active_request_timeout)
	set_hsm_param active_request_timeout 1
	# to be sure the cdt will wake up frequently so
	# it will be able to cancel the "old" request
	local old_loop=$(get_hsm_param loop_period)
	set_hsm_param loop_period 1
	cdt_enable

	copytool setup

	# Prevent archive from completing
	copytool_suspend
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE STARTED

	# Let the request timeout
	wait_request_state $fid ARCHIVE CANCELED

	set_hsm_param active_request_timeout $old_to
	set_hsm_param loop_period $old_loop
}
run_test 251 "Coordinator request timeout"

test_252() {
	local f=$DIR/$tdir/$tfile
	local fid=$(create_empty_file "$f")

	# to have a short test
	stack_trap "set_hsm_param loop_period $(get_hsm_param loop_period)" EXIT
	set_hsm_param loop_period 1

	copytool setup

	# Prevent archive from completing
	copytool_suspend
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE STARTED
	rm -f "$f"

	stack_trap "set_hsm_param active_request_timeout \
		    $(get_hsm_param active_request_timeout)" EXIT
	set_hsm_param active_request_timeout 1

	wait_request_state $fid ARCHIVE CANCELED
	copytool_continue
}
run_test 252 "Timeout'ed running archive of a removed file should be canceled"

test_253() {
	local rc
	# test needs a running copytool
	copytool setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/$tfile

	dd if=/dev/zero of=$f bs=1MB count=10
	local fid=$(path2fid $f)

	$LFS hsm_archive $f || error "could not archive file"
	wait_request_state $fid ARCHIVE SUCCEED

	# clear locks to discard inode data
	cancel_lru_locks osc

	#define OBD_FAIL_MDC_MERGE              0x807
	$LCTL set_param fail_loc=0x807

	#expect error here, instead of release with wrong size
	$LFS hsm_release $f
	rc=$?
	if ((rc == 0)); then
		file_size=$(stat -c '%s' $f)
		if ((file_size != 10485760)); then
			error "Wrong file size after hsm_release"
		fi
	else
		echo "could not release file"
	fi
}
run_test 253 "Check for wrong file size after release"

test_254a()
{
	[ $MDS1_VERSION -lt $(version_code 2.10.56) ] &&
		skip "need MDS version at least 2.10.56"

	# Check that the counters are initialized to 0
	local count
	for request_type in archive restore remove; do
		count="$(get_hsm_param ${request_type}_count)" ||
			error "Reading ${request_type}_count failed with $?"

		[ "$count" -eq 0 ] ||
			error "Expected ${request_type}_count to be " \
			      "0 != '$count'"
	done
}
run_test 254a "Request counters are initialized to zero"

test_254b()
{
	[ $MDS1_VERSION -lt $(version_code 2.10.56) ] &&
		skip "need MDS version at least 2.10.56"

	# The number of request to launch (at least 32)
	local request_count=$((RANDOM % 32 + 32))
	printf "Will launch %i requests of each type\n" "$request_count"

	# Launch a copytool to process requests
	copytool setup

	# Set hsm.max_requests to allow starting all requests at the same time
	stack_trap \
		"set_hsm_param max_requests $(get_hsm_param max_requests)" EXIT
	set_hsm_param max_requests "$request_count"

	local timeout
	local count
	for request_type in archive restore remove; do
		printf "Checking %s requests\n" "${request_type}"
		# Suspend the copytool to give us time to read the proc files
		copytool_suspend

		for ((i = 0; i < $request_count; i++)); do
			case $request_type in
			archive)
				create_empty_file "$DIR/$tdir/$tfile-$i" \
					>/dev/null 2>&1
				;;
			restore)
				lfs hsm_release "$DIR/$tdir/$tfile-$i"
				;;
			esac
			$LFS hsm_${request_type} "$DIR/$tdir/$tfile-$i"
		done

		# Give the coordinator 10 seconds to start every request
		timeout=10
		while get_hsm_param actions | grep -q WAITING; do
			sleep 1
			let timeout-=1
			[ $timeout -gt 0 ] ||
				error "${request_type^} requests took too " \
				      "long to start"
		done

		count="$(get_hsm_param ${request_type}_count)"
		[ "$count" -eq "$request_count" ] ||
			error "Expected '$request_count' (!= '$count') " \
			      "active $request_type requests"

		# Let the copytool process the requests
		copytool_continue
		# Give it 10 seconds maximum
		timeout=10
		while get_hsm_param actions | grep -q STARTED; do
			sleep 1
			let timeout-=1
			[ $timeout -gt 0 ] ||
				error "${request_type^} requests took too " \
				      "long to complete"
		done

		count="$(get_hsm_param ${request_type}_count)"
		[ "$count" -eq 0 ] ||
			error "Expected 0 (!= '$count') " \
			      "active $request_type requests"
	done
}
run_test 254b "Request counters are correctly incremented and decremented"

test_255()
{
	[ $MDS1_VERSION -lt $(version_code 2.12.0) ] &&
		skip "Need MDS version at least 2.12.0"

	local file="$DIR/$tdir/$tfile"
	local fid=$(create_empty_file "$file")

	# How do you make sure the coordinator has consumed any outstanding
	# event, without triggering an event yourself?
	#
	# You wait for a request to disappear from the coordinator's llog.

	# Warning: the setup represents 90% of this test

	# Create and process an HSM request
	copytool setup
	"$LFS" hsm_archive "$file"
	wait_request_state $fid ARCHIVE SUCCEED

	kill_copytools
	wait_copytools || error "failed to stop copytools"

	# Launch a new HSM request
	rm "$file"
	create_empty_file "$file"
	"$LFS" hsm_archive "$file"

	cdt_shutdown

	# Have the completed request be removed as soon as the cdt wakes up
	stack_trap "set_hsm_param grace_delay $(get_hsm_param grace_delay)" EXIT
	set_hsm_param grace_delay 1
	# (Hopefully, time on the MDS will behave nicely)
	do_facet $SINGLEMDS sleep 2 &

	# Increase `loop_period' as a mean to prevent the coordinator from
	# waking itself up to do some housekeeping.
	stack_trap "set_hsm_param loop_period $(get_hsm_param loop_period)" EXIT
	set_hsm_param loop_period 1000

	wait $! || error "waiting failed"
	cdt_enable
	wait_request_state $fid ARCHIVE ""
	# The coordinator will not wake up on its own for ~`loop_period' secs...

	# ... Unless a copytool registers. Now the real test begins
	copytool setup
	wait_request_state $(path2fid "$file") ARCHIVE SUCCEED
}
run_test 255 "Copytool registration wakes the coordinator up"

# tests 260[a-c] rely on the parsing of the copytool's log file, they might
# break in the future because of that.
test_260a()
{
	[ $MDS1_VERSION -lt $(version_code 2.11.56) ] &&
		skip "need MDS version 2.11.56 or later"

	local -a files=("$DIR/$tdir/$tfile".{0..15})
	local file

	for file in "${files[@]}"; do
		create_small_file "$file"
	done

	# Set a few hsm parameters
	stack_trap \
		"set_hsm_param loop_period $(get_hsm_param loop_period)" EXIT
	set_hsm_param loop_period 1
	stack_trap \
		"set_hsm_param max_requests $(get_hsm_param max_requests)" EXIT
	set_hsm_param max_requests 3

	# Release one file
	copytool setup
	"$LFS" hsm_archive "${files[0]}"
	wait_request_state "$(path2fid "${files[0]}")" ARCHIVE SUCCEED
	"$LFS" hsm_release "${files[0]}"

	# Stop the copytool
	kill_copytools
	wait_copytools || error "copytools failed to stop"

	# Send several archive requests
	for file in "${files[@]:1}"; do
		"$LFS" hsm_archive "$file"
	done

	# Send one restore request
	"$LFS" hsm_restore "${files[0]}"

	# Launch a copytool
	copytool setup

	# Wait for all the requests to complete
	wait_request_state "$(path2fid "${files[0]}")" RESTORE SUCCEED
	for file in "${files[@]:1}"; do
		wait_request_state "$(path2fid "$file")" ARCHIVE SUCCEED
	done

	# Collect the actions in the order in which the copytool processed them
	local -a actions=(
		$(do_facet "$SINGLEAGT" grep -o '\"RESTORE\\|ARCHIVE\"' \
			"$(copytool_logfile "$SINGLEAGT")")
		)

	printf '%s\n' "${actions[@]}"

	local action
	for action in "${actions[@]:0:3}"; do
		[ "$action" == RESTORE ] && return
	done

	error "Too many ARCHIVE requests were run before the RESTORE request"
}
run_test 260a "Restore request have priority over other requests"

# This test is very much tied to the implementation of the current priorisation
# mechanism in the coordinator. It might not make sense to keep it in the future
test_260b()
{
	[ $MDS1_VERSION -lt $(version_code 2.11.56) ] &&
		skip "need MDS version 2.11.56 or later"

	local -a files=("$DIR/$tdir/$tfile".{0..15})
	local file

	for file in "${files[@]}"; do
		create_small_file "$file"
	done

	# Set a few hsm parameters
	stack_trap \
		"set_hsm_param loop_period $(get_hsm_param loop_period)" EXIT
	set_hsm_param loop_period 1
	stack_trap \
		"set_hsm_param max_requests $(get_hsm_param max_requests)" EXIT
	set_hsm_param max_requests 3

	# Release one file
	copytool setup --archive-id 2
	"$LFS" hsm_archive --archive 2 "${files[0]}"
	wait_request_state "$(path2fid "${files[0]}")" ARCHIVE SUCCEED
	"$LFS" hsm_release "${files[0]}"

	# Stop the copytool
	kill_copytools
	wait_copytools || error "copytools failed to stop"

	# Send several archive requests
	for file in "${files[@]:1}"; do
		"$LFS" hsm_archive "$file"
	done

	# Send one restore request
	"$LFS" hsm_restore "${files[0]}"

	# Launch a copytool
	copytool setup
	copytool setup --archive-id 2

	# Wait for all the requests to complete
	wait_request_state "$(path2fid "${files[0]}")" RESTORE SUCCEED
	for file in "${files[@]:1}"; do
		wait_request_state "$(path2fid "$file")" ARCHIVE SUCCEED
	done

	# Collect the actions in the order in which the copytool processed them
	local -a actions=(
		$(do_facet "$SINGLEAGT" grep -o '\"RESTORE\\|ARCHIVE\"' \
			"$(copytool_logfile "$SINGLEAGT")")
		)

	printf '%s\n' "${actions[@]}"

	local action
	for action in "${actions[@]:0:3}"; do
		[ "$action" == RESTORE ] && return
	done

	error "Too many ARCHIVE requests were run before the RESTORE request"
}
run_test 260b "Restore request have priority over other requests"

# This test is very much tied to the implementation of the current priorisation
# mechanism in the coordinator. It might not make sense to keep it in the future
test_260c()
{
	[ $MDS1_VERSION -lt $(version_code 2.12.0) ] &&
		skip "Need MDS version at least 2.12.0"

	local -a files=("$DIR/$tdir/$tfile".{0..15})
	local file

	for file in "${files[@]}"; do
		create_small_file "$file"
	done

	# Set a few hsm parameters
	stack_trap \
		"set_hsm_param loop_period $(get_hsm_param loop_period)" EXIT
	set_hsm_param loop_period 1000
	stack_trap \
		"set_hsm_param max_requests $(get_hsm_param max_requests)" EXIT
	set_hsm_param max_requests 3

	# Release one file
	copytool setup --archive-id 2
	"$LFS" hsm_archive --archive 2 "${files[0]}"
	wait_request_state "$(path2fid "${files[0]}")" ARCHIVE SUCCEED
	"$LFS" hsm_release "${files[0]}"

	# Stop the copytool
	kill_copytools
	wait_copytools || error "copytools failed to stop"

	# Force the next coordinator run to do housekeeping
	cdt_shutdown
	cdt_enable

	"$LFS" hsm_archive "${files[1]}"

	# Launch a copytool
	copytool setup
	copytool setup --archive-id 2

	wait_request_state "$(path2fid "${files[1]}")" ARCHIVE SUCCEED
	# The coordinator just did a housekeeping run it won't do another one
	# for around `loop_period' seconds => requests will not be reordered
	# if it costs too much (ie. when the coordinator has to discard a whole
	# hal)

	# Send several archive requests
	for file in "${files[@]:2}"; do
		"$LFS" hsm_archive "$file"
	done

	# Send one restore request
	"$LFS" hsm_restore "${files[0]}"

	# Wait for all the requests to complete
	wait_request_state "$(path2fid "${files[0]}")" RESTORE SUCCEED
	for file in "${files[@]:2}"; do
		wait_request_state "$(path2fid "$file")" ARCHIVE SUCCEED
	done

	# Collect the actions in the order in which the copytool processed them
	local -a actions=(
		$(do_facet "$SINGLEAGT" grep -o '\"RESTORE\\|ARCHIVE\"' \
			"$(copytool_logfile "$SINGLEAGT")")
		)

	printf '%s\n' "${actions[@]}"

	local action
	for action in "${actions[@]:0:3}"; do
		[ "$action" == RESTORE ] &&
			error "Restore requests should not be prioritised" \
			      "unless the coordinator is doing housekeeping"
	done
	return 0
}
run_test 260c "Requests are not reordered on the 'hot' path of the coordinator"

test_300() {
	[ "$CLIENTONLY" ] && skip "CLIENTONLY mode" && return

	# the only way to test ondisk conf is to restart MDS ...
	echo "Stop coordinator and remove coordinator state at mount"
	# stop coordinator
	cdt_shutdown
	# clean on disk conf set by default
	cdt_clear_mount_state
	cdt_check_state stopped

	# check cdt still off after umount/remount
	fail $SINGLEMDS
	cdt_check_state stopped

	echo "Set coordinator start at mount, and start coordinator"
	cdt_set_mount_state enabled

	# check cdt is on
	cdt_check_state enabled

	# check cdt still on after umount/remount
	fail $SINGLEMDS
	cdt_check_state enabled

	# we are back to original state (cdt started at mount)
}
run_test 300 "On disk coordinator state kept between MDT umount/mount"

test_301() {
	[ "$CLIENTONLY" ] && skip "CLIENTONLY mode" && return

	local ai=$(get_hsm_param default_archive_id)
	local new=$((ai + 1))

	set_hsm_param default_archive_id $new -P
	fail $SINGLEMDS
	local res=$(get_hsm_param default_archive_id)

	# clear value
	set_hsm_param default_archive_id "" "-P -d"

	[[ $new == $res ]] || error "Value after MDS restart is $res != $new"
}
run_test 301 "HSM tunnable are persistent"

test_302() {
	[ "$CLIENTONLY" ] && skip "CLIENTONLY mode" && return

	local ai=$(get_hsm_param default_archive_id)
	local new=$((ai + 1))

	# stop coordinator
	cdt_shutdown

	set_hsm_param default_archive_id $new -P

	local mdtno
	for mdtno in $(seq 1 $MDSCOUNT); do
		fail mds${mdtno}
	done

	# check cdt is on
	cdt_check_state enabled

	local res=$(get_hsm_param default_archive_id)

	# clear value
	set_hsm_param default_archive_id "" "-P -d"

	[[ $new == $res ]] || error "Value after MDS restart is $res != $new"
}
run_test 302 "HSM tunnable are persistent when CDT is off"

test_400() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return

	copytool setup

	mkdir -p $DIR/$tdir

	local dir_mdt0=$DIR/$tdir/mdt0
	local dir_mdt1=$DIR/$tdir/mdt1

	# create 1 dir per MDT
	stack_trap "rm -rf $dir_mdt0" EXIT
	$LFS mkdir -i 0 $dir_mdt0 || error "lfs mkdir"
	stack_trap "rm -rf $dir_mdt1" EXIT
	$LFS mkdir -i 1 $dir_mdt1 || error "lfs mkdir"

	# create 1 file in each MDT
	local fid1=$(create_small_file $dir_mdt0/$tfile)
	local fid2=$(create_small_file $dir_mdt1/$tfile)

	# check that hsm request on mdt0 is sent to the right MDS
	$LFS hsm_archive $dir_mdt0/$tfile || error "lfs hsm_archive"
	wait_request_state $fid1 ARCHIVE SUCCEED 0 &&
		echo "archive successful on mdt0"

	# check that hsm request on mdt1 is sent to the right MDS
	$LFS hsm_archive $dir_mdt1/$tfile || error "lfs hsm_archive"
	wait_request_state $fid2 ARCHIVE SUCCEED 1 &&
		echo "archive successful on mdt1"
}
run_test 400 "Single request is sent to the right MDT"

test_401() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return

	copytool setup

	mkdir -p $DIR/$tdir

	local dir_mdt0=$DIR/$tdir/mdt0
	local dir_mdt1=$DIR/$tdir/mdt1

	# create 1 dir per MDT
	stack_trap "rm -rf $dir_mdt0" EXIT
	$LFS mkdir -i 0 $dir_mdt0 || error "lfs mkdir"
	stack_trap "rm -rf $dir_mdt1" EXIT
	$LFS mkdir -i 1 $dir_mdt1 || error "lfs mkdir"

	# create 1 file in each MDT
	local fid1=$(create_small_file $dir_mdt0/$tfile)
	local fid2=$(create_small_file $dir_mdt1/$tfile)

	# check that compound requests are shunt to the rights MDTs
	$LFS hsm_archive $dir_mdt0/$tfile $dir_mdt1/$tfile ||
		error "lfs hsm_archive"
	wait_request_state $fid1 ARCHIVE SUCCEED 0 &&
		echo "archive successful on mdt0"
	wait_request_state $fid2 ARCHIVE SUCCEED 1 &&
		echo "archive successful on mdt1"
}
run_test 401 "Compound requests split and sent to their respective MDTs"

mdc_change_state() # facet, MDT_pattern, activate|deactivate
{
	local facet=$1
	local pattern="$2"
	local state=$3
	local node=$(facet_active_host $facet)
	local mdc
	for mdc in $(do_facet $facet "$LCTL dl | grep -E ${pattern}-mdc" |
			awk '{print $4}'); do
		echo "$3 $mdc on $node"
		do_facet $facet "$LCTL --device $mdc $state" || return 1
	done
}

test_402a() {
	# deactivate all mdc on agent1
	mdc_change_state $SINGLEAGT "$FSNAME-MDT000." "deactivate"

	copytool setup --no-fail

	check_agent_unregistered "uuid" # match any agent

	# no expected running copytool
	search_copytools $agent && error "Copytool start should have failed"

	# reactivate MDCs
	mdc_change_state $SINGLEAGT "$FSNAME-MDT000." "activate"
}
run_test 402a "Copytool start fails if all MDTs are inactive"

test_402b() {
	copytool setup

	mkdir -p $DIR/$tdir

	local f=$DIR/$tdir/$tfile
	touch $f || error "touch $f failed"
	local fid=$(path2fid $f)

#define OBD_FAIL_MDS_HSM_CT_REGISTER_NET	0x14d
	do_facet $SINGLEAGT lctl set_param fail_loc=0x14d
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f

	# give time for CDT to send request and to keep it for retry
	wait_for_loop_period

	wait_request_state $fid ARCHIVE WAITING

	do_facet $SINGLEAGT lctl set_param fail_loc=0

	# request should succeed now
	wait_request_state $fid ARCHIVE SUCCEED
}
run_test 402b "CDT must retry request upon slow start of CT"

test_403() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return

        local agent=$(facet_active_host $SINGLEAGT)

	# deactivate all mdc for MDT0001
	mdc_change_state $SINGLEAGT "$FSNAME-MDT0001" "deactivate"

	copytool setup
	local uuid=$(get_agent_uuid $agent)
	# check the agent is registered on MDT0000, and not on MDT0001
	check_agent_registered_by_mdt $uuid 0
	check_agent_unregistered_by_mdt $uuid 1

	# check running copytool process
	search_copytools $agent || error "No running copytools on $agent"

	# reactivate all mdc for MDT0001
	mdc_change_state $SINGLEAGT "$FSNAME-MDT0001" "activate"

	# make sure the copytool is now registered to all MDTs
	check_agent_registered $uuid
}
run_test 403 "Copytool starts with inactive MDT and register on reconnect"

test_404() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return

	copytool setup

	# create files on both MDT0000 and MDT0001
	mkdir -p $DIR/$tdir

	local dir_mdt0=$DIR/$tdir/mdt0
	stack_trap "rm -rf $dir_mdt0" EXIT
	$LFS mkdir -i 0 $dir_mdt0 || error "lfs mkdir"

	# create 1 file on mdt0
	local fid1=$(create_small_file $dir_mdt0/$tfile)

	# deactivate all mdc for MDT0001
	mdc_change_state $SINGLEAGT "$FSNAME-MDT0001" "deactivate"

	# send an HSM request for files in MDT0000
	$LFS hsm_archive $dir_mdt0/$tfile || error "lfs hsm_archive"

	# check for completion of files in MDT0000
	wait_request_state $fid1 ARCHIVE SUCCEED 0 &&
		echo "archive successful on mdt0"

	# reactivate all mdc for MDT0001
	mdc_change_state $SINGLEAGT "$FSNAME-MDT0001" "activate"
}
run_test 404 "Inactive MDT does not block requests for active MDTs"

test_405() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return

	copytool setup

	mkdir -p $DIR/$tdir

	local striped_dir=$DIR/$tdir/striped_dir

	# create striped dir on all of MDTs
	$LFS mkdir -i 0 -c $MDSCOUNT $striped_dir || error "lfs mkdir"

	local fid1=$(create_small_sync_file $striped_dir/${tfile}_0)
	local fid2=$(create_small_sync_file $striped_dir/${tfile}_1)
	local fid3=$(create_small_sync_file $striped_dir/${tfile}_2)
	local fid4=$(create_small_sync_file $striped_dir/${tfile}_3)

	local idx1=$($LFS getstripe -m $striped_dir/${tfile}_0)
	local idx2=$($LFS getstripe -m $striped_dir/${tfile}_1)
	local idx3=$($LFS getstripe -m $striped_dir/${tfile}_2)
	local idx4=$($LFS getstripe -m $striped_dir/${tfile}_3)

	# check that compound requests are shunt to the rights MDTs
	$LFS hsm_archive $striped_dir/${tfile}_0 $striped_dir/${tfile}_1  \
			 $striped_dir/${tfile}_2 $striped_dir/${tfile}_3 ||
		error "lfs hsm_archive"

	wait_request_state $fid1 ARCHIVE SUCCEED $idx1 &&
		echo "archive successful on $fid1"
	wait_request_state $fid2 ARCHIVE SUCCEED $idx2 &&
		echo "archive successful on $fid2"
	wait_request_state $fid3 ARCHIVE SUCCEED $idx3 &&
		echo "archive successful on $fid3"
	wait_request_state $fid4 ARCHIVE SUCCEED $idx4 &&
		echo "archive successful on $fid4"

	$LFS hsm_release $striped_dir/${tfile}_0 || error "lfs hsm_release 1"
	$LFS hsm_release $striped_dir/${tfile}_1 || error "lfs hsm_release 2"
	$LFS hsm_release $striped_dir/${tfile}_2 || error "lfs hsm_release 3"
	$LFS hsm_release $striped_dir/${tfile}_3 || error "lfs hsm_release 4"

	cat $striped_dir/${tfile}_0 > /dev/null || error "cat ${tfile}_0 failed"
	cat $striped_dir/${tfile}_1 > /dev/null || error "cat ${tfile}_1 failed"
	cat $striped_dir/${tfile}_2 > /dev/null || error "cat ${tfile}_2 failed"
	cat $striped_dir/${tfile}_3 > /dev/null || error "cat ${tfile}_3 failed"
}
run_test 405 "archive and release under striped directory"

test_406() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0

	[ $MDS1_VERSION -lt $(version_code 2.7.64) ] &&
		skip "need MDS version at least 2.7.64"

	local fid
	local mdt_index

	fid=$(create_small_file $DIR/$tdir/$tfile)
	echo "old fid $fid"

	copytool setup

	$LFS hsm_archive $DIR/$tdir/$tfile
	wait_request_state "$fid" ARCHIVE SUCCEED
	$LFS hsm_release $DIR/$tdir/$tfile

	# Should migrate $tdir but not $tfile.
	$LFS migrate -m1 $DIR/$tdir &&
		error "migrating HSM an archived file should fail"

	$LFS hsm_restore $DIR/$tdir/$tfile
	wait_request_state "$fid" RESTORE SUCCEED

	$LFS hsm_remove $DIR/$tdir/$tfile
	wait_request_state "$fid" REMOVE SUCCEED

	cat $DIR/$tdir/$tfile > /dev/null ||
		error "cannot read $DIR/$tdir/$tfile"

	$LFS migrate -m1 $DIR/$tdir ||
		error "cannot complete migration after HSM remove"

	mdt_index=$($LFS getstripe -m $DIR/$tdir)
	if ((mdt_index != 1)); then
		error "expected MDT index 1, got $mdt_index"
	fi

	# Refresh fid after migration.
	fid=$(path2fid $DIR/$tdir/$tfile)
	echo "new fid $fid"

	$LFS hsm_archive $DIR/$tdir/$tfile
	wait_request_state "$fid" ARCHIVE SUCCEED 1

	lctl set_param debug=+trace
	$LFS hsm_release $DIR/$tdir/$tfile ||
		error "cannot release $DIR/$tdir/$tfile"

	$LFS hsm_restore $DIR/$tdir/$tfile
	wait_request_state "$fid" RESTORE SUCCEED 1

	cat $DIR/$tdir/$tfile > /dev/null ||
		error "cannot read $DIR/$tdir/$tfile"
}
run_test 406 "attempting to migrate HSM archived files is safe"

test_407() {
	local f=$DIR/$tdir/$tfile
	local f2=$DIR2/$tdir/$tfile
	local fid=$(create_empty_file "$f")

	copytool setup

	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $f
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $f

#define OBD_FAIL_MDS_HSM_CDT_DELAY      0x164
	do_facet $SINGLEMDS $LCTL set_param fail_val=5 fail_loc=0x164

	# Prevent restore from completing
	copytool_suspend

	md5sum $f &
	# 1st request holds layout lock while appropriate
	# RESTORE record is still not added to llog
	md5sum $f2 &
	sleep 2

	do_facet $SINGLEMDS "$LCTL get_param $HSM_PARAM.actions"
	# after umount hsm_actions->O/x/x log shouldn't have
	# double RESTORE records like below
	#[0x200000401:0x1:0x0]...0x58d03a0d/0x58d03a0c action=RESTORE...WAITING
	#[0x200000401:0x1:0x0]...0x58d03a0c/0x58d03a0d action=RESTORE...WAITING
	sleep 30 &&
		do_facet $SINGLEMDS "$LCTL get_param $HSM_PARAM.actions"&
	fail $SINGLEMDS
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	do_facet $SINGLEMDS "$LCTL get_param $HSM_PARAM.actions"

	copytool_continue
	wait_all_done 100 $fid
}
run_test 407 "Check for double RESTORE records in llog"

test_500()
{
	[ "$MDS1_VERSION" -lt $(version_code 2.6.92) ] &&
		skip "HSM migrate is not supported"

	test_mkdir -p $DIR/$tdir

	if [ "$CLIENT_VERSION" -lt $(version_code 2.11.56) ] ||
	     [ "$MDS1_VERSION" -lt $(version_code 2.11.56) ];
	then
		llapi_hsm_test -d $DIR/$tdir -b ||
			error "One llapi HSM test failed"
	else
		llapi_hsm_test -d $DIR/$tdir ||
			error "One llapi HSM test failed"
	fi
}
run_test 500 "various LLAPI HSM tests"

test_600() {
	[ "$MDS1_VERSION" -lt $(version_code 2.10.58) ] &&
		skip "need MDS version at least 2.10.58"

	mkdir -p $DIR/$tdir

	local f=$DIR/$tdir/$tfile

	changelog_register
	# set changelog_mask to ALL
	changelog_chmask "ALL"

	chmod 777 $DIR/$tdir
	$RUNAS touch $f || error "touch $f failed as $RUNAS_ID"
	local fid=$(path2fid $f)

	local entry
	entry=$(changelog_find -type CREAT -target-fid $fid -uid "$RUNAS_ID" \
			       -gid "$RUNAS_GID") ||
		error "No matching CREAT entry"

	# Parse the changelog
	eval local -A changelog=$(changelog2array $entry)
	local nid="${changelog[nid]}"

	# Check its NID
	echo "Got NID '$nid'"
	[ -n "$nid" ] && [[ "${CLIENT_NIDS[*]}" =~ $nid ]] ||
		error "nid '$nid' does not match any client NID:" \
		      "${CLIENT_NIDS[@]}"
}
run_test 600 "Changelog fields 'u=' and 'nid='"

test_601() {
	[ $MDS1_VERSION -lt $(version_code 2.10.58) ] &&
		skip "need MDS version at least 2.10.58"

	mkdir -p $DIR/$tdir

	local f=$DIR/$tdir/$tfile

	changelog_register
	# set changelog_mask to ALL
	changelog_chmask "ALL"

	touch $f || error "touch $f failed"
	local fid=$(path2fid $f)

	changelog_clear
	cat $f || error "cat $f failed"

	changelog_find -type OPEN -target-fid $fid -mode "r--" ||
		error "No matching OPEN entry"
}
run_test 601 "OPEN Changelog entry"

test_602() {
	[ $MDS1_VERSION -lt $(version_code 2.10.58) ] &&
		skip "need MDS version at least 2.10.58"

	stack_trap "restore_opencache" EXIT
	disable_opencache

	mkdir -p $DIR/$tdir

	local f=$DIR/$tdir/$tfile

	changelog_register
	# set changelog_mask to ALL
	changelog_chmask "ALL"

	touch $f || error "touch $f failed"
	local fid=$(path2fid $f)

	changelog_clear
	cat $f || error "cat $f failed"

	changelog_find -type CLOSE -target-fid $fid || error "No CLOSE entry"

	changelog_clear
	changelog_dump
	echo f > $f || error "write $f failed"
	changelog_dump

	changelog_find -type CLOSE -target-fid $fid || error "No CLOSE entry"

	# remove OPEN from changelog_mask
	changelog_chmask "-OPEN"

	changelog_clear
	changelog_dump
	cat $f || error "cat $f failed"
	changelog_dump

	changelog_find -type CLOSE -target-fid $fid &&
		error "There should be no CLOSE entry"

	changelog_clear
	changelog_dump
	echo f > $f || error "write $f failed"
	changelog_dump

	changelog_find -type CLOSE -target-fid $fid || error "No CLOSE entry"
}
run_test 602 "Changelog record CLOSE only if open+write or OPEN recorded"

test_603() {
	[ $MDS1_VERSION -lt $(version_code 2.10.58) ] &&
		skip "need MDS version at least 2.10.58"

	mkdir -p $DIR/$tdir

	local f=$DIR/$tdir/$tfile

	changelog_register
	# set changelog_mask to ALL
	changelog_chmask "ALL"

	touch $f || error "touch $f failed"
	local fid=$(path2fid $f)

	setfattr -n user.xattr1 -v "value1" $f || error "setfattr $f failed"

	changelog_clear
	getfattr -n user.xattr1 $f || error "getfattr $f failed"

	changelog_find -type GXATR -target-fid $fid -xattr "user.xattr1" ||
		error "No matching GXATR entry"
}
run_test 603 "GETXATTR Changelog entry"

test_604() {
	[ $MDS1_VERSION -lt $(version_code 2.10.58) ] &&
		skip "need MDS version at least 2.10.58"

	mkdir -p $DIR/$tdir

	local f=$DIR/$tdir/$tfile
	local f2=$DIR2/$tdir/$tfile
	local procname="mdd.$FSNAME-MDT0000.changelog_deniednext"
	local timeout
	timeout="$(do_facet mds1 "$LCTL" get_param -n "$procname")"
	stack_trap "do_facet mds1 '$LCTL' set_param '$procname=$timeout'" EXIT
	do_facet mds1 lctl set_param "$procname=20"


	changelog_register
	# set changelog_mask to ALL
	changelog_chmask "ALL"

	touch $f || error "touch $f failed"
	local fid=$(path2fid $f)

	chmod 600 $f

	changelog_clear
	changelog_dump
	$RUNAS cat $f2 && error "cat $f2 by user $RUNAS_ID should have failed"
	changelog_dump

	local entry
	entry=$(changelog_find -type NOPEN -target-fid $fid -uid "$RUNAS_ID" \
			       -gid "$RUNAS_GID" -mode "r--") ||
		error "No matching NOPEN entry"

	# Parse the changelog
	eval local -A changelog=$(changelog2array $entry)
	local nid="${changelog[nid]}"

	# Check its NID
	echo "Got NID '$nid'"
	[ -n "$nid" ] && [[ "${CLIENT_NIDS[*]}" =~ $nid ]] ||
		error "nid '$nid' does not match any client NID:" \
		      "${CLIENT_NIDS[@]}"

	changelog_clear
	changelog_dump
	$RUNAS cat $f2 && error "cat $f2 by user $RUNAS_ID should have failed"
	changelog_dump

	changelog_find -type NOPEN -target-fid $fid &&
		error "There should be no NOPEN entry"

	# Sleep for `changelog_deniednext` seconds
	sleep 20

	changelog_clear
	changelog_dump
	$RUNAS cat $f2 && error "cat $f by user $RUNAS_ID should have failed"
	changelog_dump

	entry=$(changelog_find -type NOPEN -target-fid $fid -uid "$RUNAS_ID" \
			       -gid "$RUNAS_GID" -mode "r--") ||
		error "No matching NOPEN entry"

	# Parse the changelog
	eval local -A changelog=$(changelog2array $entry)
	local nid="${changelog[nid]}"

	# Check the NID
	echo "Got NID '$nid'"
	[ -n "$nid" ] && [[ "${CLIENT_NIDS[*]}" =~ $nid ]] ||
		error "nid '$nid' does not match any client NID:" \
		      "${CLIENT_NIDS[@]}"
}
run_test 604 "NOPEN Changelog entry"

test_605() {
	[ $MDS1_VERSION -lt $(version_code 2.10.58) ] &&
		skip "need MDS version at least 2.10.58"

	stack_trap "restore_opencache" EXIT
	disable_opencache

	mkdir -p $DIR/$tdir

	local f=$DIR/$tdir/$tfile
	local f2=$DIR2/$tdir/$tfile

	changelog_register
	# set changelog_mask to ALL
	changelog_chmask "ALL"

	touch $f || error "touch $f failed"
	local fid=$(path2fid $f)

	changelog_clear
	changelog_dump
	exec 3<> $f || error "open $f failed"
	changelog_dump

	local entry
	changelog_find -type OPEN -target-fid $fid || error "No OPEN entry"

	changelog_clear
	changelog_dump
	exec 4<> $f || error "open $f failed"
	changelog_dump

	changelog_find -type OPEN -target-fid $fid &&
		error "There should be no OPEN entry"

	exec 4>&- || error "close $f failed"
	changelog_dump

	changelog_find -type CLOSE -target-fid $fid &&
		error "There should be no CLOSE entry"

	changelog_clear
	changelog_dump
	# access in rw, so different access mode should generate entries
	cat $f || error "cat $f failed"
	changelog_dump

	changelog_find -type OPEN -target-fid $fid || error "No OPEN entry"

	changelog_find -type CLOSE -target-fid $fid || error "No CLOSE entry"

	changelog_clear
	changelog_dump
	# same access as first one, should not generate new entries
	exec 4<> $f || error "open $f failed"
	changelog_dump

	changelog_find -type OPEN -target-fid $fid &&
		error "There should be no OPEN entry"

	exec 4>&- || error "close $f failed"
	changelog_dump

	changelog_find -type CLOSE -target-fid $fid &&
		error "There should be no CLOSE entry"

	changelog_clear
	changelog_dump
	# access by different user should generate new entries
	$RUNAS cat $f || error "cat $f by user $RUNAS_ID failed"
	changelog_dump

	changelog_find -type OPEN -target-fid $fid || error "No OPEN entry"

	changelog_find -type CLOSE -target-fid $fid || error "No CLOSE entry"

	changelog_clear
	changelog_dump
	exec 3>&- || error "close $f failed"
	changelog_dump

	changelog_find -type CLOSE -target-fid $fid || error "No CLOSE entry"
}
run_test 605 "Test OPEN and CLOSE rate limit in Changelogs"

test_606() {
	[ $MDS1_VERSION -lt $(version_code 2.10.58) ] &&
		skip "need MDS version at least 2.10.58"

	local llog_reader=$(do_facet mgs "which llog_reader 2> /dev/null")
	llog_reader=${llog_reader:-$LUSTRE/utils/llog_reader}
	[ -z $(do_facet mgs ls -d $llog_reader 2> /dev/null) ] &&
			skip_env "missing llog_reader"

	mkdir -p $DIR/$tdir

	local f=$DIR/$tdir/$tfile

	changelog_register
	# set changelog_mask to ALL
	changelog_chmask "ALL"

	chmod 777 $DIR/$tdir
	$RUNAS touch $f || error "touch $f failed as $RUNAS_ID"
	local fid=$(path2fid $f)
	rm $f || error "rm $f failed"

	local mntpt=$(facet_mntpt mds1)
	local pass=true
	local entry

	#remount mds1 as ldiskfs or zfs type
	stop mds1 || error "stop mds1 failed"
	stack_trap "unmount_fstype mds1; start mds1 $(mdsdevname 1)\
		$MDS_MOUNT_OPTS" EXIT
	mount_fstype mds1 || error "remount mds1 failed"

	for ((i = 0; i < 1; i++)); do
		do_facet mds1 $llog_reader $mntpt/changelog_catalog
		local cat_file=$(do_facet mds1 $llog_reader \
				$mntpt/changelog_catalog | awk \
				'{match($0,"path=([^ ]+)",a)}END{print a[1]}')
		[ -n "$cat_file" ] || error "no catalog file"

		entry=$(do_facet mds1 $llog_reader $mntpt/$cat_file |
			awk "/CREAT/ && /target:\[$fid\]/ {print}")
		[ -n "$entry" ] || error "no CREAT entry"
	done

	local uidgid=$(echo $entry |
		sed 's+.*\ user:\([0-9][0-9]*:[0-9][0-9]*\)\ .*+\1+')
	[ -n "$uidgid" ] || error "uidgid is empty"
	echo "Got UID/GID $uidgid"
	[ "$uidgid" = "$RUNAS_ID:$RUNAS_GID" ] ||
		error "uidgid '$uidgid' != '$RUNAS_ID:$RUNAS_GID'"
	local nid=$(echo $entry |
		sed 's+.*\ nid:\(\S\S*@\S\S*\)\ .*+\1+')
	[ -n "$nid" ] || error "nid is empty"
	echo "Got NID $nid"
	[ -n "$nid" ] && [[ "${CLIENT_NIDS[*]}" =~ $nid ]] ||
		error "nid '$nid' does not match any NID ${CLIENT_NIDS[@]}"
}
run_test 606 "llog_reader groks changelog fields"

complete $SECONDS
check_and_cleanup_lustre
exit_status
