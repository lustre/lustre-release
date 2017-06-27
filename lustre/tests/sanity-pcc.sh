#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# exit on error
set -e
set +o monitor

SRCDIR=$(dirname $0)
export PATH=$PWD/$SRCDIR:$SRCDIR:$PWD/$SRCDIR/utils:$PATH:/sbin:/usr/sbin

ONLY=${ONLY:-"$*"}
# bug number for skipped test:
ALWAYS_EXCEPT=""
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

ENABLE_PROJECT_QUOTAS=${ENABLE_PROJECT_QUOTAS:-true}

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}

. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

MULTIOP=${MULTIOP:-multiop}
OPENFILE=${OPENFILE:-openfile}
MOUNT_2=${MOUNT_2:-"yes"}
FAIL_ON_ERROR=false

# script only handles up to 10 MDTs (because of MDT_PREFIX)
[ $MDSCOUNT -gt 9 ] &&
	error "script cannot handle more than 9 MDTs, please fix" && exit

check_and_setup_lustre

if [[ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.12.52) ]]; then
	skip_env "Need MDS version at least 2.12.52" && exit
fi

# $RUNAS_ID may get set incorrectly somewhere else
if [[ $UID -eq 0 && $RUNAS_ID -eq 0 ]]; then
	skip_env "\$RUNAS_ID set to 0, but \$UID is also 0!" && exit
fi
check_runas_id $RUNAS_ID $RUNAS_GID $RUNAS
if getent group nobody; then
	GROUP=nobody
elif getent group nogroup; then
	GROUP=nogroup
else
	error "No generic nobody group"
fi

build_test_filter

# if there is no CLIENT1 defined, some tests can be ran on localhost
CLIENT1=${CLIENT1:-$HOSTNAME}
# if CLIENT2 doesn't exist then use CLIENT1 instead
# All tests should use CLIENT2 with MOUNT2 only therefore it will work if
# $CLIENT2 == CLIENT1
# Exception is the test which need two separate nodes
CLIENT2=${CLIENT2:-$CLIENT1}

check_file_size()
{
	local client="$1"
	local fpath="$2"
	local expected_size="$3"

	size=$(do_facet $client stat "--printf=%s" $fpath)
	[[ $size == "$expected_size" ]] || error \
		"expected $fpath size: $expected_size got: $size"
}

check_lpcc_sizes()
{
	local client="$1"
	local lpcc_fpath="$2"
	local lustre_fpath="$3"
	local expected_size="$4"

	check_file_size $client $lpcc_fpath $expected_size
	check_file_size $client $lustre_fpath $expected_size
}

check_file_data()
{
	local client="$1"
	local path="$2"
	local expected_data="$3"

	path_data=$(do_facet $client cat $path)
	[[ "x$path_data" == "x$expected_data" ]] || error \
		"expected $path: $expected_data, got: $path_data"
}

check_lpcc_data()
{
	local client="$1"
	local lpcc_fpath="$2"
	local lustre_fpath="$3"
	local expected_data="$4"

	check_file_data  "$client" "$lpcc_fpath" "$expected_data"
	check_file_data  "$client" "$lustre_fpath" "$expected_data"
}

lpcc_fid2path()
{
	local hsm_root="$1"
	local lustre_path="$2"
	local fid=$(path2fid $lustre_path)

	local -a f_seq
	local -a f_oid
	local -a f_ver

	f_seq=$(echo $fid | awk -F ':' '{print $1}')
	f_oid=$(echo $fid | awk -F ':' '{print $2}')
	f_ver=$(echo $fid | awk -F ':' '{print $3}')

	printf "%s/%04x/%04x/%04x/%04x/%04x/%04x/%s" \
		$hsm_root $(($f_oid & 0xFFFF)) \
		$(($f_oid >> 16 & 0xFFFF)) \
		$(($f_seq & 0xFFFF)) \
		$(($f_seq >> 16 & 0xFFFF)) \
		$(($f_seq >> 32 & 0xFFFF)) \
		$(($f_seq >> 48 & 0xFFFF)) $fid
}

check_lpcc_state()
{
	local lustre_path="$1"
	local expected_state="$2"
	local state=$(do_facet $SINGLEAGT $LFS pcc state $lustre_path |
			awk -F 'type: ' '{print $2}' | awk -F ',' '{print $1}')

	[[ "x$state" == "x$expected_state" ]] || error \
		"$lustre_path expected pcc state: $expected_state, but got: $state"
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

cleanup_pcc_mapping() {
	do_facet $SINGLEAGT $LCTL pcc clear $MOUNT
}

setup_pcc_mapping() {
	local hsm_root=$(hsm_root)

	cleanup_pcc_mapping
	do_facet $SINGLEAGT $LCTL pcc add $MOUNT $hsm_root \
		-p "$HSM_ARCHIVE_NUMBER\ 100"
}

lpcc_rw_test() {
	local restore="$1"
	local project="$2"
	local project_id=100
	local agt_facet=$SINGLEAGT
	local hsm_root=$(hsm_root)
	local file=$DIR/$tdir/$tfile
	local -a state
	local -a lpcc_path
	local -a size

	$project && enable_project_quota

	do_facet $SINGLEAGT rm -rf $hsm_root
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"

	is_project_quota_supported || project=false

	do_facet $SINGLEAGT mkdir -p $DIR/$tdir
	setup_pcc_mapping
	$project && lfs project -sp $project_id $DIR/$tdir

	do_facet $SINGLEAGT "echo -n attach_origin > $file"
	if ! $project; then
		check_lpcc_state $file "none"
		do_facet $SINGLEAGT $LFS pcc attach -i \
			$HSM_ARCHIVE_NUMBER $file ||
			error "pcc attach $file failed"
	fi

	check_lpcc_state $file "readwrite"
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"
	lpcc_path=$(lpcc_fid2path $hsm_root $file)
	check_lpcc_data $SINGLEAGT $lpcc_path $file "attach_origin"

	do_facet $SINGLEAGT dd if=/dev/zero of=$file bs=7654321 count=1
	check_lpcc_sizes $SINGLEAGT $lpcc_path $file 7654321

	do_facet $SINGLEAGT $TRUNCATE $file 1234567 ||
		error "truncate failed"
	check_lpcc_sizes $SINGLEAGT $lpcc_path $file 1234567
	check_lpcc_state $file "readwrite"

	do_facet $SINGLEAGT "echo -n file_data > $file"
	check_lpcc_state $file "readwrite"
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"
	check_lpcc_data $SINGLEAGT $lpcc_path $file "file_data"

	if [ $CLIENTCOUNT -lt 2 -o $restore ]; then
		$LFS hsm_restore $file || error \
			"failed to restore $file"
		wait_request_state $(path2fid $file) RESTORE SUCCEED
	else
		path_data=$(do_node $CLIENT2 cat $file)
		[[ "x$path_data" == "xfile_data" ]] || error \
			"expected file_data, got: $path_data"
	fi

	check_lpcc_state $file "none"
	# HSM exists archived status
	check_hsm_flags $file "0x00000009"

	echo -n "new_data" > $file
	check_lpcc_state $file "none"
	# HSM exists dirty archived status
	check_hsm_flags $file "0x0000000b"
	check_file_data $SINGLEAGT $file "new_data"

	echo "Attach and detach testing"
	rm -f $file
	do_facet $SINGLEAGT "echo -n new_data2 > $file"
	if ! $project; then
		check_lpcc_state $file "none"
		do_facet $SINGLEAGT $LFS pcc attach -i \
			$HSM_ARCHIVE_NUMBER $file ||
			error "PCC attach $file failed"
	fi
	check_lpcc_state $file "readwrite"
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"
	do_facet $SINGLEAGT "echo -n attach_detach > $file"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "PCC detach $file failed"
	check_lpcc_state $file "none"
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"
	check_file_data $SINGLEAGT $file "attach_detach"

	cleanup_pcc_mapping
}

test_1a() {
	lpcc_rw_test true false
}
run_test 1a "Test manual lfs pcc attach with manual HSM restore"

test_1b() {
	lpcc_rw_test false false
}
run_test 1b "Test manual lfs pcc attach with restore on remote access"

test_1c() {
	lpcc_rw_test true true
}
run_test 1c "Test automated attach using Project ID with manual HSM restore"

test_1d() {
	lpcc_rw_test false true
}
run_test 1d "Test Project ID with remote access"


#
# When a process created a LPCC file and holding the open,
# another process on the same client should be able to open the file.
#
test_2() {
	local project_id=100
	local agt_facet=$SINGLEAGT
	local hsm_root=$(hsm_root)
	local agt_host=$(facet_active_host $SINGLEAGT)

	! is_project_quota_supported &&
		skip "project quota is not supported" && return

	enable_project_quota
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping
	file=$DIR/$tdir/multiop
	mkdir -p $DIR/$tdir
	rm -f $file

	do_facet $SINGLEAGT $LFS project -sp $project_id $DIR/$tdir ||
		error "failed to set project quota"
	rmultiop_start $agt_host $file O_c || error "open $file failed"
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"
	do_facet $SINGLEAGT "echo -n multiopen_data > $file" ||
		error "failed to echo multiopen_data to $file"

	lpcc_path=$(lpcc_fid2path $hsm_root $file)
	do_facet $SINGLEAGT ls -l $lpcc_path ||
		error "failed to ls $lpcc_path"
	check_lpcc_data $SINGLEAGT $lpcc_path $file "multiopen_data"
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"

	rmultiop_stop $agt_host || error "close $file failed"
	cleanup_pcc_mapping
}
run_test 2 "Test multi open when creating"

test_3() {
	local file=$DIR/$tdir/$tfile

	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"

	echo "Start to attach/detach the file: $file"
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none"

	echo "Repeat to attach/detach the same file: $file"
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none"

	cleanup_pcc_mapping
}
run_test 3 "Repeat attach/detach operations"

complete $SECONDS
check_and_cleanup_lustre
exit_status
