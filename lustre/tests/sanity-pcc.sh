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
ALWAYS_EXCEPT="$SANITY_PCC_EXCEPT "
# bug number for skipped test:
ALWAYS_EXCEPT+=""
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

ENABLE_PROJECT_QUOTAS=${ENABLE_PROJECT_QUOTAS:-true}
HSMTOOL_ARCHIVE_FORMAT=v2

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}

. $LUSTRE/tests/test-framework.sh
init_test_env "$@"
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

if [[ "$MDS1_VERSION" -lt $(version_code 2.12.52) ]]; then
	skip "Need MDS version at least 2.12.52"
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

if [[ -r /etc/redhat-release ]]; then
	rhel_version=$(sed -e 's/[^0-9.]*//g' /etc/redhat-release)
	if (( $(version_code $rhel_version) >= $(version_code 9.3.0) )); then
		always_except LU-17289 102          # fio io_uring
		always_except LU-17781 33	    # inconsistent LSOM
	elif (( $(version_code $rhel_version) >= $(version_code 8.9.0) )); then
		always_except LU-17781 33	    # inconsistent LSOM
	fi
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
	local pid=$4

	# if $pid is set, then run command within namespace for that process
	path_data=$(do_facet $client ${pid:+nsenter -t $pid -U -m} cat $path)
	[[ "x$path_data" == "x$expected_data" ]] ||
		error "expected $path: $expected_data, got: $path_data"
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

	local seq=$(echo $fid | awk -F ':' '{print $1}')
	local oid=$(echo $fid | awk -F ':' '{print $2}')
	local ver=$(echo $fid | awk -F ':' '{print $3}')

	case "$HSMTOOL_ARCHIVE_FORMAT" in
		v1)
			printf "%s/%04x/%04x/%04x/%04x/%04x/%04x/%s" \
				$hsm_root $((oid & 0xFFFF)) \
				$((oid >> 16 & 0xFFFF)) \
				$((seq & 0xFFFF)) \
				$((seq >> 16 & 0xFFFF)) \
				$((seq >> 32 & 0xFFFF)) \
				$((seq >> 48 & 0xFFFF)) $fid
			;;
		v2)
			printf "%s/%04x/%s" $hsm_root $(((oid ^ seq) & 0xFFFF)) $fid
			;;
	esac
}

check_lpcc_state()
{
	local lustre_path="$1"
	local expected_state="$2"
	local facet=${3:-$SINGLEAGT}
	local myRUNAS="$4"
	local state=$(do_facet $facet $myRUNAS $LFS pcc state $lustre_path |
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
	local facet=${1:-$SINGLEAGT}

	echo "Cleanup PCC backend on $MOUNT"
	do_facet $facet $LCTL pcc clear $MOUNT
}

setup_pcc_mapping() {
	local facet=${1:-$SINGLEAGT}
	local hsm_root=${hsm_root:-$(hsm_root "$facet")}
	local param="$2"

	[ -z "$param" ] && param="projid={100}\ rwid=$HSM_ARCHIVE_NUMBER"
	stack_trap "cleanup_pcc_mapping $facet" EXIT
	do_facet $facet $LCTL pcc add $MOUNT $hsm_root -p "$param" ||
		error "Setup PCC backend $hsm_root on $MOUNT failed"
}

umount_loopdev() {
	local facet=$1
	local mntpt=$2
	local rc

	do_facet $facet lsof $mntpt || true
	do_facet $facet $UMOUNT $mntpt
	rc=$?
	return $rc
}

setup_loopdev() {
	local facet=$1
	local file=$2
	local mntpt=$3
	local size=${4:-50}

	do_facet $facet mkdir -p $mntpt || error "mkdir -p $mntpt failed"
	stack_trap "do_facet $facet rmdir $mntpt" EXIT
	do_facet $facet dd if=/dev/zero of=$file bs=1M count=$size
	stack_trap "do_facet $facet rm -f $file" EXIT
	do_facet $facet mount
	do_facet $facet $UMOUNT $mntpt
	do_facet $facet mount
	do_facet $facet mkfs.ext4 $file ||
		error "mkfs.ext4 $file failed"
	do_facet $facet file $file
	do_facet $facet mount -t ext4 -o loop,usrquota,grpquota $file $mntpt ||
		error "mount -o loop,usrquota,grpquota $file $mntpt failed"
	stack_trap "umount_loopdev $facet $mntpt" EXIT
}

setup_loopdev_project() {
	local facet=$1
	local file=$2
	local mntpt=$3
	local size=${4:-50}

	do_facet $facet mkdir -p $mntpt || error "mkdir -p $mntpt failed"
	stack_trap "do_facet $facet rmdir $mntpt" EXIT
	do_facet $facet dd if=/dev/zero of=$file bs=1M count=$size
	stack_trap "do_facet $facet rm -f $file" EXIT
	do_facet $facet $UMOUNT $mntpt
	do_facet $facet mkfs.ext4 -O project,quota $file ||
		error "mkfs.ext4 -O project,quota $file failed"
	do_facet $facet file $file
	do_facet $facet mount -t ext4 -o loop,prjquota $file $mntpt ||
		error "mount -o loop,prjquota $file $mntpt failed"
	stack_trap "umount_loopdev $facet $mntpt" EXIT
	do_facet $facet mount | grep $mntpt
}

lpcc_rw_test() {
	local restore="$1"
	local project="$2"
	local project_id=100
	local agt_facet=$SINGLEAGT
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tdir/$tfile
	local -a state
	local -a lpcc_path
	local -a size

	$project && enable_project_quota

	do_facet $SINGLEAGT rm -rf $hsm_root
	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"

	is_project_quota_supported || project=false

	do_facet $SINGLEAGT $LFS mkdir -i0 -c1 $DIR/$tdir
	setup_pcc_mapping $SINGLEAGT "projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ pccrw=1"
	$project && lfs project -sp $project_id $DIR2/$tdir

	do_facet $SINGLEAGT "echo -n attach_origin > $file"
	if ! $project; then
		check_lpcc_state $file "none"
		do_facet $SINGLEAGT $LFS pcc attach -w \
			-i $HSM_ARCHIVE_NUMBER $file ||
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

	echo "Restore testing..."
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
		do_facet $SINGLEAGT $LFS pcc attach -w \
			-i $HSM_ARCHIVE_NUMBER $file ||
			error "PCC attach $file failed"
	fi
	check_lpcc_state $file "readwrite"
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"
	do_facet $SINGLEAGT "echo -n attach_detach > $file"
	echo "Start to detach the $file"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "PCC detach $file failed"
	wait_request_state $(path2fid $file) REMOVE SUCCEED

	check_lpcc_state $file "none"
	# The file is removed from PCC
	check_hsm_flags $file "0x00000000"
	check_file_data $SINGLEAGT $file "attach_detach"
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

test_1e() {
	local file=$DIR/$tdir/$tfile
	local hsm_root=$(hsm_root)
	local -a lpcc_path

	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0\ pccrw=1"
	$LCTL pcc list $MOUNT
	mkdir_on_mdt0 $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	chmod 777 $DIR/$tdir || error "chmod 777 $DIR/$tdir failed"

	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"
	do_facet $SINGLEAGT $RUNAS $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER \
		$file || error "failed to attach file $file"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $RUNAS dd if=$file of=/dev/null bs=1024 count=1 ||
		error "failed to dd read from $file"
	do_facet $SINGLEAGT $RUNAS $TRUNCATE $file 256 ||
		error "failed to truncate $file"
	do_facet $SINGLEAGT $RUNAS $TRUNCATE $file 2048 ||
		error "failed to truncate $file"
	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"
	check_lpcc_state $file "readwrite"

	do_facet $SINGLEAGT $RUNAS $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none"

	# non-root user is forbidden to access PCC file directly
	lpcc_path=$(lpcc_fid2path $hsm_root $file)
	do_facet $SINGLEAGT $RUNAS touch $lpcc_path &&
		error "non-root user can touch access PCC file $lpcc_path"
	do_facet $SINGLEAGT $RUNAS dd if=$lpcc_path of=/dev/null bs=1024 \
		count=1 && error "non-root user can read PCC file $lpcc_path"
	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$lpcc_path bs=1024 \
		count=1 && error "non-root user can write PCC file $lpcc_path"

	local perm=$(do_facet $SINGLEAGT stat -c %a $lpcc_path)

	[[ $perm == "0" ]] || error "PCC file permission ($perm) is not zero"

	do_facet $SINGLEAGT $RUNAS $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER \
		$file || error "failed to attach file $file"
	check_lpcc_state $file "readwrite"

	do_facet $SINGLEAGT $RUNAS $LFS pcc detach $file ||
		error "failed to detach file $file"
	wait_request_state $(path2fid $file) REMOVE SUCCEED
	check_lpcc_state $file "none"
}
run_test 1e "Test RW-PCC with non-root user"

test_1f() {
	local project_id=100
	local agt_facet=$SINGLEAGT
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tdir/$tfile

	is_project_quota_supported || skip "project quota is not supported"

	enable_project_quota
	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ open_attach=0\ stat_attach=0\ pccrw=1"

	do_facet $SINGLEAGT $LFS mkdir -i0 -c1 $DIR/$tdir
	chmod 777 $DIR/$tdir || error "chmod 0777 $DIR/$tdir failed"
	$LFS project -sp $project_id $DIR/$tdir ||
		error "failed to set project for $DIR/$tdir"

	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"

	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $RUNAS dd if=$file of=/dev/null bs=1024 count=1 ||
		error "failed to dd read from $file"
	do_facet $SINGLEAGT $RUNAS $TRUNCATE $file 256 ||
		error "failed to truncate $file"
	do_facet $SINGLEAGT $RUNAS $TRUNCATE $file 2048 ||
		error "failed to truncate $file"
	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$file bs=256 count=1 ||
		error "failed to dd write from $file"
	check_lpcc_state $file "readwrite"

	# non-root user is forbidden to access PCC file directly
	lpcc_path=$(lpcc_fid2path $hsm_root $file)
	do_facet $SINGLEAGT $RUNAS touch $lpcc_path &&
		error "non-root user can touch access PCC file $lpcc_path"
	do_facet $SINGLEAGT $RUNAS dd if=$lpcc_path of=/dev/null bs=1024 \
		count=1 && error "non-root user can read PCC file $lpcc_path"
	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$lpcc_path bs=1024 \
		count=1 && error "non-root user can write PCC file $lpcc_path"

	do_facet $SINGLEAGT $RUNAS $LFS pcc detach $file ||
		error "failed to detach file $file"
	wait_request_state $(path2fid $file) REMOVE SUCCEED
	check_lpcc_state $file "none"
}
run_test 1f "Test auto RW-PCC cache with non-root user"

test_1g() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT "projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ pccrw=1"

	dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"
	chmod 600 $file || error "chmod 600 $file failed"
	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$file bs=1024 count=1 &&
		error "non-root user can dd write $file"
	do_facet $SINGLEAGT $RUNAS dd if=$file of=/dev/null bs=1024 count=1 &&
		error "non-root user can dd read $file"
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$file bs=1024 count=1 &&
		error "non-root user can dd write to $file"
	do_facet $SINGLEAGT $RUNAS dd if=$file of=/dev/null bs=1024 count=1 &&
		error "non-root user can dd read $file"
	chmod 777 $DIR2/$tfile || error "chmod 777 $DIR2/$tfile failed"
	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "non-root user cannot write $file with permission (777)"

	do_facet $SINGLEAGT $RUNAS $LFS pcc detach $file &&
		error "non-root user or non owner can detach $file"
	chown $RUNAS_ID $file || error "chown $RUNAS_ID $file failed"
	do_facet $SINGLEAGT $RUNAS $LFS pcc detach $file ||
		error "failed to detach file $file"
	wait_request_state $(path2fid $file) REMOVE SUCCEED
	check_lpcc_state $file "none"
	do_facet $SINGLEAGT $RUNAS dd if=$file of=/dev/null bs=1024 count=1 ||
		error "non-root user cannot read to $file with permisson (777)"
}
run_test 1g "General permission test for RW-PCC"

#
# When a process created a LPCC file and holding the open,
# another process on the same client should be able to open the file.
#
test_2a() {
	local project_id=100
	local agt_facet=$SINGLEAGT
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local agt_host=$(facet_active_host $SINGLEAGT)

	is_project_quota_supported || skip "project quota is not supported"

	enable_project_quota
	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT "projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ pccrw=1"
	file=$DIR/$tdir/multiop
	$LFS mkdir -i -1 -c $MDSCOUNT $DIR/$tdir
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

	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "failed to detach $file"
	rmultiop_stop $agt_host || error "close $file failed"
}
run_test 2a "Test multi open when creating"

get_remote_client() {
	current_id=$(do_facet $SINGLEAGT hostname)
	for client in ${CLIENTS//,/ }
	do
		r_id=$(do_node $client hostname)
		if [ $r_id != $current_id ]; then
			echo $client
			return
		fi
	done
}

#
# When a process created a LPCC file and holding the open, another
# process on the different client should be able to open the file
# and perform IO on the file.
#
test_2b() {
	local agt_facet=$SINGLEAGT
	local agt_host=$(facet_active_host $SINGLEAGT)
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"

	needclients 2 || return 0

	remote_client=$(get_remote_client)

	enable_project_quota
	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT "projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ pccrw=1"
	file=$DIR/$tdir/multiop
	mkdir -p $DIR/$tdir
	rm -f $file

	do_facet $SINGLEAGT "echo -n file_data > $file"
	do_facet $SINGLEAGT lfs pcc attach -w -i $HSM_ARCHIVE_NUMBER \
		$file || error "PCC attach $file failed"
	check_lpcc_state $file "readwrite"

	rmultiop_start $agt_host $file O_c || error "open $file failed"

	do_node $remote_client "echo -n multiopen_data > $file"

	# PCC cached file should be automatically detached
	check_lpcc_state $file "none"

	check_file_data $SINGLEAGT $file "multiopen_data"
	rmultiop_stop $agt_host || error "close $file failed"
	check_file_data $SINGLEAGT $file "multiopen_data"

	do_node $remote_client cat $file || error \
		"cat $file on remote client failed"
	do_node $remote_client echo -n "multiopen_data" > $file \
		|| error "write $file on remote client failed"
}
run_test 2b "Test multi remote open when creating"

test_2c() {
	local agt_host=$(facet_active_host $SINGLEAGT)
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tdir/$tfile
	local file2=$DIR2/$tdir/$tfile

	enable_project_quota
	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT "projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ pccrw=1"
	mkdir -p $DIR/$tdir
	rm -f $file

	do_facet $SINGLEAGT "echo -n file_data > $file"
	do_facet $SINGLEAGT lfs pcc attach -w -i $HSM_ARCHIVE_NUMBER \
		$file || error "PCC attach $file failed"
	check_lpcc_state $file "readwrite"

	rmultiop_start $agt_host $file O_c || error "open $file failed"

	echo -n multiopen_data > $file2

	# PCC cached file should be automatically detached
	check_lpcc_state $file "none"

	check_file_data $SINGLEAGT $file "multiopen_data"
	rmultiop_stop $agt_host || error "close $file failed"
	check_file_data $SINGLEAGT $file "multiopen_data"

	cat $file2 || error "cat $file on mount $MOUNT2 failed"
	echo -n "multiopen_data" > $file2 ||
		error "write $file on mount $MOUNT2 failed"
}
run_test 2c "Test multi open on different mount points when creating"

test_3a() {
	local file=$DIR/$tdir/$tfile
	local file2=$DIR2/$tdir/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0\ pccrw=1\ pccro=1"

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	dd if=/dev/zero of=$file2 bs=1024 count=1 ||
		error "failed to dd write to $file"

	echo "Start to RW-PCC attach/detach the file: $file"
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none"

	echo "Repeat to RW-PCC attach/detach the same file: $file"
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none"

	rm -f $file || error "failed to remove $file"
	echo "pccro_data" > $file

	echo "Start to RO-PCC attach/detach the file: $file"
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readonly"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none"

	echo "Repeat to RO-PCC attach/detach the same file: $file"
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readonly"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none"
}
run_test 3a "Repeat attach/detach operations"

test_3b() {
	local n
	local file=$DIR/$tdir/$tfile

	needclients 3 || return 0

	# Start all of the copytools and setup PCC
	for n in $(seq $AGTCOUNT); do
		copytool setup -f agt$n -a $n -m $MOUNT -h $(hsm_root agt$n)
		setup_pcc_mapping agt$n "projid={100}\ rwid=$n\ auto_attach=0\ pccrw=1\ pccro=1"
	done

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"

	echo "Start to RW-PCC attach/detach $file on $agt1_HOST"
	do_facet agt1 $LFS pcc attach -w -i 1 $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite" agt1
	do_facet agt1 $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none" agt1

	echo "Repeat to RW-PCC attach/detach $file on $agt2_HOST"
	do_facet agt2 $LFS pcc attach -w -i 2 $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite" agt2
	do_facet agt2 $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none" agt2

	echo "Try RW-PCC attach on two agents"
	do_facet agt1 $LFS pcc attach -w -i 1 $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite" agt1
	do_facet agt2 $LFS pcc attach -w -i 2 $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite" agt2
	# The later attach PCC agent should succeed,
	# the former agent should be detached automatically.
	check_lpcc_state $file "none" agt1
	do_facet agt2 $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none" agt2

	echo "Start to RO-PCC attach/detach $file on $agt1_HOST"
	do_facet agt1 $LFS pcc attach -r -i 1 $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readonly" agt1
	do_facet agt1 $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none" agt1

	echo "Repeat to RO-PCC attach/detach $file on $agt2_HOST"
	do_facet agt2 $LFS pcc attach -r -i 2 $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readonly" agt2
	do_facet agt2 $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none" agt2

	echo "Try RO-PCC attach on two agents"
	do_facet agt1 $LFS pcc attach -r -i 1 $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readonly" agt1
	do_facet agt2 $LFS pcc attach -r -i 2 $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readonly" agt2
	check_lpcc_state $file "readonly" agt1
	do_facet agt2 $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none" agt2
	do_facet agt1 $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none" agt1
}
run_test 3b "Repeat attach/detach operations on multiple clients"

test_4() {
	local project_id=100
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local excepts="-e 7 -e 8 -e 9"

	is_project_quota_supported || skip "project quota is not supported"

	enable_project_quota
	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT "projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ pccrw=1"

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	lfs project -sp $project_id $DIR/$tdir ||
		error "lfs project -sp $project_id $DIR/$tdir failed"

	# 1. mmap_sanity tst7 failed on the local ext4 filesystem.
	#    It seems that Lustre filesystem does special process for tst 7.
	# 2. Current CentOS8 kernel does not strictly obey POSIX syntax for
	#    mmap() within the maping but beyond current end of the underlying
	#    files: It does not send SIGBUS signals to the process.
	# 3. For negative file offset, sanity_mmap also failed on 48 bits
	#    ldiksfs backend due to too large offset: "Value too large for
	#    defined data type".
	# mmap_sanity tst7/tst8/tst9 all failed on Lustre and local ext4.
	# Thus, we exclude sanity tst7/tst8/tst9 from the PCC testing.
	$LUSTRE/tests/mmap_sanity -d $DIR/$tdir -m $DIR2/$tdir $excepts ||
		error "mmap_sanity test failed"
	sync; sleep 1; sync

	# Revoke the layout lock, the PCC-cached file will be
	# detached automatically.
	do_facet $SINGLEAGT $LCTL \
		set_param ldlm.namespaces.*mdc*.lru_size=clear
	rm -rf $DIR/$tdir || error "failed to remove $DIR/$tdir"
}
run_test 4 "Auto cache test for mmap"

test_5() {
	local file=$DIR/$tfile
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT "projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ pccrw=1"

	do_facet $SINGLEAGT "echo -n attach_mmap_data > $file" ||
		error "echo $file failed"

	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite"

	local content=$($MMAP_CAT $file)

	[[ $content == "attach_mmap_data" ]] ||
		error "mmap cat data mismatch: $content"

	$LFS hsm_restore $file || error "failed to restore $file"
	wait_request_state $(path2fid $file) RESTORE SUCCEED
	check_lpcc_state $file "none"

	content=$($MMAP_CAT $file)
	[[ $content == "attach_mmap_data" ]] ||
		error "mmap cat data mismatch: $content"
}
run_test 5 "Mmap & cat a RW-PCC cached file"

test_6() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile
	local content

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT "projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ pccrw=1"

	echo -n mmap_write_data > $file || error "echo write $file failed"
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite"

	do_facet $SINGLEAGT $MULTIOP $file OSMWUc ||
		error "could not mmap $file"
	check_lpcc_state $file "readwrite"
	content=$(do_facet $SINGLEAGT $MMAP_CAT $file)
	# After mmap write via multiop, the first character of each page
	# increases with 1.
	[[ $content == "nmap_write_data" ]] ||
		error "mmap write data mismatch: $content"
	check_lpcc_state $file "readwrite"

	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "failed to detach file $file"
	wait_request_state $(path2fid $file) REMOVE SUCCEED

	content=$(do_facet $SINGLEAGT $MMAP_CAT $file)
	[[ $content == "nmap_write_data" ]] ||
		error "mmap write data mismatch: $content"
}
run_test 6 "Test mmap write on RW-PCC "

test_7a() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile
	local content

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT "projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ pccrw=1"

	echo "QQQQQ" > $file
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite"
	check_file_data $SINGLEAGT $file "QQQQQ"
	# define OBD_FAIL_LLITE_PCC_DETACH_MKWRITE	0x1412
	do_facet $SINGLEAGT $LCTL set_param fail_loc=0x1412
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"

	# multiop mmap write increase the first character of each page with 1
	do_facet $SINGLEAGT $MULTIOP $file OSMWUc ||
		error "mmap write $file failed"
	check_lpcc_state $file "none"
	content=$(do_facet $SINGLEAGT $MMAP_CAT $file)
	[[ $content == "RQQQQ" ]] || error "data mismatch: $content"
}
run_test 7a "Fake file detached between fault() and page_mkwrite() for RW-PCC"

test_7b() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile
	local content
	local pid

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0\ pccrw=1"

	echo "QQQQQ" > $file
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite"
	check_file_data $SINGLEAGT $file "QQQQQ"
	# define OBD_FAIL_LLITE_PCC_MKWRITE_PAUSE	0x1413
	do_facet $SINGLEAGT $LCTL set_param fail_loc=0x1413 fail_val=20
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"

	# multiop mmap write increases the first character of each page with 1
	do_facet $SINGLEAGT $MULTIOP $file OSMWUc &
	pid=$!

	sleep 3
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "failed to detach file $file"

	wait $pid || error "multiop mmap write failed"
	check_lpcc_state $file "none"
	content=$(do_facet $SINGLEAGT $MMAP_CAT $file)
	[[ $content == "RQQQQ" ]] || error "data mismatch: $content"
}
run_test 7b "Test the race with concurrent mkwrite and detach"

test_8() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT "projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ pccrw=1"

	echo "QQQQQ" > $file
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite"
	check_file_data $SINGLEAGT $file "QQQQQ"

	# define OBD_FAIL_LLITE_PCC_FAKE_ERROR	0x1411
	do_facet $SINGLEAGT $LCTL set_param fail_loc=0x1411
	do_facet $SINGLEAGT "echo -n ENOSPC_write > $file"
	# Above write will return -ENOSPC failure and retry the IO on normal
	# IO path. It will restore the HSM released file.
	check_lpcc_state $file "none"
	check_file_data $SINGLEAGT $file "ENOSPC_write"
}
run_test 8 "Test fake -ENOSPC tolerance for RW-PCC"

test_9() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.9a"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50

	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMVER" -h "$hsm_root"
	setup_pcc_mapping $SINGLEAGT "projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ pccrw=1"
	do_facet $SINGLEAGT $LCTL pcc list $MOUNT

	touch $file || error "touch $file failed"
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "fail to attach $file"
	check_lpcc_state $file "readwrite"
	# write 60M data, it is larger than the capacity of PCC backend
	do_facet $SINGLEAGT dd if=/dev/zero of=$file bs=1M count=60 ||
		error "fail to dd write $file"
	check_lpcc_state $file "none"
	check_file_size $SINGLEAGT $file 62914560
}
run_test 9 "Test -ENOSPC tolerance on loop PCC device for RW-PCC"

test_usrgrp_quota() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local state="readonly"
	local mode="pccro"
	local ug=$1
	local rw=$2
	local id=$RUNAS_ID

	[[ $ug == "g" ]] && id=$RUNAS_GID
	[[ -z $rw ]] || {
		state="readwrite"
		mode="pccrw"
	}

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	do_facet $SINGLEAGT quotacheck -c$ug $mntpt ||
		error "quotacheck -c$ug $mntpt failed"
	do_facet $SINGLEAGT quotaon -$ug $mntpt ||
		error "quotaon -$ug $mntpt failed"
	do_facet $SINGLEAGT setquota -$ug $id 0 20480 0 0 $mntpt ||
		error "setquota -$ug $id on $mntpt failed"
	do_facet $SINGLEAGT repquota -${ug}vs $mntpt

	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMVER" -h "$hsm_root"
	setup_pcc_mapping $SINGLEAGT "projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ $mode=1"
	do_facet $SINGLEAGT $LCTL pcc list $MOUNT

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"

	local file1=$DIR/$tdir/${ug}quotaA
	local file2=$DIR/$tdir/${ug}quotaB

	dd if=/dev/zero of=$file1 bs=1M count=15 ||
		error "dd write $file1 failed"
	dd if=/dev/zero of=$file2 bs=1M count=15 ||
		error "dd write $file2 failed"
	chown $RUNAS_ID:$RUNAS_GID $file1 ||
		error "chown $RUNAS_ID:$RUNAS_GID $file1 failed"
	chown $RUNAS_ID:$RUNAS_GID $file2 ||
		error "chown $RUNAS_ID:$RUNAS_GID $file2 failed"
	do_facet $SINGLEAGT $RUNAS $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $rw \
		$file1 || error "attach $file1 failed"
	do_facet $SINGLEAGT $RUNAS $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $rw \
		$file2 && error "attach $file2 should fail due to quota limit"
	check_lpcc_state $file1 $state
	check_lpcc_state $file2 "none"

	if [[ -z $rw ]]; then
		do_facet $SINGLEAGT $LFS pcc detach $file1 ||
			error "detach $file1 failed"
		return 0
	fi

	echo "Test -EDQUOT error tolerance for RW-PCC"
	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$file1 bs=1M count=30 ||
		error "dd write $file1 failed"
	# -EDQUOT error should be tolerated via fallback to normal Lustre path.
	check_lpcc_state $file1 "none"
}

test_10a() {
	test_usrgrp_quota "u" "-w"
}
run_test 10a "Test RW-PCC with user quota on loop PCC device"

test_10b() {
	test_usrgrp_quota "g" "-w"
}
run_test 10b "Test RW-PCC with group quota on loop PCC device"

test_10c() {
	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	test_usrgrp_quota "u"
}
run_test 10c "Test RO-PCC with user quota on loop PCC device"

test_10d() {
	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	test_usrgrp_quota "g"
}
run_test 10d "Test RO-PCC with group quota on loop PCC device"

test_usrgrp_edquot() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile
	local id=$RUNAS_ID
	local ug=$1

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	[[ $ug == "g" ]] && id=$RUNAS_GID
	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	do_facet $SINGLEAGT quotacheck -c$ug $mntpt ||
		error "quotacheck -c$ug $mntpt failed"
	do_facet $SINGLEAGT quotaon -$ug $mntpt ||
		error "quotaon -$ug $mntpt failed"
	do_facet $SINGLEAGT setquota -$ug $id 0 4096 0 0 $mntpt ||
		error "setquota -$ug $id on $mntpt failed"
	do_facet $SINGLEAGT repquota -${ug}vs $mntpt
	do_facet $SINGLEAGT mkdir $hsm_root || error "mkdir $hsm_root failed"
	setup_pcc_mapping $SINGLEAGT \
		"${ug}id={$id}\ roid=$HSM_ARCHIVE_NUMBER\ pccro=1"
	do_facet $SINGLEAGT $LCTL pcc list $MOUNT

	dd if=/dev/zero of=$file bs=1M count=2 ||
		error "dd write $file failed"
	chown $RUNAS_ID:$RUNAS_GID $file ||
		error "chown $RUNAS_ID:$RUNAS_GID $file failed"
	do_facet $SINGLEAGT $RUNAS dd if=$file of=/dev/null bs=1M count=2 ||
		error "dd read $file failed"
	check_lpcc_state $file "readonly"
	$LFS getstripe -v $file
	do_facet $SINGLEAGT dd if=/dev/zero of=$file bs=1M count=5 ||
		error "dd write $file failed"
	check_lpcc_state $file "none"
	do_facet $SINGLEAGT $RUNAS dd if=$file of=/dev/null bs=1M count=5 ||
		error "dd read $file failed"
	do_facet $SINGLEAGT $LFS pcc state $file
	$LFS getstripe -v $file
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "PCC-RO attach $file failed"

	do_facet $SINGLEAGT $LFS pcc detach $file || error "detach $file failed"
}

test_10e() {
	test_usrgrp_edquot "u"
}
run_test 10e "Tolerate -EDQUOT failure when auto PCC-RO attach with user quota"

test_10f() {
	test_usrgrp_edquot "g"
}
run_test 10f "Tolerate -EDQUOT failure when auto PCC-RO attach with group quota"

test_11() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile
	local -a lpcc_path
	local lpcc_dir

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT "projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ pccrw=1"

	do_facet $SINGLEAGT "echo -n QQQQQ > $file"
	lpcc_path=$(lpcc_fid2path $hsm_root $file)
	lpcc_dir=$(dirname $lpcc_path)
	echo "Lustre file: $file LPCC dir: $lpcc_dir"
	do_facet $SINGLEAGT mkdir -p $lpcc_dir ||
		error "mkdir -p $lpcc_dir failed"
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach $file"
	check_lpcc_state $file "readwrite"
	check_file_data $SINGLEAGT $file "QQQQQ"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "failed to detach $file"
	rm $file || error "rm $file failed"

	# The parent directory of the PCC file is immutable
	do_facet $SINGLEAGT "echo -n immutable_dir > $file"
	lpcc_path=$(lpcc_fid2path $hsm_root $file)
	lpcc_dir=$(dirname $lpcc_path)
	echo "Lustre file: $file LPCC dir: $lpcc_dir"
	do_facet $SINGLEAGT mkdir -p $lpcc_dir ||
		error "mkdir -p $lpcc_dir failed"
	do_facet $SINGLEAGT chattr +i $lpcc_dir ||
		error "chattr +i $lpcc_dir failed"
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file &&
		error "attach $file with immutable directory should be failed"
	do_facet $SINGLEAGT chattr -i $lpcc_dir ||
		error "chattr -i $lpcc_dir failed"
	rm $file || error "rm $file failed"

	# The PCC file path is set to a directory
	do_facet $SINGLEAGT "echo -n pcc_file_path_is_dir > $file"
	lpcc_path=$(lpcc_fid2path $hsm_root $file)
	do_facet $SINGLEAGT mkdir -p $lpcc_path ||
		error "mkdir -p $lpcc_path failed"
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file &&
		error "attach $file should fail as PCC path is a directory"
	rm $file || error "rm $file failed"
}
run_test 11 "Test attach fault injection with simulated PCC file path"

test_12() {
	local file=$DIR/$tfile
	local hsm_root=$(hsm_root)
	local -a lpcc_path
	local pid

	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0\ pccrw=1"

	echo  -n race_rw_attach_hsmremove > $file
	lpcc_path=$(lpcc_fid2path $hsm_root $file)
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "attach $file failed"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "detach $file failed"
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"
	# define OBD_FAIL_LLITE_PCC_ATTACH_PAUSE	0x1414
	do_facet $SINGLEAGT $LCTL set_param fail_loc=0x1414 fail_val=20
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file &
	pid=$!
	$LFS hsm_state $file
	sleep 3
	wait_request_state $(path2fid $file) RESTORE SUCCEED
	$LFS hsm_remove $file || error "hsm remove $file failed"
	wait $pid
	do_facet $SINGLEAGT "[ -f $lpcc_path ]"	&&
		error "RW-PCC cached file '$lpcc_path' should be removed"

	return 0
}
run_test 12 "RW-PCC attach races with concurrent HSM remove"

test_rule_id() {
	local idstr="${1}id"
	local rule="${idstr}={$2}"
	local myRUNAS="$3"
	local file=$DIR/$tdir/$tfile

	setup_pcc_mapping $SINGLEAGT \
		"$rule\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0\ pccrw=1"
	$LCTL pcc list $MOUNT

	do_facet $SINGLEAGT $LFS mkdir -i 0 $DIR/$tdir
	chmod 777 $DIR/$tdir || error "chmod 0777 $DIR/$tdir failed"

	rm -f $file || error "rm $file failed"
	do_facet $SINGLEAGT $myRUNAS dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $myRUNAS dd if=$file of=/dev/null bs=1024 count=1 ||
		error "failed to dd read from $file"
	do_facet $SINGLEAGT $myRUNAS $TRUNCATE $file 256 ||
		error "failed to truncate $file"
	do_facet $SINGLEAGT $myRUNAS $TRUNCATE $file 2048 ||
		error "failed to truncate $file"
	do_facet $SINGLEAGT $myRUNAS dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write from $file"
	check_lpcc_state $file "readwrite"

	do_facet $SINGLEAGT $myRUNAS $LFS pcc detach $file ||
		error "failed to detach file $file"
	wait_request_state $(path2fid $file) REMOVE SUCCEED
	check_lpcc_state $file "none"

	cleanup_pcc_mapping
}

test_13a() {
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	test_rule_id "u" "$RUNAS_ID" "runas -u $RUNAS_ID"
	test_rule_id "g" "$RUNAS_GID" "runas -u $RUNAS_ID -g $RUNAS_GID"
}
run_test 13a "Test auto RW-PCC create caching for UID/GID rule"

test_13b() {
	local file

	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"fname={*.h5\ suffix.*\ Mid*dle}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0\ pccrw=1"
	$LCTL pcc list $MOUNT

	do_facet $SINGLEAGT mkdir -p $DIR/$tdir
	chmod 777 $DIR/$tdir || error "chmod 0777 $DIR/$tdir failed"

	file=$DIR/$tdir/prefix.h5
	do_facet $SINGLEAGT dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $myRUNAS $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none"
	rm $file || error "rm $file failed"

	file=$DIR/$tdir/suffix.doc
	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $myRUNAS $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none"
	rm $file || error "rm $file failed"

	file=$DIR/$tdir/MidPADdle
	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $myRUNAS $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none"
	rm $file || error "rm $file failed"

	file=$DIR/$tdir/Midpad
	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"
	check_lpcc_state $file "none"
	rm $file || error "rm $file failed"
}
run_test 13b "Test auto RW-PCC create caching for file name with wildcard"

test_13c() {
	local file
	local myRUNAS
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"

	is_project_quota_supported || skip "project quota is not supported"

	enable_project_quota
	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100\ 200}\&fname={*.h5},uid={$RUNAS_ID}\&gid={$RUNAS_GID}\ rwid=$HSM_ARCHIVE_NUMBER\ pccrw=1"
	$LCTL pcc list $MOUNT
	do_facet $SINGLEAGT mkdir -p $DIR/$tdir
	chmod 777 $DIR/$tdir || error "chmod 0777 $DIR/$tdir failed"

	mkdir -p $DIR/$tdir/proj || error "mkdir $DIR/$tdir/proj failed"
	mkdir -p $DIR/$tdir/proj2 || error "mkdir $DIR/$tdir/proj2 failed"
	$LFS project -sp 100 $DIR/$tdir/proj ||
		error "failed to set project for $DIR/$tdir/proj"
	$LFS project -sp 200 $DIR/$tdir/proj2 ||
		error "failed to set project for $DIR/$tdir/proj2"

	file=$DIR/$tdir/proj/notcache
	do_facet $SINGLEAGT dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"
	check_lpcc_state $file "none"
	rm $file || error "rm $file failed"

	file=$DIR/$tdir/proj/autocache.h5
	do_facet $SINGLEAGT dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "failed to detach $file"
	rm $file || error "rm $file failed"

	file=$DIR/$tdir/proj2/notcache
	do_facet $SINGLEAGT dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"
	check_lpcc_state $file "none"
	rm $file || error "rm $file failed"

	file=$DIR/$tdir/proj2/autocache.h5
	do_facet $SINGLEAGT dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "failed to detach $file"
	rm $file || error "rm $file failed"

	file=$DIR/$tdir/ugidcache
	myRUNAS="runas -u $RUNAS_ID -g $RUNAS_GID"
	do_facet $SINGLEAGT $myRUNAS dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "failed to detach $file"
	rm $file || error "rm $file failed"
}
run_test 13c "Check auto RW-PCC create caching for UID/GID/ProjID/fname rule"

test_14() {
	local file=$DIR/$tdir/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0\ pccrw=1\ pccro=1"

	mkdir -p $DIR/$tdir || error "mkdir -p $DIR/$tdir failed"
	do_facet $SINGLEAGT "echo -n autodetach_data > $file"
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER \
		$file || error "PCC attach $file failed"
	check_lpcc_state $file "readwrite"

	# Revoke the layout lock, the PCC-cached file will be
	# detached automatically.
	do_facet $SINGLEAGT $LCTL \
		set_param ldlm.namespaces.*mdc*.lru_size=clear
	check_file_data $SINGLEAGT $file "autodetach_data"
	check_lpcc_state $file "none"

	rm $file || error "rm $file failed"
	do_facet $SINGLEAGT "echo -n ro_autodetach_data > $file"
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "PCC attach $file failed"
	check_lpcc_state $file "readonly"

	# Revoke the layout lock, the PCC-cached file will be
	# detached automatically.
	do_facet $SINGLEAGT $LCTL \
		set_param ldlm.namespaces.*mdc*.lru_size=clear
	check_file_data $SINGLEAGT $file "ro_autodetach_data"
	check_lpcc_state $file "none"
}
run_test 14 "Revocation of the layout lock should detach the file automatically"

test_15() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tdir/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT "projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ pccrw=1\ pccro=1"

	mkdir_on_mdt0 $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	chmod 777 $DIR/$tdir || error "chmod 777 $DIR/$tdir failed"

	echo "Verify open attach for non-root user"
	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"
	do_facet $SINGLEAGT $RUNAS $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER \
		$file || error "failed to attach file $file"
	do_facet $SINGLEAGT $RUNAS $LFS pcc state $file
	check_lpcc_state $file "readwrite" $SINGLEAGT "$RUNAS"
	# Revoke the layout lock, the PCC-cached file will be
	# detached automatically.
	do_facet $SINGLEAGT $LCTL \
		set_param ldlm.namespaces.*mdc*.lru_size=clear
	check_lpcc_state $file "none" $SINGLEAGT "$RUNAS"
	do_facet $SINGLEAGT $RUNAS $MULTIOP $file oc ||
		error "failed to open $file"
	check_lpcc_state $file "readwrite" $SINGLEAGT "$RUNAS"
	# Detach the file but keep the cache , as the file layout generation
	# is not changed, so the file is still valid cached in PCC, and can
	# be reused from PCC cache directly.
	do_facet $SINGLEAGT $RUNAS $LFS pcc detach -k $file ||
		error "PCC detach $file failed"
	check_lpcc_state $file "none" $SINGLEAGT "$RUNAS"
	do_facet $SINGLEAGT $RUNAS $MULTIOP $file oc ||
		error "failed to open $file"
	check_lpcc_state $file "readwrite" $SINGLEAGT "$RUNAS"
	do_facet $SINGLEAGT $RUNAS $LFS pcc detach $file ||
		error "PCC detach $file failed"
	rm $file || error "rm $file failed"

	echo "Verify auto attach at open for RW-PCC"
	do_facet $SINGLEAGT "echo -n autoattach_data > $file"
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER \
		$file || error "RW-PCC attach $file failed"
	check_lpcc_state $file "readwrite"

	# Revoke the layout lock, the PCC-cached file will be
	# detached automatically.
	do_facet $SINGLEAGT $LCTL \
		set_param ldlm.namespaces.*mdc*.lru_size=clear
	check_file_data $SINGLEAGT $file "autoattach_data"
	check_lpcc_state $file "readwrite"

	# Detach the file with -k option, as the file layout generation
	# is not changed, so the file is still valid cached in PCC,
	# and can be reused from PCC cache directly.
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "RW-PCC detach $file failed"
	check_lpcc_state $file "none"
	do_facet $SINGLEAGT $MULTIOP $file oc || error "failed to open $file"
	check_lpcc_state $file "readwrite"
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"
	check_file_data $SINGLEAGT $file "autoattach_data"

	# HSM restore the PCC cached file, the layout generation
	# was changed, so the file can not be auto attached.
	$LFS hsm_restore $file || error "failed to restore $file"
	wait_request_state $(path2fid $file) RESTORE SUCCEED
	check_lpcc_state $file "none"
	# HSM exists archived status
	check_hsm_flags $file "0x00000009"

	echo "Verify auto attach at open for RO-PCC"
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER -r $file ||
		error "RO-PCC attach $file failed"
	check_lpcc_state $file "readonly"

	# Revoke the layout lock, the PCC-cached file will be
	# detached automatically.
	do_facet $SINGLEAGT $LCTL \
		set_param ldlm.namespaces.*mdc*.lru_size=clear
	check_file_data $SINGLEAGT $file "autoattach_data"
	check_lpcc_state $file "readonly"

	# Detach the file with "-k" option, as the file layout generation
	# is not changed, so the file is still valid cached in PCC,
	# and can be reused from PCC cache directly.
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "RO-PCC detach $file failed"
	check_lpcc_state $file "none"
	do_facet $SINGLEAGT $MULTIOP $file oc || error "failed to open $file"
	check_lpcc_state $file "readonly"
	check_file_data $SINGLEAGT $file "autoattach_data"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "RO-PCC detach $file failed"
}
run_test 15 "Test auto attach at open when file is still valid cached"

test_16() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile
	local -a lpcc_path

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT "projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ pccrw=1\ pccro=1"

	echo "Test detach for RW-PCC"
	do_facet $SINGLEAGT "echo -n detach_data > $file"
	lpcc_path=$(lpcc_fid2path $hsm_root $file)
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER \
		$file || error "RW-PCC attach $file failed"
	check_lpcc_state $file "readwrite"
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"

	echo "Test for reusing valid PCC cache"
	# Valid PCC cache can be reused
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "PCC detach $file failed"
	check_lpcc_state $file "none"
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"

	echo "Test for the default detach"
	# Permanent detach by default, it will remove the PCC copy
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "RW-PCC detach $file failed"
	wait_request_state $(path2fid $file) REMOVE SUCCEED
	check_lpcc_state $file "none"
	# File is removed from PCC backend
	check_hsm_flags $file "0x00000000"
	do_facet $SINGLEAGT "[ -f $lpcc_path ]"	&&
		error "RW-PCC cached file '$lpcc_path' should be removed"

	echo "Test detach for RO-PCC"
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER -r $file ||
		error "RO-PCC attach $file failed"
	check_lpcc_state $file "readonly"

	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "RO-PCC detach $file failed"
	check_lpcc_state $file "none"
	# Reading the file will re-attach the file in readonly mode
	do_facet $SINGLEAGT cat $file || error "cat $file failed"
	check_lpcc_state $file "readonly"

	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "RO-PCC detach $file failed"
	check_lpcc_state $file "none"
	do_facet $SINGLEAGT "[ -f $lpcc_path ]"	&&
		error "RO-PCC cached file '$lpcc_path' should be removed"

	return 0
}
run_test 16 "Test detach with different options"

test_17() {
	local agt_host=$(facet_active_host $SINGLEAGT)
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ open_attach=0\ stat_attach=0\ pccrw=1"

	do_facet $SINGLEAGT $LCTL pcc list $MOUNT

	do_facet $SINGLEAGT "echo -n layout_refresh_data > $file"
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "PCC attach $file failed"
	check_lpcc_state $file "readwrite"

	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "PCC detach $file failed"
	check_lpcc_state $file "none"

	# Truncate should attach the file into PCC automatically
	# as the PCC copy is still valid.
	echo "Verify auto attach during IO for truncate"
	do_facet $SINGLEAGT $TRUNCATE $file 4 || error "truncate $file failed"
	check_lpcc_state $file "readwrite"

	echo "Verify auto attach during IO for read/write"
	rmultiop_start $agt_host $file O_r || error "open $file failed"
	sleep 3

	# Revoke the layout lock, the PCC-cached file will be
	# detached automatically.
	do_facet $SINGLEAGT $LCTL \
		set_param ldlm.namespaces.*mdc*.lru_size=clear

	check_lpcc_state $file "none"
	rmultiop_stop $agt_host || error "close $file failed"
	sleep 3
	check_lpcc_state $file "readwrite"

	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "PCC detach $file failed"
	check_lpcc_state $file "none"
}
run_test 17 "Test auto attach for layout refresh"

test_18() {
	local agt_host=$(facet_active_host $SINGLEAGT)
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile
	local oldmd5
	local newmd5

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ pccrw=1"

	do_facet $SINGLEAGT $LCTL pcc list $MOUNT
	do_facet $SINGLEAGT dd if=/dev/urandom of=$file bs=1M count=4 ||
		error "failed to write $file"
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach $file"
	do_facet $SINGLEAGT $LFS pcc state $file
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $LFS pcc detach --keep $file ||
		error "failed to detach $file"
	do_facet $SINGLEAGT $LFS pcc state $file
	$CHECKSTAT -s 4194304 $file
	dd if=/dev/zero of=$DIR2/$tfile seek=1k bs=1k count=1 ||
		error "failed to write $DIR2/$tfile"
	oldmd5=$(md5sum $DIR2/$tfile | awk '{print $1}')
	$CHECKSTAT -s 1049600 $DIR2/$tfile || error "$DIR2/$tfile size wrong"

	local lpcc_path=$(lpcc_fid2path $hsm_root $file)

	do_facet $SINGLEAGT $LFS pcc state $file
	check_file_size $SINGLEAGT $lpcc_path 4194304
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach $file"
	check_lpcc_sizes $SINGLEAGT $lpcc_path $file 1049600
	newmd5=$(do_facet $SINGLEAGT md5sum $file | awk '{print $1}')
	[ "$oldmd5" == "$newmd5" ] || error "md5sum differ: $oldmd5 != $newmd5"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "failed to detach $file"
}
run_test 18 "Verify size correctness after re-attach the file"

test_19() {
	local agt_host=$(facet_active_host $SINGLEAGT)
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0\ pccrw=1"

	do_facet $SINGLEAGT "echo -n QQQQQ > $file" || error "echo $file failed"
	lpcc_path=$(lpcc_fid2path $hsm_root $file)
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "Failed to attach $file"
	check_lpcc_state $file "readwrite"
	check_lpcc_sizes $SINGLEAGT $file $lpcc_path 5
	do_facet $SINGLEAGT $LFS pcc detach --keep $file ||
		error "Failed to detach $file"
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "Failed to attach $file"
	check_lpcc_sizes $SINGLEAGT $file $lpcc_path 5
	do_facet $SINGLEAGT $LFS pcc detach --keep $file ||
		error "Failed to detach $file"
}
run_test 19 "Verify the file re-attach works as expected"

test_20() {
	local agt_host=$(facet_active_host $SINGLEAGT)
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	setup_loopdev $SINGLEAGT $loopfile $mntpt 120
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ pccrw=1"

	do_facet $SINGLEAGT "echo -n QQQQQ > $file" ||
		error "echo $file failed"
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "Failed to attach $file"
	do_facet $SINGLEAGT "echo 3 > /proc/sys/vm/drop_caches"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT "echo 3 > /proc/sys/vm/drop_caches"
	do_facet $SINGLEAGT "echo 3 > /proc/sys/vm/drop_caches"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "Failed to detach $file"
}
run_test 20 "Auto attach works after the inode was once evicted from cache"

test_21a() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0"

	do_facet $SINGLEAGT "echo -n pccro_as_mirror_layout > $file"
	echo "Plain layout info before PCC-RO attach '$file':"
	$LFS getstripe -v $file
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "RW-PCC attach $file failed"
	check_lpcc_state $file "readonly"
	echo -e "\nFLR layout info after PCC-RO attach '$file':"
	$LFS getstripe -v $file
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none"
	echo -e "\nFLR layout info after PCC-RO detach '$file':"
	$LFS getstripe -v $file

	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readonly"
	echo -e "\nFLR layout info after RO-PCC attach $file again:"
	$LFS getstripe -v $file
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none"
	echo -e "\nFLR layout info after RO-PCC detach '$file' again:"
	$LFS getstripe -v $file
}
run_test 21a "PCC-RO storing as a plain HSM mirror component for plain layout"

test_21b() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	do_facet $SINGLEAGT mkdir -p $hsm_root ||
		error "failed to mkdir $hsm_root"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0"

	$LFS mirror create -N -S 4M -c 2 -N -S 1M -c -1  $file ||
		error "create mirrored file $file failed"
	#do_facet $SINGLEAGT "echo -n pccro_as_mirror_layout > $file"
	echo "FLR layout before PCC-RO attach '$file':"
	$LFS getstripe -v $file
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readonly"
	echo -e "\nFLR layout after PCC-RO attach '$file':"
	$LFS getstripe -v $file
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none"
	echo -e "\nFLR layout info after PCC-RO detach '$file':"
	$LFS getstripe -v $file

	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readonly"
	echo -e "\nFLR layout after PCC-RO attach '$file' again:"
	$LFS getstripe -v $file
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none"
	echo -e "\nFLR layout info after PCC-RO detach '$file':"
	$LFS getstripe -v $file
}
run_test 21b "PCC-RO stroing as a plain HSM mirror component for FLR layouts"

test_21c() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile
	local fid

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0"

	do_facet $SINGLEAGT "echo -n pccro_hsm_release > $file"
	fid=$(path2fid $file)
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $file ||
		error "Archive $file failed"
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_state $file

	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER -r $file ||
		error "RO-PCC attach $file failed"
	# HSM exists archived status
	check_hsm_flags $file "0x00000009"
	check_lpcc_state $file "readonly"
	check_file_data $SINGLEAGT $file "pccro_hsm_release"

	$LFS hsm_release $file || error "HSM released $file failed"
	$LFS getstripe $file
	$LFS hsm_state $file
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "failed to detach $file"
	check_lpcc_state $file "none"

	unlink $file || error "unlink $file failed"
}
run_test 21c "Verify HSM release works storing PCC-RO as HSM mirror component"

test_21d() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping

	echo "pccro_init_data" > $file
	$LFS getstripe $file
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to PCC-RO attach file $file"
	check_lpcc_state $file "readonly"
	echo "PCC-RO attach '$file':"
	$LFS getstripe -v $file

	echo "Write invalidated PCC-RO cache:"
	echo -n "write_mod_data" > $file
	check_lpcc_state $file "none"
	$LFS getstripe -v $file
	check_file_data $SINGLEAGT $file "write_mod_data"
}
run_test 21d "Write should invalidate PCC-RO caching"

test_21e() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping

	echo "pccro_init_data" > $file
	$LFS getstripe $file
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to PCC-RO attach file $file"
	check_lpcc_state $file "readonly"
	echo "PCC-RO attach '$file':"
	$LFS getstripe -v $file

	echo "Trucate invalidate PCC-RO file '$file':"
	$TRUNCATE $file 256 || error "failed to truncate $file"
	$LFS getstripe -v $file
	check_lpcc_state $file "none"
	check_file_size $SINGLEAGT $file 256
}
run_test 21e "Truncate should invalidate PCC-RO caching"

test_21f() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping

	echo "pccro_mmap_data" > $file
	$LFS getstripe $file
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to PCC-RO attach file $file"
	check_lpcc_state $file "readonly"
	echo "PCC-RO attach '$file':"
	$LFS getstripe -v $file

	echo "Mmap write invalidate PCC-RO caching:"
	# Mmap write will invalidate the RO-PCC cache
	do_facet $SINGLEAGT $MULTIOP $file OSMWUc ||
		error "mmap write $file failed"
	check_lpcc_state $file "none"
	$LFS getstripe -v $file
	# After mmap-write by MULTIOP, the first character of the content
	# will be increased with 1.
	content=$(do_facet $SINGLEAGT $MMAP_CAT $file)
	[[ $content == "qccro_mmap_data" ]] ||
		error "mmap_cat data mismatch: $content"
}
run_test 21f "mmap write should invalidate PCC-RO caching"

test_21g() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0"

	$LFS mirror create -N -S 4M -c 2 -N -S 1M -c -1  $file ||
		error "create mirrored file '$file' failed"
	do_facet $SINGLEAGT "echo -n pccro_as_mirror_layout > $file"
	echo "FLR layout before PCC-RO attach '$file':"
	$LFS getstripe -v $file
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to PCC-RO attach '$file'"
	echo "FLR layout after PCC-RO attach '$file':"
	$LFS getstripe -v $file
	echo "Layout after Write invalidate '$file':"
	echo -n pccro_write_invalidate_mirror > $file
	$LFS getstripe -v $file
}
run_test 21g "PCC-RO for file under FLR write pending state"

test_21h() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0"

	$LFS mirror create -N -S 4M -c 2 -N -S 1M -c -1  $file ||
		error "create mirrored file $file failed"
	#do_facet $SINGLEAGT "echo -n pccro_as_mirror_layout > $file"
	echo "FLR layout before PCC-RO attach '$file':"
	$LFS getstripe -v $file
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readonly"
	echo -e "\nFLR layout after PCC-RO attach '$file':"
	$LFS getstripe -v $file

	$LFS mirror extend -N -S 8M -c -1 $file ||
		error "mirror extend $file failed"
	echo -e "\nFLR layout after extend a mirror:"
	$LFS getstripe -v $file
	$LFS pcc state $file
	check_lpcc_state $file "none"

	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readonly"
	echo -e "\nFLR layout after PCC-RO attach '$file' again:"
	$LFS getstripe -v $file
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none"
}
run_test 21h "Extend mirror once file was PCC-RO cached"

test_21i() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile
	local file2=$DIR2/$tfile
	local fid

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0\ pccro=1\ pccrw=1"

	do_facet $SINGLEAGT "echo -n hsm_release_pcc_file > $file"
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "RW-PCC attach $file failed"
	check_lpcc_state $file "readwrite"
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"

	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "RW-PCC detach $file failed"
	check_lpcc_state $file "none"
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"

	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to PCC-RO attach $file"

	$LFS hsm_state $file
	$LFS hsm_release $file || error "HSM released $file failed"
	echo "Layout after HSM release $file:"
	$LFS getstripe -v $file
	echo "PCC state $file:"
	$LFS pcc state $file
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER -r $file ||
		error "RO-PCC attach $file failed"
	echo "Layout after PCC-RO attach $file again:"
	$LFS getstripe -v $file
	echo "PCC state:"
	$LFS pcc state $file

	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "RW-PCC detach $file failed"
	check_lpcc_state $file "none"
}
run_test 21i "HSM release increase layout gen, should invalidate PCC-RO cache"

test_22() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile
	local file2=$DIR2/$tfile
	local fid

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0\ pccrw=1\ pccro=1"

	do_facet $SINGLEAGT "echo -n roattach_data > $file"

	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "RW-PCC attach $file failed"
	check_lpcc_state $file "readwrite"
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"

	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "RW-PCC detach $file failed"
	check_lpcc_state $file "none"
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"

	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER -r $file ||
		error "RO-PCC attach $file failed"
	echo "Layout after PCC-RO attach $file:"
	$LFS getstripe -v $file
	# HSM exists archived status
	check_hsm_flags $file "0x00000009"
	check_lpcc_state $file "readonly"
	check_file_data $SINGLEAGT $file "roattach_data"

	$LFS hsm_release $file || error "HSM released $file failed"
	echo "Layout after HSM release $file:"
	$LFS getstripe -v $file
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER -r $file ||
		error "RO-PCC attach $file failed"
	echo "Layout after PCC-RO attach $file again:"
	$LFS getstripe -v $file
	check_lpcc_state $file "readonly"
	check_file_data $SINGLEAGT $file "roattach_data"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "failed to detach $file"
	echo "Layout after PCC-RO detach $file:"
	$LFS getstripe -v $file
	rm -f $file2 || error "rm -f $file failed"
	do_facet $SINGLEAGT "echo -n roattach_data2 > $file"
	fid=$(path2fid $file)
	$LFS hsm_archive --archive $HSM_ARCHIVE_NUMBER $file ||
		error "Archive $file failed"
	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_release $file || error "HSM released $file failed"
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER -r $file ||
		error "RO-PCC attach $file failed"
	check_lpcc_state $file "readonly"
	check_file_data $SINGLEAGT $file "roattach_data2"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "RO-PCC detach $file failed"
}
run_test 22 "Test RO-PCC attach for the HSM released file"

test_23() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile
	local -a lpcc_path

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping

	echo "pccro_data" > $file
	lpcc_path=$(lpcc_fid2path $hsm_root $file)

	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to RO-PCC attach file $file"
	check_lpcc_state $file "readonly"
	check_lpcc_data $SINGLEAGT $lpcc_path $file "pccro_data"

	local content=$(do_facet $SINGLEAGT $MMAP_CAT $file)

	[[ $content == "pccro_data" ]] ||
		error "mmap_cat data mismatch: $content"
	check_lpcc_state $file "readonly"

	echo -n "write_mod_data" > $file
	echo "Write should invalidate the RO-PCC cache:"
	$LFS getstripe -v $file
	check_lpcc_state $file "none"
	check_file_data $SINGLEAGT $file "write_mod_data"

	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to RO-PCC attach file $file"
	check_lpcc_state $file "readonly"
	echo "PCC-RO attach '$file' again:"
	$LFS getstripe -v $file

	echo "Truncate invalidate the RO-PCC cache:"
	$TRUNCATE $file 256 || error "failed to truncate $file"
	$LFS getstripe -v $file
	echo "Finish trucate operation"
	check_lpcc_state $file "none"
	check_file_size $SINGLEAGT $file 256

	echo "Mmap write invalidates RO-PCC caching"
	echo -n mmap_write_data > $file || error "echo write $file failed"
	$LFS getstripe -v $file
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to RO-PCC attach file $file"
	check_lpcc_state $file "readonly"
	echo "PCC-RO attach '$file' again:"
	$LFS getstripe -v $file
	echo "Mmap write $file via multiop"
	# Mmap write will invalidate the RO-PCC cache
	do_facet $SINGLEAGT $MULTIOP $file OSMWUc ||
		error "mmap write $file failed"
	check_lpcc_state $file "none"
	$LFS getstripe -v $file
	# After mmap-write by MULTIOP, the first character of the content
	# increases 1.
	content=$(do_facet $SINGLEAGT $MMAP_CAT $file)
	[[ $content == "nmap_write_data" ]] ||
		error "mmap_cat data mismatch: $content"
}
run_test 23 "Test write/truncate/mmap-write invalidating RO-PCC caching"

test_24a() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tdir/$tfile
	local -a lpcc_path

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0"
	$LCTL pcc list $MOUNT
	mkdir -p $DIR/$tdir
	chmod 777 $DIR/$tdir

	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"
	do_facet $SINGLEAGT $RUNAS $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER \
		$file || error "failed to attach file $file"
	check_lpcc_state $file "readonly"
	do_facet $SINGLEAGT $RUNAS dd if=$file of=/dev/null bs=1024 count=1 ||
		error "failed to dd read from $file"
	check_lpcc_state $file "readonly"

	do_facet $SINGLEAGT $RUNAS $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none"

	# non-root user is forbidden to access PCC file directly
	lpcc_path=$(lpcc_fid2path $hsm_root $file)
	do_facet $SINGLEAGT $RUNAS touch $lpcc_path &&
		error "non-root user can touch access PCC file $lpcc_path"
	do_facet $SINGLEAGT $RUNAS dd if=$lpcc_path of=/dev/null bs=1024 \
		count=1 && error "non-root user can read PCC file $lpcc_path"
	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$lpcc_path bs=1024 \
		count=1 && error "non-root user can write PCC file $lpcc_path"

	do_facet $SINGLEAGT $RUNAS $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER \
		$file || error "failed to attach file $file"
	check_lpcc_state $file "readonly"

	# Test RO-PCC detach as non-root user
	do_facet $SINGLEAGT $RUNAS $LFS pcc detach $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none"
	do_facet $SINGLEAGT "[ -f $lpcc_path ]"	&&
		error "RO-PCC cached file '$lpcc_path' should be removed"

	return 0
}
run_test 24a "Test RO-PCC with non-root user"

test_24b() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tdir/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write $file"
	chmod 600 $file || error "chmod 600 $file failed"
	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$file bs=1024 count=1 &&
		error "non-root user can dd write $file"
	do_facet $SINGLEAGT $RUNAS dd if=$file of=/dev/null bs=1024 count=1 &&
		error "non-root user can dd read $file"
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readonly"
	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$file bs=1024 count=1 &&
		error "non-root user can dd write $file"
	do_facet $SINGLEAGT $RUNAS dd if=$file of=/dev/null bs=1024 count=1 &&
		error "non-root user can dd read $file"
	chmod 777 $file || error "chmod 777 $file failed"
	do_facet $SINGLEAGT $RUNAS dd if=$file of=/dev/null bs=1024 count=1 ||
		error "non-root user cannot read $file with permission (777)"
	check_lpcc_state $file "readonly"

	do_facet $SINGLEAGT $RUNAS $LFS pcc detach $file &&
		error "non-root user or non owner can detach $file"
	chown $RUNAS_ID $file || error "chown $RUNAS_ID $file failed"
	do_facet $SINGLEAGT $RUNAS $LFS pcc detach $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none"
	do_facet $SINGLEAGT $RUNAS dd if=$file of=/dev/null bs=1024 count=1 ||
		error "non-root user cannot read $file with permission (777)"
}
run_test 24b "General permission test for RO-PCC"

test_25() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tdir/$tfile
	local content

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"

	echo "ro_fake_mmap_cat_err" > $file
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach RO-PCC file $file"
	check_lpcc_state $file "readonly"
	check_file_data $SINGLEAGT $file "ro_fake_mmap_cat_err"

	# define OBD_FAIL_LLITE_PCC_FAKE_ERROR	0x1411
	do_facet $SINGLEAGT $LCTL set_param fail_loc=0x1411
	content=$(do_facet $SINGLEAGT $MMAP_CAT $file)
	[[ $content == "ro_fake_mmap_cat_err" ]] ||
		error "failed to fall back to Lustre I/O path for mmap-read"
	# Above mmap read will return VM_FAULT_SIGBUS failure and
	# retry the IO on normal IO path.
	check_lpcc_state $file "none"
	check_file_data $SINGLEAGT $file "ro_fake_mmap_cat_err"

	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "failed to detach RO-PCC file $file"
	check_lpcc_state $file "none"

	do_facet $SINGLEAGT $LCTL set_param fail_loc=0
	echo "ro_fake_cat_err" > $file
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach RO-PCC file $file"
	check_lpcc_state $file "readonly"
	check_file_data $SINGLEAGT $file "ro_fake_cat_err"

	# define OBD_FAIL_LLITE_PCC_FAKE_ERROR	0x1411
	do_facet $SINGLEAGT $LCTL set_param fail_loc=0x1411
	# Fake read I/O will return -EIO failure and
	# retry the IO on normal IO path.
	check_file_data $SINGLEAGT $file "ro_fake_cat_err"
	check_lpcc_state $file "readonly"

	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "failed to detach RO-PCC file $file"
	check_lpcc_state $file "none"
}
run_test 25 "Tolerate fake read failure for RO-PCC"

test_26() {
	local agt_host=$(facet_active_host $SINGLEAGT)
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER" -h "$hsm_root"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0\ pccrw=1\ pccro=1"

	echo -n attach_keep_open > $file
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "attach $file failed"
	check_lpcc_state $file "readonly"
	rmultiop_start $agt_host $file O_c || error "multiop $file failed"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "detach $file failed"
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "attach $file failed"
	check_lpcc_state $file "readonly"
	check_file_data $SINGLEAGT $file "attach_keep_open"
	check_lpcc_state $file "readonly"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "detach $file failed"
	rmultiop_stop $agt_host || error "multiop $file close failed"

	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "attach $file failed"
	check_lpcc_state $file "readonly"
	rmultiop_start $agt_host $file O_c || error "multiop $file failed"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "detach $file failed"
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "attach $file failed"
	check_lpcc_state $file "readonly"
	check_file_data $SINGLEAGT $file "attach_keep_open"
	check_lpcc_state $file "readonly"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "detach $file failed"
	rmultiop_stop $agt_host || error "multiop $file close failed"

	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "attach $file failed"
	check_lpcc_state $file "readonly"
	rmultiop_start $agt_host $file O_c || error "multiop $file failed"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "detach $file failed"
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "attach $file failed"
	check_lpcc_state $file "readonly"
	check_file_data $SINGLEAGT $file "attach_keep_open"
	check_lpcc_state $file "readonly"
	rmultiop_stop $agt_host || error "multiop $file close failed"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "detach $file failed"

	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "attach $file failed"
	check_lpcc_state $file "readwrite"
	rmultiop_start $agt_host $file O_c || error "multiop $file failed"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "detach $file failed"
	wait_request_state $(path2fid $file) REMOVE SUCCEED
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "attach $file failed"
	check_lpcc_state $file "readonly"
	check_file_data $SINGLEAGT $file "attach_keep_open"
	check_lpcc_state $file "readonly"
	rmultiop_stop $agt_host || error "multiop $file close failed"
	check_lpcc_state $file "readonly"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "detach $file failed"

	rm $file || error "rm $file failed"
	echo -n attach_keep_open > $file
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "attach $file failed"
	check_lpcc_state $file "readwrite"
	rmultiop_start $agt_host $file O_c || error "multiop $file failed"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "detach $file failed"
	wait_request_state $(path2fid $file) REMOVE SUCCEED
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "attach $file failed"
	check_lpcc_state $file "readonly"
	check_file_data $SINGLEAGT $file "attach_keep_open"
	check_lpcc_state $file "readonly"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "detach $file failed"
	rmultiop_stop $agt_host || error "multiop $file close failed"
	check_lpcc_state $file "none"
}
run_test 26 "Repeat the attach/detach when the file has multiple openers"

test_27() {
	local agt_host=$(facet_active_host $SINGLEAGT)
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER" -h "$hsm_root"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ open_attach=1\ pccrw=1\ pccro=1"

	echo -n auto_attach_multi_open > $file
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "attach $file failed"
	check_lpcc_state $file "readwrite"
	rmultiop_start $agt_host $file O_c || error "multiop $file failed"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "detach $file failed"
	check_lpcc_state $file "none"
	check_file_data $SINGLEAGT $file "auto_attach_multi_open"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "detach $file failed"
	wait_request_state $(path2fid $file) REMOVE SUCCEED
	check_lpcc_state $file "none"
	rmultiop_stop $agt_host || error "multiop $file close failed"

	rm $file || error "rm $file failed"
	echo -n auto_attach_multi_open > $file
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "attach $file failed"
	check_lpcc_state $file "readwrite"
	rmultiop_start $agt_host $file O_c || error "multiop $file failed"
	do_facet $SINGLEAGT $LCTL \
		set_param ldlm.namespaces.*mdc*.lru_size=clear
	check_lpcc_state $file "none"
	check_file_data $SINGLEAGT $file "auto_attach_multi_open"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "detach $file failed"
	wait_request_state $(path2fid $file) REMOVE SUCCEED
	check_lpcc_state $file "none"
	rmultiop_stop $agt_host || error "multiop $file close failed"

	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "attach $file failed"
	check_lpcc_state $file "readonly"
	rmultiop_start $agt_host $file O_c || error "multiop $file failed"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "detach $file failed"
	check_lpcc_state $file "none"
	check_file_data $SINGLEAGT $file "auto_attach_multi_open"
	check_lpcc_state $file "readonly"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "detach $file failed"
	check_lpcc_state $file "none"
	rmultiop_stop $agt_host || error "multiop $file close failed"

	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "attach $file failed"
	check_lpcc_state $file "readonly"
	rmultiop_start $agt_host $file O_c || error "multiop $file failed"
	do_facet $SINGLEAGT $LCTL \
		set_param ldlm.namespaces.*mdc*.lru_size=clear
	check_lpcc_state $file "none"
	check_file_data $SINGLEAGT $file "auto_attach_multi_open"
	check_lpcc_state $file "readonly"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "detach $file failed"
	check_lpcc_state $file "none"
	rmultiop_stop $agt_host || error "multiop $file close failed"
}
run_test 27 "Auto attach at open when the file has multiple openers"

test_28() {
	local agt_host=$(facet_active_host $SINGLEAGT)
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile
	local file2=$DIR2/$tfile
	local multipid

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER" -h "$hsm_root"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0\ pccrw=1"

	echo -n rw_attach_hasopen_fail > $file
	rmultiop_start $agt_host $file O_c || error "multiop $file failed"
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file &&
		error "attach $file should fail"
	rmultiop_stop $agt_host || error "multiop $file close failed"
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "attach $file should fail"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "detach $file failed"
	check_lpcc_state $file "none"

	multiop_bg_pause $file2 O_c || error "multiop $file2 failed"
	multipid=$!
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file &&
		error "attach $file should fail"
	kill -USR1 $multipid
	wait $multipid || error "multiop $file2 close failed"
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach $file"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "detach $file failed"
	check_lpcc_state $file "none"
}
run_test 28 "RW-PCC attach should fail when the file has cluster-wide openers"

test_29a() {
	local project_id=100
	local agt_facet=$SINGLEAGT
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tdir/$tfile
	local file2=$DIR2/$tdir/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	is_project_quota_supported || skip "project quota is not supported"

	enable_project_quota
	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={$project_id}\ rwid=$HSM_ARCHIVE_NUMBER\ pccro=1"
	$LCTL pcc list $MOUNT

	do_facet $SINGLEAGT mkdir -p $DIR/$tdir ||
		error "mkdir $DIR/$tdir failed"
	do_facet $SINGLEAGT "echo -n ro_uptodate > $file" ||
		error "failed to write $file"
	check_lpcc_state $file "none"
	$LFS project -sp $project_id $file ||
		error "failed to set project for $file"
	$LFS project -d $file
	check_file_data $SINGLEAGT $file "ro_uptodate"
	check_lpcc_state $file "readonly"
	check_file_data $SINGLEAGT $file "ro_uptodate"

	echo -n Update_ro_data > $file2
	check_lpcc_state $file "none"
	check_file_data $SINGLEAGT $file "Update_ro_data"
	check_lpcc_state $file "readonly"

	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "failed to detach $file"
}
run_test 29a "Auto readonly caching on RO-PCC backend for O_RDONLY open"

test_29b() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/myfile.dat

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	do_facet $SINGLEAGT mkdir $hsm_root || error "mkdir $hsm_root failed"
	setup_pcc_mapping $SINGLEAGT \
		"fname={*.dat}\ roid=$HSM_ARCHIVE_NUMBER\ pccro=1"
	do_facet $SINGLEAGT $LCTL pcc list $MOUNT

	do_facet $SINGLEAGT dd if=/dev/zero of=$file bs=4k count=1 ||
		error "Write $file failed"
	do_facet $SINGLEAGT dd if=$file of=/dev/null bs=4k count=1 ||
		error "Read $file failed"
	do_facet $SINGLEAGT $LFS pcc state $file
	check_lpcc_state $file "readonly"
	do_facet $SINGLEAGT dd if=/dev/zero of=$file bs=4k count=1 ||
		error "Write $file failed"
	sysctl vm.drop_caches=3
	do_facet $SINGLEAGT dd if=$file of=/dev/null bs=4k count=1 ||
		error "Read $file failed"
	do_facet $SINGLEAGT $LFS pcc state $file
	check_lpcc_state $file "readonly"

	do_facet $SINGLEAGT $LFS pcc detach $file || error "detach $file failed"
}
run_test 29b "Auto PCC-RO attach in atomic_open"

test_30() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT "projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ pccrw=1\ pccro=1"

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"

	file=$DIR/$tdir/rwattach
	echo -n backend_del_attach > $file
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "RW-PCC attach $file failed"

	file=$DIR/$tdir/rwattachrm
	echo -n backend_del_attach_rm > $file
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "RW-PCC attach $file failed"
	rm $file || error "rm $file failed"

	file=$DIR/$tdir/roattach
	echo -n backend_del_roattach_rm > $file
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "RO-PCC attach $file failed"

	do_facet $SINGLEAGT $LCTL pcc list $MOUNT
	do_facet $SINGLEAGT $LCTL pcc del -v -v -v -v $MOUNT $hsm_root ||
		error "lctl pcc del $MOUNT $hsm_root failed"
}
run_test 30 "Test lctl pcc del command"

test_31() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local -a lpcc_path1
	local -a lpcc_path2
	local -a lpcc_path3
	local file

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0\ pccrw=1\ pccro=1"

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"

	file=$DIR/$tdir/rwattach
	echo -n backend_del_attach > $file
	lpcc_path1=$(lpcc_fid2path $hsm_root $file)
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "RW-PCC attach $file failed"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "RW-PCC detach $file failed"
	check_lpcc_state $file "none"

	file=$DIR/$tdir/rwattachrm
	echo -n backend_del_attach_rm > $file
	lpcc_path2=$(lpcc_fid2path $hsm_root $file)
	do_facet $SINGLEAGT $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER $file ||
		error "RW-PCC attach $file failed"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "RW-PCC detach $file failed"
	check_lpcc_state $file "none"
	rm $file || error "rm $file failed"

	file=$DIR/$tdir/roattach
	echo -n backend_del_roattach_rm > $file
	lpcc_path3=$(lpcc_fid2path $hsm_root $file "readonly")
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "RO-PCC attach $file failed"
	check_lpcc_state $file "readonly"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "RO-PCC detach $file failed"
	check_lpcc_state $file "none"

	do_facet $SINGLEAGT $LCTL pcc list $MOUNT
	do_facet $SINGLEAGT $LCTL pcc del -v -v -v -v -k $MOUNT $hsm_root ||
		error "lctl pcc del -k $MOUNT $hsm_root failed"

	do_facet $SINGLEAGT "[ -f $lpcc_path1 ]" ||
		error "PCC copy $lpcc_path1 should retain"
	do_facet $SINGLEAGT "[ -f $lpcc_path2 ]" ||
		error "PCC copy $lpcc_path1 should retain"
	do_facet $SINGLEAGT "[ -f $lpcc_path3 ]" ||
		error "PCC copy $lpcc_path1 should retain"
}
run_test 31 "Test lctl pcc del command with --keep option"

test_32() {
	local agt_host=$(facet_active_host $SINGLEAGT)
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile
	local -a lpcc_path

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0"

	do_facet $SINGLEAGT echo -n roattach_removed > $file
	lpcc_path=$(lpcc_fid2path $hsm_root $file "readonly")
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "RO-PCC attach $file failed"
	rmultiop_start $agt_host $file o_rc || error "multiop $file failed"
	sleep 3
	do_facet $SINGLEAGT rm $lpcc_path || error "rm $lpcc_path failed"
	rmultiop_stop $agt_host || error "multiop $file read failed"
	check_lpcc_state $file "readonly"

	local content=$(do_facet $SINGLEAGT cat $file)
	[[ $content == "roattach_removed" ]] || error "data mismatch: $content"
	check_lpcc_state $file "readonly"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "RO-PCC detach $file failed"
	check_lpcc_state $file "none"

	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "RO-PCC attach $file failed"
	do_facet $SINGLEAGT rm $lpcc_path || error "rm $lpcc_path failed"
	check_lpcc_state $file "readonly"
	content=$(do_facet $SINGLEAGT cat $file)
	[[ $content == "roattach_removed" ]] || error "data mismatch: $content"
	check_lpcc_state $file "readonly"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "RO-PCC detach $file failed"
	check_lpcc_state $file "none"
}
run_test 32 "Test for RO-PCC when PCC copy is deleted"

test_33() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/myfile.doc
	local file2=$DIR2/myfile.doc

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	stack_trap "restore_opencache" EXIT
	disable_opencache

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"

	setup_pcc_mapping $SINGLEAGT \
		"fname={*.doc}\&size\<{1M}\ roid=$HSM_ARCHIVE_NUMBER\ pccro=1"
	do_facet $SINGLEAGT $LCTL pcc list $MOUNT
	touch $file || error "touch $file failed"
	$TRUNCATE $file $((1048576 * 2)) || error "Truncate $file failed"
	do_facet $SINGLEAGT $MULTIOP $file oc ||
		error "failed to readonly open $file"
	check_lpcc_state $file "none"
	do_facet $SINGLEAGT $LFS pcc state $file
	$TRUNCATE $file $((1048576 / 2)) || error "Truncate $file failed"
	do_facet $SINGLEAGT $LFS pcc state $file
	do_facet $SINGLEAGT $MULTIOP $file oc ||
		error "failed to readonly open $file"
	check_lpcc_state $file "readonly"
	cleanup_pcc_mapping

	setup_pcc_mapping $SINGLEAGT \
		"fname={*.doc}\&size\<{5M}\&size\>{3M}\ roid=5\ pccro=1"
	do_facet $SINGLEAGT $LCTL pcc list $MOUNT
	do_facet $SINGLEAGT $MULTIOP $file oc ||
		error "failed to readonly open $file"
	check_lpcc_state $file "none"
	$TRUNCATE $file2 $((1048576 * 6)) || error "Truncate $file2 failed"
	do_facet $SINGLEAGT $MULTIOP $file oc ||
		error "failed to readonly open $file"
	check_lpcc_state $file "none"
	$TRUNCATE $file2 $((1048576 * 4)) || error "Truncate $file2 failed"
	do_facet $SINGLEAGT $MULTIOP $file oc ||
		error "failed to readonly open $file"
	check_lpcc_state $file "readonly"
	cleanup_pcc_mapping

	setup_pcc_mapping $SINGLEAGT \
		"fname={*.doc}\&size={5M\ 3M}\ roid=5\ pccro=1"
	do_facet $SINGLEAGT $LCTL pcc list $MOUNT
	do_facet $SINGLEAGT $MULTIOP $file oc ||
		error "failed to readonly open $file"
	check_lpcc_state $file "none"
	$TRUNCATE $file $((1048576 * 5)) || error "Truncate $file failed"
	do_facet $SINGLEAGT $MULTIOP $file oc ||
		error "failed to readonly open $file"
	check_lpcc_state $file "readonly"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "failed to detach $file"
	$TRUNCATE $file $((1048576 * 4)) || error "Truncate $file failed"
	do_facet $SINGLEAGT $MULTIOP $file oc ||
		error "failed to readonly open $file"
	check_lpcc_state $file "none"
	$TRUNCATE $file $((1048576 * 3)) || error "Truncate $file failed"
	do_facet $SINGLEAGT $MULTIOP $file oc ||
		error "failed to readonly open $file"
	check_lpcc_state $file "readonly"
	cleanup_pcc_mapping
}
run_test 33 "Cache rule with comparator (>, =, <) for file size"

test_34() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	is_project_quota_supported || skip "project quota is not supported"

	enable_project_quota
	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"

	setup_pcc_mapping $SINGLEAGT \
		"projid\>{100}\ roid=5\ pccro=1"
	do_facet $SINGLEAGT $LCTL pcc list $MOUNT
	do_facet $SINGLEAGT "echo -n QQQQQ > $file" ||
		error "failed to write $file"
	do_facet $SINGLEAGT $MULTIOP $file oc ||
		error "failed to readonly open $file"
	check_lpcc_state $file "none"
	$LFS project -p 99 $file || error "failed to set project for $file"
	$LFS project -d $file
	do_facet $SINGLEAGT $MULTIOP $file oc ||
		error "failed to readonly open $file"
	check_lpcc_state $file "none"
	$LFS project -p 101 $file || error "failed to set project for $file"
	$LFS project -d $file
	do_facet $SINGLEAGT $MULTIOP $file oc ||
		error "failed to readonly open $file"
	check_lpcc_state $file "readonly"
	cleanup_pcc_mapping

	setup_pcc_mapping $SINGLEAGT \
		"projid\<{100}\ roid=5\ pccro=1"
	do_facet $SINGLEAGT $LCTL pcc list $MOUNT
	do_facet $SINGLEAGT $MULTIOP $file oc ||
		error "failed to readonly open $file"
	check_lpcc_state $file "none"
	$LFS project -p 102 $file || error "failed to set project for $file"
	$LFS project -d $file
	do_facet $SINGLEAGT $MULTIOP $file oc ||
		error "failed to readonly open $file"
	check_lpcc_state $file "none"
	$LFS project -p 99 $file || error "failed to set project for $file"
	$LFS project -d $file
	do_facet $SINGLEAGT $MULTIOP $file oc ||
		error "failed to readonly open $file"
	check_lpcc_state $file "readonly"
	cleanup_pcc_mapping

	setup_pcc_mapping $SINGLEAGT \
		"projid\<{120}\&projid\>{110}\ roid=5\ pccro=1"
	do_facet $SINGLEAGT $LCTL pcc list $MOUNT
	do_facet $SINGLEAGT $MULTIOP $file oc ||
		error "failed to readonly open $file"
	check_lpcc_state $file "none"
	$LFS project -p 105 $file || error "failed to set project for $file"
	$LFS project -d $file
	do_facet $SINGLEAGT $MULTIOP $file oc ||
		error "failed to readonly open $file"
	check_lpcc_state $file "none"
	$LFS project -p 121 $file || error "failed to set project for $file"
	$LFS project -d $file
	do_facet $SINGLEAGT $MULTIOP $file oc ||
		error "failed to readonly open $file"
	check_lpcc_state $file "none"
	$LFS project -p 115 $file || error "failed to set project for $file"
	$LFS project -d $file
	do_facet $SINGLEAGT $MULTIOP $file oc ||
		error "failed to readonly open $file"
	check_lpcc_state $file "readonly"
	cleanup_pcc_mapping
}
run_test 34 "Cache rule with comparator (>, <) for Project ID range"

test_35() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile
	local -a lpcc_path

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping

	echo "pccro_mmap_data" > $file
	lpcc_path=$(lpcc_fid2path $hsm_root $file)
	do_facet $SINGLEAGT $LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to PCC-RO attach file $file"
	check_lpcc_state $file "readonly"
	check_lpcc_data $SINGLEAGT $lpcc_path $file "pccro_mmap_data"

	local content=$(do_facet $SINGLEAGT $MMAP_CAT $file)

	[[ $content == "pccro_mmap_data" ]] ||
		error "mmap_cat data mismatch: $content"
	check_lpcc_state $file "readonly"

	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "failed to PCC-RO detach $file"
	content=$(do_facet $SINGLEAGT $MMAP_CAT $file)
	[[ $content == "pccro_mmap_data" ]] ||
		error "mmap_cat data mismatch: $content"
	check_lpcc_state $file "none"
}
run_test 35 "mmap fault test"

test_36_base() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile
	local -a lpcc_path
	local state="readonly"
	local rw="$1"

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
                skip "Server does not support PCC-RO"

	[[ -z $rw ]] || state="readwrite"
	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT "projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ pccrw=1\ pccro=1"

	echo -n backend_clear_verify > $file
	lpcc_path=$(lpcc_fid2path $hsm_root $file)
	do_facet $SINGLEAGT $LFS pcc attach $rw -i $HSM_ARCHIVE_NUMBER $file ||
		error "PCC attach $ro $file failed"
	check_lpcc_state $file "$state"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "PCC detach -k $file failed"
	do_facet $SINGLEAGT "[ -f $lpcc_path1 ]" ||
		error "PCC copy $lpcc_path should retain"
	do_facet $SINGLEAGT $LCTL pcc clear -v $MOUNT ||
		error "lctl pcc clear -v $MOUNT failed"
	do_facet $SINGLEAGT "[ -f $lpcc_path ]" &&
		error "PCC copy $lpcc_path should be removed"
	rm $file || error "rm $file failed"
}

test_36a() {
	test_36_base "-w"
}
run_test 36a "Stale RW-PCC copy should be deleted after remove the PCC backend"

test_36b() {
	test_36_base
}
run_test 36b "Stale RO-PCC copy should be deleted after remove the PCC backend"

test_37() {
	local loopfile="$TMP/$tfile"
	local loopfile2="$TMP/$tfile.2"
	local mntpt="/mnt/pcc.$tdir"
	local mntpt2="/mnt/pcc.$tdir.2"
	local file=$DIR/$tdir/$tfile
	local file2=$DIR2/$tdir/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	touch $file

	setup_loopdev client $loopfile $mntpt 50
	setup_loopdev client $loopfile2 $mntpt2 50
	$LCTL pcc add $MOUNT $mntpt -p \
		"projid={2} roid=$HSM_ARCHIVE_NUMBER auto_attach=0 pccro=1" ||
		error "failed to config PCC for $MOUNT $mntpt"
	$LCTL pcc add $MOUNT2 $mntpt2 -p \
		"projid={2} roid=$HSM_ARCHIVE_NUMBER auto_attach=0 pccro=1" ||
		error "failed to config PCC for $MOUNT2 $mntpt2"
	$LCTL pcc list $MOUNT
	$LCTL pcc list $MOUNT2

	cancel_lru_locks mdc
#define CFS_FAIL_ONCE | OBD_FAIL_MDS_LL_PCCRO
	$LCTL set_param -n fail_loc=0x80000176 fail_val=10
	$LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file &
	sleep 2
	$LFS pcc attach -r -i $HSM_ARCHIVE_NUMBER $file2
	wait
	$LFS pcc state $file
	$LFS pcc state $file2

	check_lpcc_state $file "readonly" client
	check_lpcc_state $file2 "readonly" client

	$LCTL pcc clear $MOUNT
	$LCTL pcc clear $MOUNT2
}
run_test 37 "Multiple readers on a shared file with PCC-RO mode"

test_38() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local dir=$DIR/$tdir
	local file=$dir/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	is_project_quota_supported || skip "project quota is not supported"

	enable_project_quota
	mkdir $dir || error "mkdir $dir failed"
	$LFS project -sp 100 $dir ||
		error "failed to set project for $dir"
	echo "QQQQQ" > $file

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	do_facet $SINGLEAGT mkdir $hsm_root || error "mkdir $hsm_root failed"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ roid=$HSM_ARCHIVE_NUMBER\ pccro=1"

	do_facet $SINGLEAGT $LFS pcc state $file ||
		error "failed to get PCC state for $file"
	check_lpcc_state $file "none"
	do_facet $SINGLEAGT cat $file || error "cat $file failed"
	check_lpcc_state $file "readonly"
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "failed to detach $file"
	check_lpcc_state $file "none"
}
run_test 38 "Verify LFS pcc state does not trigger prefetch for auto PCC-RO"

test_39() {
	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	quotaon --help |& grep -q 'project quotas' ||
		skip "Not support project quota on local filesystem"

	is_project_quota_supported || skip "project quota is not supported"

	enable_project_quota

	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local dir=$DIR/$tdir
	local file=$dir/$tfile
	local id=100

	setup_loopdev_project $SINGLEAGT $loopfile $mntpt 50
	do_facet $SINGLEAGT quotaon -Ppv $mntpt
	do_facet $SINGLEAGT setquota -P $id 0 4096 0 0 $mntpt ||
		error "setquota -P $id on $mntpt failed"
	do_facet $SINGLEAGT repquota -Pvs $mntpt

	do_facet $SINGLEAGT mkdir $hsm_root || error "mkdir $hsm_root failed"
	setup_pcc_mapping $SINGLEAGT \
		"projid={$id}\ roid=$HSM_ARCHIVE_NUMBER\ proj_quota=1\ pccro=1"
	do_facet $SINGLEAGT $LCTL pcc list $MOUNT

	do_facet $SINGLEAGT mkdir -p $dir || error "mkdir $dir failed"
	do_facet $SINGLEAGT dd if=/dev/zero of=$file bs=1M count=2 ||
		error "Write $file failed"
	$LFS project -p $id $file || error "failed to set project for $file"
	$LFS project -d $file
	do_facet $SINGLEAGT dd if=$file of=/dev/null bs=1M count=2 ||
		error "Read $file failed"
	do_facet $SINGLEAGT $LFS pcc state $file
	check_lpcc_state $file "readonly"
	do_facet $SINGLEAGT repquota -Pvs $mntpt
	do_facet $SINGLEAGT dd if=/dev/zero of=$file bs=1M count=5 ||
		error "Write $file failed"
	check_lpcc_state $file "none"
	do_facet $SINGLEAGT dd if=$file of=/dev/null bs=1M count=5 ||
		error "Read $file failed"
	do_facet $SINGLEAGT repquota -Pvs $mntpt
	do_facet $SINGLEAGT $LFS pcc state $file
	check_lpcc_state $file "none"
}
run_test 39 "Test Project quota on loop PCC device"

wait_readonly_attach_fini() {
	local file=$1
	local facet=${2:-$SINGLEAGT}
	local cmd="$LFS pcc state $file | grep -E -c 'type: readonly'"

	echo $cmd
	wait_update_facet $facet "$cmd" "1" 50 ||
		error "Async attach $file timed out"
}

calc_stats_facet() {
	local paramfile="$1"
	local stat="$2"
	local facet=${3:-$SINGLEAGT}

	do_facet $facet $LCTL get_param -n $paramfile |
		awk '/^'$stat'/ { sum += $2 } END { printf("%0.0f", sum) }'
}

test_40() {
	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	is_project_quota_supported || skip "project quota is not supported"

	enable_project_quota

	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local dir=$DIR/$tdir
	local file=$dir/$tfile
	local id=100

	setup_loopdev $SINGLEAGT $loopfile $mntpt 200
	do_facet $SINGLEAGT mkdir $hsm_root || error "mkdir $hsm_root failed"
	setup_pcc_mapping $SINGLEAGT \
		"projid={$id}\ roid=$HSM_ARCHIVE_NUMBER\ pccro=1"
	do_facet $SINGLEAGT $LCTL pcc list $MOUNT

	mkdir -p $dir || error "mkdir $dir failed"
	do_facet $SINGLEAGT dd if=/dev/zero of=$file bs=1M count=50 ||
		error "Write $file failed"

	$LFS project -p $id $file || error "failed to set project for $file"
	$LFS project -d $file
	do_facet $SINGLEAGT $LFS pcc detach $file
	do_facet $SINGLEAGT $LFS pcc state $file

	do_facet $SINGLEAGT $LCTL set_param ldlm.namespaces.*osc*.lru_size=clear
	do_facet $SINGLEAGT $LCTL set_param osc.*.stats=clear
	#define OBD_FAIL_OST_BRW_PAUSE_BULK
	set_nodes_failloc "$(osts_nodes)" 0x214 1
	echo 3 > /proc/sys/vm/drop_caches

	local stime
	local time1
	local time2
	local rpcs_before
	local rpcs_after

	do_facet $SINGLEAGT $LCTL set_param llite.*.pcc_async_threshold=5MB

	echo "Test open attach with pcc_async_threshold=5MB"
	stime=$SECONDS
	# Open with O_RDONLY flag will trigger auto attach
	do_facet $SINGLEAGT $MULTIOP $file oc ||
		error "failed to readonly open $file"

	rpcs_before=$(calc_stats_facet osc.*.stats ost_read)
	do_facet $SINGLEAGT dd if=$file of=/dev/null bs=1M count=1 iflag=direct
	rpcs_after=$(calc_stats_facet osc.*.stats ost_read)
	echo "Before: $rpcs_before After: $rpcs_after"
	[ $rpcs_after -gt $rpcs_before ] ||
		error "should send read RPCs to OSTs $rpcs_before: $rpcs_after"
	time1=$((SECONDS - stime))
	do_facet $SINGLEAGT $LFS pcc state $file
	wait_readonly_attach_fini $file

	do_facet $SINGLEAGT $LFS pcc detach $file
	do_facet $SINGLEAGT $LFS pcc state $file
	do_facet $SINGLEAGT $LCTL set_param llite.*.pcc_async_threshold=1G
	do_facet $SINGLEAGT $LCTL set_param ldlm.namespaces.*osc*.lru_size=clear
	do_facet $SINGLEAGT $LCTL set_param osc.*.stats=clear

	echo "Test open attach with async_threshold=1G"
	stime=$SECONDS
	# Open with O_RDONLY flag will trigger auto attach
	do_facet $SINGLEAGT $MULTIOP $file oc ||
		error "failed to readonly open $file"
	do_facet $SINGLEAGT $LFS pcc state $file
	rpcs_before=$(calc_stats_facet osc.*.stats ost_read)
	do_facet $SINGLEAGT dd if=$file of=/dev/null bs=1M count=1 iflag=direct
	rpcs_after=$(calc_stats_facet osc.*.stats ost_read)
	time2=$((SECONDS - stime))
	echo "Before: $rpcs_before After: $rpcs_after"
	[ $rpcs_after -eq $rpcs_before ] ||
		error "should not send OST_READ RPCs to OSTs"

	echo "Time1: $time1 Time2: $time2"
	# Occasionally async can take a tiny bit longer due to races, that's OK
	[ $time1 -le $((time2 + 1)) ] ||
		error "Total time for async open attach should be smaller"

	do_facet $SINGLEAGT $LFS pcc detach $file
	do_facet $SINGLEAGT $LFS pcc state $file
	do_facet $SINGLEAGT $LCTL set_param llite.*.pcc_async_threshold=5MB
	do_facet $SINGLEAGT $LCTL set_param ldlm.namespaces.*osc*.lru_size=clear

	echo "Read 1MB data with async_threshold=5MB"
	stime=$SECONDS
	do_facet $SINGLEAGT dd if=$file of=/dev/null bs=1M count=1 iflag=direct
	time1=$((SECONDS - stime))
	wait_readonly_attach_fini $file

	do_facet $SINGLEAGT $LFS pcc detach $file
	do_facet $SINGLEAGT $LFS pcc state $file
	do_facet $SINGLEAGT $LCTL set_param llite.*.pcc_async_threshold=1G
	do_facet $SINGLEAGT $LCTL set_param ldlm.namespaces.*osc*.lru_size=clear

	echo "Read 1MB data with async_threshold=1G"
	stime=$SECONDS
	do_facet $SINGLEAGT dd if=$file of=/dev/null bs=1M count=1 iflag=direct
	time2=$((SECONDS - stime))

	echo "Time1: $time1 Time2: $time2"
	# Occasionally async can take a tiny bit longer due to races, that's OK
	[ $time1 -le $((time2 + 1)) ] ||
		error "Total time for async open attach should be smaller"
}
run_test 40 "Test async open attach in the background for PCC-RO file"

test_41() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	do_facet $SINGLEAGT mkdir $hsm_root || error "mkdir $hsm_root failed"
	setup_pcc_mapping $SINGLEAGT \
		"mtime\>{1m}\ roid=$HSM_ARCHIVE_NUMBER\ pccro=1"
	do_facet $SINGLEAGT $LCTL pcc list $MOUNT

	echo "pcc_ro_data" > $file || error "echo $file failed"
	do_facet $SINGLEAGT cat $file || error "cat $file failed"
	check_lpcc_state $file "none"

	local mtime=$(date -d "2min ago" +%s)

	do_facet $SINGLEAGT touch -m -d @$mtime $file ||
		error "failed to change mtime for $file $mtime"
	do_facet $SINGLEAGT cat $file || error "cat $file failed"
	check_lpcc_state $file "readonly"
}
run_test 41 "Test mtime rule for PCC-RO open attach with O_RDONLY mode"

test_42() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 60
	do_facet $SINGLEAGT mkdir $hsm_root || error "mkdir $hsm_root failed"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ roid=$HSM_ARCHIVE_NUMBER\ ropcc=1"
	do_facet $SINGLEAGT $LCTL pcc list $MOUNT

	do_facet $SINGLEAGT echo -n attach_id_not_specified > $file ||
		error "Write $file failed"
	do_facet $SINGLEAGT $LFS pcc attach -r $file ||
		error "PCC attach -r $file failed"
	do_facet $SINGLEAGT $LFS pcc state $file
	check_lpcc_state $file "readonly"
}
run_test 42 "PCC attach without attach ID specified"

test_43() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 60
	do_facet $SINGLEAGT mkdir $hsm_root || error "mkdir $hsm_root failed"
	setup_pcc_mapping $SINGLEAGT \
		"size\<{100M}\ roid=$HSM_ARCHIVE_NUMBER\ ropcc=1"
	do_facet $SINGLEAGT $LCTL pcc list $MOUNT

	echo "attach_root_user_data" > $file || error "echo $file failed"

	do_facet $SINGLEAGT $LFS pcc state $file
	# Attach by non-root user should fail.
	do_facet $SINGLEAGT $RUNAS $LFS pcc attach -r $file &&
		error "PCC attach -r $file should fail for non-root user"
	do_facet $SINGLEAGT $RUNAS $LFS pcc state $file
	check_lpcc_state $file "none"
}
run_test 43 "Auto attach at open() should add capacity owner check"

test_44() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile
	local count=50
	local bs="1M"

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev client $loopfile $mntpt 60
	mkdir $hsm_root || error "mkdir $hsm_root failed"
	setup_pcc_mapping client \
		"projid={0}\ roid=$HSM_ARCHIVE_NUMBER\ ropcc=1\ mmap_conv=0"
	$LCTL pcc list $MOUNT

	local thresh=$($LCTL get_param -n llite.*.pcc_async_threshold |
		       head -n 1)

	stack_trap "$LCTL set_param llite.*.pcc_async_threshold=$thresh"
	$LCTL set_param llite.*.pcc_async_threshold=0

	dd if=/dev/zero of=$file bs=$bs count=$count ||
		error "Write $file failed"

	local n=16
	local lpid
	local -a rpids

	$LFS getstripe -v $file
	clear_stats llite.*.stats

	for ((i = 0; i < $n; i++)); do
		(
		while [ ! -e $DIR/$tfile.lck ]; do
			dd if=$file of=/dev/null bs=$bs count=$count ||
				error "Read $file failed"
			sleep 0.$((RANDOM % 4 + 1))
		done
		)&
		rpids[$i]=$!
	done

	(
		while [ ! -e $DIR/$tfile.lck ]; do
			$LCTL set_param -n ldlm.namespaces.*mdc*.lru_size=clear ||
				error "cancel_lru_locks mdc failed"
			sleep 0.2
		done
	)&
	lpid=$!

	sleep 60
	touch $DIR/$tfile.lck

	for ((i = 0; i < $n; i++)); do
		wait ${rpids[$i]} || error "$?: read failed"
	done
	wait $lpid || error "$?: lock cancel failed"

	echo "Finish ========"
	$LFS getstripe -v $file
	$LCTL get_param llite.*.stats

	local attach_num=$(calc_stats llite.*.stats pcc_attach)
	local detach_num=$(calc_stats llite.*.stats pcc_detach)
	local autoat_num=$(calc_stats llite.*.stats pcc_auto_attach)

	echo "attach $attach_num detach $detach_num auto_attach $autoat_num"
	(( $attach_num <= 1 )) || error "attach more than 1 time: $attach_num"
	rm -f $DIR/$tfile.lck
}
run_test 44 "Verify valid auto attach without re-fetching the whole files"

test_45() {
	local loopfile="$TMP/$tfile"
	local loopfile2="$TMP/$tfile.2"
	local mntpt="/mnt/pcc.$tdir"
	local mntpt2="/mnt/pcc.$tdir.2"
	local file1=$DIR/$tfile
	local file2=$DIR2/$tfile
	local count=50
	local bs="1M"

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev client $loopfile $mntpt 100
	setup_loopdev client $loopfile2 $mntpt2 100
	stack_trap "$LCTL pcc clear $MOUNT" EXIT
	$LCTL pcc add $MOUNT $mntpt -p \
		"projid={0} roid=$HSM_ARCHIVE_NUMBER ropcc=1" ||
		error "failed to config PCC for $MOUNT $mntpt"
	stack_trap "$LCTL pcc clear $MOUNT2" EXIT
	$LCTL pcc add $MOUNT2 $mntpt2 -p \
		"projid={0} roid=$HSM_ARCHIVE_NUMBER ropcc=1" ||
		error "failed to config PCC for $MOUNT2 $mntpt2"
	$LCTL pcc list $MOUNT
	$LCTL pcc list $MOUNT2

	local thresh=$(do_facet $SINGLEAGT $LCTL get_param -n \
		       llite.*.pcc_async_threshold | head -n 1)

	stack_trap "do_facet $SINGLEAGT $LCTL \
		    set_param llite.*.pcc_async_threshold=$thresh"
	do_facet $SINGLEAGT $LCTL set_param llite.*.pcc_async_threshold=0

	dd if=/dev/zero of=$file1 bs=$bs count=$count ||
		error "Write $file1 failed"

	local n=16
	local lpid
	local -a pids1
	local -a pids2

	$LFS getstripe -v $file1
	clear_stats llite.*.stats

	for ((i = 0; i < $n; i++)); do
		(
		while [ ! -e $DIR/$tfile.lck ]; do
			dd if=$file1 of=/dev/null bs=$bs count=$count ||
				error "Read $file failed"
			sleep 0.$((RANDOM % 4 + 1))
		done
		)&
		pids1[$i]=$!
	done

	for ((i = 0; i < $n; i++)); do
		(
		while [ ! -e $DIR/$tfile.lck ]; do
			dd if=$file2 of=/dev/null bs=$bs count=$count ||
				error "Read $file failed"
			sleep 0.$((RANDOM % 4 + 1))
		done
		)&
		pids2[$i]=$!
	done

	sleep 60
	touch $DIR/$tfile.lck
	for ((i = 0; i < $n; i++)); do
		wait ${pids1[$i]} || error "$?: read failed"
		wait ${pids2[$i]} || error "$?: read failed"
	done

	$LFS getstripe -v $file1
	$LCTL get_param llite.*.stats

	local attach_num=$(calc_stats llite.*.stats pcc_attach)
	local detach_num=$(calc_stats llite.*.stats pcc_detach)
	local autoat_num=$(calc_stats llite.*.stats pcc_auto_attach)

	echo "attach $attach_num detach $detach_num auto_attach $autoat_num"
	(( attach_num <= 2 )) || error "attach more than 2 time: $attach_num"
	rm -f $DIR/$tfile.lck
}
run_test 45 "Concurrent read access from two mount points"

test_46() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile
	local fsuuid=$($LFS getname $MOUNT | awk '{print $1}')

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev client $loopfile $mntpt 60
	mkdir $hsm_root || error "mkdir $hsm_root failed"
	setup_pcc_mapping client \
		"projid={0}\ roid=$HSM_ARCHIVE_NUMBER\ ropcc=1\ mmap_conv=0"
	$LCTL pcc list $MOUNT

	local mode=$($LCTL get_param -n llite.$fsuuid.pcc_mode)
	$RUNAS id

	echo "Mode: $mode"
	echo "QQQQQ" > $file || error "write $file failed"
	chmod 664 $file || error "chomd $file failed"

	$LCTL set_param llite.$fsuuid.pcc_mode="0" ||
		error "Set PCC mode failed"
	stack_trap "$LCTL set_param llite.$fsuuid.pcc_mode=$mode" EXIT
	$RUNAS $LFS pcc attach -r $file &&
		error "User should not attach $file"
	$RUNAS cat $file || error "cat $file failed"
	check_lpcc_state $file "none" client

	$LCTL set_param llite.$fsuuid.pcc_mode="0400" ||
		error "Set PCC mode failed"
	stack_trap "$LCTL set_param llite.$fsuuid.pcc_mode=$mode" EXIT
	$RUNAS $LFS pcc attach -r $file &&
		error "User should not attach $file"
	$RUNAS cat $file || error "cat $file failed"
	check_lpcc_state $file "none" client

	$LCTL set_param llite.$fsuuid.pcc_mode="0004" ||
		error "Set PCC mode failed"
	$RUNAS cat $file || error "cat $file failed"
	$LFS pcc state $file
	check_lpcc_state $file "readonly" client
	$RUNAS $LFS pcc detach $file || error "Detach $file failed"

	$RUNAS stat $file || error "stat $file failed"
	$LFS pcc attach -r $file || error "failed to attach $file"
	check_lpcc_state $file "readonly" client
	$RUNAS $LFS pcc detach $file || error "failed to detach $file"

	$LCTL set_param llite.$fsuuid.pcc_mode="0040" ||
		error "Set PCC mode failed"
	chmod 660 $file || error "chmod $file failed"
	$RUNAS cat $file || error "cat $file failed"
	$LFS pcc state $file
	check_lpcc_state $file "readonly" client
	$RUNAS $LFS pcc detach $file || error "failed to detach $file"

	$RUNAS $LFS pcc attach -r $file || error "attach $file failed"
	stat $file || error "stat $file failed"
	$LFS pcc state $file
	check_lpcc_state $file "readonly" client
	$RUNAS $LFS pcc detach $file || error "Detach $file failed"
}
run_test 46 "Verify PCC mode setting works correctly"

test_47() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev client $loopfile $mntpt 60
	mkdir $hsm_root || error "mkdir $hsm_root failed"
	setup_pcc_mapping client \
		"projid={0}\ roid=$HSM_ARCHIVE_NUMBER\ ropcc=1\ mmap_conv=0"
	$LCTL pcc list $MOUNT

	local mtime0
	local mtime1

	echo "QQQQQ" > $file || error "echo $file failed"
	mtime0=$(stat -c "%Y" $file);

	sleep 3
	cat $file || error "cat $file failed"
	wait_readonly_attach_fini $file client
	mtime1=$(stat -c "%Y" $file)

	(( mtime0 == mtime1 )) || error "mtime changed from $mtime0 to $mtime1"
}
run_test 47 "mtime should be kept once file attached into PCC"

test_96() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file1=$DIR/$tfile
	local file2=$DIR2/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 60
	do_facet $SINGLEAGT mkdir $hsm_root || error "mkdir $hsm_root failed"
	setup_pcc_mapping $SINGLEAGT \
		"projid={0}\ roid=$HSM_ARCHIVE_NUMBER\ pccro=1\ mmap_conv=0"
	do_facet $SINGLEAGT $LCTL pcc list $MOUNT

	local thresh=$(do_facet $SINGLEAGT $LCTL get_param -n \
		       llite.*.pcc_async_threshold | head -n 1)

	stack_trap "do_facet $SINGLEAGT $LCTL set_param \
		    llite.*.pcc_async_threshold=$thresh"
	do_facet $SINGLEAGT $LCTL set_param llite.*.pcc_async_threshold=1G

	local rpid11
	local rpid12
	local rpid13
	local rpid21
	local rpid22
	local rpid23
	local lpid

	local bs="1M"
	local count=50

	do_facet $SINGLEAGT dd if=/dev/zero of=$file1 bs=$bs count=$count ||
		error "Write $file failed"

	(
		while [ ! -e $DIR/sanity-pcc.96.lck ]; do
			do_facet $SINGLEAGT dd if=$file1 of=/dev/null bs=$bs count=$count ||
				error "Read $file failed"
			sleep 0.$((RANDOM % 4 + 1))
		done
	)&
	rpid11=$!

	(
		while [ ! -e $DIR/sanity-pcc.96.lck ]; do
			do_facet $SINGLEAGT dd if=$file1 of=/dev/null bs=$bs count=$count ||
				error "Read $file failed"
			sleep 0.$((RANDOM % 4 + 1))
		done
	)&
	rpid12=$!

	(
		while [ ! -e $DIR/sanity-pcc.96.lck ]; do
			do_facet $SINGLEAGT dd if=$file1 of=/dev/null bs=$bs count=$count ||
				error "Read $file failed"
			sleep 0.$((RANDOM % 4 + 1))
		done
	)&
	rpid13=$!

	(
		while [ ! -e $DIR/sanity-pcc.96.lck ]; do
			do_facet $SINGLEAGT dd if=$file2 of=/dev/null bs=$bs count=$count ||
				error "Read $file failed"
			sleep 0.$((RANDOM % 4 + 1))
		done
	)&
	rpid21=$!

	(
		while [ ! -e $DIR/sanity-pcc.96.lck ]; do
			do_facet $SINGLEAGT dd if=$file2 of=/dev/null bs=$bs count=$count ||
				error "Read $file failed"
			sleep 0.$((RANDOM % 4 + 1))
		done
	)&
	rpid22=$!

	(
		while [ ! -e $DIR/sanity-pcc.96.lck ]; do
			do_facet $SINGLEAGT dd if=$file2 of=/dev/null bs=$bs count=$count ||
				error "Read $file failed"
			sleep 0.$((RANDOM % 4 + 1))
		done
	)&
	rpid23=$!

	(
		while [ ! -e $DIR/sanity-pcc.96.lck ]; do
			do_facet $SINGLEAGT $LCTL set_param -n ldlm.namespaces.*mdc*.lru_size=clear ||
				error "cancel_lru_locks mdc failed"
			sleep 0.5
		done
	)&
	lpid=$!

	sleep 60
	touch $DIR/sanity-pcc.96.lck

	echo "Finish ========"
	wait $rpid11 || error "$?: read failed"
	wait $rpid12 || error "$?: read failed"
	wait $rpid13 || error "$?: read failed"
	wait $rpid21 || error "$?: read failed"
	wait $rpid22 || error "$?: read failed"
	wait $rpid23 || error "$?: read failed"
	wait $lpid || error "$?: lock cancel failed"

	do_facet $SINGLEAGT $LFS pcc detach $file
	rm -f $DIR/sanity-pcc.96.lck
}
run_test 96 "Auto attach from multiple read process on a node"

test_97() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 60
	do_facet $SINGLEAGT mkdir $hsm_root || error "mkdir $hsm_root failed"
	setup_pcc_mapping $SINGLEAGT \
		"projid={0}\ roid=$HSM_ARCHIVE_NUMBER\ pccro=1\ mmap_conv=0"
	do_facet $SINGLEAGT $LCTL pcc list $MOUNT

	local thresh=$(do_facet $SINGLEAGT $LCTL get_param -n \
		       llite.*.pcc_async_threshold | head -n 1)

	stack_trap "do_facet $SINGLEAGT $LCTL set_param \
		    llite.*.pcc_async_threshold=$thresh"
	do_facet $SINGLEAGT $LCTL set_param llite.*.pcc_async_threshold=1G

	local mpid1
	local mpid2
	local lpid

	do_facet $SINGLEAGT dd if=/dev/zero of=$file bs=1M count=50 ||
		error "Write $file failed"

	(
		while [ ! -e $DIR/sanity-pcc.97.lck ]; do
			echo "T1. $MMAP_CAT $file ..."
			do_facet $SINGLEAGT $MMAP_CAT $file > /dev/null ||
				error "$MMAP_CAT $file failed"
			sleep 0.$((RANDOM % 4 + 1))
		done
	)&
	mpid1=$!

	(
		while [ ! -e $DIR/sanity-pcc.97.lck ]; do
			echo "T2. $MMAP_CAT $file ..."
			do_facet $SINGLEAGT $MMAP_CAT $file > /dev/null ||
				error "$MMAP_CAT $file failed"
			sleep 0.$((RANDOM % 4 + 1))
		done
	)&
	mpid2=$!

	(
		while [ ! -e $DIR/sanity-pcc.97.lck ]; do
			do_facet $SINGLEAGT $LCTL set_param -n ldlm.namespaces.*mdc*.lru_size=clear ||
				error "cancel_lru_locks mdc failed"
			sleep 0.1
		done
	)&
	lpid=$!

	sleep 120
	stack_trap "rm -f $DIR/sanity-pcc.97.lck"
	touch $DIR/sanity-pcc.97.lck
	wait $mpid1 || error "$?: mmap1 failed"
	wait $mpid2 || error "$?: mmap2 failed"
	wait $lpid || error "$?: cancel locks failed"

	do_facet $SINGLEAGT $LFS pcc detach $file
	rm -f $DIR/sanity-pcc.97.lck
}
run_test 97 "two mmap I/O and layout lock cancel"

test_98() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 60
	do_facet $SINGLEAGT mkdir $hsm_root || error "mkdir $hsm_root failed"
	setup_pcc_mapping $SINGLEAGT \
		"projid={0}\ roid=$HSM_ARCHIVE_NUMBER\ pccro=1\ mmap_conv=0"
	do_facet $SINGLEAGT $LCTL pcc list $MOUNT

	local thresh=$(do_facet $SINGLEAGT $LCTL get_param -n \
		       llite.*.pcc_async_threshold | head -n 1)

	stack_trap "do_facet $SINGLEAGT $LCTL set_param \
		    llite.*.pcc_async_threshold=$thresh"
	do_facet $SINGLEAGT $LCTL set_param llite.*.pcc_async_threshold=0

	local rpid1
	local rpid2
	local rpid3
	local mpid1
	local mpid2
	local mpid3
	local lpid1
	local lpid2

	do_facet $SINGLEAGT dd if=/dev/zero of=$file bs=1M count=50 ||
		error "Write $file failed"

	(
		while [ ! -e $DIR/sanity-pcc.98.lck ]; do
			do_facet $SINGLEAGT dd if=$file of=/dev/null bs=1M count=50 ||
				error "Read $file failed"
			sleep 0.$((RANDOM % 4 + 1))
		done
	)&
	rpid1=$!

	(
		while [ ! -e $DIR/sanity-pcc.98.lck ]; do
			do_facet $SINGLEAGT dd if=$file of=/dev/null bs=1M count=50 ||
				error "Read $file failed"
			sleep 0.$((RANDOM % 4 + 1))
		done
	)&
	rpid2=$!

	(
		while [ ! -e $DIR/sanity-pcc.98.lck ]; do
			do_facet $SINGLEAGT dd if=$file of=/dev/null bs=1M count=50 ||
				error "Read $file failed"
			sleep 0.$((RANDOM % 4 + 1))
		done
	)&
	rpid3=$!

	(
		while [ ! -e $DIR/sanity-pcc.98.lck ]; do
			do_facet $SINGLEAGT $MMAP_CAT $file > /dev/null ||
				error "$MMAP_CAT $file failed"
			sleep 0.$((RANDOM % 2 + 1))
		done
	)&
	mpid1=$!

	(
		while [ ! -e $DIR/sanity-pcc.98.lck ]; do
			do_facet $SINGLEAGT $LCTL set_param -n ldlm.namespaces.*mdc*.lru_size=clear ||
				error "cancel_lru_locks mdc failed"
			sleep 0.1
		done
	)&
	lpid1=$!

	(
		while [ ! -e $DIR/sanity-pcc.98.lck ]; do
			do_facet $SINGLEAGT $LCTL set_param -n ldlm.namespaces.*osc*.lru_size=clear ||
				error "cancel_lru_locks mdc failed"
			sleep 0.1
		done
	)&
	lpid2=$!

	sleep 60
	stack_trap "rm -f $DIR/sanity-pcc.98.lck"
	touch $DIR/sanity-pcc.98.lck
	wait $rpid1 || error "$?: read failed"
	wait $rpid2 || error "$?: read failed"
	wait $rpid3 || error "$?: read failed"
	wait $mpid1 || error "$?: mmap failed"
	wait $lpid1 || error "$?: cancel locks failed"
	wait $lpid2 || error "$?: cancel locks failed"

	do_facet $SINGLEAGT $LFS pcc detach $file
	rm -f $DIR/sanity-pcc.98.lck
}
run_test 98 "racer between auto attach and mmap I/O"

test_99() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 60
	do_facet $SINGLEAGT mkdir $hsm_root || error "mkdir $hsm_root failed"
	setup_pcc_mapping $SINGLEAGT \
		"projid={0}\ roid=$HSM_ARCHIVE_NUMBER\ pccro=1"
	do_facet $SINGLEAGT $LCTL pcc list $MOUNT

	do_facet $SINGLEAGT dd if=/dev/zero of=$file bs=1M count=50 ||
		error "Write $file failed"

	local rpid
	local rpid2
	local wpid
	local upid
	local dpid
	local lpcc_path

	lpcc_path=$(lpcc_fid2path $hsm_root $file)
	(
		while [ ! -e $DIR/sanity-pcc.99.lck ]; do
			do_facet $SINGLEAGT dd if=/dev/zero of=$file bs=1M count=50 conv=notrunc ||
				error "failed to write $file"
			sleep 0.$((RANDOM % 4 + 1))
		done
	)&
	wpid=$!

	(
		while [ ! -e $DIR/sanity-pcc.99.lck ]; do
			do_facet $SINGLEAGT dd if=$file of=/dev/null bs=1M count=50 ||
				error "failed to write $file"
			sleep 0.$((RANDOM % 4 + 1))
		done
	)&
	rpid=$!

	(
		while [ ! -e $DIR/sanity-pcc.99.lck ]; do
			do_facet $SINGLEAGT $MMAP_CAT $file > /dev/null ||
				error "failed to mmap_cat $file"
			sleep 0.$((RANDOM % 4 + 1))
		done
	)&
	rpid2=$!

	(
		while [ ! -e $DIR/sanity-pcc.99.lck ]; do
			echo "Unlink $lpcc_path"
			do_facet $SINGLEAGT unlink $lpcc_path
			sleep 1
		done
		true
	)&
	upid=$!

	(
		while [ ! -e $DIR/sanity-pcc.99.lck ]; do
			echo "Detach $file ..."
			do_facet $SINGLEAGT $LFS pcc detach $file
			sleep 0.$((RANDOM % 8 + 1))
		done
	)&
	dpid=$!

	sleep 60
	stack_trap "rm -f $DIR/sanity-pcc.99.lck"
	touch $DIR/sanity-pcc.99.lck
	wait $wpid || error "$?: write failed"
	wait $rpid || error "$?: read failed"
	wait $rpid2 || error "$?: read2 failed"
	wait $upid || error "$?: unlink failed"
	wait $dpid || error "$?: detach failed"

	do_facet $SINGLEAGT $LFS pcc detach $file
	rm -f $DIR/sanity-pcc.99.lck
}
run_test 99 "race among unlink | mmap read | write | detach for PCC-RO file"

test_100() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	setup_loopdev $SINGLEAGT $loopfile $mntpt 60
	do_facet $SINGLEAGT mkdir $hsm_root || error "mkdir $hsm_root failed"
	setup_pcc_mapping $SINGLEAGT \
		"projid={0}\ roid=$HSM_ARCHIVE_NUMBER\ pccro=1"
	do_facet $SINGLEAGT $LCTL pcc list $MOUNT

	do_facet $SINGLEAGT dd if=/dev/zero of=$file bs=1M count=50 ||
		error "Write $file failed"

	local rpid
	local rpid2
	local wpid
	local upid
	local dpid
	local lpcc_path

	lpcc_path=$(lpcc_fid2path $hsm_root $file)
	(
		while [ ! -e $DIR/sanity-pcc.100.lck ]; do
			do_facet $SINGLEAGT dd if=/dev/zero of=$file bs=1M count=50 ||
				error "failed to write $file"
			sleep 0.$((RANDOM % 4 + 1))
		done
	)&
	wpid=$!

	(
		while [ ! -e $DIR/sanity-pcc.100.lck ]; do
			do_facet $SINGLEAGT dd if=$file of=/dev/null bs=1M count=50 ||
				error "failed to write $file"
			sleep 0.$((RANDOM % 4 + 1))
		done
	)&
	rpid=$!

	(
		while [ ! -e $DIR/sanity-pcc.100.lck ]; do
			do_facet $SINGLEAGT dd if=$file of=/dev/null bs=1M count=50 ||
				error "failed to write $file"
			sleep 0.$((RANDOM % 4 + 1))
		done
	)&
	rpid2=$!

	(
		while [ ! -e $DIR/sanity-pcc.100.lck ]; do
			echo "Unlink $lpcc_path"
			do_facet $SINGLEAGT unlink $lpcc_path
			sleep 1
		done
		true
	)&
	upid=$!

	(
		while [ ! -e $DIR/sanity-pcc.100.lck ]; do
			echo "Detach $file ..."
			do_facet $SINGLEAGT $LFS pcc detach $file
			sleep 0.$((RANDOM % 8 + 1))
		done
	)&
        dpid=$!

	sleep 60
	stack_trap "rm -f $DIR/sanity-pcc.100.lck"
	touch $DIR/sanity-pcc.100.lck
	wait $wpid || error "$?: write failed"
	wait $rpid || error "$?: read failed"
	wait $rpid2 || error "$?: read2 failed"
	wait $upid || error "$?: unlink failed"
	wait $dpid || error "$?: detach failed"

	do_facet $SINGLEAGT $LFS pcc detach $file
	rm -f $DIR/sanity-pcc.100.lck
}
run_test 100 "race among PCC unlink | read | write | detach for PCC-RO file"

#test 101: containers and PCC
#LU-15170: Test mount namespaces with PCC
#This tests the cases where the PCC mount is not present in the container by
#creating a mount namespace without the PCC mount in it (this is probably the
#standard config for most containers)
test_101a() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tdir/$tfile

	# Some kernels such as RHEL7 default to 0 user namespaces
	local maxuserns=$(do_facet $SINGLEAGT cat /proc/sys/user/max_user_namespaces)
	do_facet $SINGLEAGT "echo 10 > /proc/sys/user/max_user_namespaces"
	stack_trap "do_facet $SINGLEAGT 'echo $maxuserns > /proc/sys/user/max_user_namespaces'"

	# disable apparmor checking of userns temporarily
	if [[ "$CLIENT_OS_ID" == "ubuntu" ]] &&
	   (( $CLIENT_OS_VERSION_CODE >= $(version_code 24) )); then
		local userns_val

		userns_val=$(do_facet $SINGLEAGT \
			sysctl -n kernel.apparmor_restrict_unprivileged_userns)
		if (( "$userns_val" != 0 )); then
			do_facet $SINGLEAGT \
				sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
			stack_trap "do_facet $SINGLEAGT sysctl -w kernel.apparmor_restrict_unprivileged_userns=$userns_val"
		fi
	fi

	echo "creating user namespace for $RUNAS_ID"
	# Create a mount and user namespace with this command, and leave the
	# process running so we can do the rest of our steps
	local start=$SECONDS
	local PID=$(do_facet $SINGLEAGT \
		    "$RUNAS unshare -Um sleep 600 &>/dev/null & echo \\\$!")
	local elapsed=$((SECONDS - start))
	local count=0

	do_facet $SINGLEAGT ps auxww | grep sleep
	echo "Created NS: child (sleep) pid=$PID in $elapsed seconds"
	[[ -n "$PID" ]] || error "remote sleep start failed"
	stack_trap "do_facet $SINGLEAGT kill -9 $PID" EXIT
	(( elapsed < 300 )) || error "remote sleep took $elapsed sec to start"

	# Map 'RUNAS' to root in the namespace, so it has rights to do whatever
	# This is handled by '-r' in unshare in newer versions
	do_facet $SINGLEAGT $RUNAS newuidmap $PID 0 $RUNAS_ID 1 ||
		error "could not map uid $RUNAS_ID to root in namespace"
	do_facet $SINGLEAGT $RUNAS newgidmap $PID 0 $RUNAS_GID 1 ||
		error "could not map gid $RUNAS_GID to root in namespace"

	# Create PCC after creating namespace; namespace will not have PCC
	# mount
	setup_loopdev $SINGLEAGT $loopfile $mntpt 50

	# Create a temp file inside the PCC mount to verify mount namespace
	do_facet $SINGLEAGT touch $mntpt/$tfile.tmp
	stack_trap "do_facet $SINGLEAGT rm -f $mntpt/$tfile.tmp" EXIT
	echo "Check for temp file in PCC mount"
	do_facet $SINGLEAGT test -f $mntpt/$tfile.tmp ||
		error "Should see $mntpt/$tfile.tmp"
	echo "Check for temp file in PCC mount from inside namespace"
	do_facet $SINGLEAGT nsenter -t $PID -U -m test -f $mntpt/$tfile.tmp &&
		error "Should not see $mntpt/$tfile.tmp from namespace"
	rm -f $mntpt/$tfile.tmp

	# Finish PCC setup
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT "projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ pccrw=1"

	mkdir_on_mdt0 $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	chmod 777 $DIR/$tdir || error "chmod 777 $DIR/$tdir failed"

	echo "Verify open attach from inside mount namespace"
	do_facet $SINGLEAGT nsenter -t $PID -U -m dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"
	do_facet $SINGLEAGT nsenter -t $PID -U -m $LFS pcc attach -w \
		-i $HSM_ARCHIVE_NUMBER $file || error "cannot attach $file"
	do_facet $SINGLEAGT nsenter -t $PID -U -m $LFS pcc state $file

	check_lpcc_state $file "readwrite" $SINGLEAGT "$RUNAS"
	# Revoke the layout lock, the PCC-cached file will be
	# detached automatically.
	do_facet $SINGLEAGT $LCTL set_param ldlm.namespaces.*mdc*.lru_size=clear
	check_lpcc_state $file "none" $SINGLEAGT "$RUNAS"
	do_facet $SINGLEAGT $RUNAS $MULTIOP $file oc ||
		error "failed to open $file"
	check_lpcc_state $file "readwrite" $SINGLEAGT "$RUNAS"
	# Detach the file but keep the cache, as the file layout generation
	# is not changed, so the file is still valid cached in PCC, and can
	# be reused from PCC cache directly.
	do_facet $SINGLEAGT nsenter -t $PID -U -m $LFS pcc detach -k $file ||
		error "PCC detach $file failed"
	check_lpcc_state $file "none" $SINGLEAGT "$RUNAS"
	do_facet $SINGLEAGT nsenter -t $PID -U -m $MULTIOP $file oc ||
		error "failed to open $file"
	check_lpcc_state $file "readwrite" $SINGLEAGT "$RUNAS"
	do_facet $SINGLEAGT nsenter -t $PID -U -m $LFS pcc detach $file ||
		error "PCC detach $file failed"
	do_facet $SINGLEAGT nsenter -t $PID -U -m dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"
	rm -f $file || error "rm $file failed"

	echo "Verify auto attach at open from inside NS for RW-PCC"
	# nsenter has strange behavior with echo, which means we have to place
	# this in a script so we can use sh, otherwise it doesn't execute echo
	# in the namespace
	# NB: using /bin/echo instead of the shell built in does not help
	echo "echo -n autoattach_data > $file" > $DIR/$tdir/$tfile.shell
	# File is owned by root, make it accessible to RUNAS user
	chmod a+rw $DIR/$tdir/$tfile.shell
	stack_trap 'rm -f $DIR/$tdir/$tfile.shell' EXIT
	do_facet $SINGLEAGT nsenter -t $PID -U -m "bash $DIR/$tdir/$tfile.shell"
	do_facet $SINGLEAGT nsenter -t $PID -U -m $LFS pcc attach -w -i $HSM_ARCHIVE_NUMBER \
		$file || error "RW-PCC attach $file failed"
	check_lpcc_state $file "readwrite"

	# Revoke the layout lock, the PCC-cached file will be
	# detached automatically.
	do_facet $SINGLEAGT $LCTL set_param ldlm.namespaces.*mdc*.lru_size=clear
	check_file_data $SINGLEAGT $file "autoattach_data" $PID
	check_lpcc_state $file "readwrite"

	# Detach the file with -k option, as the file layout generation
	# is not changed, so the file is still valid cached in PCC,
	# and can be reused from PCC cache directly.
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "RW-PCC detach $file failed"
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"
	check_file_data $SINGLEAGT $file "autoattach_data" $PID
	check_lpcc_state $file "readwrite"

	# HSM restore the PCC cached file, the layout generation
	# was changed, so the file can not be auto attached.
	$LFS hsm_restore $file || error "failed to restore $file"
	wait_request_state $(path2fid $file) RESTORE SUCCEED
	check_lpcc_state $file "none"
	# HSM exists archived status
	check_hsm_flags $file "0x00000009"
}
run_test 101a "Test auto attach in mount namespace (simulated container)"

test_102() {
	grep -q io_uring_setup /proc/kallsyms ||
		skip "Client OS does not support io_uring I/O engine"
	io_uring_probe || skip "kernel does not support io_uring fully"

	$LCTL get_param -n mdc.*.connect_flags | grep -q pcc_ro ||
		skip "Server does not support PCC-RO"

	which fio || skip_env "no fio installed"
	fio --enghelp | grep -q io_uring ||
		skip_env "fio does not support io_uring I/O engine"

	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile

	setup_loopdev client $loopfile $mntpt 60
	mkdir $hsm_root || error "mkdir $hsm_root failed"
	setup_pcc_mapping client \
		"projid={0}\ roid=$HSM_ARCHIVE_NUMBER\ pccro=1"

	local thresh=$($LCTL get_param -n llite.*.pcc_async_threshold |
		       head -n 1)

	stack_trap "do_facet $SINGLEAGT $LCTL set_param \
		    llite.*.pcc_async_threshold=$thresh"
	do_facet $SINGLEAGT $LCTL set_param llite.*.pcc_async_threshold=0

	local ioengine="io_uring"
	local numjobs=2
	local size=10M

	do_facet $SINGLEAGT fio --name=seqwrite --ioengine=$ioengine	\
		--bs=$PAGE_SIZE --direct=1 --numjobs=$numjobs	\
		--iodepth=64 --size=$size --filename=$file --rw=write ||
		error "fio seqwrite $file failed"

	# Read the file will trigger the buffered read from Lustre OSTs and
	# write to PCC copy as @pcc_async_threshold is set with 0.
	do_facet $SINGLEAGT fio --name=seqread --ioengine=$ioengine	\
		--bs=$PAGE_SIZE --direct=1 --numjobs=$numjobs	\
		--iodepth=64 --size=$size --filename=$file --rw=read ||
		error "fio seqread $file failed"
}
run_test 102 "PCC-RO should not hange for io_uring I/O engine"

complete_test $SECONDS
check_and_cleanup_lustre
exit_status
