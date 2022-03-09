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
HSMTOOL_ARCHIVE_FORMAT=v1

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

	do_facet $facet $LCTL pcc clear $MOUNT
}

setup_pcc_mapping() {
	local facet=${1:-$SINGLEAGT}
	local hsm_root=${hsm_root:-$(hsm_root "$facet")}
	local param="$2"

	[ -z "$param" ] && param="projid={100}\ rwid=$HSM_ARCHIVE_NUMBER"
	stack_trap "cleanup_pcc_mapping $facet" EXIT
	do_facet $facet $LCTL pcc add $MOUNT $hsm_root -p $param
}

setup_loopdev() {
	local facet=$1
	local file=$2
	local mntpt=$3
	local size=${4:-50}

	do_facet $facet mkdir -p $mntpt || error "mkdir -p $hsm_root failed"
	stack_trap "do_facet $facet rm -rf $mntpt" EXIT
	do_facet $facet dd if=/dev/zero of=$file bs=1M count=$size
	stack_trap "do_facet $facet rm -f $file" EXIT
	do_facet $facet mkfs.ext4 $file ||
		error "mkfs.ext4 $file failed"
	do_facet $facet file $file
	do_facet $facet mount -t ext4 -o loop,usrquota,grpquota $file $mntpt ||
		error "mount -o loop,usrquota,grpquota $file $mntpt failed"
	stack_trap "do_facet $facet $UMOUNT $mntpt" EXIT
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
		do_facet $SINGLEAGT $LFS pcc attach -i \
			$HSM_ARCHIVE_NUMBER $file ||
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
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0"
	$LCTL pcc list $MOUNT
	mkdir_on_mdt0 $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	chmod 777 $DIR/$tdir || error "chmod 777 $DIR/$tdir failed"

	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"
	do_facet $SINGLEAGT $RUNAS $LFS pcc attach -i $HSM_ARCHIVE_NUMBER \
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

	do_facet $SINGLEAGT $RUNAS $LFS pcc attach -i $HSM_ARCHIVE_NUMBER \
		$file || error "failed to attach file $file"
	check_lpcc_state $file "readwrite"

	do_facet $SINGLEAGT $RUNAS $LFS pcc detach $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none"
	wait_request_state $(path2fid $file) REMOVE SUCCEED
}
run_test 1e "Test RW-PCC with non-root user"

test_1f() {
	local project_id=100
	local agt_facet=$SINGLEAGT
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tdir/$tfile

	! is_project_quota_supported &&
		skip "project quota is not supported"

	enable_project_quota
	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ open_attach=0\ stat_attach=0"

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
	setup_pcc_mapping

	dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"
	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$file bs=1024 count=1 &&
		error "non-root user can dd write to $file"
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$file bs=1024 count=1 &&
		error "non-root user can dd write to $file"
	chmod 777 $file || error "chmod 777 $file failed"
	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "non-root user cannot write $file with permission (777)"

	do_facet $SINGLEAGT $RUNAS $LFS pcc detach $file &&
		error "non-root user or non owner can detach $file"
	chown $RUNAS_ID $file || error "chown $RUNAS_ID $file failed"
	do_facet $SINGLEAGT $RUNAS $LFS pcc detach $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none"
	wait_request_state $(path2fid $file) REMOVE SUCCEED
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

	! is_project_quota_supported &&
		skip "project quota is not supported" && return

	enable_project_quota
	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping
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
	setup_pcc_mapping
	file=$DIR/$tdir/multiop
	mkdir -p $DIR/$tdir
	rm -f $file

	do_facet $SINGLEAGT "echo -n file_data > $file"
	do_facet $SINGLEAGT lfs pcc attach -i $HSM_ARCHIVE_NUMBER \
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
	setup_pcc_mapping
	mkdir -p $DIR/$tdir
	rm -f $file

	do_facet $SINGLEAGT "echo -n file_data > $file"
	do_facet $SINGLEAGT lfs pcc attach -i $HSM_ARCHIVE_NUMBER \
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

	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0"

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"

	echo "Start to attach/detach the file: $file"
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none"

	echo "Repeat to attach/detach the same file: $file"
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite"
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
		copytool setup -f agt$n -a $n -m $MOUNT
		setup_pcc_mapping agt$n "projid={100}\ rwid=$n\ auto_attach=0"
	done

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"

	echo "Start to attach/detach $file on $agt1_HOST"
	do_facet agt1 $LFS pcc attach -i 1 $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite" agt1
	do_facet agt1 $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none" agt1

	echo "Repeat to attach/detach $file on $agt2_HOST"
	do_facet agt2 $LFS pcc attach -i 2 $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite" agt2
	do_facet agt2 $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none" agt2

	echo "Try attach on two agents"
	do_facet agt1 $LFS pcc attach -i 1 $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite" agt1
	do_facet agt2 $LFS pcc attach -i 2 $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite" agt2
	# The later attach PCC agent should succeed,
	# the former agent should be detached automatically.
	check_lpcc_state $file "none" agt1
	do_facet agt2 $LFS pcc detach -k $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none" agt2
}
run_test 3b "Repeat attach/detach operations on multiple clients"

test_4() {
	local project_id=100
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local excepts="-e 6 -e 7 -e 8 -e 9"

	! is_project_quota_supported &&
		skip "project quota is not supported" && return

	enable_project_quota
	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	lfs project -sp $project_id $DIR/$tdir ||
		error "lfs project -sp $project_id $DIR/$tdir failed"

	# 1. mmap_sanity tst7 failed on the local ext4 filesystem.
	#    It seems that Lustre filesystem does special process for tst 7.
	# 2. There is a mmap problem for PCC when multiple clients read/write
	#    on a shared mmapped file for mmap_sanity tst 6.
	# 3. Current CentOS8 kernel does not strictly obey POSIX syntax for
	#    mmap() within the maping but beyond current end of the underlying
	#    files: It does not send SIGBUS signals to the process.
	# 4. For negative file offset, sanity_mmap also failed on 48 bits
	#    ldiksfs backend due to too large offset: "Value too large for
	#    defined data type".
	# mmap_sanity tst7/tst8/tst9 all failed on Lustre and local ext4.
	# Thus, we exclude sanity tst6/tst7/tst8/tst9 from the PCC testing.
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
	setup_pcc_mapping

	do_facet $SINGLEAGT "echo -n attach_mmap_data > $file" ||
		error "echo $file failed"

	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file ||
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
	setup_pcc_mapping

	echo -n mmap_write_data > $file || error "echo write $file failed"
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file ||
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
	setup_pcc_mapping

	echo "QQQQQ" > $file
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file ||
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
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0"

	echo "QQQQQ" > $file
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file ||
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
	setup_pcc_mapping

	echo "QQQQQ" > $file
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file ||
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
	setup_pcc_mapping
	do_facet $SINGLEAGT $LCTL pcc list $MOUNT

	touch $file || error "touch $file failed"
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file ||
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
	local ug=$1
	local id=$RUNAS_ID

	[[ $ug == "g" ]] && id=$RUNAS_GID

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	do_facet $SINGLEAGT quotacheck -c$ug $mntpt ||
		error "quotacheck -c$ug $mntpt failed"
	do_facet $SINGLEAGT quotaon -$ug $mntpt ||
		error "quotaon -$ug $mntpt failed"
	do_facet $SINGLEAGT setquota -$ug $id 0 20480 0 0 $mntpt ||
		error "setquota -$ug $id on $mntpt failed"
	do_facet $SINGLEAGT repquota -${ug}vs $mntpt

	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMVER" -h "$hsm_root"
	setup_pcc_mapping
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
	do_facet $SINGLEAGT $RUNAS $LFS pcc attach -i $HSM_ARCHIVE_NUMBER \
		$file1 || error "attach $file1 failed"
	do_facet $SINGLEAGT $RUNAS $LFS pcc attach -i $HSM_ARCHIVE_NUMBER \
		$file2 && error "attach $file2 should fail due to quota limit"
	check_lpcc_state $file1 "readwrite"
	check_lpcc_state $file2 "none"

	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$file1 bs=1M count=30 ||
		error "dd write $file1 failed"
	# -EDQUOT error should be tolerated via fallback to normal Lustre path.
	check_lpcc_state $file1 "none"
	do_facet $SINGLEAGT $LFS pcc detach -k $file1 ||
		error "failed to detach file $file"
	rm $file1 $file2
}

test_10a() {
	test_usrgrp_quota "u"
}
run_test 10a "Test RW-PCC with user quota on loop PCC device"

test_10b() {
	test_usrgrp_quota "g"
}
run_test 10b "Test RW-PCC with group quota on loop PCC device"

test_11() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile
	local -a lpcc_path
	local lpcc_dir

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping

	do_facet $SINGLEAGT "echo -n QQQQQ > $file"
	lpcc_path=$(lpcc_fid2path $hsm_root $file)
	lpcc_dir=$(dirname $lpcc_path)
	echo "Lustre file: $file LPCC dir: $lpcc_dir"
	do_facet $SINGLEAGT mkdir -p $lpcc_dir ||
		error "mkdir -p $lpcc_dir failed"
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file ||
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
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file &&
		error "attach $file with immutable directory should be failed"
	do_facet $SINGLEAGT chattr -i $lpcc_dir ||
		error "chattr -i $lpcc_dir failed"
	rm $file || error "rm $file failed"

	# The PCC file path is set to a directory
	do_facet $SINGLEAGT "echo -n pcc_file_path_is_dir > $file"
	lpcc_path=$(lpcc_fid2path $hsm_root $file)
	do_facet $SINGLEAGT mkdir -p $lpcc_path ||
		error "mkdir -p $lpcc_path failed"
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file &&
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
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0"

	echo  -n race_rw_attach_hsmremove > $file
	lpcc_path=$(lpcc_fid2path $hsm_root $file)
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file ||
		error "attach $file failed"
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "detach $file failed"
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"
	# define OBD_FAIL_LLITE_PCC_ATTACH_PAUSE	0x1414
	do_facet $SINGLEAGT $LCTL set_param fail_loc=0x1414 fail_val=20
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file &
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
		"$rule\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0"
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
	test_rule_id "u" "500" "runas -u 500"
	test_rule_id "g" "500" "runas -u 500 -g 500"
}
run_test 13a "Test auto RW-PCC create caching for UID/GID rule"

test_13b() {
	local file

	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"fname={*.h5\ suffix.*\ Mid*dle}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0"
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

	! is_project_quota_supported &&
		echo "Skip project quota is not supported" && return 0

	enable_project_quota
	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100\ 200}\&fname={*.h5},uid={500}\&gid={1000}\ rwid=$HSM_ARCHIVE_NUMBER"
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
	myRUNAS="runas -u 500 -g 1000"
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

	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0"

	mkdir -p $DIR/$tdir || error "mkdir -p $DIR/$tdir failed"
	do_facet $SINGLEAGT "echo -n autodetach_data > $file"
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER \
		$file || error "PCC attach $file failed"
	check_lpcc_state $file "readwrite"

	# Revoke the layout lock, the PCC-cached file will be
	# detached automatically.
	do_facet $SINGLEAGT $LCTL \
		set_param ldlm.namespaces.*mdc*.lru_size=clear
	check_file_data $SINGLEAGT $file "autodetach_data"
	check_lpcc_state $file "none"
}
run_test 14 "Revocation of the layout lock should detach the file automatically"

test_15() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tdir/$tfile

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping

	mkdir_on_mdt0 $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	chmod 777 $DIR/$tdir || error "chmod 777 $DIR/$tdir failed"

	echo "Check open attach for non-root user"
	do_facet $SINGLEAGT $RUNAS dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"
	do_facet $SINGLEAGT $RUNAS $LFS pcc attach -i $HSM_ARCHIVE_NUMBER \
		$file || error "failed to attach file $file"
	do_facet $SINGLEAGT $RUNAS $LFS pcc state $file
	check_lpcc_state $file "readwrite" $SINGLEAGT "$RUNAS"
	# Revoke the layout lock, the PCC-cached file will be
	# detached automatically.
	do_facet $SINGLEAGT $LCTL \
		set_param ldlm.namespaces.*mdc*.lru_size=clear
	check_lpcc_state $file "readwrite" $SINGLEAGT "$RUNAS"
	# Detach the file but keep the cache , as the file layout generation
	# is not changed, so the file is still valid cached in PCC, and can
	# be reused from PCC cache directly.
	do_facet $SINGLEAGT $RUNAS $LFS pcc detach -k $file ||
		error "PCC detach $file failed"
	check_lpcc_state $file "readwrite" $SINGLEAGT "$RUNAS"
	do_facet $SINGLEAGT $RUNAS $LFS pcc detach $file ||
		error "PCC detach $file failed"
	rm $file || error "rm $file failed"

	echo "check open attach for root user"
	do_facet $SINGLEAGT "echo -n autoattach_data > $file"
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER \
		$file || error "PCC attach $file failed"
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
		error "PCC detach $file failed"
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

}
run_test 15 "Test auto attach at open when file is still valid cached"

test_16() {
	local loopfile="$TMP/$tfile"
	local mntpt="/mnt/pcc.$tdir"
	local hsm_root="$mntpt/$tdir"
	local file=$DIR/$tfile
	local -a lpcc_path

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping

	do_facet $SINGLEAGT "echo -n detach_data > $file"
	lpcc_path=$(lpcc_fid2path $hsm_root $file)
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER \
		$file || error "PCC attach $file failed"
	check_lpcc_state $file "readwrite"
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"

	echo "Test for reusing valid PCC cache"
	# Valid PCC cache can be reused
	do_facet $SINGLEAGT $LFS pcc detach -k $file ||
		error "PCC detach $file failed"
	check_lpcc_state $file "readwrite"
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"

	echo "Test for the default detach"
	# Permanent detach by default, it will remove the PCC copy
	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "PCC detach $file failed"
	wait_request_state $(path2fid $file) REMOVE SUCCEED
	check_lpcc_state $file "none"
	# File is removed from PCC backend
	check_hsm_flags $file "0x00000000"
	do_facet $SINGLEAGT "[ -f $lpcc_path ]"	&&
		error "RW-PCC cached file '$lpcc_path' should be removed"

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
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ open_attach=0\ stat_attach=0"

	do_facet $SINGLEAGT $LCTL pcc list $MOUNT

	do_facet $SINGLEAGT "echo -n layout_refresh_data > $file"
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file ||
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
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER"

	do_facet $SINGLEAGT $LCTL pcc list $MOUNT
	do_facet $SINGLEAGT dd if=/dev/urandom of=$file bs=1M count=4 ||
		error "failed to write $file"
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file ||
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
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file ||
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
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER\ auto_attach=0"

	do_facet $SINGLEAGT "echo -n QQQQQ > $file" || error "echo $file failed"
	lpcc_path=$(lpcc_fid2path $hsm_root $file)
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file ||
		error "Failed to attach $file"
	check_lpcc_state $file "readwrite"
	check_lpcc_sizes $SINGLEAGT $file $lpcc_path 5
	do_facet $SINGLEAGT $LFS pcc detach --keep $file ||
		error "Failed to detach $file"
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file ||
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

	setup_loopdev $SINGLEAGT $loopfile $mntpt 50
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping $SINGLEAGT \
		"projid={100}\ rwid=$HSM_ARCHIVE_NUMBER"

	do_facet $SINGLEAGT "echo -n QQQQQ > $file" ||
		error "echo $file failed"
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file ||
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

	echo "creating user namespace for $RUNAS_ID"
	# Create a mount and user namespace with this command, and leave the
	# process running so we can do the rest of our steps
	do_facet $SINGLEAGT $RUNAS unshare -Um sleep 600 &
	# Let the child start...
	sleep 2
	# Get the sleep PID so we can find its namespace and kill it later
	PID=$(do_facet $SINGLEAGT pgrep sleep)
	stack_trap "do_facet $SINGLEAGT kill -9 $PID" EXIT
	echo "Created NS: child (sleep) pid $PID"
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
	setup_pcc_mapping $SINGLEAGT "projid={100}\ rwid=$HSM_ARCHIVE_NUMBER"

	mkdir_on_mdt0 $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	chmod 777 $DIR/$tdir || error "chmod 777 $DIR/$tdir failed"

	echo "Verify open attach from inside mount namespace"
	do_facet $SINGLEAGT nsenter -t $PID -U -m dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"
	do_facet $SINGLEAGT nsenter -t $PID -U -m $LFS pcc attach \
		-i $HSM_ARCHIVE_NUMBER $file || error "cannot attach $file"
	do_facet $SINGLEAGT nsenter -t $PID -U -m $LFS pcc state $file

	check_lpcc_state $file "readwrite" $SINGLEAGT "$RUNAS"
	# Revoke the layout lock, the PCC-cached file will be
	# detached automatically.
	do_facet $SINGLEAGT $LCTL set_param ldlm.namespaces.*mdc*.lru_size=clear
	check_lpcc_state $file "readwrite" $SINGLEAGT "$RUNAS"
	# Detach the file but keep the cache, as the file layout generation
	# is not changed, so the file is still valid cached in PCC, and can
	# be reused from PCC cache directly.
	do_facet $SINGLEAGT nsenter -t $PID -U -m $LFS pcc detach -k $file ||
		error "PCC detach $file failed"
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
	do_facet $SINGLEAGT nsenter -t $PID -U -m "sh $DIR/$tdir/$tfile.shell"
	do_facet $SINGLEAGT nsenter -t $PID -U -m $LFS pcc attach -i $HSM_ARCHIVE_NUMBER \
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
	check_lpcc_state $file "readwrite"
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"
	check_file_data $SINGLEAGT $file "autoattach_data" $PID

	# HSM restore the PCC cached file, the layout generation
	# was changed, so the file can not be auto attached.
	$LFS hsm_restore $file || error "failed to restore $file"
	wait_request_state $(path2fid $file) RESTORE SUCCEED
	check_lpcc_state $file "none"
	# HSM exists archived status
	check_hsm_flags $file "0x00000009"
}
run_test 101a "Test auto attach in mount namespace (simulated container)"

complete $SECONDS
check_and_cleanup_lustre
exit_status
