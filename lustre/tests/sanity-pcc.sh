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
MMAP_CAT=${MMAP_CAT:-mmap_cat}
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
	local facet=${3:-$SINGLEAGT}
	local state=$(do_facet $facet $LFS pcc state $lustre_path |
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

	[ -z "$param" ] && param="$HSM_ARCHIVE_NUMBER\ 100"
	cleanup_pcc_mapping $facet
	do_facet $facet $LCTL pcc add $MOUNT $hsm_root -p $param
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
	echo "Start to detach the $file"
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
test_2a() {
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
	local hsm_root=$(hsm_root)
	local agt_host=$(facet_active_host $SINGLEAGT)

	needclients 2 || return 0

	remote_client=$(get_remote_client)

	enable_project_quota
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
	cleanup_pcc_mapping
}
run_test 2b "Test multi remote open when creating"

test_2c() {
	local agt_host=$(facet_active_host $SINGLEAGT)
	local file=$DIR/$tdir/$tfile
	local file2=$DIR2/$tdir/$tfile

	enable_project_quota
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

	cleanup_pcc_mapping
}
run_test 2c "Test multi open on different mount points when creating"

test_3a() {
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
run_test 3a "Repeat attach/detach operations"

test_3b() {
	local n
	local file=$DIR/$tdir/$tfile

	needclients 3 || return 0

	# Start all of the copytools and setup PCC
	for n in $(seq $AGTCOUNT); do
		copytool setup -f agt$n -a $n -m $MOUNT
		setup_pcc_mapping agt$n "$n\ 100"
	done

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	dd if=/dev/zero of=$file bs=1024 count=1 ||
		error "failed to dd write to $file"

	echo "Start to attach/detach $file on $agt1_HOST"
	do_facet agt1 $LFS pcc attach -i 1 $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite" agt1
	do_facet agt1 $LFS pcc detach $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none" agt1

	echo "Repeat to attach/detach $file on $agt2_HOST"
	do_facet agt2 $LFS pcc attach -i 2 $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite" agt2
	do_facet agt2 $LFS pcc detach $file ||
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
	do_facet agt2 $LFS pcc detach $file ||
		error "failed to detach file $file"
	check_lpcc_state $file "none" agt2

	for n in $(seq $AGTCOUNT); do
		cleanup_pcc_mapping agt$n
	done
}
run_test 3b "Repeat attach/detach operations on multiple clients"

test_4() {
	local project_id=100

	! is_project_quota_supported &&
		skip "project quota is not supported" && return

	enable_project_quota
	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	lfs project -sp $project_id $DIR/$tdir ||
		error "lfs project -sp $project_id $DIR/$tdir failed"

	# mmap_sanity tst7 failed on the local ext4 filesystem.
	# It seems that Lustre filesystem does special process for tst 7.
	# Thus, we exclude tst7 from the PCC testing.
	$LUSTRE/tests/mmap_sanity -d $DIR/$tdir -m $DIR2/$tdir -e 7 ||
		error "mmap_sanity test failed"
	sync; sleep 1; sync

	cleanup_pcc_mapping
}
run_test 4 "Auto cache test for mmap"

test_5() {
	local file=$DIR/$tdir/$tfile

	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
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

	cleanup_pcc_mapping
}
run_test 5 "Mmap & cat a RW-PCC cached file"

test_6() {
	local file=$DIR/$tdir/$tfile
	local content

	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"

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

	content=$(do_facet $SINGLEAGT $MMAP_CAT $file)
	[[ $content == "nmap_write_data" ]] ||
		error "mmap write data mismatch: $content"

	cleanup_pcc_mapping
}
run_test 6 "Test mmap write on RW-PCC "

test_7a() {
	local file=$DIR/$tdir/$tfile
	local content

	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
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

	cleanup_pcc_mapping
}
run_test 7a "Fake file detached between fault() and page_mkwrite() for RW-PCC"

test_7b() {
	local file=$DIR/$tdir/$tfile
	local content
	local pid

	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	echo "QQQQQ" > $file
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file ||
		error "failed to attach file $file"
	check_lpcc_state $file "readwrite"
	check_file_data $SINGLEAGT $file "QQQQQ"
	# define OBD_FAIL_LLITE_PCC_MKWRITE_PAUSE	0x1413
	do_facet $SINGLEAGT $LCTL set_param fail_loc=0x1413 fail_val=20
	# HSM released exists archived status
	check_hsm_flags $file "0x0000000d"

	# multiop mmap write increase the first character of each page with 1
	do_facet $SINGLEAGT $MULTIOP $file OSMWUc &
	pid=$!

	do_facet $SINGLEAGT $LFS pcc detach $file ||
		error "failed to detach file $file"

	wait $pid || error "multiop mmap write failed"
	check_lpcc_state $file "none"
	content=$(do_facet $SINGLEAGT $MMAP_CAT $file)
	[[ $content == "RQQQQ" ]] || error "data mismatch: $content"

	cleanup_pcc_mapping
}
run_test 7b "Test the race with concurrent mkwrite and detach"

test_8() {
	local file=$DIR/$tdir/$tfile

	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"

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

	cleanup_pcc_mapping
}
run_test 8 "Test fake -ENOSPC tolerance for RW-PCC"

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

	cleanup_pcc_mapping
}
run_test 9 "Test -ENOSPC tolerance on loop PCC device for RW-PCC"

test_10() {
	local file=$DIR/$tdir/$tfile
	local hsm_root=$(hsm_root)
	local file=$DIR/$tdir/$tfile
	local -a lpcc_path
	local lpcc_dir

	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
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
	do_facet $SINGLEAGT $LFS pcc detach $file ||
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

	cleanup_pcc_mapping
}
run_test 10 "Test attach fault injection with simulated PCC file path"

test_11() {
	local file=$DIR/$tfile
	local pid

	copytool setup -m "$MOUNT" -a "$HSM_ARCHIVE_NUMBER"
	setup_pcc_mapping

	echo  -n race_rw_attach_hsmremove > $file
	do_facet $SINGLEAGT $LFS pcc attach -i $HSM_ARCHIVE_NUMBER $file ||
		error "attach $file failed"
	do_facet $SINGLEAGT $LFS pcc detach $file || error "detach $file failed"
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
	wait $pid && error "RW-PCC attach $file should fail"

	cleanup_pcc_mapping
}
run_test 11 "RW-PCC attach races with concurrent HSM remove"

complete $SECONDS
check_and_cleanup_lustre
exit_status
