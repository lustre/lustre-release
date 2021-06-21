#!/bin/bash
set -e

{
cat << 'HEADER'
#!/bin/bash
set -e

ONLY=${ONLY:-"$*"}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
init_logging

# bug number for skipped test:
ALWAYS_EXCEPT="$PJDFSTEST_EXCEPT "
# bug number for skipped test: LU-12922		LU-1158
ALWAYS_EXCEPT+="               chown_00	utimensat_08"
build_test_filter

PJDFSTEST_DIR=${PJDFSTEST_DIR:-"/usr/share/pjdfstest"}
PJDFSTEST_BIN=${PJDFSTEST_BIN:-"/bin/pjdfstest"}
EXT4_LOG=${EXT4_LOG:-"$TMP/pjdfstest-ext4"}
LUSTRE_LOG=${LUSTRE_LOG:-"$TMP/pjdfstest-lustre"}

check_and_setup_lustre

if [[ ! -f $PJDFSTEST_DIR/pjdfstest ]]; then
	# copy the bin to the suite dir
	if ! cp -af $PJDFSTEST_BIN $PJDFSTEST_DIR; then
		error "Copy pjdfstest binary failed"
	fi
fi

run_pjdfstest() {
	local mntpnt=$1
	local pjdfstest=$2
	local report=$3
	local rc=0
	local cmd

	which prove > /dev/null || skip_env "must have prove installed"

	cmd="prove -f $pjdfstest &> $report"

	pushd $mntpnt > /dev/null
	echo $cmd
	if ! eval $cmd; then
		rc=${PIPESTATUS[0]}
	fi
	popd > /dev/null

	return $rc
}

run_lustre_ext4() {
	local pjdfstest=$1

	log "Run $pjdfstest against ext4 filesystem"
	run_pjdfstest $EXT4_MNTPT $pjdfstest $EXT4_LOG

	log "Run $pjdfstest against lustre filesystem"
	mkdir_on_mdt0 $MOUNT/pjdfstest
	run_pjdfstest $MOUNT/pjdfstest $pjdfstest $LUSTRE_LOG
}

setup_ext4() {
	local loop_file=$1
	local mntpt=$2
	local size=${3:-50}

	mkdir -p $mntpt || error "mkdir -p $mntpt failed"
	stack_trap "rm -rf $mntpt"
	dd if=/dev/zero of=$loop_file bs=1M count=$size
	stack_trap "rm -f $loop_file"
	mkfs.ext4 $loop_file > /dev/null ||
		error "mkfs.ext4 $loop_file failed"
	file $loop_file
	mount -t ext4 -o loop,usrquota,grpquota $loop_file $mntpt ||
		error "mount -o loop,usrquota,grpquota $loop_file $mntpt failed"
	stack_trap "$UMOUNT $mntpt"
}

compare_report() {
	local ext4_summary=$TMP/pjdfstest-ext4-summary
	local lustre_summary=$TMP/pjdfstest-lustre-summary
	local summary="Test Summary Report"
	local summary_end="Files"
	local diff=$TMP/pjdfstest-diff
	local rc=0

	# filter out the summary and delete the duration part to compare
	sed -n '/'"$summary"'/,/'"$summary_end"'/p' "$EXT4_LOG" |
		sed '$d'> $ext4_summary
	sed -n '/'"$summary"'/,/'"$summary_end"'/p' "$LUSTRE_LOG" |
		sed '$d' > $lustre_summary
	grep -vf $ext4_summary $lustre_summary > $diff

	[ -s $diff ] && rc=1
	log "ext4 report"
	cat $EXT4_LOG || error_noexit "Cannot open file"
	log "lustre report"
	cat $LUSTRE_LOG || error_noexit "Cannot open file"

	rm -f $TMP/pjdfstest-* ||
		error_noexit "Cannot remove pjdfstest tmp files"
	return $rc
}

# All tests will be run on Lustre and an ext4 file system. Set up
# an ext4 file system
EXT4_MNTPT=/mnt/pjdfstest.ext4
LOOP_FILE=$TMP/loop_file
setup_ext4 $LOOP_FILE $EXT4_MNTPT

# Create users and groups required by the tests
mds=$(facet_host mds1)

USR=(pjd_usr1 pjd_usr2 pjd_usr3)
USRID=(65535 65533 65532)
GRP=(pjd_grp1 pjd_grp2 pjd_grp3)
GRPID=(65535 65533 65531)

idx=0
for grp_id in ${GRPID[@]}; do
	echo "setup up GRPID $grp_id for group ${GRP[$idx]} on $mds"
	do_rpc_nodes $mds add_group $grp_id ${GRP[$idx]}
	stack_trap "do_rpc_nodes $mds groupdel ${GRP[$idx]}"
	idx=$((idx+1))
done

idx=0
for user_id in ${USRID[@]}; do
	echo "setup up USRID $user_id for user ${USR[$idx]}"
	do_rpc_nodes $mds add_user $user_id ${USR[$idx]} \
		${GRPID[$idx]} $DIR/${USR[$idx]}
	stack_trap "do_rpc_nodes $mds userdel ${USR[$idx]}"
	idx=$((idx+1))
done
HEADER

PJDFSTEST_DIR=${PJDFSTEST_DIR:-"/usr/share/pjdfstest"}
# enable globstar so ** can get all dir recursively
shopt -s globstar
for testname in $PJDFSTEST_DIR/**/*.t; do
	test_dir=$(dirname $testname)
	test_grp=$(basename $test_dir)
	sub_t="${test_grp}_$(basename $testname .t)"
	# execute the "desc=" line and set it the environment for our use
	eval $(grep "^desc=" $testname)

	cat - <<SUBTEST
test_$sub_t() {
	run_lustre_ext4 $testname
	compare_report || error "$testname against lustre failed"
}
run_test $sub_t "$desc"
SUBTEST
done

cat << 'TAIL'
complete $SECONDS
check_and_cleanup_lustre
exit_status
TAIL
} > $TMP/run_pjdfstest.sh
bash $TMP/run_pjdfstest.sh

