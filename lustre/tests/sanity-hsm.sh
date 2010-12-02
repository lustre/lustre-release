#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# Run test by setting NOSETUP=true when ltest has setup env for us
#
# exit on error
set -e
set +o monitor

SRCDIR=`dirname $0`
export PATH=$PWD/$SRCDIR:$SRCDIR:$PWD/$SRCDIR/utils:$PATH:/sbin:/usr/sbin/

ONLY=${ONLY:-"$*"}
SANITY_HSM_EXCEPT=${SANITY_HSM_EXCEPT:-""}
ALWAYS_EXCEPT="$SANITY_HSM_EXCEPT"
# bug number for skipped test:
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

[ "$ALWAYS_EXCEPT$EXCEPT" ] &&
	echo "Skipping tests: `echo $ALWAYS_EXCEPT $EXCEPT`"

TMP=${TMP:-/tmp}

ORIG_PWD=${PWD}
MCREATE=${MCREATE:-mcreate}

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}

. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

SANITYLOG=${TESTSUITELOG:-$TMP/$(basename $0 .sh).log}
FAIL_ON_ERROR=false

[ "$SANITYLOG" ] && rm -f $SANITYLOG || true
check_and_setup_lustre

if [ $MDSCOUNT -ge 2 ]; then
	skip_env "Only run with single MDT for now" && exit
fi

if [ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.3.61) ]; then
	skip_env "Need MDS version at least 2.3.61" && exit
fi

DIR=${DIR:-$MOUNT}
assert_DIR

build_test_filter

# $RUNAS_ID may get set incorrectly somewhere else
[ $UID -eq 0 -a $RUNAS_ID -eq 0 ] &&
	error "\$RUNAS_ID set to 0, but \$UID is also 0!"

check_runas_id $RUNAS_ID $RUNAS_GID $RUNAS

copytool_cleanup() {
	# TODO: add copytool cleanup code here!
	return
}

copytool_setup() {
	rm -rf $HSM_ARCHIVE
	mkdir -p $HSM_ARCHIVE
}

fail() {
	copytool_cleanup
	error $*
}

export HSMTOOL=${HSMTOOL:-"lhsmtool_posix"}
export HSMTOOL_VERBOSE=${HSMTOOL_VERBOSE:-""}
HSM_ARCHIVE=${HSM_ARCHIVE:-$TMP/arc}
HSM_ARCHIVE_NUMBER=2

path2fid() {
	$LFS path2fid $1 | tr -d '[]'
}

make_small() {
	local file2=${1/$DIR/$DIR}
	dd if=/dev/urandom of=$file2 count=2 bs=1M
		path2fid $1
}

test_1() {
	mkdir -p $DIR/$tdir
	chmod 777 $DIR/$tdir

	TESTFILE=$DIR/$tdir/file
	$RUNAS touch $TESTFILE

	# User flags
	local state=$($RUNAS $LFS hsm_state $TESTFILE | cut -f 2 -d" ")
	[[ $state == "(0x00000000)" ]] ||
		error "wrong initial hsm state $state"

	$RUNAS $LFS hsm_set --norelease $TESTFILE ||
		error "user could not change hsm flags"
	state=$($RUNAS $LFS hsm_state $TESTFILE | cut -f 2 -d" ")
	[[ $state == "(0x00000010)" ]] ||
		error "wrong hsm state $state, should be: --norelease"

	$RUNAS $LFS hsm_clear --norelease $TESTFILE ||
		error "user could not clear hsm flags"
	state=$($RUNAS $LFS hsm_state $TESTFILE | cut -f 2 -d" ")
	[[ $state == "(0x00000000)" ]] ||
		error "wrong hsm state $state, should be empty"

	# User could not change those flags...
	$RUNAS $LFS hsm_set --exists $TESTFILE &&
		error "user should not set this flag"
	state=$($RUNAS $LFS hsm_state $TESTFILE | cut -f 2 -d" ")
	[[ $state == "(0x00000000)" ]] ||
		error "wrong hsm state $state, should be empty"

	# ...but root can
	$LFS hsm_set --exists $TESTFILE ||
		error "root could not change hsm flags"
	state=$($RUNAS $LFS hsm_state $TESTFILE | cut -f 2 -d" ")
	[[ $state == "(0x00000001)" ]] ||
		error "wrong hsm state $state, should be: --exists"

	$LFS hsm_clear --exists $TESTFILE ||
		error "root could not clear hsm state"
	state=$($RUNAS $LFS hsm_state $TESTFILE | cut -f 2 -d" ")
	[[ $state == "(0x00000000)" ]] ||
		error "wrong hsm state $state, should be empty"
}
run_test 1 "lfs hsm flags root/non-root access"

test_2() {
	mkdir -p $DIR/$tdir
	TESTFILE=$DIR/$tdir/file
	touch $TESTFILE

	# New files are not dirty
	local state=$($LFS hsm_state $TESTFILE | cut -f 2 -d" ")
	[[ $state == "(0x00000000)" ]] ||
		error "wrong hsm state $state, should be empty"

	# For test, we simulate an archived file.
	$LFS hsm_set --exists $TESTFILE || error "user could not change hsm flags"
	state=$($LFS hsm_state $TESTFILE | cut -f 2 -d" ")
	[[ $state == "(0x00000001)" ]] ||
		error "wrong hsm state $state, should be: --exists"

	# chmod do not put the file dirty
	chmod 600 $TESTFILE || error "could not chmod test file"
	state=$($LFS hsm_state $TESTFILE | cut -f 2 -d" ")
	[[ $state == "(0x00000001)" ]] ||
		error "wrong hsm state $state, should be: --exists"

	# chown do not put the file dirty
	chown $RUNAS_ID $TESTFILE || error "could not chown test file"
	state=$($LFS hsm_state $TESTFILE | cut -f 2 -d" ")
	[[ $state == "(0x00000001)" ]] ||
		error "wrong hsm state $state, should be: --exists"

	# truncate put the file dirty
	$TRUNCATE $TESTFILE 1 || error "could not truncate test file"
	state=$($LFS hsm_state $TESTFILE | cut -f 2 -d" ")
	[[ $state == "(0x00000003)" ]] ||
		error "wrong hsm state $state, should be 0x00000003"

	$LFS hsm_clear --dirty $TESTFILE || error "could not clear hsm flags"
	state=$($LFS hsm_state $TESTFILE | cut -f 2 -d" ")
	[[ $state == "(0x00000001)" ]] ||
		error "wrong hsm state $state, should be: --exists"
}
run_test 2 "Check file dirtyness when doing setattr"

test_3() {
	mkdir -p $DIR/$tdir
	TESTFILE=$DIR/$tdir/file

	# New files are not dirty
	cp -p /etc/passwd $TESTFILE
	local state=$($LFS hsm_state $TESTFILE | cut -f 2 -d" ")
	[[ $state == "(0x00000000)" ]] ||
		error "wrong hsm state $state, should be empty"

	# For test, we simulate an archived file.
	$LFS hsm_set --exists $TESTFILE ||
		error "user could not change hsm flags"
	state=$($LFS hsm_state $TESTFILE | cut -f 2 -d" ")
	[[ $state == "(0x00000001)" ]] ||
		error "wrong hsm state $state, should be: --exists"

	# Reading a file, does not set dirty
	cat $TESTFILE > /dev/null || error "could not read file"
	state=$($LFS hsm_state $TESTFILE | cut -f 2 -d" ")
	[[ $state == "(0x00000001)" ]] ||
		error "wrong hsm state $state, should be: --exists"

	# Open for write without modifying data, does not set dirty
	openfile -f O_WRONLY $TESTFILE || error "could not open test file"
	state=$($LFS hsm_state $TESTFILE | cut -f 2 -d" ")
	[[ $state == "(0x00000001)" ]] ||
		error "wrong hsm state $state, should be: --exists"

	# Append to a file sets it dirty
	cp -p /etc/passwd $TESTFILE.append || error "could not create file"
	$LFS hsm_set --exists $TESTFILE.append ||
		error "user could not change hsm flags"
	dd if=/etc/passwd of=$TESTFILE.append bs=1 count=3 \
	   conv=notrunc oflag=append status=noxfer ||
		error "could not append to test file"
	state=$($LFS hsm_state $TESTFILE.append | cut -f 2 -d" ")
	[[ $state == "(0x00000003)" ]] ||
		error "wrong hsm state $state, should be 0x00000003"

	# Modify a file sets it dirty
	cp -p /etc/passwd $TESTFILE.modify || error "could not create file"
	$LFS hsm_set --exists $TESTFILE.modify ||
		error "user could not change hsm flags"
	dd if=/dev/zero of=$TESTFILE.modify bs=1 count=3 \
	   conv=notrunc status=noxfer ||
		error "could not modify test file"
	state=$($LFS hsm_state $TESTFILE.modify | cut -f 2 -d" ")
	[[ $state == "(0x00000003)" ]] ||
		error "wrong hsm state $state, should be 0x00000003"

	# Open O_TRUNC sets dirty
	cp -p /etc/passwd $TESTFILE.trunc || error "could not create file"
	$LFS hsm_set --exists $TESTFILE.trunc ||
		error "user could not change hsm flags"
	cp /etc/group $TESTFILE.trunc || error "could not override a file"
	state=$($LFS hsm_state $TESTFILE.trunc | cut -f 2 -d" ")
	[[ $state == "(0x00000003)" ]] ||
		error "wrong hsm state $state, should be 0x00000003"

	# Mmapped a file sets dirty
	cp -p /etc/passwd $TESTFILE.mmap || error "could not create file"
	$LFS hsm_set --exists $TESTFILE.mmap ||
		error "user could not change hsm flags"
	multiop $TESTFILE.mmap OSMWUc || error "could not mmap a file"
	state=$($LFS hsm_state $TESTFILE.mmap | cut -f 2 -d" ")
	[[ $state == "(0x00000003)" ]] ||
		error "wrong hsm state $state, should be 0x00000003"
}
run_test 3 "Check file dirtyness when opening for write"

test_11() {
	mkdir -p $DIR/$tdir $HSM_ARCHIVE/$tdir
	cp /etc/hosts $HSM_ARCHIVE/$tdir/$tfile
	local f=$DIR/$tdir/$tfile
	$HSMTOOL $HSMTOOL_VERBOSE --archive $HSM_ARCHIVE_NUMBER \
		--hsm_root $HSM_ARCHIVE --import $tdir/$tfile $f $MOUNT ||
		error "import failed"
	echo -n "Verifying released state: "
	$LFS hsm_state $f
	$LFS hsm_state $f | grep -q "released exists archived" ||
		error "flags not set"
	local LSZ=$(stat -c "%s" $f)
	local ASZ=$(stat -c "%s" $HSM_ARCHIVE/$tdir/$tfile)
	echo "Verifying imported size $LSZ=$ASZ"
	[[ $LSZ -eq $ASZ ]] || error "Incorrect size $LSZ != $ASZ"
	echo -n "Verifying released pattern: "
	local PTRN=$($GETSTRIPE -L $f)
	echo $PTRN
	[[ $PTRN == 80000001 ]] || error "Is not released"
	local fid=$(path2fid $f)
	echo "Verifying new fid $fid in archive"
	local AFILE=$(ls $HSM_ARCHIVE/*/*/*/*/*/*/$fid) || \
		error "fid $fid not in archive $HSM_ARCHIVE"
}
run_test 11 "Import a file"

test_20() {
	mkdir -p $DIR/$tdir

	local f=$DIR/$tdir/sample
	touch $f

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
	copytool_setup

	mkdir -p $DIR/$tdir
	local f=$DIR/$tdir/test_release

	# Create a file and check its states
	local fid=$(make_small $f)
	$LFS hsm_state $f | grep -q " (0x00000000)" ||
		fail "wrong clean hsm state"

#	$LFS hsm_archive $f || fail "could not archive file"
#	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_set --archived --exist $f || fail "could not archive file"

	[ $(stat -c "%b" $f) -ne "0" ] || fail "wrong block number"
	local sz=$(stat -c "%s" $f)
	[ $sz -ne "0" ] || fail "file size should not be zero"

	# Release and check states
	$LFS hsm_release $f || fail "could not release file"
	$LFS hsm_state $f | grep -q " (0x0000000d)" ||
		fail "wrong released hsm state"
	[ $(stat -c "%b" $f) -eq "0" ] || fail "wrong block number"
	[ $(stat -c "%s" $f) -eq $sz ] || fail "wrong file size"

	# Check we can release an file without stripe info
	f=$f.nolov
	$MCREATE $f
	fid=$(path2fid $f)
	$LFS hsm_state $f | grep -q " (0x00000000)" ||
		fail "wrong clean hsm state"

#	$LFS hsm_archive $f || fail "could not archive file"
#	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_set --archived --exist $f || fail "could not archive file"

	# Release and check states
	$LFS hsm_release $f || fail "could not release file"
	$LFS hsm_state $f | grep -q " (0x0000000d)" ||
		fail "wrong released hsm state"

	# Release again a file that is already released is OK
	$LFS hsm_release $f || fail "second release should succeed"
	$LFS hsm_state $f | grep -q " (0x0000000d)" ||
		fail "wrong released hsm state"

	copytool_cleanup
}
run_test 21 "Simple release tests"

test_22() {
	# test needs a running copytool
	copytool_setup

	mkdir -p $DIR/$tdir

	local f=$DIR/$tdir/test_release
	local swap=$DIR/$tdir/test_swap

	# Create a file and check its states
	local fid=$(make_small $f)
	$LFS hsm_state $f | grep -q " (0x00000000)" ||
		fail "wrong clean hsm state"

#	$LFS hsm_archive $f || fail "could not archive file"
#	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_set --archived --exist $f || fail "could not archive file"

	# Release and check states
	$LFS hsm_release $f || fail "could not release file"
	$LFS hsm_state $f | grep -q " (0x0000000d)" ||
		fail "wrong released hsm state"

	make_small $swap || fail "could not create $swap"
	$LFS swap_layouts $swap $f && fail "swap_layouts should failed"

	true
	copytool_cleanup
}
run_test 22 "Could not swap a release file"


test_23() {
	# test needs a running copytool
	copytool_setup

	mkdir -p $DIR/$tdir

	local f=$DIR/$tdir/test_mtime

	# Create a file and check its states
	local fid=$(make_small $f)
	$LFS hsm_state $f | grep -q " (0x00000000)"  ||
		fail "wrong clean hsm state"

#	$LFS hsm_archive $f || fail "could not archive file"
#	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_set --archived --exist $f || fail "could not archive file"

	# Set modification time in the past
	touch -m -a -d @978261179 $f

	# Release and check states
	$LFS hsm_release $f || fail "could not release file"
	$LFS hsm_state $f | grep -q " (0x0000000d)" ||
		fail "wrong released hsm state"
	local MTIME=$(stat -c "%Y" $f)
	local ATIME=$(stat -c "%X" $f)
	[ $MTIME -eq "978261179" ] || fail "bad mtime: $MTIME"
	[ $ATIME -eq "978261179" ] || fail "bad atime: $ATIME"

	copytool_cleanup
}
run_test 23 "Release does not change a/mtime (utime)"

test_24() {
	# test needs a running copytool
	copytool_setup

	mkdir -p $DIR/$tdir

	local f=$DIR/$tdir/test_mtime

	# Create a file and check its states
	local fid=$(make_small $f)
	$LFS hsm_state $f | grep -q " (0x00000000)" ||
		fail "wrong clean hsm state"

	# ensure mtime is different
	sleep 1
	echo "append" >> $f
	local MTIME=$(stat -c "%Y" $f)
	local ATIME=$(stat -c "%X" $f)

#	$LFS hsm_archive $f || fail "could not archive file"
#	wait_request_state $fid ARCHIVE SUCCEED
	$LFS hsm_set --archived --exist $f || fail "could not archive file"

	# Release and check states
	$LFS hsm_release $f || fail "could not release file"
	$LFS hsm_state $f | grep -q " (0x0000000d)" ||
		fail "wrong released hsm state"

	[ "$(stat -c "%Y" $f)" -eq "$MTIME" ] ||
		fail "mtime should be $MTIME"

#	[ "$(stat -c "%X" $f)" -eq "$ATIME" ] ||
#		fail "atime should be $ATIME"

	copytool_cleanup
}
run_test 24 "Release does not change a/mtime (i/o)"

log "cleanup: ======================================================"
cd $ORIG_PWD
check_and_cleanup_lustre
echo '=========================== finished ==============================='
[ -f "$SANITYLOG" ] && cat $SANITYLOG && grep -q FAIL $SANITYLOG && exit 1 ||
	true
echo "$0: completed"
