#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
set -e

SRCDIR=$(dirname $0)
export PATH=$PWD/$SRCDIR:$SRCDIR:$PWD/$SRCDIR/../utils:$PATH:/sbin

ONLY=${ONLY:-"$*"}
# Bug number for skipped test:
ALWAYS_EXCEPT="$SANITY_PFL_EXCEPT"
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

[ "$ALWAYS_EXCEPT$EXCEPT" ] &&
	echo "Skipping tests: $ALWAYS_EXCEPT $EXCEPT"

TMP=${TMP:-/tmp}
CHECKSTAT=${CHECKSTAT:-"checkstat -v"}

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

check_and_setup_lustre

if [[ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.9.51) ]]; then
	skip_env "Need MDS version at least 2.9.51" && exit
fi

build_test_filter

[ $UID -eq 0 -a $RUNAS_ID -eq 0 ] &&
	error "\$RUNAS_ID set to 0, but \$UID is also 0!"
check_runas_id $RUNAS_ID $RUNAS_GID $RUNAS

test_0() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs" && return

	local comp_file=$DIR/$tfile
	local rw_len=$((3 * 1024 * 1024))	# 3M

	rm -f $comp_file

	$LFS setstripe -E 1m -S 1M -c 1 -E -1 -c 1 $comp_file ||
		error "Create $comp_file failed"

	local ost_idx1=$($LFS getstripe -I 1 -i $comp_file)
	local ost_idx2=$($LFS getstripe -I 2 -i $comp_file)

	[ $ost_idx1 -eq $ost_idx2 ] && error "$ost_idx1 == $ost_idx2"

	small_write $comp_file $rw_len || error "Verify RW failed"

	rm -f $comp_file || error "Delete $comp_file failed"
}
run_test 0 "Create full components file, no reused OSTs"

test_1() {
	local comp_file=$DIR/$tfile
	local rw_len=$((3 * 1024 * 1024))	# 3M

	rm -f $comp_file

	$LFS setstripe -E 1m -S 1m -o 0 -E -1 -o 0 $comp_file ||
		error "Create $comp_file failed"

	local ost_idx1=$($LFS getstripe -I 1 -i $comp_file)
	local ost_idx2=$($LFS getstripe -I 2 -i $comp_file)

	[ $ost_idx1 -ne $ost_idx2 ] && error "$ost_idx1 != $ost_idx2"

	small_write $comp_file $rw_len || error "Verify RW failed"

	rm -f $comp_file || error "Delete $comp_file failed"
}
run_test 1 "Create full components file, reused OSTs"

test_2() {
	local comp_file=$DIR/$tfile
	local rw_len=$((5 * 1024 * 1024))	# 5M

	rm -f $comp_file

	$LFS setstripe -E 1m -S 1m $comp_file ||
		error "Create $comp_file failed"

	local comp_cnt=$($LFS getstripe --component-count $comp_file)
	[ $comp_cnt -ne 1 ] && error "component count $comp_cnt != 1"

	dd if=/dev/zero of=$comp_file bs=1M count=1 > /dev/null 2>&1 ||
		error "Write first component failed"
	dd if=$comp_file of=/dev/null bs=1M count=1 > /dev/null 2>&1 ||
		error "Read first component failed"

	dd if=/dev/zero of=$comp_file bs=1M count=2 > /dev/null 2>&1 &&
		error "Write beyond component should fail"
	dd if=$comp_file of=/dev/null bs=1M count=2 > /dev/null 2>&1 &&
		error "Read beyond component should fail"

	$LFS setstripe --component-add -E 2M -c 1 $comp_file ||
		error "Add component to $comp_file failed"

	comp_cnt=$($LFS getstripe --component-count $comp_file)
	[ $comp_cnt -ne 2 ] && error "component count $comp_cnt != 2"

	$LFS setstripe --component-add -E -1 -c 3 $comp_file ||
		error "Add last component to $comp_file failed"

	comp_cnt=$($LFS getstripe --component-count $comp_file)
	[ $comp_cnt -ne 3 ] && error "component count $comp_cnt != 3"

	small_write $comp_file $rw_len || error "Verify RW failed"

	rm -f $comp_file || error "Delete $comp_file failed"
}
run_test 2 "Add component to existing file"

del_comp_and_verify() {
	local comp_file=$1
	local id=$2
	local left=$3
	local size=$4

	local opt="-I"
	if [ $id == "init" ]; then
		opt="--component-flags"
	fi

	$LFS setstripe --component-del $opt $id $comp_file ||
		error "Delete component $id from $comp_file failed"

	local comp_cnt=$($LFS getstripe --component-count $comp_file)
	if grep -q "has no stripe info" <<< "$comp_cnt" ; then
		comp_cnt=0
	fi
	[ $comp_cnt -ne $left ] && error "$comp_cnt != $left"

	$CHECKSTAT -s $size $comp_file || error "size != $size"
}

test_3() {
	local comp_file=$DIR/$tfile

	rm -f $comp_file

	$LFS setstripe -E 1M -E 64M -c 2 -E -1 -c 3 $comp_file ||
		error "Create $comp_file failed"

	local comp_cnt=$($LFS getstripe --component-count $comp_file)
	[ $comp_cnt -ne 3 ] && error "component count $comp_cnt != 3"

	dd if=/dev/zero of=$comp_file bs=1M count=2

	$LFS setstripe --component-del -I 2 $comp_file &&
		error "Component deletion makes hole"

	del_comp_and_verify $comp_file 3 2 $((2 * 1024 * 1024))
	del_comp_and_verify $comp_file 2 1 $((1 * 1024 * 1024))
	del_comp_and_verify $comp_file 1 0 0

	rm -f $comp_file || error "Delete $comp_file failed"

	$LFS setstripe -E 1M -E 16M -E -1 $comp_file ||
		error "Create second $comp_file failed"

	del_comp_and_verify $comp_file "init" 0 0
	rm -f $comp_file || error "Delete second $comp_file failed"
}
run_test 3 "Delete component from existing file"

test_4() {
	skip "Not supported in PFL" && return
	# In PFL project, only LCME_FL_INIT is supported, and it can't
	# be altered by application.
}
run_test 4 "Modify component flags in existing file"

test_5() {
	local parent=$DIR/$tdir
	local comp_file=$DIR/$tdir/$tfile
	local subdir=$parent/subdir

	rm -fr $parent
	mkdir -p $parent || error "Create dir $parent failed"

	# set default layout to parent directory
	$LFS setstripe -E 64M -c 2 -i 0 -E -1 -c 4 -i 0 $parent ||
		error "Set default layout to $parent failed"

	# create file under parent
	touch $comp_file || error "Create $comp_file failed"
	local comp_cnt=$($LFS getstripe --component-count $comp_file)
	[ $comp_cnt -ne 2 ] && error "file $comp_cnt != 2"

	local ost_idx=$($LFS getstripe -I 1 -i $comp_file)
	[ $ost_idx -ne 0 ] &&
		error "component 1 ost_idx $ost_idx != 0"

	ost_idx=$($LFS getstripe -I 2 -i $comp_file)
	[ $ost_idx -ne 0 ] &&
		error "component 2 ost_idx $ost_idx != 0"

	# create subdir under parent
	mkdir -p $subdir || error "Create subdir $subdir failed"

	comp_cnt=$($LFS getstripe -d --component-count $subdir)
	[ $comp_cnt -ne 2 ] && error "subdir $comp_cnt != 2"

	# create file under subdir
	touch $subdir/$tfile || error "Create $subdir/$tfile failed"

	comp_cnt=$($LFS getstripe --component-count $subdir/$tfile)
	[ $comp_cnt -ne 2 ] && error "$subdir/$tfile $comp_cnt != 2"

	# delete default layout setting from parent
	$LFS setstripe -d $parent ||
		error "Delete default layout from $parent failed"

	comp_cnt=$($LFS getstripe -d --component-count $parent)
	[ ! -z "$comp_cnt" ] && error "$comp_cnt isn't empty"

	rm -f $comp_file || error "Delete $comp_file failed"
	rm -f $subdir/$tfile || error "Delete $subdir/$tfile failed"
	rm -r $subdir || error "Delete subdir $subdir failed"
	rmdir $parent || error "Delete dir $parent failed"
}
run_test 5 "Inherit composite layout from parent directory"

test_6() {
	local comp_file=$DIR/$tfile

	rm -f $DIR/$tfile

	$LFS setstripe -c 1 -S 128K $comp_file ||
		error "Create v1 $comp_file failed"

	local comp_cnt=$($LFS getstripe --component-count $comp_file)
	[ ! -z "$comp_cnt" ] && error "Wrong component count $comp_cnt"

	dd if=/dev/urandom of=$comp_file bs=1M count=5 oflag=sync ||
		error "Write to v1 $comp_file failed"

	local old_chksum=$(md5sum $comp_file)

	# Migrate v1 to composite
	$LFS migrate -E 1M -S 512K -c 1 -E -1 -S 1M -c 2 $comp_file ||
		error "Migrate(v1 -> composite) $comp_file failed"

	comp_cnt=$($LFS getstripe --component-count $comp_file)
	[ "$comp_cnt" -ne 2 ] && error "$comp_cnt != 2"

	local chksum=$(md5sum $comp_file)
	[ "$old_chksum" != "$chksum" ] &&
		error "(v1 -> compsoite) $old_chksum != $chksum"

	# Migrate composite to composite
	$LFS migrate -E 1M -S 1M -c 2 -E 4M -S 1M -c 2 \
		-E -1 -S 3M -c 3 $comp_file ||
		error "Migrate(compsoite -> composite) $comp_file failed"

	comp_cnt=$($LFS getstripe --component-count $comp_file)
	[ "$comp_cnt" -ne 3 ] && error "$comp_cnt != 3"

	chksum=$(md5sum $comp_file)
	[ "$old_chksum" != "$chksum" ] &&
		error "(composite -> compsoite) $old_chksum != $chksum"

	# Migrate composite to v1
	$LFS migrate -c 2 -S 2M $comp_file ||
		error "Migrate(composite -> v1) $comp_file failed"

	comp_cnt=$($LFS getstripe --component-count $comp_file)
	[ ! -z "$comp_cnt" ] && error "$comp_cnt isn't empty"

	chksum=$(md5sum $comp_file)
	[ "$old_chksum" != "$chksum" ] &&
		error "(composite -> v1) $old_chksum != $chksum"

	rm -f $comp_file || "Delete $comp_file failed"
}
run_test 6 "Migrate composite file"

test_7() {
	mkdir -p $DIR/$tdir || error "mkdir failed"
	chmod 0777 $DIR/$tdir || error "chmod $tdir failed"

	local comp_file=$DIR/$tdir/$tfile
	$RUNAS $LFS setstripe -E 1M -c 1 $comp_file ||
		error "Create composite file $comp_file failed"

	$RUNAS $LFS setstripe --component-add -E 64M -c 4 $comp_file ||
		error "Add component to $comp_file failed"

	$RUNAS $LFS setstripe --component-del -I 2 $comp_file ||
		error "Delete component from $comp_file failed"

	$RUNAS $LFS setstripe --component-add -E -1 -c 5 $comp_file ||
		error "Add last component to $comp_file failed"

	rm $comp_file || "Delete composite failed"
}
run_test 7 "Add/Delete/Create composite file by non-privileged user"

test_8() {
	local parent=$DIR/$tdir

	rm -fr $parent
	mkdir -p $parent || error "Create dir $parent failed"

	$LFS setstripe -E 2M -c 1 -S 1M -E 16M -c 2 -S 2M \
		-E -1 -c 4 -S 4M $parent ||
		error "Set default layout to $parent failed"

	sh rundbench -C -D $parent 2 || error "debench failed"

	rm -fr $parent || error "Delete dir $parent failed"
}
run_test 8 "Run debench over composite files"

test_9() {
	local comp_file=$DIR/$tfile

	rm -f $comp_file

	$LFS setstripe -E 1m -S 1m $comp_file ||
		error "Create $comp_file failed"

	local comp_cnt=$($LFS getstripe --component-count $comp_file)
	[ $comp_cnt -ne 1 ] && error "component count $comp_cnt != 1"

	replay_barrier $SINGLEMDS

	$LFS setstripe --component-add -E 2M -c 1 $comp_file ||
		error "Add component to $comp_file failed"

	local f1=$($LFS getstripe -I 2 $comp_file |
			awk '/l_fid:/ {print $7}')

	fail $SINGLEMDS

	local f2=$($LFS getstripe -I 2 $comp_file |
			awk '/l_fid:/ {print $7}')
	[ $f1 == $f2 ] || error "$f1 != $f2"
}
run_test 9 "Replay component add"

component_dump() {
	echo $($LFS getstripe $1 |
		awk '$1 == "lcm_entry_count:" { printf("%d", $2) }
		     $1 == "lcme_extent.e_start:" { printf("[%#lx", $2) }
		     $1 == "lcme_extent.e_end:" { printf(",%s]", $2) }')
}

test_10() {
	local parent=$DIR/$tdir

	rm -rf $parent
	$LFS setstripe -d $MOUNT || error "clear root layout"

	# set root composite layout
	$LFS setstripe -E 2M -c 1 -S 1M -E 16M -c2 -S 2M \
		-E -1 -c 4 -S 4M $MOUNT ||
		error "Set root layout failed"

	mkdir -p $parent || error "Create dir $parent failed"
	# set a different layout for parent
	$LFS setstripe -E -1 -c 1 -S 1M $parent ||
		error "set $parent layout failed"
	touch $parent/file1

	local f1_entry=$(component_dump $parent/file1)

	# delete parent's layout
	$LFS setstripe -d $parent || error "Clear $parent layout failed"
	touch $parent/file2

	local f2_entry=$(component_dump $parent/file2)

	# verify layout inheritance
	local eof="EOF"
	local f1_expect="1[0,EOF]"
	local f2_expect="3[0,2097152][0x200000,16777216][0x1000000,EOF]"

	echo "f1 expect=$f1_expect"
	echo "f1 get   =$f1_entry"
	echo "f2 expect=$f2_expect"
	echo "f2 get   =$f2_entry"

	[  x$f1_expect != x$f1_entry ] &&
		error "$parent/file1 does not inherite parent layout"
	[  x$f2_expect != x$f2_entry ] &&
		error "$parent/file2 does not inherite root layout"
	return 0
}
run_test 10 "Inherit composite template from root"

complete $SECONDS
check_and_cleanup_lustre
exit_status
