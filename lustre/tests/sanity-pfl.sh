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

	local comp_file=$DIR/$tdir/$tfile
	local rw_len=$((3 * 1024 * 1024))	# 3M

	test_mkdir $DIR/$tdir
	rm -f $comp_file

	$LFS setstripe -E 1m -S 1M -c 1 -E -1 -c 1 $comp_file ||
		error "Create $comp_file failed"

	#instantiate all components, so that objs are allocted
	dd if=/dev/zero of=$comp_file bs=1k count=1 seek=2k

	local ost_idx1=$($LFS getstripe -I1 -i $comp_file)
	local ost_idx2=$($LFS getstripe -I2 -i $comp_file)

	[ $ost_idx1 -eq $ost_idx2 ] && error "$ost_idx1 == $ost_idx2"

	small_write $comp_file $rw_len || error "Verify RW failed"

	rm -f $comp_file || error "Delete $comp_file failed"
}
run_test 0 "Create full components file, no reused OSTs"

test_1() {
	local comp_file=$DIR/$tdir/$tfile
	local rw_len=$((3 * 1024 * 1024))	# 3M

	test_mkdir $DIR/$tdir
	rm -f $comp_file

	$LFS setstripe -E 1m -S 1m -o 0 -E -1 -o 0 $comp_file ||
		error "Create $comp_file failed"

	#instantiate all components, so that objs are allocted
	dd if=/dev/zero of=$comp_file bs=1k count=1 seek=2k

	local ost_idx1=$($LFS getstripe -I1 -i $comp_file)
	local ost_idx2=$($LFS getstripe -I2 -i $comp_file)

	[ $ost_idx1 -ne $ost_idx2 ] && error "$ost_idx1 != $ost_idx2"

	small_write $comp_file $rw_len || error "Verify RW failed"

	rm -f $comp_file || error "Delete $comp_file failed"
}
run_test 1 "Create full components file, reused OSTs"

test_2() {
	local comp_file=$DIR/$tdir/$tfile
	local rw_len=$((5 * 1024 * 1024))	# 5M

	test_mkdir $DIR/$tdir
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
	dd if=$comp_file of=/dev/null bs=1M count=2 > /dev/null 2>&1 ||
		error "Read beyond component should short read, not fail"

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

	local opt="-I "
	if [ $id == "init" -o $id == "^init" ]; then
		opt="--component-flags="
	fi

	$LFS setstripe --component-del $opt$id $comp_file ||
		error "Delete component $id from $comp_file failed"

	local comp_cnt=$($LFS getstripe --component-count $comp_file)
	if grep -q "has no stripe info" <<< "$comp_cnt" ; then
		comp_cnt=0
	fi
	[ $comp_cnt -ne $left ] && error "$comp_cnt != $left"

	$CHECKSTAT -s $size $comp_file || error "size != $size"
}

test_3() {
	local comp_file=$DIR/$tdir/$tfile

	test_mkdir $DIR/$tdir
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

	del_comp_and_verify $comp_file "^init" 1 0
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
	test_mkdir $parent || error "Create dir $parent failed"

	# set default layout to parent directory
	$LFS setstripe -E 64M -c 2 -i 0 -E -1 -c 4 -i 0 $parent ||
		error "Set default layout to $parent failed"

	# create file under parent
	touch $comp_file || error "Create $comp_file failed"
	local comp_cnt=$($LFS getstripe --component-count $comp_file)
	[ $comp_cnt -ne 2 ] && error "file $comp_cnt != 2"

	#instantiate all components, so that objs are allocted
	dd if=/dev/zero of=$comp_file bs=1k count=1 seek=65k

	local ost_idx=$($LFS getstripe -I1 -i $comp_file)
	[ $ost_idx -ne 0 ] &&
		error "component 1 ost_idx $ost_idx != 0"

	ost_idx=$($LFS getstripe -I2 -i $comp_file)
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
	[ $comp_cnt -ne 0 ] && error "$comp_cnt isn't 0"

	rm -f $comp_file || error "Delete $comp_file failed"
	rm -f $subdir/$tfile || error "Delete $subdir/$tfile failed"
	rm -r $subdir || error "Delete subdir $subdir failed"
	rmdir $parent || error "Delete dir $parent failed"
}
run_test 5 "Inherit composite layout from parent directory"

test_6() {
	local comp_file=$DIR/$tdir/$tfile

	test_mkdir $DIR/$tdir
	rm -f $DIR/$tfile

	$LFS setstripe -c 1 -S 128K $comp_file ||
		error "Create v1 $comp_file failed"

	local comp_cnt=$($LFS getstripe --component-count $comp_file)
	[ $comp_cnt -ne 0 ] && error "Wrong component count $comp_cnt"

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
	[ $comp_cnt -ne 0 ] && error "$comp_cnt isn't 0"

	chksum=$(md5sum $comp_file)
	[ "$old_chksum" != "$chksum" ] &&
		error "(composite -> v1) $old_chksum != $chksum"

	rm -f $comp_file || "Delete $comp_file failed"
}
run_test 6 "Migrate composite file"

test_7() {
	test_mkdir -p $DIR/$tdir || error "mkdir failed"
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
	test_mkdir -p $parent || error "Create dir $parent failed"

	$LFS setstripe -E 2M -c 1 -S 1M -E 16M -c 2 -S 2M \
		-E -1 -c 4 -S 4M $parent ||
		error "Set default layout to $parent failed"

	sh rundbench -C -D $parent 2 || error "dbench failed"

	rm -fr $parent || error "Delete dir $parent failed"
}
run_test 8 "Run dbench over composite files"

test_9() {
	local comp_file=$DIR/$tdir/$tfile

	test_mkdir $DIR/$tdir
	rm -f $comp_file

	$LFS setstripe -E 1m -S 1m -E 2M -c 1 $comp_file ||
		error "Create $comp_file failed"

	local comp_cnt=$($LFS getstripe --component-count $comp_file)
	[ $comp_cnt -ne 2 ] && error "component count $comp_cnt != 2"

	replay_barrier $SINGLEMDS

	# instantiate the 2nd component
	dd if=/dev/zero of=$comp_file bs=1k count=1 seek=2k

	local f1=$($LFS getstripe -I2 $comp_file |
			awk '/l_fid:/ {print $7}')
	echo "before MDS recovery, the ost fid of 2nd component is $f1"
	fail $SINGLEMDS

	local f2=$($LFS getstripe -I2 $comp_file |
			awk '/l_fid:/ {print $7}')
	echo "after MDS recovery, the ost fid of 2nd component is $f2"
	[ "x$f1" == "x$f2" ] || error "$f1 != $f2"
}
run_test 9 "Replay layout extend object instantiation"

component_dump() {
	echo $($LFS getstripe $1 |
		awk '$1 == "lcm_entry_count:" { printf("%d", $2) }
		     $1 == "lcme_extent.e_start:" { printf("[%#lx", $2) }
		     $1 == "lcme_extent.e_end:" { printf(",%s]", $2) }')
}

test_10() {
	local parent=$DIR/$tdir
	local root_layout=$(get_layout_param $MOUNT)

	rm -rf $parent
	$LFS setstripe -d $MOUNT || error "clear root layout"

	# set root composite layout
	$LFS setstripe -E 2M -c 1 -S 1M -E 16M -c2 -S 2M \
		-E -1 -c 4 -S 4M $MOUNT ||
		error "Set root layout failed"

	test_mkdir -p $parent || error "Create dir $parent failed"
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

	$LFS setstripe $root_layout $MOUNT
	return 0
}
run_test 10 "Inherit composite template from root"

test_11() {
	local comp_file=$DIR/$tdir/$tfile
	test_mkdir $DIR/$tdir
	rm -f $comp_file

	# only 1st component instantiated
	$LFS setstripe -E 1m -E 2m -E 3m -E -1 $comp_file ||
		error "Create $comp_file failed"

	local f1=$($LFS getstripe -I1 $comp_file | grep "l_fid")
	[[ -z $f1 ]] && error "1: 1st component uninstantiated"
	local f2=$($LFS getstripe -I2 $comp_file | grep "l_fid")
	[[ -n $f2 ]] && error "1: 2nd component instantiated"
	local f3=$($LFS getstripe -I3 $comp_file | grep "l_fid")
	[[ -n $f3 ]] && error "1: 3rd component instantiated"
	local f4=$($LFS getstripe -I4 $comp_file | grep "l_fid")
	[[ -n $f4 ]] && error "1: 4th component instantiated"

	# the first 2 components instantiated
	$TRUNCATE $comp_file $((1024*1024*1+1))

	f2=$($LFS getstripe -I2 $comp_file | grep "l_fid")
	[[ -z $f2 ]] && error "2: 2nd component uninstantiated"
	f3=$($LFS getstripe -I3 $comp_file | grep "l_fid")
	[[ -n $f3 ]] && error "2: 3rd component instantiated"
	f4=$($LFS getstripe -I4 $comp_file | grep "l_fid")
	[[ -n $f4 ]] && error "2: 4th component instantiated"

	# the first 3 components instantiated
	$TRUNCATE $comp_file $((1024*1024*3))
	$TRUNCATE $comp_file $((1024*1024*1+1))

	f2=$($LFS getstripe -I2 $comp_file | grep "l_fid")
	[[ -z $f2 ]] && error "2: 2nd component uninstantiated"
	f3=$($LFS getstripe -I3 $comp_file | grep "l_fid")
	[[ -z $f3 ]] && error "3: 3rd component uninstantiated"
	f4=$($LFS getstripe -I4 $comp_file | grep "l_fid")
	[[ -n $f4 ]] && error "3: 4th component instantiated"

	# all 4 components instantiated, using append write
	dd if=/dev/zero of=$comp_file bs=1k count=1 seek=2k
	ls -l $comp_file
	rwv -f $comp_file -w -a -n 2 $((1024*1023)) 1
	ls -l $comp_file

	f4=$($LFS getstripe -I4 $comp_file | grep "l_fid")
	[[ -z $f4 ]] && error "4: 4th component uninstantiated"

	return 0
}
run_test 11 "Verify component instantiation with write/truncate"

test_12() {
	[ $OSTCOUNT -lt 3 ] && skip "needs >= 3 OSTs" && return

	local file=$DIR/$tdir/$tfile
	test_mkdir $DIR/$tdir
	rm -f $file

	# specify ost list for component
	$LFS setstripe -E1m -c2 -o0,1 -E2m -c2 -o1,2 -E3m -c2 -o2,1 \
		-E4m -c1 -i2 -E-1 $file ||
		error "Create $file failed"

	# clear lod component cache
	stop $SINGLEMDS || error "stop MDS"
	local MDT_DEV=$(mdsdevname ${SINGLEMDS//mds/})
	start $SINGLEMDS $MDT_DEV $MDS_MOUNT_OPTS || error "start MDS"

	# instantiate all components
	$TRUNCATE $file $((1024*1024*4+1))

	#verify object alloc order
	local o1=$($LFS getstripe -I1 $file |
			awk '/l_ost_idx:/ {printf("%d",$5)}')
	[[ $o1 != "01" ]] && error "$o1 is not 01"

	local o2=$($LFS getstripe -I2 $file |
			awk '/l_ost_idx:/ {printf("%d",$5)}')
	[[ $o2 != "12" ]] && error "$o2 is not 12"

	local o3=$($LFS getstripe -I3 $file |
			awk '/l_ost_idx:/ {printf("%d",$5)}')
	[[ $o3 != "21" ]] && error "$o3 is not 21"

	local o4=$($LFS getstripe -I4 $file |
			awk '/l_ost_idx:/ {printf("%d",$5)}')
	[[ $o4 != "2" ]] && error "$o4 is not 2"

	return 0
}
run_test 12 "Verify ost list specification"

test_13() { # LU-9311
	[ $OSTCOUNT -lt 8 ] && skip "needs >= 8 OSTs" && return

	local file=$DIR/$tfile
	local dd_count=4
	local dd_size=$(($dd_count * 1024 * 1024))
	local real_size

	rm -f $file
	$LFS setstripe -E 1M -c 1 -E 2M -c 2 -E -1 -c -1 -i 1 $file ||
		error "Create $file failed"
	dd if=/dev/zero of=$file bs=1M count=$dd_count
	real_size=$(stat -c %s $file)
	[ $real_size -eq $dd_size ] ||
		error "dd actually wrote $real_size != $dd_size bytes"

	rm -f $file
}
run_test 13 "shouldn't reprocess granted resent request"

test_14() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs" && return
	local file=$DIR/$tdir/$tfile
	test_mkdir -p $DIR/$tdir
	rm -f $file

	$LFS setstripe -E1m -c1 -S1m --pool="pool1" -E2m \
			-E4m -c2 -S2m --pool="pool2" -E-1 $file ||
		error "Create $file failed"

	# check --pool inheritance
	local pool
	pool="$($LFS getstripe -I2 --pool $file)"
	[ x"$pool" != "xpool1" ] && $LFS getstripe -I2 $file &&
		error "$file: component 2 doesn't have poolname pool1"
	pool="$($LFS getstripe -I4 --pool $file)"
	[ x"$pool" != "xpool2" ] && $LFS getstripe -I4 $file &&
		error "$file: component 4 doesn't have poolname pool2"

	#check --stripe-count inheritance
	local count
	count="$($LFS getstripe -I2 -c $file)"
	[ $count -ne 1 ] && $LFS getstripe -I2 $file &&
		error "$file: component 2 doesn't have 1 stripe_count"
	count="$($LFS getstripe -I4 -c $file)"
	[ $count -ne 2 ] && $LFS getstripe -I4 $file &&
		error "$file: component 4 doesn't have 2 stripe_count"

	#check --stripe-size inheritance
	local size
	size="$($LFS getstripe -I2 -S $file)"
	[ $size -ne $((1024*1024)) ] && $LFS getstripe -I2 $file &&
		error "$file: component 2 doesn't have 1M stripe_size"
	size="$($LFS getstripe -I4 -S $file)"
	[ $size -ne $((1024*1024*2)) ] && $LFS getstripe -I4 $file &&
		error "$file: component 4 doesn't have 2M stripe_size"

	return 0
}
run_test 14 "Verify setstripe poolname/stripe_count/stripe_size inheritance"

test_15() {
	local parent=$DIR/$tdir

	rm -fr $parent
	test_mkdir $parent || error "Create dir $parent failed"

	$LFS setstripe -d $parent || error "delete default layout"

	$LFS setstripe -E 1M -E 10M -E eof $parent/f1 || error "create f1"
	$LFS setstripe -E 4M -E 20M -E eof $parent/f2 || error "create f2"
	test_mkdir $parent/subdir || error "create subdir"
	$LFS setstripe -E 6M -E 30M -E eof $parent/subdir ||
		error "setstripe to subdir"
	$LFS setstripe -E 8M -E eof $parent/subdir/f3 || error "create f3"
	$LFS setstripe -c 1 $parent/subdir/f4 || error "create f4"

	# none
	local found=$($LFS find --component-start +2M -E -15M $parent | wc -l)
	[ $found -eq 0 ] || error "start+2M, end-15M, $found != 0"

	# f2, f3
	found=$($LFS find --component-start +2M -E -35M $parent | wc -l)
	[ $found -eq 2 ] || error "start+2M, end-35M, $found != 2"

	# subdir
	found=$($LFS find --component-start +4M -E -eof $parent | wc -l)
	[ $found -eq 1 ] || error "start+4M, end-eof, $found != 1"

	local flg_opts="--component-flags init"
	# none
	found=$($LFS find --component-start 1M -E 10M $flg_opts $parent | wc -l)
	[ $found -eq 0 ] ||
		error "before write: start=1M, end=10M, flag=init, $found != 0"

	dd if=/dev/zero of=$parent/f1 bs=1M count=2 ||
		error "dd $parent/f1 failed"

	# f1
	found=$($LFS find --component-start 1M -E 10M $flg_opts $parent | wc -l)
	[ $found -eq 1 ] ||
		error "after write: start=1M, end=10M, flag=init, $found != 1"

	local ext_opts="--component-start -1M -E +5M"
	# parent, subdir, f3, f4
	found=$($LFS find $ext_opts $parent | wc -l)
	[ $found -eq 4 ] || error "start-1M, end+5M, $found != 4"

	local cnt_opts="--component-count +2"
	# subdir
	found=$($LFS find $ext_opts $cnt_opts $parent | wc -l)
	[ $found -eq 1 ] || error "start-1M, end+5M, count+2, $found != 1"

	# none
	found=$($LFS find $ext_opts $cnt_opts $flg_opts $parent | wc -l)
	[ $found -eq 0 ] ||
		error "start-1M, end+5M, count+2, flag=init, $found != 0"

	# f3, f4
	found=$($LFS find $ext_opts ! $cnt_opts $flg_opts $parent | wc -l)
	[ $found -eq 2 ] ||
		error "start-1M, end+5M, !count+2, flag=init, $found != 2"
}
run_test 15 "Verify component options for lfs find"

test_17() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs" && return
	local file=$DIR/$tdir/$tfile
	test_mkdir -p $DIR/$tdir
	rm -f $file

	$LFS setstripe -E1m -E2m -c2 -E-1 -c-1 $file ||
		error "Create $file failed"

	local s1=$($LFS getstripe -I1 -v $file | awk '/lcme_size:/{print $2}')
	local s2=$($LFS getstripe -I2 -v $file | awk '/lcme_size:/{print $2}')
	local s3=$($LFS getstripe -I3 -v $file | awk '/lcme_size:/{print $2}')
	echo "1st init: comp size 1:$s1 2:$s2 3:$s3"

	# init 2nd component
	$TRUNCATE $file $((1024*1024+1))
	local s1n=$($LFS getstripe -I1 -v $file | awk '/lcme_size:/{print $2}')
	local s2n=$($LFS getstripe -I2 -v $file | awk '/lcme_size:/{print $2}')
	echo "2nd init: comp size 1:$s1n 2:$s2n 3:$s3"

	[ $s1 -eq $s1n ] || error "1st comp size $s1 should == $s1n"
	[ $s2 -lt $s2n ] || error "2nd comp size $s2 should < $s2n"

	# init 3rd component
	$TRUNCATE $file $((1024*1024*2+1))
	s1n=$($LFS getstripe -I1 -v $file | awk '/lcme_size:/{print $2}')
	s2n=$($LFS getstripe -I2 -v $file | awk '/lcme_size:/{print $2}')
	local s3n=$($LFS getstripe -I3 -v $file | awk '/lcme_size:/{print $2}')
	echo "3rd init: comp size 1:$s1n 2:$s2n 3:$s3n"

	[ $s1 -eq $s1n ] || error "1st comp size $s1 should == $s1n"
	[ $s2 -lt $s2n ] || error "2nd comp size $s2 should < $s2n"
	[ $s3 -lt $s3n ] || error "3rd comp size $s3 should < $s3n"
}
run_test 17 "Verify LOVEA grows with more component inited"

complete $SECONDS
check_and_cleanup_lustre
exit_status
