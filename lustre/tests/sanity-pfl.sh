#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
set -e

ONLY=${ONLY:-"$*"}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
init_logging

# bug number for skipped test:
ALWAYS_EXCEPT="$SANITY_PFL_EXCEPT "
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

# Skip tests for PPC that fail frequently
if [[ $(uname -m) = ppc64 ]]; then
	# bug number:    LU-13186 LU-13205 LU-13207 LU-13186
	ALWAYS_EXCEPT+=" 14       16a      16b      17"
fi

if [[ "$ost1_FSTYPE" == "zfs" ]]; then
	# bug #:	LU-1941
	ALWAYS_EXCEPT+="24a"
fi
build_test_filter

check_and_setup_lustre

if [[ "$MDS1_VERSION" -lt $(version_code 2.9.51) ]]; then
	skip_env "Need MDS version at least 2.9.51"
fi

[ $UID -eq 0 -a $RUNAS_ID -eq 0 ] &&
	error "\$RUNAS_ID set to 0, but \$UID is also 0!"
check_runas_id $RUNAS_ID $RUNAS_GID $RUNAS

assert_DIR
rm -rf $DIR/[Rdfs][0-9]*

test_0a() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"

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
run_test 0a "Create full components file, no reused OSTs"

test_0b() {
	[[ $($LCTL get_param mdc.*.import |
		grep "connect_flags:.*overstriping") ]] ||
		skip "server does not support overstriping"
	large_xattr_enabled || skip_env "no large xattr support"

	local comp_file=$DIR/$tdir/$tfile

	test_mkdir $DIR/$tdir

	$LFS setstripe -E -1 -C $LOV_MAX_STRIPE_COUNT $comp_file ||
		error "Create $comp_file failed"

	local count=$($LFS getstripe -I1 -c $comp_file)
	[ $count -eq $LOV_MAX_STRIPE_COUNT ] ||
		error "stripe count of first component is shrinked to $count"

	rm -f $comp_file || error "Delete $comp_file failed"

	# Create file with 1.1*LOV_MAX_STRIPE_COUNT stripes should succeed
	$LFS setstripe -E 1m -C $((LOV_MAX_STRIPE_COUNT / 10)) -E -1 \
		-C $LOV_MAX_STRIPE_COUNT $comp_file ||
		error "Create $comp_file failed"

	local count=$($LFS getstripe -I2 -c $comp_file)
	[ $count -eq $LOV_MAX_STRIPE_COUNT ] ||
		error "stripe count of second component is shrinked to $count"

	rm -f $comp_file || error "Delete $comp_file failed"

	# Create file with 3*LOV_MAX_STRIPE_COUNT stripes should fail
	$LFS setstripe -E 200G -C $LOV_MAX_STRIPE_COUNT \
		-E 500G -C $LOV_MAX_STRIPE_COUNT \
		-E -1 -C $LOV_MAX_STRIPE_COUNT $comp_file &&
		error "Create $comp_file succeeded"

	rm -f $comp_file || error "Delete $comp_file failed"
}
run_test 0b "Verify comp stripe count limits"

test_0c() {
	[[ $($LCTL get_param mdc.*.import |
		grep "connect_flags:.*overstriping") ]] ||
		skip "server does not support overstriping"
	[ $(lustre_version_code $SINGLEMDS) -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	large_xattr_enabled || skip_env "no large xattr support"

	local comp_file=$DIR/$tdir/$tfile

	test_mkdir $DIR/$tdir

	$LFS setstripe -E -1 -C $LOV_MAX_STRIPE_COUNT -z 128M $comp_file ||
		error "Create $comp_file failed"

	local count=$($LFS getstripe -I1 -c $comp_file)
	[ $count -eq $LOV_MAX_STRIPE_COUNT ] ||
		error "stripe count is shrinked to $count"
}
run_test 0c "Verify SEL comp stripe count limits"

test_0d() {
	local td=$DIR/$tdir
	local tf=$td/$tfile
	local comp_end
	local stripe_size

	# Create parent directory
	test_mkdir $td

	# Component end must be a multiple of stripe size
	# and a multiple of 64KiB to align with the minimum
	# stripe size value.
	# Values below 4096 are assumed to be in KiB units.
	$LFS setstripe -E 127 $tf-1 > /dev/null 2>&1 &&
		error "creating $tf-1 with '-E 127' should fail"

	$LFS setstripe -E 128 -S 512 $tf-1 > /dev/null 2>&1 &&
		error "creating $tf-1 with '-E 128 -S 512' should fail"

	$LFS setstripe -E 128 $tf-1 ||
		error "creating $tf-1 failed"

	yes | dd bs=1K count=129 iflag=fullblock of=$tf-1 &&
		error "writing to $tf-1 should fail"

	yes | dd bs=1K count=128 iflag=fullblock of=$tf-1 ||
		error "writing to $tf-1 failed"

	comp_end=$($LFS getstripe -I1 -E $tf-1)
	stripe_size=$($LFS getstripe -I1 -S $tf-1)

	[[ $comp_end == $((128 * 1024)) ]] ||
		error "incorrect component end '$comp_end' for $tf-1"

	[[ $stripe_size == $((128 * 1024)) ]] ||
		error "incorrect stripe size '$stripe_size' for $tf-1"

	rm $tf-1 || error "removing $tf-1 failed"

	# The stripe size must be a multiple of 64KiB.
	# Values below 4096 are assumed to be in KiB units.
	$LFS setstripe -E -1 -S 2047 $tf-2 > /dev/null 2>&1 &&
		error "creating $tf-2 with '-S 2047' should fail"

	$LFS setstripe -E -1 -S 2048 $tf-2 ||
		error "creating $tf-2 failed"

	stripe_size=$($LFS getstripe -I1 -S $tf-2)
	[[ $stripe_size == $((2048 * 1024)) ]] ||
		error "incorrect stripe size '$stripe_size' for $tf-2"

	rm $tf-2 || error "removing $tf-2 failed"
}
run_test 0d "Verify comp end and stripe size"

test_1a() {
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
run_test 1a "Create full components file, reused OSTs"

# test overstriping (>1 stripe/OST within a component)
test_1b() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs" && return
	[[ $($LCTL get_param mdc.*.import |
		grep "connect_flags:.*overstriping") ]] ||
		skip "server does not support overstriping"

	local comp_file=$DIR/$tdir/$tfile
	local rw_len=$((3 * 1024 * 1024))	# 3M

	test_mkdir $DIR/$tdir

	$LFS setstripe -E 1m -S 1m -o 0,0 -E -1 -o 1,1,0,0 $comp_file ||
		error "Create $comp_file failed"

	#instantiate all components, so that objs are allocted
	dd if=/dev/zero of=$comp_file bs=1k count=1 seek=1M

	$LFS getstripe $comp_file
	local OSTS_1=$($LFS getstripe -I1 $comp_file | grep -o 'l_ost_idx.*' |
		      awk -e '{print $2}' | tr "\n" "\0")
	local OSTS_2=$($LFS getstripe -I2 $comp_file | grep -o 'l_ost_idx.*' |
		      awk -e '{print $2}' | tr "\n" "\0")

	echo ":"$OSTS_1":"
	echo ":"$OSTS_2":"
	[ "$OSTS_1" = "0,0," ] || error "incorrect OSTs($OSTS_1) in component 1"
	[ "$OSTS_2" = "1,1,0,0," ] ||
		error "incorrect OSTs($OSTS_2) in component 2"

	small_write $comp_file $rw_len || error "Verify RW failed"

	rm -f $comp_file || error "Delete $comp_file failed"
}
run_test 1b "Create full components file, overstriping in components"

# test overstriping with max stripe count
test_1c() {
	[[ $($LCTL get_param mdc.*.import |
		grep "connect_flags:.*overstriping") ]] ||
		skip "server does not support overstriping"
	large_xattr_enabled || skip_env "no large xattr support"

	local comp_file=$DIR/$tdir/$tfile
	local rw_len=$((3 * 1024 * 1024))	# 3M

	test_mkdir $DIR/$tdir

	$LFS setstripe -E 1m -C 10 -E 10M -C 100 -E -1 \
	    -C $LOV_MAX_STRIPE_COUNT $comp_file ||
		error "Create $comp_file failed"

	# Seek & write in to last component so all objects are allocated
	dd if=/dev/zero of=$comp_file bs=1k count=1 seek=20000

	local count=$($LFS getstripe -c -I1 $DIR/$tdir/$tfile)
	[ $count -eq 10 ] || error "comp1 stripe count $count, should be 10"
	count=$($LFS getstripe -c -I2 $DIR/$tdir/$tfile)
	[ $count -eq 100 ] || error "comp2 stripe count $count, should be 100"
	count=$($LFS getstripe -c -I3 $DIR/$tdir/$tfile)
	[ $count -eq $LOV_MAX_STRIPE_COUNT ] ||
		error "comp4 stripe count $count != $LOV_MAX_STRIPE_COUNT"

	small_write $comp_file $rw_len || error "Verify RW failed"

	rm -f $comp_file || error "Delete $comp_file failed"
}
run_test 1c "Test overstriping w/max stripe count"

base_test_2() {
	local comp_file=$DIR/$tdir/$tfile
	local rw_len=$((5 * 1024 * 1024))	# 5M
	local params=$1

	test_mkdir $DIR/$tdir
	rm -f $comp_file

	multiop $comp_file oO_RDWR:O_CREAT:O_LOV_DELAY_CREATE:c ||
		error "create failed $comp_file"

	$LFS setstripe --component-add $params $comp_file ||
		error "Add component to $comp_file failed"

	check_component_count $comp_file 1

	dd if=/dev/zero of=$comp_file bs=1M count=1 > /dev/null 2>&1 ||
		error "Write first component failed"
	dd if=$comp_file of=/dev/null bs=1M count=1 > /dev/null 2>&1 ||
		error "Read first component failed"

	dd if=/dev/zero of=$comp_file bs=1M count=2 > /dev/null 2>&1 &&
		error "Write beyond component should fail"
	dd if=$comp_file of=/dev/null bs=1M count=2 > /dev/null 2>&1 ||
		error "Read beyond component should short read, not fail"

	$LFS setstripe --component-add -E 2M -S 1M -c 1 $comp_file ||
		error "Add component to $comp_file failed"

	check_component_count $comp_file 2

	$LFS setstripe --component-add -E -1 -c 3 $comp_file ||
		error "Add last component to $comp_file failed"

	check_component_count $comp_file 3

	small_write $comp_file $rw_len || error "Verify RW failed"

	rm -f $comp_file || error "Delete $comp_file failed"
}

test_2a() {
	base_test_2 "-E 1m -S 1m"
}
run_test 2a "Add components to existing file"

test_2b () {
	base_test_2 "-E 1m -L mdt"
}
run_test 2b "Add components w/DOM to existing file"

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

base_test_3() {
	local comp_file=$DIR/$tdir/$tfile
	local params=$1

	test_mkdir $DIR/$tdir
	rm -f $comp_file

	$LFS setstripe $params $comp_file || error "Create $comp_file failed"

	check_component_count $comp_file 3

	dd if=/dev/zero of=$comp_file bs=1M count=2

	$LFS setstripe --component-del -I 2 $comp_file &&
		error "Component deletion makes hole"

	del_comp_and_verify $comp_file 3 2 $((2 * 1024 * 1024))
	del_comp_and_verify $comp_file 2 1 $((1 * 1024 * 1024))
	del_comp_and_verify $comp_file 1 0 0

	rm -f $comp_file || error "Delete $comp_file failed"

	$LFS setstripe -E 1M -S 1M -E 16M -E -1 $comp_file ||
		error "Create second $comp_file failed"

	del_comp_and_verify $comp_file "^init" 1 0
	del_comp_and_verify $comp_file "init" 0 0
	rm -f $comp_file || error "Delete second $comp_file failed"
}

test_3a() {
	base_test_3 "-E 1M -S 1M -E 64M -c 2 -E -1 -c 3"
}
run_test 3a "Delete components from existing file"

test_3b() {
	base_test_3 "-E 1M -L mdt -E 64M -S 1M -c 2 -E -1 -c 3"
}
run_test 3b "Delete components w/DOM from existing file"

test_4() {
	skip "Not supported in PFL"
	# In PFL project, only LCME_FL_INIT is supported, and it can't
	# be altered by application.
}
run_test 4 "Modify component flags in existing file"

test_5() {
	local parent=$DIR/$tdir
	local comp_file=$DIR/$tdir/$tfile
	local subdir=$parent/subdir

	rm -fr $parent
	test_mkdir $parent

	# set default layout to parent directory
	$LFS setstripe -E 64M -c 2 -i 0 -E -1 -c 4 -i 0 $parent ||
		error "Set default layout to $parent failed"

	# create file under parent
	touch $comp_file || error "Create $comp_file failed"
	check_component_count $comp_file 2

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

	check_component_count $subdir/$tfile 2

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

	check_component_count $comp_file 0

	dd if=/dev/urandom of=$comp_file bs=1M count=5 oflag=sync ||
		error "Write to v1 $comp_file failed"

	local old_chksum=$(md5sum $comp_file)

	# Migrate v1 to composite
	$LFS migrate -E 1M -S 512K -c 1 -E -1 -S 1M -c 2 $comp_file ||
		error "Migrate(v1 -> composite) $comp_file failed"

	check_component_count $comp_file 2

	local chksum=$(md5sum $comp_file)
	[ "$old_chksum" != "$chksum" ] &&
		error "(v1 -> compsoite) $old_chksum != $chksum"

	# Migrate composite to composite
	$LFS migrate -E 1M -S 1M -c 2 -E 4M -S 1M -c 2 \
		-E -1 -S 3M -c 3 $comp_file ||
		error "Migrate(compsoite -> composite) $comp_file failed"

	check_component_count $comp_file 3

	chksum=$(md5sum $comp_file)
	[ "$old_chksum" != "$chksum" ] &&
		error "(composite -> compsoite) $old_chksum != $chksum"

	# Migrate composite to v1
	$LFS migrate -c 2 -S 2M $comp_file ||
		error "Migrate(composite -> v1) $comp_file failed"

	check_component_count $comp_file 0

	chksum=$(md5sum $comp_file)
	[ "$old_chksum" != "$chksum" ] &&
		error "(composite -> v1) $old_chksum != $chksum"

	rm -f $comp_file || "Delete $comp_file failed"
}
run_test 6 "Migrate composite file"

test_7() {
	test_mkdir $DIR/$tdir
	chmod 0777 $DIR/$tdir || error "chmod $tdir failed"

	local comp_file=$DIR/$tdir/$tfile
	$RUNAS $LFS setstripe -E 1M -S 1M -c 1 $comp_file ||
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
	test_mkdir $parent

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

	$LFS setstripe -E 1M -S 1M -E -1 -c 1 $comp_file ||
		error "Create $comp_file failed"

	check_component_count $comp_file 2

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
	local root=$MOUNT

	save_layout_restore_at_exit $MOUNT

	rm -rf $parent

	# mount root on $MOUNT2 if FILESET is set
	if [ -n "$FILESET" ]; then
		FILESET="" mount_client $MOUNT2 ||
			error "mount $MOUNT2 fail"
		root=$MOUNT2
	fi

	$LFS setstripe -d $root || error "clear root layout"

	# set root composite layout
	$LFS setstripe -E 2M -c 1 -S 1M -E 16M -c2 -S 2M \
		-E -1 -c 4 -S 4M $root ||
		error "Set root layout failed"

	if [ "$root" == "$MOUNT2" ]; then
		umount_client $MOUNT2 ||
			error "umount $MOUNT2 fail"
	fi

	test_mkdir $parent
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

test_11a() {
	local comp_file=$DIR/$tdir/$tfile
	test_mkdir $DIR/$tdir
	rm -f $comp_file

	# only 1st component instantiated
	$LFS setstripe -E 1M -S 1M -E 2M -E 3M -E -1 $comp_file ||
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
	# Truncate to exact start of new component - LU-12586
	$TRUNCATE $comp_file $((1024*1024*1))

	f2=$($LFS getstripe -I2 $comp_file | grep "l_fid")
	[[ -z $f2 ]] && error "2: 2nd component uninstantiated"
	f3=$($LFS getstripe -I3 $comp_file | grep "l_fid")
	[[ -n $f3 ]] && error "2: 3rd component instantiated"
	f4=$($LFS getstripe -I4 $comp_file | grep "l_fid")
	[[ -n $f4 ]] && error "2: 4th component instantiated"

	# the first 3 components instantiated
	$TRUNCATE $comp_file $((1024*1024*3 - 1))
	$TRUNCATE $comp_file $((1024*1024*1+1))

	f2=$($LFS getstripe -I2 $comp_file | grep "l_fid")
	[[ -z $f2 ]] && error "3: 2nd component uninstantiated"
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
run_test 11a "Verify component instantiation with write/truncate"

test_11b() {
	[ $OSTCOUNT -lt 4 ] && skip "needs >= 4 OSTs"

	local file=$DIR/$tdir/$tfile

	test_mkdir $DIR/$tdir
	rm -f $file

	$LFS setstripe -E 1m -E 1g -c 4 -E eof $DIR/$tdir ||
		error "setstripe dir $DIR/$tdir failed"
	expand_truncate_test $file ||
		error "expand_truncate_test failed on $file"
}
run_test 11b "truncate file set file size correctly"

test_12() {
	[ $OSTCOUNT -lt 3 ] && skip "needs >= 3 OSTs"

	local file=$DIR/$tdir/$tfile
	test_mkdir $DIR/$tdir
	rm -f $file

	# specify ost list for component
	$LFS setstripe -E 1M -S 1M -c 2 -o 0,1 -E 2M -c 2 -o 1,2 \
		-E 3M -c 2 -o 2,1 -E 4M -c 1 -i 2 -E -1 $file ||
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
	[ $OSTCOUNT -lt 8 ] && skip "needs >= 8 OSTs"

	local file=$DIR/$tfile
	local dd_count=4
	local dd_size=$(($dd_count * 1024 * 1024))
	local real_size

	rm -f $file
	$LFS setstripe -E 1M -S 1M -c 1 -E 2M -c 2 -E -1 -c -1 -i 1 $file ||
		error "Create $file failed"
	dd if=/dev/zero of=$file bs=1M count=$dd_count
	real_size=$(stat -c %s $file)
	[ $real_size -eq $dd_size ] ||
		error "dd actually wrote $real_size != $dd_size bytes"

	rm -f $file
}
run_test 13 "shouldn't reprocess granted resent request"

test_14() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
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
	test_mkdir $parent

	$LFS setstripe -d $parent || error "delete default layout"

	$LFS setstripe -E 1M -S 1M -E 10M -E eof $parent/f1 || error "create f1"
	$LFS setstripe -E 4M -E 20M -E eof $parent/f2 || error "create f2"
	test_mkdir $parent/subdir
	$LFS setstripe -E 6M -S 1M -c1 -E 30M -c4 -E eof -c -1 $parent/subdir ||
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

	# check last component stripe count
	if [ $OSTCOUNT -gt 1 ]; then
		touch $parent/subdir/f5
		$TRUNCATE $parent/subdir/f5 $((32*1024*1024))
		found=$($LFS find $parent/subdir -c $OSTCOUNT)
		[[ "$found" == "$parent/subdir/f5" ]] ||
			error "got '$found' with stripe_count=$OSTCOUNT, not f5"
	fi
}
run_test 15 "Verify component options for lfs find"

test_16a() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	large_xattr_enabled || skip_env "ea_inode feature disabled"

	local file=$DIR/$tdir/$tfile
	local dir=$DIR/$tdir/dir
	local temp=$DIR/$tdir/template
	rm -rf $DIR/$tdir
	test_mkdir $DIR/$tdir

	#####################################################################
	#	                    1. PFL file
	# set stripe for source file
	$LFS setstripe -E1m -S 1M -c2 -o0,1 -E2m -c2 -E3m -o1,0 -E4m -c1 -E-1 \
		$file || error "Create $file failed"

	echo "1. PFL file"
	verify_yaml_layout $file $file.copy $temp "1. PFL file"

	#####################################################################
	#	                    2. plain file
	# set stripe for source file
	rm -f $file
	$LFS setstripe -c2 -o0,1 -i1 $file || error "Create $file failed"

	rm -f $file.copy
	echo "2. plain file"
	verify_yaml_layout $file $file.copy $temp "2. plain file"

	#####################################################################
	#	                    3. PFL dir
	# set stripe for source dir
	test_mkdir $dir
	$LFS setstripe -E1m -S 1M -c2 -E2m -c1 -E-1 $dir ||
		error "setstripe $dir failed"

	test_mkdir $dir.copy
	echo "3. PFL dir"
	verify_yaml_layout $dir $dir.copy $temp.dir "3. PFL dir"

	#####################################################################
	#	                    4. plain dir
	# set stripe for source dir
	$LFS setstripe -c2 -i-1 $dir || error "setstripe $dir failed"

	echo "4. plain dir"
	verify_yaml_layout $dir $dir.copy $temp.dir "4. plain dir"
}
run_test 16a "Verify setstripe/getstripe with YAML config file"

test_16b() {
	[[ $($LCTL get_param mdc.*.import |
		grep "connect_flags:.*overstriping") ]] ||
		skip "server does not support overstriping"
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[[ $OSTCOUNT -ge $(($LOV_MAX_STRIPE_COUNT / 2)) ]] &&
		skip_env "too many osts, skipping"
	large_xattr_enabled || skip_env "ea_inode feature disabled"

	local file=$DIR/$tdir/$tfile
	local dir=$DIR/$tdir/dir
	local temp=$DIR/$tdir/template
	# We know OSTCOUNT < (LOV_MAX_STRIPE_COUNT / 2), so this is overstriping
	local large_count=$((LOV_MAX_STRIPE_COUNT / 2 + 10))

	rm -rf $DIR/$tdir
	test_mkdir $DIR/$tdir

	#####################################################################
	#	                    1. PFL file, overstriping in first comps
	# set stripe for source file
	$LFS setstripe -E1m -S 1M -o0,0 -E2m -o1,1 -E3m -C $large_count -E-1 \
		$file || error "Create $file failed"

	echo "1. PFL file"
	verify_yaml_layout $file $file.copy $temp "1. PFL file"

	#####################################################################
	#	                    2. plain file + overstriping
	# set stripe for source file
	rm -f $file
	$LFS setstripe -C $large_count -i1 $file || error "Create $file failed"

	rm -f $file.copy
	echo "2. plain file"
	verify_yaml_layout $file $file.copy $temp "2. plain file"

	#####################################################################
	#	                    3. PFL dir + overstriping
	# set stripe for source dir
	test_mkdir $dir
	$LFS setstripe -E1m -S 1M -o 0,0 -E2m -C $large_count -E-1 $dir ||
		error "setstripe $dir failed"

	test_mkdir $dir.copy
	echo "3. PFL dir"
	verify_yaml_layout $dir $dir.copy $temp.dir "3. PFL dir"

	#####################################################################
	#	                    4. plain dir + overstriping
	# set stripe for source dir
	$LFS setstripe -C $large_count $dir || error "setstripe $dir failed"

	echo "4. plain dir"
	verify_yaml_layout $dir $dir.copy $temp.dir "4. plain dir"
}
run_test 16b "Verify setstripe/getstripe with YAML config file + overstriping"

test_16c() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"

	local file=$DIR/$tdir/$tfile
	local dir=$DIR/$tdir/dir
	local temp=$DIR/$tdir/template
	rm -rf $DIR/$tdir
	test_mkdir $DIR/$tdir

	#####################################################################
	#	                    1. SEL file
	# set stripe for source file
	$LFS setstripe -E256M -S 1M -c2 -o0,1 -z 64M -E-1 -o1,0 -z 128M \
		$file || error "Create $file failed"

	echo "1. SEL file"
	verify_yaml_layout $file $file.copy $temp "1. PFL file"

	#####################################################################
	#	                    2. SEL dir
	# set stripe for source dir
	test_mkdir $dir
	$LFS setstripe -E256M -S 1M -c2 -z 64M -E-1 -z 128M \
		$dir || error "setstripe $dir failed"

	test_mkdir $dir.copy
	echo "2. SEL template on dir"
	verify_yaml_layout $dir $dir.copy $temp.dir "2. PFL dir"
}
run_test 16c "Verify setstripe/getstripe for SEL layout with YAML config file"

test_17() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	local file=$DIR/$tdir/$tfile
	test_mkdir -p $DIR/$tdir
	rm -f $file

	$LFS setstripe -E 1M -S 1M -E 2M -c 2 -E -1 -c -1 $file ||
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

check_distribution() {
	local file=$1
	local objs
	local ave
	local obj_min_one=$((OSTCOUNT - 1))

	objs=$($LFS getstripe $file |
		awk '/l_ost_idx:/ { print $5 }' | wc -l)
	let ave=$((objs / OSTCOUNT))

	# collect objects per OST distribution
	$LFS getstripe $file | awk '/l_ost_idx:/ { print $5 }' | tr -d "," |
		(inuse=( $(for i in $(seq 0 $obj_min_one); do echo 0; done) )
		while read O; do
			let inuse[$O]=$((1 + ${inuse[$O]}))
		done;

		# verify object distribution varies no more than +-1
		for idx in $(seq 0 $obj_min_one); do
			let dif=$((${inuse[$idx]} - ave))
			let dif=${dif#-}
			if [ "$dif" -gt 1 ]; then
				echo "OST${idx}: ${inuse[$idx]} objects"
				error "bad distribution on OST${idx}"
			fi
		done)
}

test_18() {
	local file1=$DIR/${tfile}-1
	local file2=$DIR/${tfile}-2
	local file3=$DIR/${tfile}-3

	rm -f $file1 $file2 $file3

	$LFS setstripe -E 1m -S 1m $file1 ||
		error "Create $file1 failed"
	$LFS setstripe -E 1m -S 1m $file2 ||
		error "Create $file2 failed"
	$LFS setstripe -E 1m -S 1m $file3 ||
		error "Create $file3 failed"

	local objs=$((OSTCOUNT+1))
	for comp in $(seq 1 $OSTCOUNT); do
		$LFS setstripe --component-add -E $((comp+1))M -c 1 $file1 ||
			error "Add component to $file1 failed 2"
		$LFS setstripe --component-add -E $((comp+1))M -c 1 $file2 ||
			error "Add component to $file2 failed 2"
		$LFS setstripe --component-add -E $((comp+1))M -c 1 $file3 ||
			error "Add component to $file3 failed 2"
	done

	$LFS setstripe --component-add -E -1 -c -1 $file1 ||
		error "Add component to $file1 failed 3"
	$LFS setstripe --component-add -E -1 -c -1 $file2 ||
		error "Add component to $file2 failed 3"
	$LFS setstripe --component-add -E -1 -c -1 $file3 ||
		error "Add component to $file3 failed 3"

	# Instantiate all components
	dd if=/dev/urandom of=$file1 bs=1M count=$((objs+1)) ||
		error "dd failed for $file1"
	dd if=/dev/urandom of=$file2 bs=1M count=$((objs+1)) ||
		error "dd failed for $file2"
	dd if=/dev/urandom of=$file3 bs=1M count=$((objs+1)) ||
		error "dd failed for $file3"

	check_distribution $file1
	check_distribution $file2
	check_distribution $file3

}
run_test 18 "check component distribution"

test19_io_base() {
	local comp_file=$1
	local already_created=${2:-0}
	local rw_len=$((3 * 1024 * 1024))       # 3M
	local flg_opts=""
	local found=""

	if [ $already_created != 1 ]; then
		test_mkdir -p $DIR/$tdir
		$LFS setstripe --extension-size 64M -c 1 -E -1 $comp_file ||
			error "Create $comp_file failed"
	fi

	# write past end of first component, so it is extended
	dd if=/dev/zero of=$comp_file bs=1M count=1 seek=127 conv=notrunc ||
		error "dd to extend failed"

	local ost_idx1=$($LFS getstripe -I1 -i $comp_file)
	local ost_idx2=$($LFS getstripe -I2 -i $comp_file)

	[ $ost_idx1 -eq $ost_idx2 ] && error "$ost_idx1 == $ost_idx2"
	[ $ost_idx2 -ne "-1" ] && error "second component init $ost_idx2"

	flg_opts="--comp-flags init"
	found=$($LFS find --comp-start 0 -E 128M $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: Extended first component not found"

	flg_opts="--comp-flags extension"
	found=$($LFS find --comp-start 128M -E EOF $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: second component not found"

	found=$($LFS find -z 64M $comp_file | wc -l)
	[ $found -eq 1 ] || error "component not found by ext size"

	found=$($LFS find --extension-size +63M $comp_file | wc -l)
	[ $found -eq 1 ] || error "component not found by +ext size"

	found=$($LFS find --ext-size -65M $comp_file | wc -l)
	[ $found -eq 1 ] || error "component not found by -ext size"

	found=$($LFS find -z 65M $comp_file | wc -l)
	[ $found -eq 0 ] || error "component found by wrong ext size"

	found=$($LFS find -z +65M $comp_file | wc -l)
	[ $found -eq 0 ] || error "component found by wrong +ext size"

	found=$($LFS find -z -63M $comp_file | wc -l)
	[ $found -eq 0 ] || error "component found by wrong -ext size"

	found=$($LFS find ! -z 64M $comp_file | wc -l)
	[ $found -eq 0 ] || error "component found by negation of ext size"

	found=$($LFS find ! -z +63M $comp_file | wc -l)
	[ $found -eq 0 ] || error "component found by negation of +ext size"

	found=$($LFS find ! -z -65M $comp_file | wc -l)
	[ $found -eq 0 ] || error "component found by negation of -ext size"

	found=$($LFS find ! -z 65M $comp_file | wc -l)
	[ $found -eq 1 ] ||
		error "component not found by negation of wrong ext size"

	found=$($LFS find ! -z +65M $comp_file | wc -l)
	[ $found -eq 1 ] ||
		error "component not found by negation of wrong +ext size"

	found=$($LFS find ! -z -63M $comp_file | wc -l)
	[ $found -eq 1 ] ||
		error "component not found by negation of wrong -ext size"

	found=$($LFS find -S +1M $comp_file | wc -l)
	[ $found -eq 0 ] || error "component found by wrong +stripe size"

	found=$($LFS find -c 1 $comp_file | wc -l)
	[ $found -eq 1 ] || error "component not found by stripe count"

	small_write $comp_file $rw_len || error "Verify RW failed"

	sel_layout_sanity $comp_file 2
}

# Self-extending PFL tests
test_19a() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	test19_io_base $DIR/$tdir/$tfile
}
run_test 19a "Simple test of extension behavior"

# Same as 19a, but with default layout set on directory rather than on file
test_19b() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	local comp_dir=$DIR/$tdir/$tdir
	local flg_opts=""
	local found=""

	test_mkdir -p $DIR/$tdir
	$LFS setstripe --ext-size 64M -c 1 -E -1 $DIR/$tdir ||
		error "Setstripe on $DIR/$tdir failed"

	# check inheritance for a sub-dir and a file
	test_mkdir $comp_dir
	found=$($LFS find --comp-start 0 -E 64M $comp_dir | wc -l)
	[ $found -eq 1 ] || error "Dir Inheritance: wrong first component size"

	flg_opts="--comp-flags extension"
	found=$($LFS find --comp-start 64M -E EOF $flg_opts $comp_dir | wc -l)
	[ $found -eq 1 ] || error "Dir Inheritance: Second component not found"

	touch $comp_file

	flg_opts="--comp-flags init"
	found=$($LFS find --comp-start 0 -E 64M $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "File Inheritance: wrong first component size"

	flg_opts="--comp-flags extension"
	found=$($LFS find --comp-start 64M -E EOF $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "File Inheritance: Second component not found"

	test19_io_base $comp_file 1
}
run_test 19b "Simple test of SEL as default layout"

# Test behavior when seeking deep in a file
test_19c() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	local flg_opts=""
	local found=""

	test_mkdir -p $DIR/$tdir

	$LFS setstripe -z 128M -E 1G -E -1 $comp_file ||
		error "Create $comp_file failed"

	# write past end of first component, so it is extended
	dd if=/dev/zero of=$comp_file bs=1M count=1 seek=130 conv=notrunc ||
		error "dd to extend failed"

	flg_opts="--comp-flags init"
	found=$($LFS find --comp-start 0M -E 256M $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: first extension component not found"

	flg_opts="--comp-flags extension,^init"
	found=$($LFS find --comp-start 256M -E 1024M $flg_opts $comp_file |\
		wc -l)
	[ $found -eq 1 ] || error "Write: second extension component not found"

	local end_1=$($LFS getstripe -I1 -E $comp_file)

	# 256 MiB
	[ $end_1 -eq 268435456 ] ||
		error "end of first component $end_1 != 268435456"

	# Write past end of extension space component, in to normal component
	# should exhaust & remove extension component
	dd if=/dev/zero bs=1M count=1 seek=1100 of=$comp_file conv=notrunc ||
		error "dd distant seek failed"

	local ost_idx1=$($LFS getstripe -I1 -i $comp_file)
	# the last component index is 3
	local ost_idx2=$($LFS getstripe -I3 -i $comp_file)

	[ $ost_idx1 -eq $ost_idx2 ] && error "$ost_idx1 == $ost_idx2"

	local start1=$($LFS getstripe -I1 --comp-start $comp_file)
	local end1=$($LFS getstripe -I1 -E $comp_file)
	local start2=$($LFS getstripe -I3 --comp-start $comp_file)
	local end2=$($LFS getstripe -I3 -E $comp_file)

	[ $start1 -eq 0 ] || error "start of first component incorrect"
	[ $end1 -eq 1073741824 ] || error "end of first component incorrect"
	[ $start2 -eq 1073741824  ] ||
		error "start of second component incorrect"
	[ "$end2" = "EOF" ] || error "end of second component incorrect"

	flg_opts="--comp-flags extension"
	found=$($LFS find $flg_opts $comp_file | wc -l)
	[ $found -eq 0 ] || error "Seek Write: extension component exists"

	sel_layout_sanity $comp_file 2
}
run_test 19c "Test self-extending layout seeking behavior"

test_19d() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	local flg_opts=""
	local found=""

	test_mkdir -p $DIR/$tdir

	$LFS setstripe -E 128M -c 1 -z 64M -E -1 $comp_file ||
		error "Create $comp_file failed"

	# This will cause component 1 to be extended to 128M, then the
	# extension space component will be removed
	dd if=/dev/zero of=$comp_file bs=130M count=1 ||
		error "dd to extend failed"

	flg_opts="--comp-flags init"
	found=$($LFS find --comp-start 0M -E 128M $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: first component not found"

	flg_opts="--comp-flags init"
	found=$($LFS find --comp-start 128M -E EOF $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: second component not found"

	sel_layout_sanity $comp_file 2

	# always remove large files in case of DO_CLEANUP=false
	rm -f $comp_file || error "Delete $comp_file failed"
}
run_test 19d "Test write which completely spans extension space component"

test_19e_check() {
	comp_file=$1

	local comp2_flags=$($LFS getstripe -I2 --comp-flags $comp_file)
	local comp3_flags=$($LFS getstripe -I3 --comp-flags $comp_file)

	[ "$comp2_flags" != "init" ] && error "$comp2_flags != init"
	[ "$comp3_flags" != "extension" ] && error "$comp3_flags != extension"

	local flg_opts=" --comp-start 2M -E 66M --comp-flags init"
	local found=$($LFS find $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: extended second component not found"

	flg_opts="--comp-start 66M -E EOF --comp-flags extension"
	found=$($LFS find $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: third component not found"

	sel_layout_sanity $comp_file 3
}

test_19e() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	local rw_len=$((3 * 1024 * 1024))       # 3M
	local flg_opts=""
	local found=""

	test_mkdir -p $DIR/$tdir

	$LFS setstripe -E 2m -E -1 -z 64M $comp_file ||
		error "Create $comp_file failed"

	replay_barrier $SINGLEMDS

	#instantiate & extend second component
	dd if=/dev/zero of=$comp_file bs=4M count=1 ||
		error "dd to extend failed"

	local ost_idx2=$($LFS getstripe -I2 -i $comp_file)
	local ost_idx3=$($LFS getstripe -I3 -i $comp_file)

	[ $ost_idx2 -eq $ost_idx3 ] && error "$ost_idx2 == $ost_idx3"
	[ $ost_idx3 -ne "-1" ] && error "third component init $ost_idx3"

	test_19e_check $comp_file

	local f1=$($LFS getstripe -I2 $comp_file | awk '/l_fid:/ {print $7}')
	echo "before MDS recovery, the ost fid of 2nd component is $f1"

	fail $SINGLEMDS

	local f2=$($LFS getstripe -I2 $comp_file | awk '/l_fid:/ {print $7}')
	echo "after MDS recovery, the ost fid of 2nd component is $f2"
	[ "x$f1" == "x$f2" ] || error "$f1 != $f2"

	# simply repeat all previous checks, but also verify components are on
	# the same OST as before

	local ost_idx2_2=$($LFS getstripe -I2 -i $comp_file)
	local ost_idx3_2=$($LFS getstripe -I3 -i $comp_file)

	[ $ost_idx2_2 -eq $ost_idx3_2 ] && error "$ost_idx2_2 == $ost_idx3_2"
	[ $ost_idx3_2 -ne "-1" ] && error "second component init $ost_idx3_2"

	# verify OST id is the same after failover
	[ $ost_idx2 -ne $ost_idx2_2 ] &&
		error "$ost_idx2 != $ost_idx2_2, changed after failover"

	test_19e_check $comp_file
}
run_test 19e "Replay of layout instantiation & extension"

test_19f() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	local flg_opts=""
	local found=""

	test_mkdir -p $DIR/$tdir

	$LFS setstripe -E 256M --comp-flags extension -E -1 $comp_file

	[ $? != 0 ] || error "should not be able to manually set extension flag"

}
run_test 19f "Rejection of invalid layouts"

test_19g() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local file1=$DIR/${tfile}-1
	local file2=$DIR/${tfile}-2

	test_mkdir -p $DIR/$tdir
	multiop $file1 oO_RDWR:O_CREAT:O_LOV_DELAY_CREATE:c ||
		error "create failed $file1"
	multiop $file2 oO_RDWR:O_CREAT:O_LOV_DELAY_CREATE:c ||
		error "create failed $file2"

	$LFS setstripe --component-add -E 1G -c 1 $file1 ||
		error "comp-add [0,1G] failed $file1"
	$LFS setstripe --component-add -E 512M -z 128M $file1 &&
		error "comp-add [1G,1G],SEL[1G,512M] succeded $file1"
	$LFS setstripe --component-add -E 10G -z 128M $file1 ||
		error "comp-add [1G,1G],SEL[1G,10G] failed $file1"
	$LFS setstripe --component-add -E -1 $file1 ||
		error "comp-add [10G,-1] failed $file1"

	$LFS setstripe --component-add -E 1G -z 32M -c 1 $file2 &&
		error "comp-add with smal ext size succeeded $file1"
	$LFS setstripe --component-add -E 1G -z 100M -c 1 $file2 &&
		error "comp-add with not aligned ext size succeeded $file1"
	$LFS setstripe --component-add -E 1G -z 128M -c 1 $file2 ||
		error "comp-add [0,128M],SEL[128M,1G] failed $file1"
	$LFS setstripe --component-add -E 10G $file2 ||
		error "comp-add [1G,10G] failed $file1"
	$LFS setstripe --component-add -E -1 -z 128M -c 1 $file2 ||
		error "comp-add [10G,10G],SEL[10G,-1] failed $file1"
	$LFS setstripe --component-add -E -1 -z 128M -c 1 $file2 &&
		error "repeated comp-add [10G,10G],SEL[10G,-1] succeeded $file1"

	$LFS getstripe $file1
	flg_opts="--comp-flags init"
	found=$($LFS find --comp-start 0 -E 1G $flg_opts $file1 | wc -l)
	[ $found -eq 1 ] || error "First component not found $file1"

	flg_opts="--comp-flags ^init"
	found=$($LFS find --comp-start 1G -E 1G $flg_opts $file1 | wc -l)
	[ $found -eq 1 ] || error "Second component not found $file1"

	flg_opts="--comp-flags ^init,extension"
	found=$($LFS find --comp-start 1G -E 10G $flg_opts $file1 | wc -l)
	[ $found -eq 1 ] || error "Third component not found $file1"

	flg_opts="--comp-flags ^init"
	found=$($LFS find --comp-start 10G -E EOF $flg_opts $file1 | wc -l)
	[ $found -eq 1 ] || error "Fourth component not found $file1"

	$LFS getstripe $file2
	flg_opts="--comp-flags init"
	found=$($LFS find --comp-start 0 -E 128M $flg_opts $file2 | wc -l)
	[ $found -eq 1 ] || error "First component not found $file2"

	flg_opts="--comp-flags extension"
	found=$($LFS find --comp-start 128M -E 1G $flg_opts $file2 | wc -l)
	[ $found -eq 1 ] || error "Second component not found $file2"

	flg_opts="--comp-flags ^init"
	found=$($LFS find --comp-start 1G -E 10G $flg_opts $file2 | wc -l)
	[ $found -eq 1 ] || error "Third component not found $file2"

	flg_opts="--comp-flags ^init"
	found=$($LFS find --comp-start 10G -E 10G $flg_opts $file2 | wc -l)
	[ $found -eq 1 ] || error "Fourth component not found $file2"

	flg_opts="--comp-flags ^init,extension"
	found=$($LFS find --comp-start 10G -E EOF $flg_opts $file2 | wc -l)
	[ $found -eq 1 ] || error "Fifth component not found $file2"
}
run_test 19g "component-add behaviour"

# Test out of space behavior
test_20a() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	local flg_opts=""
	local found=""

	test_mkdir -p $DIR/$tdir

	# without this, a previous delete can finish after we check free space
	wait_delete_completed
	wait_mds_ost_sync

	# First component is on OST0
	$LFS setstripe -E 256M -i 0 -z 64M -E -1 -z 128M $comp_file ||
		error "Create $comp_file failed"

	# write past end of first component, so it is extended
	dd if=/dev/zero of=$comp_file bs=1M count=1 seek=66 ||
		error "dd to extend failed"

	flg_opts="--comp-flags extension"
	found=$($LFS find --comp-start 128M -E 256M $flg_opts $comp_file |wc -l)
	[ $found -eq 1 ] || error "Write: Second component not found"

	local ost_idx1=$($LFS getstripe -I1 -i $comp_file)
	local wms=$(ost_watermarks_set_enospc $tfile $ost_idx1 |
		    grep "watermarks")
	stack_trap "ost_watermarks_clear_enospc $tfile $ost_idx1 $wms" EXIT

	flg_opts="--comp-flags extension"
	# Write past current init comp, but we won't extend (because no space)
	dd if=/dev/zero of=$comp_file bs=1M count=10 seek=200 ||
		error "dd write past current comp failed"

	$LFS getstripe $comp_file

	flg_opts="--comp-flags init"
	found=$($LFS find --comp-start 128M -E 256M $flg_opts $comp_file | \
		wc -l)
	[ $found -eq 1 ] || error "Write: third component not found"

	flg_opts="--comp-flags extension"
	found=$($LFS find --comp-start 256M -E EOF $flg_opts $comp_file |wc -l)
	[ $found -eq 1 ] || error "Write: fourth extension component not found"

	sel_layout_sanity $comp_file 3
}
run_test 20a "Test out of space, spillover to defined component"

test_20b() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	local flg_opts=""
	local found=""

	test_mkdir -p $DIR/$tdir

	# Pool allows us to force use of only certain OSTs
	pool_add $TESTNAME || error "Pool creation failed"
	pool_add_targets $TESTNAME 0 || error "Pool add targets failed"

	# normal component to 10M, extendable component to 1G
	# further extendable to EOF
	$LFS setstripe -E 10M -E 1G -p $TESTNAME -z 64M -E -1 -p "" -z 128M \
		$comp_file || error "Create $comp_file failed"

	replay_barrier $SINGLEMDS

	found=$($LFS find --comp-start 10M -E 10M $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Zero length component not found"

	local ost_idx1=0
	local wms=$(ost_watermarks_set_enospc $tfile $ost_idx1 |
		    grep "watermarks")
	stack_trap "ost_watermarks_clear_enospc $tfile $ost_idx1 $wms" EXIT

	# write past end of first component
	# This should remove the next component, since OST0 is out of space
	# and it is striped there (pool contains only OST0)
	dd if=/dev/zero of=$comp_file bs=1M count=1 seek=14 ||
		error "dd to extend/remove failed"

	$LFS getstripe $comp_file

	found=$($LFS find --comp-start 10M -E 10M $flg_opts $comp_file | wc -l)
	[ $found -eq 0 ] || error "Write: zero length component still present"

	flg_opts="--comp-flags init"
	found=$($LFS find --comp-start 10M -E 138M $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: second component not found"

	flg_opts="--comp-flags extension"
	found=$($LFS find --comp-start 138M -E EOF $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: third component not found"

	fail $SINGLEMDS

	found=$($LFS find --comp-start 10M -E 10M $flg_opts $comp_file | wc -l)
	[ $found -eq 0 ] || error "Failover: 0-length component still present"

	flg_opts="--comp-flags init"
	found=$($LFS find --comp-start 10M -E 138M $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Failover: second component not found"

	flg_opts="--comp-flags extension"
	found=$($LFS find --comp-start 138M -E EOF $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Failover: third component not found"

	sel_layout_sanity $comp_file 3
}
run_test 20b "Remove component without instantiation when there is no space"

test_20c() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	local flg_opts=""
	local found=""

	test_mkdir -p $DIR/$tdir

	# pool is used to limit available OSTs to 0 and 1, so we can set all
	# available OSTs out of space
	pool_add $TESTNAME || error "Pool creation failed"
	pool_add_targets $TESTNAME 0 1 || error "Pool add targets failed"

	# without this, a previous delete can finish after we check free space
	wait_delete_completed
	wait_mds_ost_sync

	$LFS setstripe -E 100M -E -1 -p $TESTNAME -z 64M $comp_file ||
		error "Create $comp_file failed"

	local ost_idx1=0
	local ost_idx2=1
	local wms=$(ost_watermarks_set_enospc $tfile $ost_idx1 |
		    grep "watermarks")
	local wms2=$(ost_watermarks_set_enospc $tfile $ost_idx2 |
		     grep "watermarks")
	stack_trap "ost_watermarks_clear_enospc $tfile $ost_idx1 $wms" EXIT
	stack_trap "ost_watermarks_clear_enospc $tfile $ost_idx2 $wms2" EXIT

	dd if=/dev/zero of=$comp_file bs=1M count=1 seek=120 &&
		error "dd should fail with ENOSPC"

	flg_opts="--comp-flags init"
	found=$($LFS find --comp-start 0M -E 100M $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: First component not found"

	flg_opts="--comp-flags ^init"
	found=$($LFS find --comp-start 100M -E 100M $flg_opts $comp_file |wc -l)
	[ $found -eq 1 ] || error "Write: 0-length component not found"

	flg_opts="--comp-flags extension"
	found=$($LFS find --comp-start 100M -E EOF $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: third extension component not found"

	sel_layout_sanity $comp_file 3
}
run_test 20c "Test inability to stripe new extension component"

test_20d() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	test_mkdir -p $DIR/$tdir

	wait_delete_completed
	wait_mds_ost_sync

	pool_add $TESTNAME || error "Pool creation failed"
	pool_add_targets $TESTNAME 0 || error "Pool add targets failed"
	$LFS setstripe -E 64m -E -1 -p $TESTNAME -z 64M $comp_file ||
		error "Create $comp_file failed"

	replay_barrier $SINGLEMDS

	local wms=$(ost_watermarks_set_low_space 0 | grep "watermarks")
	dd if=/dev/zero bs=1M count=1 seek=100 of=$comp_file
	RC=$?

	ost_watermarks_clear_enospc $tfile 0 $wms
	[ $RC -eq 0 ] || error "dd failed: $RC"

	$LFS getstripe $comp_file
	local flg_opts="--comp-start 64M -E 128M --comp-flags init"
	local found=$($LFS find $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: component (64M-128M) not found"

	local ost_idx=$($LFS getstripe -I3 -i $comp_file)
	[ "$ost_idx" != "-1" ] && error "Write: EXT component disappeared"

	fail $SINGLEMDS

	found=$($LFS find $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Failover: component (64M-128M) not found"

	ost_idx=$($LFS getstripe -I3 -i $comp_file)
	[ "$ost_idx" != "-1" ] && error "Failover: EXT component disappeared"

	sel_layout_sanity $comp_file 3
}
run_test 20d "Low on space + 0-length comp: force extension"

test_20e() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	test_mkdir -p $DIR/$tdir

	wait_delete_completed
	wait_mds_ost_sync

	pool_add $TESTNAME || error "Pool creation failed"
	pool_add_targets $TESTNAME 0 || error "Pool add targets failed"

	$LFS setstripe -E 64m -E 640M -z 64M -p $TESTNAME -E -1 $comp_file ||
		error "Create $comp_file failed"

	local wms=$(ost_watermarks_set_low_space 0 | grep "watermarks")

	dd if=/dev/zero bs=1M count=1 seek=100 of=$comp_file
	RC=$?

	ost_watermarks_clear_enospc $tfile 0 $wms
	[ $RC -eq 0 ] || error "dd failed $RC"

	$LFS getstripe $comp_file
	local flg_opts="--comp-start 64M -E EOF --comp-flags init"
	local found=$($LFS find $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: component (64M-EOF) not found"

	local ost_idx=$($LFS getstripe -I2 -i $comp_file)
	[ "$ost_idx" != "" ] && error "Write: 0-length component still exists"
	ost_idx=$($LFS getstripe -I3 -i $comp_file)
	[ "$ost_idx" != "" ] && error "Write: extension component still exists"

	sel_layout_sanity $comp_file 2
}
run_test 20e "ENOSPC with next real comp: spillover and backward extension"

# Simple DoM interaction test
test_21a() {
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	local flg_opts=""
	local found=""

	test_mkdir -p $DIR/$tdir

	# simple, correct self-extending layout after DoM component
	$LFS setstripe -E 1M -L mdt -E -1 -z 64m $comp_file || \
		error "Create $comp_file failed"

	# Write to DoM component & to self-extending comp after it
	dd if=/dev/zero bs=1M count=12 of=$comp_file ||
		error "dd to extend failed"

	flg_opts="--comp-flags init"
	found=$($LFS find --comp-start 1M -E 65M $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: extended component not found"

	flg_opts="--comp-flags extension"
	found=$($LFS find --comp-start 65M $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: extension component not found"

	sel_layout_sanity $comp_file 3
}
run_test 21a "Simple DoM interaction tests"

# DoM + extension + removal
test_21b() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	local ost_name=$(ostname_from_index 0)
	local flg_opts=""
	local found=""

	test_mkdir -p $DIR/$tdir

	# DoM, extendable component, further extendable component
	$LFS setstripe -E 1M -L mdt -E 256M -i 0 -z 64M -E -1 -z 128M \
		$comp_file || error "Create $comp_file failed"

	found=$($LFS find --comp-start 1M -E 1M $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: Zero length component not found"

	# This also demonstrates that we will avoid degraded OSTs
	do_facet ost1 $LCTL set_param -n obdfilter.$ost_name.degraded=1
	# sleep to guarantee we see the degradation
	sleep_maxage

	# un-degrade on exit
	stack_trap "do_facet ost1 $LCTL set_param -n \
		obdfilter.$ost_name.degraded=0; sleep_maxage" EXIT

	# This should remove the first component after DoM and spill over to
	# the next one
	dd if=/dev/zero bs=1M count=2 of=$comp_file ||
		error "dd to remove+spill over failed"

	found=$($LFS find --comp-start 1M -E 1M $flg_opts $comp_file | wc -l)
	[ $found -eq 0 ] || error "Write: Zero length component still present"

	flg_opts="--comp-flags init"
	found=$($LFS find --comp-start 1M -E 129M $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: extended component not found"

	flg_opts="--comp-flags extension"
	found=$($LFS find --comp-start 129M -E EOF $flg_opts $comp_file |wc -l)
	[ $found -eq 1 ] || error "Write: extension component not found"

	sel_layout_sanity $comp_file 3
}
run_test 21b "DoM followed by extendable component with removal"

# Test of repeat component behavior with OOS/degraded OST
test_22a() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	local flg_opts=""
	local found=""

	test_mkdir -p $DIR/$tdir

	$LFS setstripe -E -1 -c 1 -z 128M $comp_file ||
		error "Create $comp_file failed"

	local ost_idx1=$($LFS getstripe -I1 -i $comp_file)
	local ost_name=$(ostname_from_index $ost_idx1)

	# write past end of first component, so it is extended
	dd if=/dev/zero of=$comp_file bs=1M count=1 seek=130 ||
		error "dd to extend failed"

	flg_opts="--comp-flags extension"
	found=$($LFS find --comp-start 256M -E EOF $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: second component not found"

	# degrade OST for component 1
	do_facet ost$((ost_idx1+1)) $LCTL set_param -n \
		obdfilter.$ost_name.degraded=1
	# sleep to guarantee we see the degradation
	sleep_maxage

	# un-degrade on exit
	stack_trap "do_facet ost$((ost_idx1+1)) $LCTL set_param -n \
		obdfilter.$ost_name.degraded=0; sleep_maxage" EXIT

	replay_barrier $SINGLEMDS

	# seek past the end of current comp & write, should cause a new comp
	# to be created (ie repeat previous comp)
	dd if=/dev/zero of=$comp_file bs=1M count=1 seek=300 ||
		error "dd to repeat failed"

	local ost_idx2=$($LFS getstripe -I2 -i $comp_file)

	[ $ost_idx1 -eq $ost_idx2 ] && error "$ost_idx1 == $ost_idx2"

	flg_opts="--comp-flags init"
	found=$($LFS find --comp-start 256M $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: second component not found"

	flg_opts="--comp-flags extension"
	found=$($LFS find --comp-start 384M -E EOF $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: extension component not found"

	fail $SINGLEMDS

	local ost_idx2_2=$($LFS getstripe -I2 -i $comp_file)
	[ $ost_idx2_2 -ne $ost_idx2 ] && error "$ost_idx2_2 != $ost_idx2"

	flg_opts="--comp-flags init"
	found=$($LFS find --comp-start 256M $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Failover: second component not found"

	flg_opts="--comp-flags extension"
	found=$($LFS find --comp-start 384M -E EOF $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Failover: extension component not found"

	sel_layout_sanity $comp_file 3
}
run_test 22a "Test repeat component behavior with degraded OST"

# Test repeat behavior with low space
test_22b() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	local flg_opts=""
	local found=""

	test_mkdir -p $DIR/$tdir

	# without this, a previous delete can finish after we check free space
	wait_delete_completed
	wait_mds_ost_sync

	$LFS setstripe -E -1 -c 1 -z 128M \
		$comp_file || error "Create $comp_file failed"

	# write past end of first component, so it is extended
	dd if=/dev/zero of=$comp_file bs=1M count=1 seek=130 ||
		error "dd to extend failed"

	flg_opts="--comp-flags extension"
	found=$($LFS find --comp-start 256M -E EOF $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: Second component not found"

	# set our OST low on space
	local ost_idx1=$($LFS getstripe -I1 -i $comp_file)
	local wms=$(ost_watermarks_set_low_space $ost_idx1 | grep "watermarks")

	stack_trap "ost_watermarks_clear_enospc $tfile $ost_idx1 $wms" EXIT

	# Write past end of current space, fail to extend, causing repeat
	dd if=/dev/zero of=$comp_file bs=1M count=1 seek=300 ||
		error "dd to repeat failed"

	$LFS getstripe $comp_file

	local ost_idx2=$($LFS getstripe -I2 -i $comp_file)

	[ $ost_idx1 -eq $ost_idx2 ] && error "$ost_idx1 == $ost_idx2"

	flg_opts="--comp-flags init"
	found=$($LFS find --comp-start 256M $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: Second component not found"

	flg_opts="--comp-flags extension"
	found=$($LFS find --comp-start 384M -E EOF $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: Extension component not found"

	sel_layout_sanity $comp_file 3
}
run_test 22b "Test simple 'out of space' condition with repeat"

# This tests both "repeat" and "extend in place when repeat fails" aspects
# of repeating components
test_22c() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	local flg_opts=""
	local found=""

	test_mkdir -p $DIR/$tdir

	# pool is used to limit available OSTs to 0 and 1, so we can set all
	# available OSTs out of space
	pool_add $TESTNAME || error "Pool creation failed"
	pool_add_targets $TESTNAME 0 1 || error "Pool add targets failed"

	# without this, a previous delete can finish after we check free space
	wait_delete_completed
	wait_mds_ost_sync

	$LFS setstripe -E -1 -z 64M -c 1 -p "$TESTNAME" $comp_file || \
		error "Create $comp_file failed"

	# write past end of first component, so it is extended
	dd if=/dev/zero of=$comp_file bs=1M count=1 seek=80 conv=notrunc ||
		error "dd to extend failed"

	$LFS getstripe $comp_file

	flg_opts="--comp-flags extension"
	found=$($LFS find --comp-start 128M -E EOF $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: second component not found"

	# set our OST out of space
	local ost_idx1=$($LFS getstripe -I1 -i $comp_file)
	local wms=$(ost_watermarks_set_enospc $tfile $ost_idx1 |
		    grep "watermarks")
	stack_trap "ost_watermarks_clear_enospc $tfile $ost_idx1 $wms" EXIT

	# This should create a repeat component on a new OST
	dd if=/dev/zero of=$comp_file bs=1M count=1 seek=180 conv=notrunc ||
		error "dd to repeat failed"

	$LFS getstripe $comp_file

	local comp_cnt=$($LFS getstripe --component-count $comp_file)
	[ $comp_cnt -ne 3 ] && error "component count: $comp_cnt, should be 3"

	# New second component should be on a different OST
	local ost_idx2=$($LFS getstripe --comp-start=128m \
			 --comp-end=192m --comp-flags=init -i $comp_file)

	[ $ost_idx1 -eq $ost_idx2 ] && error "2nd comp: same OST $ost_idx1"

	local wms2=$(ost_watermarks_set_enospc $tfile $ost_idx2 |
		     grep "watermarks")
	stack_trap "ost_watermarks_clear_enospc $tfile $ost_idx2 $wms2" EXIT

	# now that the second OST is out of space (as is the first OST), we
	# attempt to extend.  This should result in an extension of the
	# existing component, rather than a new component.
	dd if=/dev/zero of=$comp_file bs=1M count=1 seek=240 conv=notrunc ||
		error "dd for forced extension failed"

	$LFS getstripe $comp_file

	# clear out of space on first OST
	ost_watermarks_clear_enospc $tfile $ost_idx1 $wms

	# finally, now that the first OST has space again, we attempt to
	# extend one last time.  This should create a new component on the
	# first OST
	dd if=/dev/zero of=$comp_file bs=1M count=1 seek=300 conv=notrunc ||
		error "dd for repeat on first OST failed"

	$LFS getstripe $comp_file

	flg_opts="--comp-flags init"
	found=$($LFS find --comp-start 128M $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: second component not found"

	flg_opts="--comp-flags init"
	found=$($LFS find --comp-start 256M $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: third component not found"

	flg_opts="--comp-flags extension"
	found=$($LFS find --comp-start 320M -E EOF $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Write: extension component not found"

	sel_layout_sanity $comp_file 4
}
run_test 22c "Test repeat with out of space on > 1 OST"

test_22d_post_check() {
	local comp_file=$1
	local name=$2
	local flg_opts="--comp-flags init"
	local found=$($LFS find --comp-start 0M -E 128M $flg_opts $comp_file |
		      wc -l)
	[ $found -eq 1 ] || {
		$LFS getstripe $comp_file
		error "$name: second component not found"
	}

	flg_opts="--comp-flags extension"
	found=$($LFS find --comp-start 128M -E EOF $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "$name: third extension component not found"

	sel_layout_sanity $comp_file 2
}

test_22d_pre() {
	local comp_file=$1
	local wms="$2"
	local RC

	# write past end of first component
	dd if=/dev/zero of=$comp_file bs=1M count=1 seek=70
	RC=$?

	ost_watermarks_clear_enospc $tfile 0 $wms
	[ $RC -eq 0 ] || error "dd to force extend failed"

	test_22d_post_check $comp_file "Write"
}

test_22d() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	local flg_opts=""
	local found=""

	test_mkdir -p $DIR/$tdir

	# without this, a previous delete can finish after we check free space
	wait_delete_completed
	wait_mds_ost_sync

	# Pool allows us to force use of only certain OSTs
	pool_add $TESTNAME || error "Pool creation failed"
	pool_add_targets $TESTNAME 0 || error "Pool add targets failed"

	# 1. Fail to extend due to OOS, try to repeat within the same pool,
	# fail to stripe (again OOS) the 0-length component, remove the
	# repeated one, force the extension on the original one.
	$LFS setstripe -E -1 -p $TESTNAME -z 64M $comp_file ||
		error "Create $comp_file failed"

	replay_barrier $SINGLEMDS

	# set our OST out of space
	local wms=$(ost_watermarks_set_enospc $tfile 0 | grep "watermarks")

	test_22d_pre $comp_file "$wms"
	fail $SINGLEMDS
	test_22d_post_check $comp_file "Failover"

	# 2. repeat with low on space: 0-length repeated component will be
	# striped, but still fails to be extended; otherwise the same as (1).
	rm -f $comp_file
	$LFS setstripe -E -1 -p $TESTNAME -z 64M $comp_file ||
		error "Create $comp_file failed"

	replay_barrier $SINGLEMDS

	# set our OST low on space
	local wms=$(ost_watermarks_set_low_space 0 | grep "watermarks")

	test_22d_pre $comp_file "$wms"
	fail $SINGLEMDS
	test_22d_post_check $comp_file "Failover"
}
run_test 22d "out of/low on space + failed to repeat + forced extension"

test_23a() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	test_mkdir -p $DIR/$tdir

	$LFS setstripe -z 64M -c 1 -E -1 $comp_file ||
		error "Create $comp_file failed"

	dd if=/dev/zero bs=1M oflag=append count=1 of=$comp_file ||
		error "dd append failed"

	local flg_opts="--comp-start 0 -E EOF --comp-flags init"
	local found=$($LFS find $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Append: first component (0-EOF) not found"

	local ost_idx=$($LFS getstripe -I2 -i $comp_file)
	[ "$ost_idx" != "" ] && error "Append: second component still exists"

	sel_layout_sanity $comp_file 1
}
run_test 23a "Append: remove EXT comp"

test_23b() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	test_mkdir -p $DIR/$tdir

	$LFS setstripe -E 64m -E -1 -z 64M $comp_file ||
		error "Create $comp_file failed"

	dd if=/dev/zero bs=1M oflag=append count=1 of=$comp_file ||
		error "dd append failed"

	local flg_opts="--comp-start 64M -E EOF --comp-flags init"
	local found=$($LFS find $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Append: component (64M-EOF) not found"

	local ost_idx=$($LFS getstripe -I3 -i $comp_file)
	[ "$ost_idx" != "" ] && error "Append: third component still exists"

	sel_layout_sanity $comp_file 2
}
run_test 23b "Append with 0-length comp: remove EXT comp"

test_23c() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	test_mkdir -p $DIR/$tdir

	wait_delete_completed
	wait_mds_ost_sync

	pool_add $TESTNAME || error "Pool creation failed"
	pool_add_targets $TESTNAME 0 || error "Pool add targets failed"
	$LFS setstripe -E 64m -E -1 -p $TESTNAME -z 64M $comp_file ||
		error "Create $comp_file failed"

	local wms=$(ost_watermarks_set_low_space 0 | grep "watermarks")
	dd if=/dev/zero bs=1M oflag=append count=1 of=$comp_file
	RC=$?

	ost_watermarks_clear_enospc $tfile 0 $wms
	[ $RC -eq 0 ] || error "dd append failed: $RC"

	local flg_opts="--comp-start 64M -E EOF --comp-flags init"
	local found=$($LFS find $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Append: component (64M-EOF) not found"

	local ost_idx=$($LFS getstripe -I3 -i $comp_file)
	[ "$ost_idx" != "" ] && error "Append: EXT component still exists"

	sel_layout_sanity $comp_file 2
}
run_test 23c "Append with low on space + 0-length comp: force extension"

test_23d() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	test_mkdir -p $DIR/$tdir

	$LFS setstripe -E 64m -E 640M -z 64M -E -1 $comp_file ||
		error "Create $comp_file failed"

	dd if=/dev/zero bs=1M oflag=append count=1 of=$comp_file ||
		error "dd append failed"

	flg_opts="--comp-start 64M -E 640M --comp-flags init"
	found=$($LFS find $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Append: component (64M-640M) not found"

	ost_idx=$($LFS getstripe -I3 -i $comp_file)
	[ "$ost_idx" != "" ] && error "Append: third component still exists"

	sel_layout_sanity $comp_file 3
}
run_test 23d "Append with 0-length comp + next real comp: remove EXT comp"

test_23e() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	test_mkdir -p $DIR/$tdir

	wait_delete_completed
	wait_mds_ost_sync

	pool_add $TESTNAME || error "Pool creation failed"
	pool_add_targets $TESTNAME 0 || error "Pool add targets failed"

	$LFS setstripe -E 64m -E 640M -z 64M -p $TESTNAME -E -1 $comp_file ||
		error "Create $comp_file failed"

	local wms=$(ost_watermarks_set_low_space 0 | grep "watermarks")

	dd if=/dev/zero bs=1M oflag=append count=1 of=$comp_file
	RC=$?

	ost_watermarks_clear_enospc $tfile 0 $wms
	[ $RC -eq 0 ] || error "dd append failed $RC"

	local flg_opts="--comp-start 64M -E EOF --comp-flags init"
	local found=$($LFS find $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Append: component (64M-EOF) not found"

	local ost_idx=$($LFS getstripe -I2 -i $comp_file)
	[ "$ost_idx" != "" ] && error "Append: 0-length component still exists"
	ost_idx=$($LFS getstripe -I3 -i $comp_file)
	[ "$ost_idx" != "" ] && error "Append: extension component still exists"

	sel_layout_sanity $comp_file 2
}
run_test 23e "Append with next real comp: spillover and backward extension"

test_23f() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs"
	[ "$MDS1_VERSION" -lt $(version_code $SEL_VER) ] &&
		skip "skipped for lustre < $SEL_VER"

	local comp_file=$DIR/$tdir/$tfile
	test_mkdir -p $DIR/$tdir

	$LFS setstripe -z 64M -c 1 -E -1 $comp_file ||
		error "Create $comp_file failed"

	local ost_idx=$($LFS getstripe -I1 -i $comp_file)
	local wms=$(ost_watermarks_set_low_space $ost_idx | grep "watermarks")

	dd if=/dev/zero bs=1M oflag=append count=1 of=$comp_file
	RC=$?

	ost_watermarks_clear_enospc $tfile $ost_idx $wms
	[ $RC -eq 0 ] || error "dd append failed"

	local flg_opts="--comp-start 64M -E EOF --comp-flags init"
	local found=$($LFS find $flg_opts $comp_file | wc -l)
	[ $found -eq 1 ] || error "Append: component (64M-EOF) not found"

	ost_idx=$($LFS getstripe -I2 -i $comp_file)
	[ "$ost_idx" != "" ] && error "Append: extension component still exists"

	sel_layout_sanity $comp_file 2
}
run_test 23f "Append with low on space: repeat and remove EXT comp"

OLDIFS="$IFS"
cleanup_24() {
	trap 0
	IFS="$OLDIFS"
}

test_24a() {
	[ "$OSTCOUNT" -lt "3" ] && skip_env "needs >= 3 OSTs"

	trap cleanup_24 EXIT RETURN

	local file=$DIR/$tfile

	$LFS setstripe -E 1m -c1 -o0 -E eof -c2 -o1,2 $file ||
		error "setstripe on $file"

	dd if=/dev/zero of=$file bs=1M count=3 || error "dd failed for $file"
	sync

	filefrag -ves $file || error "filefrag $file failed"
	filefrag_op=$(filefrag -ve -k $file |
		      sed -n '/ext:/,/found/{/ext:/d; /found/d; p}')

#Filesystem type is: bd00bd0
#File size of /mnt/lustre/f24a.sanity-pfl is 3145728 (3072 blocks of 1024 bytes)
# ext:     device_logical:        physical_offset: length:  dev: flags:
#   0:        0..    1023:    1572864..   1573887:   1024: 0000: net
#   1:        0..    1023:    1572864..   1573887:   1024: 0002: net
#   2:     1024..    2047:    1573888..   1574911:   1024: 0001: last,net
#/mnt/lustre/f24a.sanity-pfl: 3 extents found

	last_lun=$(echo $filefrag_op | cut -d: -f5)

	IFS=$'\n'
	tot_len=0
	num_luns=1
	for line in $filefrag_op; do
		frag_lun=$(echo $line | cut -d: -f5)
		ext_len=$(echo $line | cut -d: -f4)
		if [[ "$frag_lun" != "$last_lun" ]]; then
			if (( tot_len != 1024 )); then
				cleanup_24
				error "$file: OST$last_lun $tot_len != 1024"
			else
				(( num_luns += 1 ))
				tot_len=0
			fi
		fi
		(( tot_len += ext_len ))
		last_lun=$frag_lun
	done
	if (( num_luns != 3 || tot_len != 1024 )); then
		cleanup_24
		error "$file: $num_luns != 3, $tot_len != 1024 on OST$last_lun"
	fi

	echo "FIEMAP on $file succeeded"
}
run_test 24a "FIEMAP upon PFL file"

test_25() {
	local pfl_f=$DIR/$tdir/"$tfile"_pfl
	local dom_f=$DIR/$tdir/"$tfile"_dom
	local common_f=$DIR/$tdir/"$tfile"_common
	local stripe_count
	local stripe_size

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	$LFS setstripe -E 10M -S 64k -c -1 -E 20M -S 1M -E -1 -S 2M -c 1 \
		$pfl_f || error "setstripe $pfl_f failed"
	$LFS setstripe -E 256k -L mdt -E -1 -S 1M $dom_f ||
		error "setstripe $dom_f failed"
	$LFS setstripe -S 512K -c -1 $common_f ||
		error "setstripe $common_f failed"

	#verify lov_getstripe_old with PFL file
	stripe_count=$(lov_getstripe_old $pfl_f |
			awk '/stripe_count/ { print $2 }')
	stripe_size=$(lov_getstripe_old $pfl_f |
			awk '/stripe_size/ { print $2 }')
	[ $stripe_count -eq 1 ] ||
		error "stripe_count $stripe_count !=1 for $pfl_f"
	[ $stripe_size -eq 2097152 ] ||
		error "stripe_size $stripe_size != 2097152 for $pfl_f"

	#verify lov_getstripe_old with DoM file
	stripe_count=$(lov_getstripe_old $dom_f |
			awk '/stripe_count/ { print $2 }')
	stripe_size=$(lov_getstripe_old $dom_f |
			awk '/stripe_size/ { print $2 }')
	[ $stripe_count -eq 1 ] ||
		error "stripe_count $stripe_count !=1 for $dom_f"
	[ $stripe_size -eq 1048576 ] ||
		error "stripe_size $stripe_size != 1048576 for $dom_f"

	#verify lov_getstripe_old with common file
	stripe_count=$(lov_getstripe_old $common_f |
			awk '/stripe_count/ { print $2 }')
	stripe_size=$(lov_getstripe_old $common_f |
			awk '/stripe_size/ { print $2 }')
	[ $stripe_count -eq $OSTCOUNT ] ||
		error "stripe_count $stripe_count !=$OSTCOUNT for $common_f"
	[ $stripe_size -eq 524288 ] ||
		error "stripe_size $stripe_size != 524288 for $common_f"
}
run_test 25 "Verify old lov stripe API with PFL files"

complete $SECONDS
check_and_cleanup_lustre
exit_status
