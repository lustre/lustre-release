#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# e.g. ONLY="22 23" or ONLY="`seq 32 39`" or EXCEPT="31"
set -e

ONLY=${ONLY:-"$*"}
ALWAYS_EXCEPT=${ALWAYS_EXCEPT:-"34 35"}	# bugs 1365 and 1360 respectively

SRCDIR=`dirname $0`
PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$PATH

CHECKSTAT=${CHECKSTAT:-"./checkstat -v"}
CREATETEST=${CREATETEST:-createtest}
LFIND=${LFIND:-lfind}
LSTRIPE=${LSTRIPE:-lstripe}
LCTL=${LCTL:-lctl}
MCREATE=${MCREATE:-mcreate}
TOEXCL=${TOEXCL:-toexcl}
TRUNCATE=${TRUNCATE:-truncate}

if [ $UID -ne 0 ]; then
	RUNAS_ID="$UID"
	RUNAS=""
else
	RUNAS_ID=${RUNAS_ID:-500}
	RUNAS=${RUNAS:-"runas -u $RUNAS_ID"}
fi

MOUNT=${MOUNT:-/mnt/lustre}
DIR=${DIR:-$MOUNT}
export NAME=$NAME

SAVE_PWD=$PWD

clean() {
        echo -n "cln.."
        sh llmountcleanup.sh > /dev/null || exit 20
}

CLEAN=${CLEAN:-clean}
start() {
        echo -n "mnt.."
        sh llrmount.sh > /dev/null || exit 10
        echo "done"
}
START=${START:-start}

log() {
	echo "$*"
	lctl mark "$*" || true
}

run_one() {
	if ! mount | grep -q $MOUNT; then
		$START
	fi
	log "== test $1: $2"
	test_$1 || error
	pass
	cd $SAVE_PWD
	$CLEAN
}

run_test() {
	for O in $ONLY; do
		if [ "`echo $1 | grep '\<'$O'[a-z]*\>'`" ]; then
			echo ""
			run_one $1 "$2"
			return $?
		else
			echo -n "."
		fi
	done
	for X in $EXCEPT $ALWAYS_EXCEPT; do
		if [ "`echo $1 | grep '\<'$X'[a-z]*\>'`" ]; then
			echo "skipping excluded test $1"
			return 0
		fi
	done
	if [ -z "$ONLY" ]; then
		run_one $1 "$2"
		return $?
	fi
}

error() { 
    echo FAIL
    exit 1
}

pass() { 
    echo PASS
}

if ! mount | grep $MOUNT; then
	sh llmount.sh
	I_MOUNTED=yes
fi

echo preparing for tests involving mounts
EXT2_DEV=/tmp/SANITY.LOOP
dd if=/dev/zero of=$EXT2_DEV bs=1k seek=1000 count=1 > /dev/null
mke2fs -F $EXT2_DEV > /dev/null

test_0() {
	touch $DIR/f
	$CHECKSTAT -t file $DIR/f || error 
	rm $DIR/f
	$CHECKSTAT -a $DIR/f || error
}
run_test 0 "touch .../f ; rm .../f ============================="

test_1a() {
	mkdir $DIR/d1
	mkdir $DIR/d1/d2
	$CHECKSTAT -t dir $DIR/d1/d2 || error
}
run_test 1a "mkdir .../d1; mkdir .../d1/d2 ====================="

test_1b() {
	rmdir $DIR/d1/d2
	rmdir $DIR/d1
	$CHECKSTAT -a $DIR/d1 || error
}
run_test 1b "rmdir .../d1/d2; rmdir .../d1 ====================="

test_2a() {
	mkdir $DIR/d2
	touch $DIR/d2/f
	$CHECKSTAT -t file $DIR/d2/f || error
}
run_test 2a "mkdir .../d2; touch .../d2/f ======================"

test_2b() {
	rm -r $DIR/d2
	$CHECKSTAT -a $DIR/d2 || error
}
run_test 2b "rm -r .../d2; touch .../d2/f ======================"

test_3a() {
	mkdir $DIR/d3
	$CHECKSTAT -t dir $DIR/d3 || error
}
run_test 3a "mkdir .../d3 ======================================"

test_3b() {
	touch $DIR/d3/f
	$CHECKSTAT -t file $DIR/d3/f || error
}
run_test 3b "touch .../d3/f ===================================="

test_3c() {
	rm -r $DIR/d3
	$CHECKSTAT -a $DIR/d3 || error
}
run_test 3c "rm -r .../d3 ======================================"

test_4a() {
	mkdir $DIR/d4
	$CHECKSTAT -t dir $DIR/d4 || error
}
run_test 4a "mkdir .../d4 ======================================"

test_4b() {
	mkdir $DIR/d4/d2
	$CHECKSTAT -t dir $DIR/d4/d2 || error
}
run_test 4b "mkdir .../d4/d2 ==================================="

test_5() {
	mkdir $DIR/d5
	mkdir $DIR/d5/d2
	chmod 0707 $DIR/d5/d2
	$CHECKSTAT -t dir -p 0707 $DIR/d5/d2 || error
}
run_test 5 "mkdir .../d5 .../d5/d2; chmod .../d5/d2 ============"

test_6() {
	touch $DIR/f6
	chmod 0666 $DIR/f6
	$CHECKSTAT -t file -p 0666 $DIR/f6 || error
}
run_test 6 "touch .../f6; chmod .../f6 ========================="

test_7a() {
	mkdir $DIR/d7
	$MCREATE $DIR/d7/f
	chmod 0666 $DIR/d7/f
	$CHECKSTAT -t file -p 0666 $DIR/d7/f || error
}
run_test 7a "mkdir .../d7; mcreate .../d7/f; chmod .../d7/f ===="

test_7b() {
	$MCREATE $DIR/d7/f2
	echo -n foo > $DIR/d7/f2
	[ "`cat $DIR/d7/f2`" = "foo" ] || error
	$CHECKSTAT -t file -s 3 $DIR/d7/f2 || error
}
run_test 7b "mkdir .../d7; mcreate d7/f2; echo foo > d7/f2 ====="

test_8() {
	mkdir $DIR/d8
	touch $DIR/d8/f
	chmod 0666 $DIR/d8/f
	$CHECKSTAT -t file -p 0666 $DIR/d8/f || error
}
run_test 8 "mkdir .../d8; touch .../d8/f; chmod .../d8/f ======="

test_9() {
	mkdir $DIR/d9
	mkdir $DIR/d9/d2
	mkdir $DIR/d9/d2/d3
	$CHECKSTAT -t dir $DIR/d9/d2/d3 || error
}
run_test 9 "mkdir .../d9 .../d9/d2 .../d9/d2/d3 ================"

test_10() {
	mkdir $DIR/d10
	mkdir $DIR/d10/d2
	touch $DIR/d10/d2/f
	$CHECKSTAT -t file $DIR/d10/d2/f || error
}
run_test 10 "mkdir .../d10 .../d10/d2; touch .../d10/d2/f ======"

test_11() {
	mkdir $DIR/d11
	mkdir $DIR/d11/d2
	chmod 0666 $DIR/d11/d2
	chmod 0705 $DIR/d11/d2
	$CHECKSTAT -t dir -p 0705 $DIR/d11/d2 || error
}
run_test 11 "mkdir .../d11 d11/d2; chmod .../d11/d2 ============"

test_12() {
	mkdir $DIR/d12
	touch $DIR/d12/f
	chmod 0666 $DIR/d12/f
	chmod 0654 $DIR/d12/f
	$CHECKSTAT -t file -p 0654 $DIR/d12/f || error
}
run_test 12 "touch .../d12/f; chmod .../d12/f .../d12/f ========"

test_13() {
	mkdir $DIR/d13
	dd if=/dev/zero of=$DIR/d13/f count=10
	>  $DIR/d13/f
	$CHECKSTAT -t file -s 0 $DIR/d13/f || error
}
run_test 13 "creat .../d13/f; dd .../d13/f; > .../d13/f ========"

test_14() {
	mkdir $DIR/d14
	touch $DIR/d14/f
	rm $DIR/d14/f
	$CHECKSTAT -a $DIR/d14/f || error
}
run_test 14 "touch .../d14/f; rm .../d14/f; rm .../d14/f ======="

test_15() {
	mkdir $DIR/d15
	touch $DIR/d15/f
	mv $DIR/d15/f $DIR/d15/f2
	$CHECKSTAT -t file $DIR/d15/f2 || error
}
run_test 15 "touch .../d15/f; mv .../d15/f .../d15/f2 =========="

test_16() {
	mkdir $DIR/d16
	touch $DIR/d16/f
	rm -rf $DIR/d16/f
	$CHECKSTAT -a $DIR/d16/f || error
}
run_test 16 "touch .../d16/f; rm -rf .../d16/f ================="

test_17a() {
	mkdir $DIR/d17
	touch $DIR/d17/f
	ln -s $DIR/d17/f $DIR/d17/l-exist
	ls -l $DIR/d17
	$CHECKSTAT -l $DIR/d17/f $DIR/d17/l-exist || error
	$CHECKSTAT -f -t f $DIR/d17/l-exist || error
	rm -f $DIR/l-exist
	$CHECKSTAT -a $DIR/l-exist || error
}
run_test 17a "symlinks: create, remove (real) =================="

test_17b() {
	ln -s no-such-file $DIR/d17/l-dangle
	ls -l $DIR/d17
	$CHECKSTAT -l no-such-file $DIR/d17/l-dangle || error
	$CHECKSTAT -fa $DIR/d17/l-dangle || error
	rm -f $DIR/l-dangle
	$CHECKSTAT -a $DIR/l-dangle || error
}
run_test 17b "symlinks: create, remove (dangling) =============="

test_18() {
	touch $DIR/f
	ls $DIR || error
}
run_test 18 "touch .../f ; ls ... =============================="

test_19() {
	touch $DIR/f
	ls -l $DIR
	rm $DIR/f
	$CHECKSTAT -a $DIR/f || error
}
run_test 19 "touch .../f ; ls -l ... ==========================="

test_20() {
	touch $DIR/f
	rm $DIR/f
	log "1 done"
	touch $DIR/f
	rm $DIR/f
	log "2 done"
	touch $DIR/f
	rm $DIR/f
	log "3 done"
	$CHECKSTAT -a $DIR/f || error
}
run_test 20 "touch .../f ; ls -l ... ==========================="

test_21() {
	mkdir $DIR/d21
	[ -f $DIR/d21/dangle ] && rm -f $DIR/d21/dangle
	ln -s dangle $DIR/d21/link
	echo foo >> $DIR/d21/link
	cat $DIR/d21/dangle
	$CHECKSTAT -t link $DIR/d21/link || error
	$CHECKSTAT -f -t file $DIR/d21/link || error
}
run_test 21 "write to dangling link ============================"

test_22() {
	mkdir $DIR/d22
	chown $RUNAS_ID $DIR/d22
	# Tar gets pissy if it can't access $PWD *sigh*
	(cd /tmp;
	$RUNAS tar cf - /etc/hosts /etc/sysconfig/network | \
	$RUNAS tar xfC - $DIR/d22)
	ls -lR $DIR/d22/etc
	$CHECKSTAT -t dir $DIR/d22/etc || error
	$CHECKSTAT -u \#$RUNAS_ID $DIR/d22/etc || error
}
run_test 22 "unpack tar archive as non-root user ==============="

test_23() {
	mkdir $DIR/d23
	$TOEXCL $DIR/d23/f23
	$TOEXCL -e $DIR/d23/f23 || error
}
run_test 23 "O_CREAT|O_EXCL in subdir =========================="

test_24a() {
	echo '============ rename sanity ================================='
	echo '-- same directory rename'
	mkdir $DIR/R1
	touch $DIR/R1/f
	mv $DIR/R1/f $DIR/R1/g
	$CHECKSTAT -t file $DIR/R1/g || error
}
run_test 24a "touch .../R1/f; rename .../R1/f .../R1/g ========="

test_24b() {
	mkdir $DIR/R2
	touch $DIR/R2/{f,g}
	mv $DIR/R2/f $DIR/R2/g
	$CHECKSTAT -a $DIR/R2/f || error
	$CHECKSTAT -t file $DIR/R2/g || error
}
run_test 24b "touch .../R2/{f,g}; rename .../R2/f .../R2/g ====="

test_24c() {
	mkdir $DIR/R3
	mkdir $DIR/R3/f
	mv $DIR/R3/f $DIR/R3/g
	$CHECKSTAT -a $DIR/R3/f || error
	$CHECKSTAT -t dir $DIR/R3/g || error
}
run_test 24c "mkdir .../R3/f; rename .../R3/f .../R3/g ========="

test_24d() {
	mkdir $DIR/R4
	mkdir $DIR/R4/{f,g}
	perl -e "rename \"$DIR/R4/f\", \"$DIR/R4/g\";"
	$CHECKSTAT -a $DIR/R4/f || error
	$CHECKSTAT -t dir $DIR/R4/g || error
}
run_test 24d "mkdir .../R4/{f,g}; rename .../R4/f .../R4/g ====="

test_24e() {
	echo '-- cross directory renames --' 
	mkdir $DIR/R5{a,b}
	touch $DIR/R5a/f
	mv $DIR/R5a/f $DIR/R5b/g
	$CHECKSTAT -a $DIR/R5a/f || error
	$CHECKSTAT -t file $DIR/R5b/g || error
}
run_test 24e "touch .../R5a/f; rename .../R5a/f .../R5b/g ======"

test_24f() {
	mkdir $DIR/R6{a,b}
	touch $DIR/R6a/f $DIR/R6b/g
	mv $DIR/R6a/f $DIR/R6b/g
	$CHECKSTAT -a $DIR/R6a/f || error
	$CHECKSTAT -t file $DIR/R6b/g || error
}
run_test 24f "touch .../R6a/f R6b/g; mv .../R6a/f .../R6b/g ===="

test_24g() {
	mkdir $DIR/R7{a,b}
	mkdir $DIR/R7a/d
	mv $DIR/R7a/d $DIR/R7b/e
	$CHECKSTAT -a $DIR/R7a/d || error
	$CHECKSTAT -t dir $DIR/R7b/e || error
}
run_test 24g "mkdir .../R7a/d; rename .../R7a/d .../R5b/e ======"

test_24h() {
	mkdir $DIR/R8{a,b}
	mkdir $DIR/R8a/d $DIR/R8b/e
	perl -e "rename \"$DIR/R8a/d\", \"$DIR/R8b/e\";"
	$CHECKSTAT -a $DIR/R8a/d || error
	$CHECKSTAT -t dir $DIR/R8b/e || error
}
run_test 24h "mkdir .../R8{a,b} R8a/{d,e}; mv .../R8a/d .../R8b/e"

test_24i() {
	echo "-- rename error cases"
	mkdir $DIR/R9
	mkdir $DIR/R9/a
	touch $DIR/R9/f
	perl -e "rename \"$DIR/R9/f\", \"$DIR/R9/a\";"
	$CHECKSTAT -t file $DIR/R9/f || error
	$CHECKSTAT -t dir  $DIR/R9/a || error
	$CHECKSTAT -a file $DIR/R9/a/f || error
}
run_test 24i "rename file to dir error: touch f ; mkdir a ; rename f a ====="

test_24j() {
	mkdir $DIR/R10
	perl -e "rename \"$DIR/R10/f\", \"$DIR/R10/g\"" 
	$CHECKSTAT -t dir $DIR/R10 || error
	$CHECKSTAT -a $DIR/R10/f || error
	$CHECKSTAT -a $DIR/R10/g || error
}
run_test 24j "source does not exist ============================" 

test_25a() {
	echo '== symlink sanity ======================================='
	mkdir $DIR/d25
	ln -s d25 $DIR/s25
	touch $DIR/s25/foo || error
}
run_test 25a "create file in symlinked directory ==============="

test_25b() {
	$CHECKSTAT -t file $DIR/s25/foo || error
}
run_test 25b "lookup file in symlinked directory ==============="

test_26a() {
	mkdir $DIR/d26
	mkdir $DIR/d26/d26-2
	ln -s d26/d26-2 $DIR/s26
	touch $DIR/s26/foo || error
}
run_test 26a "multiple component symlink ======================="

test_26b() {
	ln -s d26/d26-2/foo $DIR/s26-2
	touch $DIR/s26-2 || error
}
run_test 26b "multiple component symlink at end of lookup ======"

test_26c() {
	mkdir $DIR/d26.2
	touch $DIR/d26.2/foo
	ln -s d26.2 $DIR/s26.2-1
	ln -s s26.2-1 $DIR/s26.2-2
	ln -s s26.2-2 $DIR/s26.2-3
	chmod 0666 $DIR/s26.2-3/foo
}
run_test 26c "chain of symlinks ================================"

# recursive symlinks (bug 439)
test_26d() {
	ln -s d26-3/foo $DIR/d26-3
}
run_test 26d "create multiple component recursive symlink ======"

test_26e() {
	rm $DIR/d26-3
}
run_test 26e "unlink multiple component recursive symlink ======"

test_27a() {
	echo '== stripe sanity ========================================'
	mkdir $DIR/d27
	$LSTRIPE $DIR/d27/f0 8192 0 1
	$CHECKSTAT -t file $DIR/d27/f0
	pass
	log "test_27b: write to one stripe file ========================="
	cp /etc/hosts $DIR/d27/f0
}
run_test 27a "one stripe file =================================="

test_27c() {
	$LSTRIPE $DIR/d27/f01 8192 0 2
	pass
	log "test_27d: write to two stripe file file f01 ================"
	dd if=/dev/zero of=$DIR/d27/f01 bs=4k count=4
}
run_test 27c "create two stripe file f01 ======================="

test_27d() {
	$LSTRIPE $DIR/d27/fdef 0 -1 0
	$CHECKSTAT -t file $DIR/d27/fdef
	#dd if=/dev/zero of=$DIR/d27/fdef bs=4k count=4
}
run_test 27d "create file with default settings ================"

test_27e() {
	$LSTRIPE $DIR/d27/f12 8192 1 2
	$LSTRIPE $DIR/d27/f12 8192 1 2 && error
	$CHECKSTAT -t file $DIR/d27/f12 || error
	#dd if=/dev/zero of=$DIR/d27/f12 bs=4k count=4
}
run_test 27e "lstripe existing file (should return error) ======"


test_27f() {
	$LSTRIPE $DIR/d27/fbad 100 1 2 || true
	dd if=/dev/zero of=$DIR/d27/f12 bs=4k count=4
}
run_test 27f "lstripe with bad stripe size (should return error on LOV)"

test_27g() {
	$MCREATE $DIR/d27/fnone || error
	pass
	log "test 27.9: lfind ============================================"
	$LFIND $DIR/d27
}
run_test 27g "mcreate file without objects to test lfind ======="

test_28() {
	mkdir $DIR/d28
	$CREATETEST $DIR/d28/ct || error
}
run_test 28 "create/mknod/mkdir with bad file types ============"

test_29() {
	mkdir $DIR/d29
	touch $DIR/d29/foo
	log 'first d29'
	ls -l $DIR/d29
	MDCDIR=${MDCDIR:-/proc/fs/lustre/ldlm/ldlm/MDC_*}
	LOCKCOUNTORIG=`cat $MDCDIR/lock_count`
	LOCKUNUSEDCOUNTORIG=`cat $MDCDIR/lock_unused_count`
	log 'second d29'
	ls -l $DIR/d29
	log 'done'
	LOCKCOUNTCURRENT=`cat $MDCDIR/lock_count`
	LOCKUNUSEDCOUNTCURRENT=`cat $MDCDIR/lock_unused_count`
	if [ $LOCKCOUNTCURRENT -gt $LOCKCOUNTORIG ]; then
		echo "CURRENT: $LOCKCOUNTCURRENT > $LOCKCOUNTORIG"
		error
	fi
	if [ $LOCKUNUSEDCOUNTCURRENT -gt $LOCKUNUSEDCOUNTORIG ]; then
		echo "UNUSED: $LOCKUNUSEDCOUNTCURRENT > $LOCKUNUSEDCOUNTORIG"
		error
	fi
}
run_test 29 "IT_GETATTR regression  ============================"

test_30() {
	cp `which ls` $DIR
	$DIR/ls /
	rm $DIR/ls
}
run_test 30 "run binary from Lustre (execve) ==================="

test_31() {
	./openunlink $DIR/f31 $DIR/f31 || error
}
run_test 31 "open-unlink file =================================="

test_32a() {
	echo "== more mountpoints and symlinks ================="
	[ -e $DIR/d32a ] && rm -fr $DIR/d32a
	mkdir -p $DIR/d32a/ext2-mountpoint 
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32a/ext2-mountpoint || error
	$CHECKSTAT -t dir $DIR/d32a/ext2-mountpoint/.. || error  
	umount $DIR/d32a/ext2-mountpoint || error
}
run_test 32a "stat d32a/ext2-mountpoint/.. ====================="

test_32b() {
	[ -e $DIR/d32b ] && rm -fr $DIR/d32b
	mkdir -p $DIR/d32b/ext2-mountpoint 
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32b/ext2-mountpoint || error
	ls -al $DIR/d32b/ext2-mountpoint/.. || error
	umount $DIR/d32b/ext2-mountpoint || error
}
run_test 32b "open d32b/ext2-mountpoint/.. ====================="
 
test_32c() {
	[ -e $DIR/d32c ] && rm -fr $DIR/d32c
	mkdir -p $DIR/d32c/ext2-mountpoint 
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32c/ext2-mountpoint || error
	mkdir -p $DIR/d32c/d2/test_dir    
	$CHECKSTAT -t dir $DIR/d32c/ext2-mountpoint/../d2/test_dir || error
	umount $DIR/d32c/ext2-mountpoint || error
}
run_test 32c "stat d32c/ext2-mountpoint/../d2/test_dir ========="

test_32d() {
	[ -e $DIR/d32d ] && rm -fr $DIR/d32d
	mkdir -p $DIR/d32d/ext2-mountpoint 
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32d/ext2-mountpoint || error
	mkdir -p $DIR/d32d/d2/test_dir    
	ls -al $DIR/d32d/ext2-mountpoint/../d2/test_dir || error
	umount $DIR/d32d/ext2-mountpoint || error
}
run_test 32d "open d32d/ext2-mountpoint/../d2/test_dir =========="

test_32e() {
	[ -e $DIR/d32e ] && rm -fr $DIR/d32e
	mkdir -p $DIR/d32e/tmp    
	TMP_DIR=$DIR/d32e/tmp       
	ln -s $DIR/d32e $TMP_DIR/symlink11 
	ln -s $TMP_DIR/symlink11 $TMP_DIR/../symlink01 
	$CHECKSTAT -t link $DIR/d32e/tmp/symlink11 || error
	$CHECKSTAT -t link $DIR/d32e/symlink01 || error
}
run_test 32e "stat d32e/symlink->tmp/symlink->lustre-subdir ====="

test_32f() {
	[ -e $DIR/d32f ] && rm -fr $DIR/d32f
	mkdir -p $DIR/d32f/tmp    
	TMP_DIR=$DIR/d32f/tmp       
	ln -s $DIR/d32f $TMP_DIR/symlink11 
	ln -s $TMP_DIR/symlink11 $TMP_DIR/../symlink01 
	ls $DIR/d32f/tmp/symlink11  || error
	ls $DIR/d32f/symlink01 || error
}
run_test 32f "open d32f/symlink->tmp/symlink->lustre-subdir ====="

test_32g() {
	[ -e $DIR/d32g ] && rm -fr $DIR/d32g
	[ -e $DIR/test_dir ] && rm -fr $DIR/test_dir
	mkdir -p $DIR/test_dir 
	mkdir -p $DIR/d32g/tmp    
	TMP_DIR=$DIR/d32g/tmp       
	ln -s $DIR/test_dir $TMP_DIR/symlink12 
	ln -s $TMP_DIR/symlink12 $TMP_DIR/../symlink02 
	$CHECKSTAT -t link $DIR/d32g/tmp/symlink12 || error
	$CHECKSTAT -t link $DIR/d32g/symlink02 || error
	$CHECKSTAT -t dir -f $DIR/d32g/tmp/symlink12 || error
	$CHECKSTAT -t dir -f $DIR/d32g/symlink02 || error
}
run_test 32g "stat d32g/symlink->tmp/symlink->lustre-subdir/test_dir"

test_32h() {
	[ -e $DIR/d32h ] && rm -fr $DIR/d32h
	[ -e $DIR/test_dir ] && rm -fr $DIR/test_dir
	mkdir -p $DIR/test_dir 
	mkdir -p $DIR/d32h/tmp    
	TMP_DIR=$DIR/d32h/tmp       
	ln -s $DIR/test_dir $TMP_DIR/symlink12 
	ln -s $TMP_DIR/symlink12 $TMP_DIR/../symlink02 
	ls $DIR/d32h/tmp/symlink12 || error
	ls $DIR/d32h/symlink02  || error
}
run_test 32h "open d32h/symlink->tmp/symlink->lustre-subdir/test_dir"

test_32i() {
	[ -e $DIR/d32i ] && rm -fr $DIR/d32i
	mkdir -p $DIR/d32i/ext2-mountpoint 
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32i/ext2-mountpoint || error
	touch $DIR/d32i/test_file
	$CHECKSTAT -t file $DIR/d32i/ext2-mountpoint/../test_file || error  
	umount $DIR/d32i/ext2-mountpoint || error
}
run_test 32i "stat d32i/ext2-mountpoint/../test_file ============"

test_32j() {
	[ -e $DIR/d32j ] && rm -fr $DIR/d32j
	mkdir -p $DIR/d32j/ext2-mountpoint 
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32j/ext2-mountpoint || error
	touch $DIR/d32j/test_file
	cat $DIR/d32j/ext2-mountpoint/../test_file || error
	umount $DIR/d32j/ext2-mountpoint || error
}
run_test 32j "open d32j/ext2-mountpoint/../test_file ============"

test_32k() {
	[ -e $DIR/d32k ] && rm -fr $DIR/d32k
	mkdir -p $DIR/d32k/ext2-mountpoint 
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32k/ext2-mountpoint  
	mkdir -p $DIR/d32k/d2
	touch $DIR/d32k/d2/test_file || error
	$CHECKSTAT -t file $DIR/d32k/ext2-mountpoint/../d2/test_file || error
	umount $DIR/d32k/ext2-mountpoint || error
}
run_test 32k "stat d32k/ext2-mountpoint/../d2/test_file ========="

test_32l() {
	[ -e $DIR/d32l ] && rm -fr $DIR/d32l
	mkdir -p $DIR/d32l/ext2-mountpoint 
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32l/ext2-mountpoint || error
	mkdir -p $DIR/d32l/d2
	touch $DIR/d32l/d2/test_file
	cat  $DIR/d32l/ext2-mountpoint/../d2/test_file || error
	umount $DIR/d32l/ext2-mountpoint || error
}
run_test 32l "open d32l/ext2-mountpoint/../d2/test_file ========="

test_32m() {
	[ -e $DIR/d32m ] && rm -fr $DIR/d32m
	mkdir -p $DIR/d32m/tmp    
	TMP_DIR=$DIR/d32m/tmp       
	ln -s $DIR $TMP_DIR/symlink11 
	ln -s $TMP_DIR/symlink11 $TMP_DIR/../symlink01 
	$CHECKSTAT -t link $DIR/d32m/tmp/symlink11 || error
	$CHECKSTAT -t link $DIR/d32m/symlink01 || error
}
run_test 32m "stat d32m/symlink->tmp/symlink->lustre-root ======="

test_32n() {
	[ -e $DIR/d32n ] && rm -fr $DIR/d32n
	mkdir -p $DIR/d32n/tmp    
	TMP_DIR=$DIR/d32n/tmp       
	ln -s $DIR $TMP_DIR/symlink11 
	ln -s $TMP_DIR/symlink11 $TMP_DIR/../symlink01 
	ls -l $DIR/d32n/tmp/symlink11  || error
	ls -l $DIR/d32n/symlink01 || error
}
run_test 32n "open d32n/symlink->tmp/symlink->lustre-root ======="

test_32o() {
	[ -e $DIR/d32o ] && rm -fr $DIR/d32o
	[ -e $DIR/test_file ] && rm -fr $DIR/test_file
	touch $DIR/test_file 
	mkdir -p $DIR/d32o/tmp    
	TMP_DIR=$DIR/d32o/tmp       
	ln -s $DIR/test_file $TMP_DIR/symlink12 
	ln -s $TMP_DIR/symlink12 $TMP_DIR/../symlink02 
	$CHECKSTAT -t link $DIR/d32o/tmp/symlink12 || error
	$CHECKSTAT -t link $DIR/d32o/symlink02 || error
	$CHECKSTAT -t file -f $DIR/d32o/tmp/symlink12 || error
	$CHECKSTAT -t file -f $DIR/d32o/symlink02 || error
}
run_test 32o "stat d32o/symlink->tmp/symlink->lustre-root/test_file"

test_32p() {
	[ -e $DIR/d32p ] && rm -fr $DIR/d32p
	[ -e $DIR/test_file ] && rm -fr $DIR/test_file
	touch $DIR/test_file 
	mkdir -p $DIR/d32p/tmp    
	TMP_DIR=$DIR/d32p/tmp       
	ln -s $DIR/test_file $TMP_DIR/symlink12 
	ln -s $TMP_DIR/symlink12 $TMP_DIR/../symlink02 
	cat $DIR/d32p/tmp/symlink12 || error
	cat $DIR/d32p/symlink02  || error
}
run_test 32p "open d32p/symlink->tmp/symlink->lustre-root/test_file"

#   chmod 444 /mnt/lustre/somefile
#   open(/mnt/lustre/somefile, O_RDWR)
#   Should return -1
test_33() {
	[ -e $DIR/test_33_file ] && rm -fr $DIR/test_33_file
	touch $DIR/test_33_file
	chmod 444 $DIR/test_33_file
	chown $RUNAS_ID $DIR/test_33_file
	$RUNAS openfile -f O_RDWR $DIR/test_33_file && error || true
}
run_test 33 "write file with mode 444 (should return error) ===="

test_34() {
	$MCREATE $DIR/f
	$TRUNCATE $DIR/f 100
	rm $DIR/f
}
run_test 34 "truncate file that has not been opened ============"

test_35() {
	[ -e $DIR/test_35_file ] && rm -fr $DIR/test_35_file
	cp /bin/sh $DIR/test_35_file
	chmod 444 $DIR/test_35_file
	chown $RUNAS_ID $DIR/test_35_file
	$DIR/test_35_file && error
	return 0
}
run_test 35 "exec file with mode 444 (should return error) ====="

test_36a() {
	log 36  "cvs operations ===================================="
	mkdir -p $DIR/cvsroot
	chown $RUNAS_ID $DIR/cvsroot
	$RUNAS cvs -d $DIR/cvsroot init 
}
run_test 36a "cvs init ========================================="

test_36b() {
	# on the LLNL clusters, runas will still pick up root's $TMP settings,
        # which will not be writable for the runas user, and then you get a CVS
	# error message with a corrupt path string (CVS bug) and panic.
	# We're not using much space, so just stick it in /tmp, which is
	# safe.
	OLDTMPDIR=$TMPDIR
	OLDTMP=$TMP
	TMPDIR=/tmp
	TMP=/tmp

	cd /etc/init.d
	$RUNAS cvs -d $DIR/cvsroot import -m "nomesg"  reposname vtag rtag

	TMPDIR=$OLDTMPDIR
	TMP=$OLDTMP
}
run_test 36b "cvs import ======================================="

test_36c() {
	cd $DIR
	mkdir -p $DIR/reposname
	chown $RUNAS_ID $DIR/reposname
	$RUNAS cvs -d $DIR/cvsroot co reposname
}
run_test 36c "cvs checkout ====================================="

test_36d() {
	cd $DIR/reposname
	$RUNAS touch foo36
	$RUNAS cvs add -m 'addmsg' foo36
}
run_test 36d "cvs add =========================================="

test_36e() {
	cd $DIR/reposname
	$RUNAS cvs update
}
run_test 36e "cvs update ======================================="

# XXX change this: use a non root user
test_36f() {
	cd $DIR/reposname
	$RUNAS cvs commit -m 'nomsg' foo36
}
run_test 36f "cvs commit ======================================="

test_37() {
	mkdir -p $DIR/dextra
	echo f > $DIR/dextra/fbugfile
	mount -t ext2 -o loop /$EXT2_DEV $DIR/dextra
	ls $DIR/dextra |grep "\<fbugfile\>" && error
	umount /$EXT2_DEV
	rm -f DIR/dextra/fbugfile
}
run_test 37 "ls a mounted file system to check the old contents ====="

# open(file, O_DIRECTORY) will leak a request and not cleanup (bug 1501)
test_38() {
        o_directory $DIR/test38
}
run_test 38 "open a regular file with O_DIRECTORY =============="
        

log "cleanup: ======================================================"
rm -r $DIR/[Rdfs][1-9]*
if [ "$I_MOUNTED" = "yes" ]; then
	sh llmountcleanup.sh || error
fi

echo '=========================== finished ==============================='
