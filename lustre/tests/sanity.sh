#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# e.g. ONLY="22 23" or ONLY="`seq 32 39`" or EXCEPT="31"
set -e

ONLY=${ONLY:-"$*"}
# bug number for skipped test: 1979
ALWAYS_EXCEPT=${ALWAYS_EXCEPT:-"42b"}
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

SRCDIR=`dirname $0`
PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$PATH

TMP=${TMP:-/tmp}

CHECKSTAT=${CHECKSTAT:-"checkstat -v"}
CREATETEST=${CREATETEST:-createtest}
LFIND=${LFIND:-lfind}
LSTRIPE=${LSTRIPE:-lstripe}
LCTL=${LCTL:-lctl}
MCREATE=${MCREATE:-mcreate}
OPENFILE=${OPENFILE:-openfile}
OPENUNLINK=${OPENUNLINK:-openunlink}
TOEXCL=${TOEXCL:-toexcl}
TRUNCATE=${TRUNCATE:-truncate}
MUNLINK=${MUNLINK:-munlink}
SOCKETSERVER=${SOCKETSERVER:-socketserver}
SOCKETCLIENT=${SOCKETCLIENT:-socketclient}
IOPENTEST1=${IOPENTEST1:-iopentest1}
IOPENTEST2=${IOPENTEST2:-iopentest2}

if [ $UID -ne 0 ]; then
	RUNAS_ID="$UID"
	RUNAS=""
else
	RUNAS_ID=${RUNAS_ID:-500}
	RUNAS=${RUNAS:-"runas -u $RUNAS_ID"}
fi

export NAME=${NAME:-local}

SAVE_PWD=$PWD

clean() {
	echo -n "cln.."
	sh llmountcleanup.sh > /dev/null || exit 20
	I_MOUNTED=no
}
CLEAN=${CLEAN:-clean}

start() {
	echo -n "mnt.."
	sh llrmount.sh > /dev/null || exit 10
	I_MOUNTED=yes
	echo "done"
}
START=${START:-start}

log() {
	echo "$*"
	lctl mark "$*" 2> /dev/null || true
}

run_one() {
	if ! mount | grep -q $DIR; then
		$START
	fi
	log "== test $1: $2"
	test_$1 || error "test_$1: $?"
	pass
	cd $SAVE_PWD
	$CLEAN
}

build_test_filter() {
        for O in $ONLY; do
            eval ONLY_${O}=true
        done
        for E in $EXCEPT $ALWAYS_EXCEPT; do
            eval EXCEPT_${E}=true
        done
}

_basetest() {
    echo $*
}

basetest() {
    IFS=abcdefghijklmnopqrstuvwxyz _basetest $1
}

run_test() {
         base=`basetest $1`
         if [ "$ONLY" ]; then
                 testname=ONLY_$1
                 if [ ${!testname}x != x ]; then
 			run_one $1 "$2"
 			return $?
                 fi
                 testname=ONLY_$base
                 if [ ${!testname}x != x ]; then
                         run_one $1 "$2"
                         return $?
                 fi
                 echo -n "."
                 return 0
 	fi
        testname=EXCEPT_$1
        if [ ${!testname}x != x ]; then
                 echo "skipping excluded test $1"
                 return 0
        fi
        testname=EXCEPT_$base
        if [ ${!testname}x != x ]; then
                 echo "skipping excluded test $1 (base $base)"
                 return 0
        fi
        run_one $1 "$2"
 	return $?
}

[ "$SANITYLOG" ] && rm -f $SANITYLOG || true

error() { 
	log "FAIL: $@"
	if [ "$SANITYLOG" ]; then
		echo "FAIL: $@" >> $SANITYLOG
	else
		exit 1
	fi
}

pass() { 
	echo PASS
}

MOUNT="`mount | awk '/^'$NAME' .* lustre_lite / { print $3 }'`"
if [ -z "$MOUNT" ]; then
	sh llmount.sh
	MOUNT="`mount | awk '/^'$NAME' .* lustre_lite / { print $3 }'`"
	[ -z "$MOUNT" ] && error "NAME=$NAME not mounted"
	I_MOUNTED=yes
fi

[ `echo $MOUNT | wc -w` -gt 1 ] && error "NAME=$NAME mounted more than once"

DIR=${DIR:-$MOUNT}
[ -z "`echo $DIR | grep $MOUNT`" ] && echo "$DIR not in $MOUNT" && exit 99

LOVNAME=`cat /proc/fs/lustre/llite/fs0/lov/common_name`
STRIPECOUNT=`cat /proc/fs/lustre/lov/$LOVNAME/numobd`

[ -f $DIR/d52a/foo ] && chattr -a $DIR/d52a/foo
[ -f $DIR/d52b/foo ] && chattr -i $DIR/d52b/foo
rm -rf $DIR/[Rdfs][1-9]*

build_test_filter

echo preparing for tests involving mounts
EXT2_DEV=${EXT2_DEV:-/tmp/SANITY.LOOP}
touch $EXT2_DEV
mke2fs -F $EXT2_DEV 1000 > /dev/null

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
run_test 2b "rm -r .../d2; checkstat .../d2/f ======================"

test_3a() {
	mkdir $DIR/d3
	$CHECKSTAT -t dir $DIR/d3 || error
}
run_test 3a "mkdir .../d3 ======================================"

test_3b() {
	if [ ! -d $DIR/d3 ]; then
		mkdir $DIR/d3
	fi
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
	if [ ! -d $DIR/d4 ]; then
		mkdir $DIR/d4
	fi
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

test_6a() {
	touch $DIR/f6a
	chmod 0666 $DIR/f6a || error
	$CHECKSTAT -t file -p 0666 -u \#$UID $DIR/f6a || error
}
run_test 6a "touch .../f6a; chmod .../f6a ======================"

test_6b() {
	[ $RUNAS_ID -eq $UID ] && echo "skipping test 6b" && return
	if [ ! -f $DIR/f6a ]; then
		touch $DIR/f6a
		chmod 0666 $DIR/f6a
	fi
	$RUNAS chmod 0444 $DIR/f6a && error
	$CHECKSTAT -t file -p 0666 -u \#$UID $DIR/f6a || error
}
run_test 6b "$RUNAS chmod .../f6a (should return error) =="

test_6c() {
	[ $RUNAS_ID -eq $UID ] && echo "skipping test 6c" && return
	touch $DIR/f6c
	chown $RUNAS_ID $DIR/f6c || error
	$CHECKSTAT -t file -u \#$RUNAS_ID $DIR/f6c || error
}
run_test 6c "touch .../f6c; chown .../f6c ======================"

test_6d() {
	[ $RUNAS_ID -eq $UID ] && echo "skipping test 6d" && return
	if [ ! -f $DIR/f6c ]; then
		touch $DIR/f6c
		chown $RUNAS_ID $DIR/f6c
	fi
	$RUNAS chown $UID $DIR/f6c && error
	$CHECKSTAT -t file -u \#$RUNAS_ID $DIR/f6c || error
}
run_test 6d "$RUNAS chown .../f6c (should return error) =="

test_6e() {
	[ $RUNAS_ID -eq $UID ] && echo "skipping test 6e" && return
	touch $DIR/f6e
	chgrp $RUNAS_ID $DIR/f6e || error
	$CHECKSTAT -t file -u \#$UID -g \#$RUNAS_ID $DIR/f6e || error
}
run_test 6e "touch .../f6e; chgrp .../f6e ======================"

test_6f() {
	[ $RUNAS_ID -eq $UID ] && echo "skipping test 6f" && return
	if [ ! -f $DIR/f6e ]; then
		touch $DIR/f6e
		chgrp $RUNAS_ID $DIR/f6e
	fi
	$RUNAS chgrp $UID $DIR/f6e && error
	$CHECKSTAT -t file -u \#$UID -g \#$RUNAS_ID $DIR/f6e || error
}
run_test 6f "$RUNAS chgrp .../f6e (should return error) =="

test_6g() {
	[ $RUNAS_ID -eq $UID ] && echo "skipping test 6g" && return
        mkdir $DIR/d6g || error
        chmod 777 $DIR/d6g || error
        $RUNAS mkdir $DIR/d6g/d || error
        chmod g+s $DIR/d6g/d || error
        mkdir $DIR/d6g/d/subdir
	$CHECKSTAT -g \#$RUNAS_ID $DIR/d6g/d/subdir || error
}
run_test 6g "Is new dir in sgid dir inheriting group?"

test_7a() {
	mkdir $DIR/d7
	$MCREATE $DIR/d7/f
	chmod 0666 $DIR/d7/f
	$CHECKSTAT -t file -p 0666 $DIR/d7/f || error
}
run_test 7a "mkdir .../d7; mcreate .../d7/f; chmod .../d7/f ===="

test_7b() {
	if [ ! -d $DIR/d7 ]; then
		mkdir $DIR/d7
	fi
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
	if [ ! -d $DIR/d17 ]; then
		mkdir $DIR/d17
	fi
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

test_19a() {
	touch $DIR/f19
	ls -l $DIR
	rm $DIR/f19
	$CHECKSTAT -a $DIR/f19 || error
}
run_test 19a "touch .../f19 ; ls -l ... ; rm .../f19 ==========="

test_19b() {
	ls -l $DIR/f19 && error || true
}
run_test 19b "ls -l .../f19 (should return error) =============="

test_19c() {
	[ $RUNAS_ID -eq $UID ] && echo "skipping test 19c" && return
	$RUNAS touch $DIR/f19 && error || true
}
run_test 19c "$RUNAS touch .../f19 (should return error) =="

test_19d() {
	cat $DIR/f19 && error || true
}
run_test 19d "cat .../f19 (should return error) =============="

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
	echo '== rename sanity =============================================='
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
run_test 24i "rename file to dir error: touch f ; mkdir a ; rename f a"

test_24j() {
	mkdir $DIR/R10
	perl -e "rename \"$DIR/R10/f\", \"$DIR/R10/g\"" 
	$CHECKSTAT -t dir $DIR/R10 || error
	$CHECKSTAT -a $DIR/R10/f || error
	$CHECKSTAT -a $DIR/R10/g || error
}
run_test 24j "source does not exist ============================" 

test_24k() {
	mkdir $DIR/R11a $DIR/R11a/d
	touch $DIR/R11a/f
	mv $DIR/R11a/f $DIR/R11a/d
	$CHECKSTAT -a $DIR/R11a/f || error
	$CHECKSTAT -t file $DIR/R11a/d/f || error
}
run_test 24k "touch .../R11a/f; mv .../R11a/f .../R11a/d ======="

test_25a() {
	echo '== symlink sanity ============================================='
	mkdir $DIR/d25
	ln -s d25 $DIR/s25
	touch $DIR/s25/foo || error
}
run_test 25a "create file in symlinked directory ==============="

test_25b() {
	if [ ! -d $DIR/d25 ]; then
		run_one	25a
	fi
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
	mkdir -p $DIR/d26b/d26-2
	ln -s d26b/d26-2/foo $DIR/s26-2
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
	if [ ! -h $DIR/d26-3 ]; then
		run_one 26d
	fi
	rm $DIR/d26-3
}
run_test 26e "unlink multiple component recursive symlink ======"

test_27a() {
	echo '== stripe sanity =============================================='
	mkdir $DIR/d27
	$LSTRIPE $DIR/d27/f0 8192 0 1 || error
	$CHECKSTAT -t file $DIR/d27/f0 || error
	pass
	log "== test_27b: write to one stripe file ========================="
	cp /etc/hosts $DIR/d27/f0 || error
}
run_test 27a "one stripe file =================================="

test_27c() {
	[ "$STRIPECOUNT" -lt "2" ] && echo "skipping 2-stripe test" && return
	if [ ! -d $DIR/d27 ]; then
		mkdir $DIR/d27
	fi
	$LSTRIPE $DIR/d27/f01 8192 0 2 || error
	[ `$LFIND $DIR/d27/f01 | grep -A 10 obdidx | wc -l` -eq 4 ] ||
		error "two-stripe file doesn't have two stripes"
	pass
	log "== test_27d: write to two stripe file file f01 ================"
	dd if=/dev/zero of=$DIR/d27/f01 bs=4k count=4 || error
}
run_test 27c "create two stripe file f01 ======================="

test_27d() {
	if [ ! -d $DIR/d27 ]; then
		mkdir $DIR/d27
	fi
	$LSTRIPE $DIR/d27/fdef 0 -1 0 || error
	$CHECKSTAT -t file $DIR/d27/fdef || error
	#dd if=/dev/zero of=$DIR/d27/fdef bs=4k count=4 || error
}
run_test 27d "create file with default settings ================"

test_27e() {
	if [ ! -d $DIR/d27 ]; then
		mkdir $DIR/d27
	fi
	$LSTRIPE $DIR/d27/f12 8192 0 2 || error
	$LSTRIPE $DIR/d27/f12 8192 0 2 && error
	$CHECKSTAT -t file $DIR/d27/f12 || error
}
run_test 27e "lstripe existing file (should return error) ======"

test_27f() {
	if [ ! -d $DIR/d27 ]; then
		mkdir $DIR/d27
	fi
	$LSTRIPE $DIR/d27/fbad 100 0 1 && error
	dd if=/dev/zero of=$DIR/d27/f12 bs=4k count=4 || error
	$LFIND $DIR/d27/fbad || error
}
run_test 27f "lstripe with bad stripe size (should return error)"

test_27g() {
	if [ ! -d $DIR/d27 ]; then
		mkdir $DIR/d27
	fi
	$MCREATE $DIR/d27/fnone || error
	pass
	log "== test 27h: lfind with no objects ============================"
	$LFIND $DIR/d27/fnone 2>&1 | grep -q "no stripe info" || error
	pass
	log "== test 27i: lfind with some objects =========================="
	touch $DIR/d27/fsome || error
	$LFIND $DIR/d27/fsome | grep -q obdidx || error
}
run_test 27g "test lfind ======================================="

test_27j() {
        if [ ! -d $DIR/d27 ]; then
                mkdir $DIR/d27
        fi
        $LSTRIPE $DIR/d27/f27j 8192 $STRIPECOUNT 1 && error || true
}
run_test 27j "lstripe with bad stripe offset (should return error)"

test_28() {
	mkdir $DIR/d28
	$CREATETEST $DIR/d28/ct || error
}
run_test 28 "create/mknod/mkdir with bad file types ============"

cancel_lru_locks() {
	for d in /proc/fs/lustre/ldlm/namespaces/$1*; do
		echo clear > $d/lru_size
	done
	grep [0-9] /proc/fs/lustre/ldlm/namespaces/$1*/lock_unused_count /dev/null
}

test_29() {
	cancel_lru_locks MDC
	mkdir $DIR/d29
	touch $DIR/d29/foo
	log 'first d29'
	ls -l $DIR/d29
	MDCDIR=${MDCDIR:-/proc/fs/lustre/ldlm/namespaces/MDC_*}
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

test_31a() {
	$OPENUNLINK $DIR/f31 $DIR/f31 || error
	$CHECKSTAT -a $DIR/f31 || error
}
run_test 31a "open-unlink file =================================="

test_31b() {
	touch $DIR/f31 || error
	ln $DIR/f31 $DIR/f31b || error
	multiop $DIR/f31b Ouc || error
	$CHECKSTAT -t file $DIR/f31 || error
}
run_test 31b "unlink file with multiple links while open ======="

test_31c() {
	touch $DIR/f31 || error
	ln $DIR/f31 $DIR/f31c || error
	multiop $DIR/f31 O_uc &
	MULTIPID=$!
	multiop $DIR/f31c Ouc
	usleep 500
	kill -USR1 $MULTIPID
	wait $MUTLIPID
}
run_test 31c "open-unlink file with multiple links ============="

test_31d() {
	opendirunlink $DIR/d31d $DIR/d31d || error
	$CHECKSTAT -a $DIR/d31d || error
}
run_test 31d "remove of open directory ========================="

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
run_test 32d "open d32d/ext2-mountpoint/../d2/test_dir ========="

test_32e() {
	[ -e $DIR/d32e ] && rm -fr $DIR/d32e
	mkdir -p $DIR/d32e/tmp    
	TMP_DIR=$DIR/d32e/tmp       
	ln -s $DIR/d32e $TMP_DIR/symlink11 
	ln -s $TMP_DIR/symlink11 $TMP_DIR/../symlink01 
	$CHECKSTAT -t link $DIR/d32e/tmp/symlink11 || error
	$CHECKSTAT -t link $DIR/d32e/symlink01 || error
}
run_test 32e "stat d32e/symlink->tmp/symlink->lustre-subdir ===="

test_32f() {
	[ -e $DIR/d32f ] && rm -fr $DIR/d32f
	mkdir -p $DIR/d32f/tmp    
	TMP_DIR=$DIR/d32f/tmp       
	ln -s $DIR/d32f $TMP_DIR/symlink11 
	ln -s $TMP_DIR/symlink11 $TMP_DIR/../symlink01 
	ls $DIR/d32f/tmp/symlink11  || error
	ls $DIR/d32f/symlink01 || error
}
run_test 32f "open d32f/symlink->tmp/symlink->lustre-subdir ===="

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
run_test 32i "stat d32i/ext2-mountpoint/../test_file ==========="

test_32j() {
	[ -e $DIR/d32j ] && rm -fr $DIR/d32j
	mkdir -p $DIR/d32j/ext2-mountpoint 
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32j/ext2-mountpoint || error
	touch $DIR/d32j/test_file
	cat $DIR/d32j/ext2-mountpoint/../test_file || error
	umount $DIR/d32j/ext2-mountpoint || error
}
run_test 32j "open d32j/ext2-mountpoint/../test_file ==========="

test_32k() {
	rm -fr $DIR/d32k
	mkdir -p $DIR/d32k/ext2-mountpoint 
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32k/ext2-mountpoint  
	mkdir -p $DIR/d32k/d2
	touch $DIR/d32k/d2/test_file || error
	$CHECKSTAT -t file $DIR/d32k/ext2-mountpoint/../d2/test_file || error
	umount $DIR/d32k/ext2-mountpoint || error
}
run_test 32k "stat d32k/ext2-mountpoint/../d2/test_file ========"

test_32l() {
	rm -fr $DIR/d32l
	mkdir -p $DIR/d32l/ext2-mountpoint 
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32l/ext2-mountpoint || error
	mkdir -p $DIR/d32l/d2
	touch $DIR/d32l/d2/test_file
	cat  $DIR/d32l/ext2-mountpoint/../d2/test_file || error
	umount $DIR/d32l/ext2-mountpoint || error
}
run_test 32l "open d32l/ext2-mountpoint/../d2/test_file ========"

test_32m() {
	rm -fr $DIR/d32m
	mkdir -p $DIR/d32m/tmp    
	TMP_DIR=$DIR/d32m/tmp       
	ln -s $DIR $TMP_DIR/symlink11 
	ln -s $TMP_DIR/symlink11 $TMP_DIR/../symlink01 
	$CHECKSTAT -t link $DIR/d32m/tmp/symlink11 || error
	$CHECKSTAT -t link $DIR/d32m/symlink01 || error
}
run_test 32m "stat d32m/symlink->tmp/symlink->lustre-root ======"

test_32n() {
	rm -fr $DIR/d32n
	mkdir -p $DIR/d32n/tmp    
	TMP_DIR=$DIR/d32n/tmp       
	ln -s $DIR $TMP_DIR/symlink11 
	ln -s $TMP_DIR/symlink11 $TMP_DIR/../symlink01 
	ls -l $DIR/d32n/tmp/symlink11  || error
	ls -l $DIR/d32n/symlink01 || error
}
run_test 32n "open d32n/symlink->tmp/symlink->lustre-root ======"

test_32o() {
	rm -fr $DIR/d32o
	rm -f $DIR/test_file
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
    log 32p_1
	rm -fr $DIR/d32p
    log 32p_2
	rm -f $DIR/test_file
    log 32p_3
	touch $DIR/test_file 
    log 32p_4
	mkdir -p $DIR/d32p/tmp    
    log 32p_5
	TMP_DIR=$DIR/d32p/tmp       
    log 32p_6
	ln -s $DIR/test_file $TMP_DIR/symlink12 
    log 32p_7
	ln -s $TMP_DIR/symlink12 $TMP_DIR/../symlink02 
    log 32p_8
	cat $DIR/d32p/tmp/symlink12 || error
    log 32p_9
	cat $DIR/d32p/symlink02 || error
    log 32p_10
}
run_test 32p "open d32p/symlink->tmp/symlink->lustre-root/test_file"

test_32q() {
	[ -e $DIR/d32q ] && rm -fr $DIR/d32q
	mkdir -p $DIR/d32q
        touch $DIR/d32q/under_the_mount
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32q
	ls $DIR/d32q/under_the_mount &&  error || true
	umount $DIR/d32q || error
}
run_test 32q "stat follows mountpoints in Lustre ========================="

test_32r() {
	[ -e $DIR/d32r ] && rm -fr $DIR/d32r
	mkdir -p $DIR/d32r
        touch $DIR/d32r/under_the_mount
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32r
	ls $DIR/d32r | grep -q under_the_mount &&  error || true
	umount $DIR/d32r || error
}
run_test 32r "opendir follows mountpoints in Lustre ========================="

#   chmod 444 /mnt/lustre/somefile
#   open(/mnt/lustre/somefile, O_RDWR)
#   Should return -1
test_33() {
	rm -f $DIR/test_33_file
	touch $DIR/test_33_file
	chmod 444 $DIR/test_33_file
	chown $RUNAS_ID $DIR/test_33_file
        log 33_1
        $RUNAS $OPENFILE -f O_RDWR $DIR/test_33_file && error || true
        log 33_2
}
run_test 33 "write file with mode 444 (should return error) ===="

TEST_34_SIZE=${TEST_34_SIZE:-2000000000000}
test_34a() {
	rm -f $DIR/test_34_file
	$MCREATE $DIR/test_34_file || error
	$LFIND $DIR/test_34_file 2>&1 | grep -q "no stripe info" || error
	$TRUNCATE $DIR/test_34_file $TEST_34_SIZE || error
	$LFIND $DIR/test_34_file 2>&1 | grep -q "no stripe info" || error
	$CHECKSTAT -s $TEST_34_SIZE $DIR/test_34_file || error
}
run_test 34a "truncate file that has not been opened ==========="

test_34b() {
	[ ! -f $DIR/test_34_file ] && run_one 34a
	$CHECKSTAT -s $TEST_34_SIZE $DIR/test_34_file || error
	$OPENFILE -f O_RDONLY $DIR/test_34_file
	$LFIND $DIR/test_34_file 2>&1 | grep -q "no stripe info" || error
	$CHECKSTAT -s $TEST_34_SIZE $DIR/test_34_file || error
}
run_test 34b "O_RDONLY opening file doesn't create objects ====="

test_34c() {
	[ ! -f $DIR/test_34_file ] && run_one 34a 
	$CHECKSTAT -s $TEST_34_SIZE $DIR/test_34_file || error
	$OPENFILE -f O_RDWR $DIR/test_34_file
	$LFIND $DIR/test_34_file 2>&1 | grep -q "no stripe info" && error
	$CHECKSTAT -s $TEST_34_SIZE $DIR/test_34_file || error
}
run_test 34c "O_RDWR opening file-with-size works =============="

test_34d() {
	dd if=/dev/zero of=$DIR/test_34_file conv=notrunc bs=4k count=1 || error
	$CHECKSTAT -s $TEST_34_SIZE $DIR/test_34_file || error
	rm $DIR/test_34_file
}
run_test 34d "write to sparse file ============================="

test_34e() {
	rm -f $DIR/test_34_file
	$MCREATE $DIR/test_34_file || error
	$TRUNCATE $DIR/test_34_file 1000 || error
	$CHECKSTAT -s 1000 $DIR/test_34_file || error
	$OPENFILE -f O_RDWR $DIR/test_34_file
	$CHECKSTAT -s 1000 $DIR/test_34_file || error
}
run_test 34e "create objects, some with size and some without =="

test_35a() {
	cp /bin/sh $DIR/test_35a_file
	chmod 444 $DIR/test_35a_file
	chown $RUNAS_ID $DIR/test_35a_file
	$RUNAS $DIR/test_35a_file && error || true
	rm $DIR/test_35a_file
}
run_test 35a "exec file with mode 444 (should return and not leak) ====="


test_36a() {
	rm -f $DIR/test_36_file
	utime $DIR/test_36_file || error
}
run_test 36a "MDS utime check (mknod, utime) ==================="

test_36b() {
	echo "" > $DIR/test_36_file
	utime $DIR/test_36_file || error
}
run_test 36b "OST utime check (open, utime) ===================="

test_36c() {
	rm -f $DIR/d36/test_36_file
	mkdir $DIR/d36
	chown $RUNAS_ID $DIR/d36
	$RUNAS utime $DIR/d36/test_36_file || error
}
run_test 36c "non-root MDS utime check (mknod, utime) =========="

test_36d() {
	[ ! -d $DIR/d36 ] && run_one 36c
	echo "" > $DIR/d36/test_36_file
	$RUNAS utime $DIR/d36/test_36_file || error
}
run_test 36d "non-root OST utime check (open, utime) ==========="

test_36e() {
	[ $RUNAS_ID -eq $UID ] && return
	[ ! -d $DIR/d36 ] && mkdir $DIR/d36
	touch $DIR/d36/test_36_file2
	$RUNAS utime $DIR/d36/test_36_file2 && error || true
}
run_test 36e "utime on non-owned file (should return error) ===="

test_37() {
	mkdir -p $DIR/dextra
	echo f > $DIR/dextra/fbugfile
	mount -t ext2 -o loop $EXT2_DEV $DIR/dextra
	ls $DIR/dextra | grep "\<fbugfile\>" && error
	umount $DIR/dextra || error
	rm -f $DIR/dextra/fbugfile || error
}
run_test 37 "ls a mounted file system to check old content ====="

test_38() {
	o_directory $DIR/test38
}
run_test 38 "open a regular file with O_DIRECTORY =============="

test_39() {
	touch $DIR/test_39_file
	touch $DIR/test_39_file2
#	ls -l  $DIR/test_39_file $DIR/test_39_file2
#	ls -lu  $DIR/test_39_file $DIR/test_39_file2
#	ls -lc  $DIR/test_39_file $DIR/test_39_file2
	sleep 2
	$OPENFILE -f O_CREAT:O_TRUNC:O_WRONLY $DIR/test_39_file2
#	ls -l  $DIR/test_39_file $DIR/test_39_file2
#	ls -lu  $DIR/test_39_file $DIR/test_39_file2
#	ls -lc  $DIR/test_39_file $DIR/test_39_file2
	[ $DIR/test_39_file2 -nt $DIR/test_39_file ] || error
}
run_test 39 "mtime changed on create ==========================="

test_40() {
	dd if=/dev/zero of=$DIR/f40 bs=4096 count=1
	$RUNAS $OPENFILE -f O_WRONLY:O_TRUNC $DIR/f40 && error
	$CHECKSTAT -t file -s 4096 $DIR/f40 || error
}
run_test 40 "failed open(O_TRUNC) doesn't truncate ============="

test_41() {
	# bug 1553
	small_write $DIR/f41 18
}
run_test 41 "test small file write + fstat ====================="

count_ost_writes() {
        cat /proc/fs/lustre/osc/*/stats |
            awk -vwrites=0 '/ost_write/ { writes += $2 } END { print writes; }'
}
start_kupdated() {
	# in 2.6, restore /proc/sys/vm/dirty_writeback_centisecs
	kill -CONT `pidof kupdated`
}
stop_kupdated() {
	# in 2.6, save and 0 /proc/sys/vm/dirty_writeback_centisecs
	kill -STOP `pidof kupdated`
	trap start_kupdated EXIT
}

# Tests 42* verify that our behaviour is correct WRT caching, file closure,
# file truncation, and file removal.
test_42a() {
	cancel_lru_locks OSC
	stop_kupdated
        sync # just to be safe
        BEFOREWRITES=`count_ost_writes`
        dd if=/dev/zero of=$DIR/f42a bs=1024 count=100
        AFTERWRITES=`count_ost_writes`
        [ $BEFOREWRITES -eq $AFTERWRITES ] || \
		error "$BEFOREWRITES < $AFTERWRITES"
	start_kupdated
}
run_test 42a "ensure that we don't flush on close =============="

test_42b() {
	cancel_lru_locks OSC
	stop_kupdated
        sync
        dd if=/dev/zero of=$DIR/f42b bs=1024 count=100
        BEFOREWRITES=`count_ost_writes`
        $MUNLINK $DIR/f42b || error "$MUNLINK $DIR/f42b: $?"
        AFTERWRITES=`count_ost_writes`
        [ $BEFOREWRITES -eq $AFTERWRITES ] ||
            error "$BEFOREWRITES < $AFTERWRITES on unlink"
        BEFOREWRITES=`count_ost_writes`
        sync || error "sync: $?"
        AFTERWRITES=`count_ost_writes`
        [ $BEFOREWRITES -eq $AFTERWRITES ] ||
            error "$BEFOREWRITES < $AFTERWRITES on sync"
        dmesg | grep 'error from obd_brw_async' && error 'error writing back'
	start_kupdated
        return 0
}
run_test 42b "test destroy of file with cached dirty data ======"

# if these tests just want to test the effect of truncation,
# they have to be very careful.  consider:
# - the first open gets a {0,EOF}PR lock
# - the first write conflicts and gets a {0, count-1}PW
# - the rest of the writes are under {count,EOF}PW
# - the open for truncate tries to match a {0,EOF}PR
#   for the filesize and cancels the PWs.
# any number of fixes (don't get {0,EOF} on open, match
# composite locks, do smarter file size management) fix
# this, but for now we want these tests to verify that
# the cancelation with truncate intent works, so we
# start the file with a full-file pw lock to match against
# until the truncate.
trunc_test() {
        test=$1
        file=$DIR/$test
        offset=$2
	cancel_lru_locks OSC
	stop_kupdated
	# prime the file with 0,EOF PW to match
	touch $file
        $TRUNCATE $file 0
        sync; sync
	# now the real test..
        dd if=/dev/zero of=$file bs=1024 count=100
        BEFOREWRITES=`count_ost_writes`
        $TRUNCATE $file $offset
        cancel_lru_locks OSC
        AFTERWRITES=`count_ost_writes`
	start_kupdated
}

test_42c() {
        trunc_test 42c 1024
        [ $BEFOREWRITES -eq $AFTERWRITES ] && \
            error "$BEFOREWRITES < $AFTERWRITES on truncate"
        rm $file
}
run_test 42c "test partial truncate of file with cached dirty data ===="

test_42d() {
        trunc_test 42d 0
        [ $BEFOREWRITES -eq $AFTERWRITES ] || \
            error "beforewrites $BEFOREWRITES != afterwrites $AFTERWRITES on truncate"
        rm $file
}
run_test 42d "test complete truncate of file with cached dirty data ===="

test_43() {
	mkdir $DIR/d43
	cp -p /bin/ls $DIR/d43/f
	exec 100>> $DIR/d43/f	
	$DIR/d43/f && error || true
	exec 100<&-
}
run_test 43 "execution of file opened for write should return -ETXTBSY=="

test_43a() {
        mkdir -p $DIR/d43
	cp -p `which multiop` $DIR/d43/multiop
        touch $DIR/d43/g
        $DIR/d43/multiop $DIR/d43/g o_c &
        MULTIPID=$!
        sleep 1
        multiop $DIR/d43/multiop Oc && error "expected error, got success"
        kill -USR1 $MULTIPID || return 2
        wait $MULTIPID || return 3
}
run_test 43a "open(RDWR) of file being executed should return -ETXTBSY=="

test_43b() {
        mkdir -p $DIR/d43
	cp -p `which multiop` $DIR/d43/multiop
        touch $DIR/d43/g
        $DIR/d43/multiop $DIR/d43/g o_c &
        MULTIPID=$!
        sleep 1
        truncate $DIR/d43/multiop 0 && error "expected error, got success"
        kill -USR1 $MULTIPID || return 2
        wait $MULTIPID || return 3
}
run_test 43b "truncate of file being executed should return -ETXTBSY===="

test_43c() {
	local testdir="$DIR/43a"
	mkdir -p $testdir
	cp $SHELL $testdir/
	( cd $(dirname $SHELL) && md5sum $(basename $SHELL) ) |  \
		( cd $testdir && md5sum -c)
}
run_test 43c "md5sum of copy into lustre================================"

test_44() {
	[  "$STRIPECOUNT" -lt "2" ] && echo "skipping 2-stripe test" && return
	dd if=/dev/zero of=$DIR/f1 bs=4k count=1 seek=127
	dd if=$DIR/f1 bs=4k count=1
}
run_test 44 "zero length read from a sparse stripe ============="

test_44a() {
    local nstripe=`$LCTL lov_getconfig $DIR | grep default_stripe_count: | \
                         awk '{print $2}'`
    local stride=`$LCTL lov_getconfig $DIR | grep default_stripe_size: | \
                      awk '{print $2}'`
    if [ $nstripe -eq 0 ] ; then
        nstripe=`$LCTL lov_getconfig $DIR | grep obd_count: | awk '{print $2}'`
    fi

    OFFSETS="0 $((stride/2)) $((stride-1))"
    for offset in $OFFSETS ; do
      for i in `seq 0 $((nstripe-1))`; do
        rm -f $DIR/44a
        local GLOBALOFFSETS=""
        local size=$((((i + 2 * $nstripe )*$stride + $offset)))  # Bytes
        ll_sparseness_write $DIR/44a $size  || error "ll_sparseness_write"
        GLOBALOFFSETS="$GLOBALOFFSETS $size"
        ll_sparseness_verify $DIR/44a $GLOBALOFFSETS \
                            || error "ll_sparseness_verify $GLOBALOFFSETS"

        for j in `seq 0 $((nstripe-1))`; do
            size=$((((j + $nstripe )*$stride + $offset)))  # Bytes
            ll_sparseness_write $DIR/44a $size || error "ll_sparseness_write"
            GLOBALOFFSETS="$GLOBALOFFSETS $size"
        done
        ll_sparseness_verify $DIR/44a $GLOBALOFFSETS \
                            || error "ll_sparseness_verify $GLOBALOFFSETS"
      done
    done
}
run_test 44a "test sparse pwrite ==============================="

dirty_osc_total() {
	tot=0
	for d in /proc/fs/lustre/osc/*/cur_dirty_bytes; do
		tot=$(($tot + `cat $d`))
	done
	echo $tot
}
do_dirty_record() {
	before=`dirty_osc_total`
	echo executing "\"$*\""
	eval $*
	after=`dirty_osc_total`
	echo before $before, after $after
}
test_45() {
	f="$DIR/45"
	stop_kupdated
	sync
	do_dirty_record "echo blah > $f"
	[ $before -eq $after ] && error "write wasn't cached"
	do_dirty_record "> $f"
	[ $before -gt $after ] || error "truncate didn't lower dirty count"
	do_dirty_record "echo blah > $f"
	[ $before -eq $after ] && error "write wasn't cached"
	do_dirty_record "sync"
	[ $before -gt $after ] || error "writeback didn't lower dirty count"
	do_dirty_record "echo blah > $f"
	[ $before -eq $after ] && error "write wasn't cached"
	do_dirty_record "cancel_lru_locks OSC"
	[ $before -gt $after ] || error "lock cancelation didn't lower dirty count"
	start_kupdated
}
run_test 45 "osc io page accounting ============================"

page_size() {
	getconf PAGE_SIZE
}

# in a 2 stripe file (lov.sh), page 63 maps to page 31 in its object.  this
# test tickles a bug where re-dirtying a page was failing to be mapped to the
# objects offset and an assert hit when an rpc was built with 63's mapped 
# offset 31 and 31's raw 31 offset. it also found general redirtying bugs.
test_46() {
	f="$DIR/46"
	stop_kupdated
	sync
	dd if=/dev/zero of=$f bs=`page_size` seek=31 count=1
	sync
	dd conv=notrunc if=/dev/zero of=$f bs=`page_size` seek=63 count=1
	dd conv=notrunc if=/dev/zero of=$f bs=`page_size` seek=31 count=1
	sync
	start_kupdated
}
run_test 46 "dirtying a previously written page ================"

# Check that device nodes are created and then visible correctly (#2091)
test_47() {
	cmknod $DIR/test_47_node || error
}
run_test 47 "Device nodes check ================================"

test_48() {
        mkdir $DIR/d48
        cd $DIR/d48
        mv $DIR/d48 $DIR/d48.new || error "move directory failed"
        mkdir $DIR/d48 || error "recreate diectory failed"
        ls || error "can't list after recreate directory"
}
run_test 48 "Access renamed current working directory ========="

test_50() {
	# bug 1485
	mkdir $DIR/d50
	cd $DIR/d50
	ls /proc/$$/cwd || error
}
run_test 50 "special situations: /proc symlinks  ==============="

test_51() {
	# bug 1516 - create an empty entry right after ".." then split dir
	mkdir $DIR/d49
	touch $DIR/d49/foo
	$MCREATE $DIR/d49/bar
	rm $DIR/d49/foo
	createmany -m $DIR/d49/longfile 201
	FNUM=202
	while [ `ls -sd $DIR/d49 | awk '{ print $1 }'` -eq 4 ]; do
		$MCREATE $DIR/d49/longfile$FNUM
		FNUM=$(($FNUM + 1))
		echo -n "+"
	done
	ls -l $DIR/d49 > /dev/null || error
}
run_test 51 "special situations: split htree with empty entry =="

test_52a() {
	[ -f $DIR/d52a/foo ] && chattr -a $DIR/d52a/foo
	mkdir -p $DIR/d52a
	touch $DIR/d52a/foo
	chattr =a $DIR/d52a/foo || error
	echo bar >> $DIR/d52a/foo || error
	cp /etc/hosts $DIR/d52a/foo && error
	rm -f $DIR/d52a/foo 2>/dev/null && error
	link $DIR/d52a/foo $DIR/d52a/foo_link 2>/dev/null && error
	echo foo >> $DIR/d52a/foo || error
	mrename $DIR/d52a/foo $DIR/d52a/foo_ren && error
	lsattr $DIR/d52a/foo | egrep -q "^-+a-+ $DIR/d52a/foo" || error
	chattr -a $DIR/d52a/foo || error

	rm -fr $DIR/d52a || error
}
run_test 52a "append-only flag test ============================"

test_52b() {
	[ -f $DIR/d52b/foo ] && chattr -i $DIR/d52b/foo
	mkdir -p $DIR/d52b
	touch $DIR/d52b/foo
	chattr =i $DIR/d52b/foo || error
	cat test > $DIR/d52b/foo && error
	cp /etc/hosts $DIR/d52b/foo && error
	rm -f $DIR/d52b/foo 2>/dev/null && error
	link $DIR/d52b/foo $DIR/d52b/foo_link 2>/dev/null && error
	echo foo >> $DIR/d52b/foo && error
	mrename $DIR/d52b/foo $DIR/d52b/foo_ren && error
	[ -f $DIR/d52b/foo ] || error
	[ -f $DIR/d52b/foo_ren ] && error
	lsattr $DIR/d52b/foo | egrep -q "^-+i-+ $DIR/d52b/foo" || error
	chattr -i $DIR/d52b/foo || error

	rm -fr $DIR/d52b || error
}
run_test 52b "immutable flag test =============================="

test_53() {
        for i in /proc/fs/lustre/osc/OSC*mds1 ; do
                ostname=`echo $i | cut -d _ -f 3-4 | sed -e s/_mds1//`
                ost_last=`cat /proc/fs/lustre/obdfilter/$ostname/last_id`
                mds_last=`cat $i/prealloc_last_id`
                echo "$ostname.last_id=$ost_last ; MDS.last_id=$mds_last"
                if [ $ost_last != $mds_last ]; then
                    error "$ostname.last_id=$ost_last ; MDS.last_id=$mds_last"
                fi
        done
}
run_test 53 "verify that MDS and OSTs agree on pre-creation====="

test_54a() {
     	$SOCKETSERVER $DIR/socket &
	sleep 1
     	$SOCKETCLIENT $DIR/socket || error
      	$MUNLINK $DIR/socket
}
run_test 54a "unix damain socket test ==========================="

test_54b() {
	f="$DIR/f54b"
	mknod $f c 1 3
	chmod 0666 $f
	dd if=/dev/zero of=$f bs=`page_size` count=1 
}
run_test 54b "char device works in lustre"

test_54c() {
	f="$DIR/f54c"
	dir="$DIR/dir54c"
	loopdev="$DIR/loop54c"
	
	mknod $loopdev b 7 1
	dd if=/dev/zero of=$f bs=`page_size` count=1024 > /dev/null
	chmod 0666 $f
	losetup $loopdev $f
	echo "make a loop file system..."	
	mkfs.ext2  -F $f > /dev/null
	mkdir -p $dir
	mount $loopdev $dir 
	dd if=/dev/zero of=$dir/tmp bs=`page_size` count=30 || error
	dd if=$dir/tmp of=/dev/zero bs=`page_size` count=30 || error
	umount $dir
}
run_test 54c "loop device works in lustre"

test_54d() {
	f="$DIR/f54d"
	string="aaaaaa"
	mknod $f p
	[ "$string" = `echo $string > $f | cat $f` ] || error
}
run_test 54d "fifo device works in lustre"

test_59() {
	echo "touch 130 files"
	for i in `seq 1 130` ; do
		touch $DIR/59-$i
	done
	echo "rm 130 files"
	for i in `seq 1 130` ; do
		rm -f $DIR/59-$i
	done
	sync
	sleep 2
        # wait for commitment of removal
}
run_test 59 "verify cancellation of llog records async=========="

test_60() {
	echo 60 "llog tests run from kernel mode"
	sh run-llog.sh
}
run_test 60 "llog sanity tests run from kernel module =========="

test_61() {
	f="$DIR/f61"
	dd if=/dev/zero of=$f bs=`page_size` count=1
	cancel_lru_locks OSC
	multiop $f OSMWUc || error
	sync
}
run_test 61 "mmap() writes don't make sync hang =========="

# bug 2330 - insufficient obd_match error checking causes LBUG
test_62() {
        f="$DIR/f62"
        echo foo > $f
        cancel_lru_locks OSC
        echo 0x405 > /proc/sys/lustre/fail_loc
        cat $f && error # expect -EIO
        multiop $f Owc && error
        echo 0 > /proc/sys/lustre/fail_loc
}
run_test 62 "verify obd_match failure doesn't LBUG (should -EIO)"

# bug 2319 - osic_wait() interrupted causes crash because of invalid waitq.
test_63() {
	for i in /proc/fs/lustre/osc/*/max_dirty_mb ; do
	echo 0 > $i
	done
	for i in `seq 10` ; do
		dd if=/dev/zero of=$DIR/syncwrite_testfile bs=8k &
		sleep 5
		kill $!
		sleep 1
	done

	for i in /proc/fs/lustre/osc/*/max_dirty_mb ; do
		echo $[ 64 ] > $i
	done
	true
}
run_test 63 "Verify osic_wait interruption does not crash"

# on the LLNL clusters, runas will still pick up root's $TMP settings,
# which will not be writable for the runas user, and then you get a CVS
# error message with a corrupt path string (CVS bug) and panic.
# We're not using much space, so just stick it in /tmp, which is safe.
OLDTMPDIR=$TMPDIR
OLDTMP=$TMP
TMPDIR=/tmp
TMP=/tmp
OLDHOME=$HOME
[ $RUNAS_ID -ne $UID ] && HOME=/tmp

test_99a() {
	echo 99 "cvs operations ===================================="
	mkdir -p $DIR/d99cvsroot
	chown $RUNAS_ID $DIR/d99cvsroot
	$RUNAS cvs -d $DIR/d99cvsroot init || error
}
run_test 99a "cvs init ========================================="

test_99b() {
	[ ! -d $DIR/d99cvsroot ] && run_one 99a
	cd /etc/init.d
	$RUNAS cvs -d $DIR/d99cvsroot import -m "nomesg" d99reposname vtag rtag
}
run_test 99b "cvs import ======================================="

test_99c() {
	[ ! -d $DIR/d99cvsroot ] && run_one 99b
	cd $DIR
	mkdir -p $DIR/d99reposname
	chown $RUNAS_ID $DIR/d99reposname
	$RUNAS cvs -d $DIR/d99cvsroot co d99reposname
}
run_test 99c "cvs checkout ====================================="

test_99d() {
	[ ! -d $DIR/d99cvsroot ] && run_one 99c
	cd $DIR/d99reposname
	$RUNAS touch foo99
	$RUNAS cvs add -m 'addmsg' foo99
}
run_test 99d "cvs add =========================================="

test_99e() {
	[ ! -d $DIR/d99cvsroot ] && run_one 99c
	cd $DIR/d99reposname
	$RUNAS cvs update
}
run_test 99e "cvs update ======================================="

test_99f() {
	[ ! -d $DIR/d99cvsroot ] && run_one 99d
	cd $DIR/d99reposname
	$RUNAS cvs commit -m 'nomsg' foo99
}
run_test 99f "cvs commit ======================================="

TMPDIR=$OLDTMPDIR
TMP=$OLDTMP
HOME=$OLDHOME

log "cleanup: ======================================================"
if [ "$I_MOUNTED" = "yes" -a "`mount | grep ^$NAME`" ]; then
	rm -rf $DIR/[Rdfs][1-9]*
	sh llmountcleanup.sh || error
fi

echo '=========================== finished ==============================='
[ -f "$SANITYLOG" ] && cat $SANITYLOG && exit 1 || true
