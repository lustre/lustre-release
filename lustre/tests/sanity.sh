#!/bin/bash

set -e

SRCDIR=`dirname $0`
PATH=$SRCDIR:$SRCDIR/../utils:$PATH

CHECKSTAT=${CHECKSTAT:-"./checkstat -v"}
CREATETEST=${CREATETEST:-createtest}
LFIND=${LFIND:-lfind}
LSTRIPE=${LSTRIPE:-lstripe}
MCREATE=${MCREATE:-mcreate}
TOEXCL=${TOEXCL:-toexcl}

RUNAS_ID=${RUNAS_ID:-500}
RUNAS=${RUNAS:-"runas -u $RUNAS_ID"}

MOUNT=${MOUNT:-/mnt/lustre}
DIR=${DIR:-$MOUNT}
export NAME=$NAME
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
	lctl mark "$*"
}

error() { 
    echo FAIL
    exit 1
}

pass() { 
    echo PASS
}

mount | grep $MOUNT || sh llmount.sh

log '== touch .../f ; rm .../f ======================== test 0'
touch $DIR/f
$CHECKSTAT -t file $DIR/f || error 
rm $DIR/f
$CHECKSTAT -a $DIR/f || error
pass
$CLEAN
$START

log '== mkdir .../d1; mkdir .../d1/d2 ================= test 1'
mkdir $DIR/d1
mkdir $DIR/d1/d2
$CHECKSTAT -t dir $DIR/d1/d2 || error
pass
$CLEAN
$START

log '== rmdir .../d1/d2; rmdir .../d1 ================= test 1b'
rmdir $DIR/d1/d2
rmdir $DIR/d1
$CHECKSTAT -a $DIR/d1 || error
pass
$CLEAN
$START

log '== mkdir .../d2; touch .../d2/f ================== test 2'
mkdir $DIR/d2
touch $DIR/d2/f
$CHECKSTAT -t file $DIR/d2/f || error
pass
$CLEAN
$START

log '== rm -r .../d2; touch .../d2/f ================== test 2b'
rm -r $DIR/d2
$CHECKSTAT -a $DIR/d2 || error
pass
$CLEAN
$START

log '== mkdir .../d3 ================================== test 3'
mkdir $DIR/d3
$CHECKSTAT -t dir $DIR/d3 || error
pass
$CLEAN
$START
log '== touch .../d3/f ================================ test 3b'
touch $DIR/d3/f
$CHECKSTAT -t file $DIR/d3/f || error
pass
$CLEAN
$START
log '== rm -r .../d3 ================================== test 3c'
rm -r $DIR/d3
$CHECKSTAT -a $DIR/d3 || error
pass
$CLEAN
$START

log '== mkdir .../d4 ================================== test 4'
mkdir $DIR/d4
$CHECKSTAT -t dir $DIR/d4 || error
pass
$CLEAN
$START
log '== mkdir .../d4/d2 =============================== test 4b'
mkdir $DIR/d4/d2
$CHECKSTAT -t dir $DIR/d4/d2 || error
pass
$CLEAN
$START

log '== mkdir .../d5; mkdir .../d5/d2; chmod .../d5/d2 = test 5'
mkdir $DIR/d5
mkdir $DIR/d5/d2
chmod 0707 $DIR/d5/d2
$CHECKSTAT -t dir -p 0707 $DIR/d5/d2 || error
pass
$CLEAN
$START

log '== touch .../f6; chmod .../f6 ==================== test 6'
touch $DIR/f6
chmod 0666 $DIR/f6
$CHECKSTAT -t file -p 0666 $DIR/f6 || error
pass
$CLEAN
$START

log '== mkdir .../d7; mcreate .../d7/f; chmod .../d7/f = test 7'
mkdir $DIR/d7
$MCREATE $DIR/d7/f
chmod 0666 $DIR/d7/f
$CHECKSTAT -t file -p 0666 $DIR/d7/f || error
pass
$CLEAN
$START

log '== mkdir .../d7; mcreate .../d7/f2; echo foo > .../d7/f2 = test 7b'
$MCREATE $DIR/d7/f2
log -n foo > $DIR/d7/f2
[ "`cat $DIR/d7/f2`" = "foo" ] || error
$CHECKSTAT -t file -s 3 $DIR/d7/f2 || error
pass
$CLEAN
$START

log '== mkdir .../d8; touch .../d8/f; chmod .../d8/f == test 8'
mkdir $DIR/d8
touch $DIR/d8/f
chmod 0666 $DIR/d8/f
$CHECKSTAT -t file -p 0666 $DIR/d8/f || error
pass
$CLEAN
$START


log '== mkdir .../d9 .../d9/d2 .../d9/d2/d3 =========== test 9'
mkdir $DIR/d9
mkdir $DIR/d9/d2
mkdir $DIR/d9/d2/d3
$CHECKSTAT -t dir $DIR/d9/d2/d3 || error
pass
$CLEAN
$START


log '== mkdir .../d10 .../d10/d2; touch .../d10/d2/f = test 10'
mkdir $DIR/d10
mkdir $DIR/d10/d2
touch $DIR/d10/d2/f
$CHECKSTAT -t file $DIR/d10/d2/f || error
pass
$CLEAN
$START

log '== mkdir .../d11 d11/d2; chmod .../d11/d2 ======= test 11'
mkdir $DIR/d11
mkdir $DIR/d11/d2
chmod 0666 $DIR/d11/d2
chmod 0705 $DIR/d11/d2
$CHECKSTAT -t dir -p 0705 $DIR/d11/d2 || error
pass
$CLEAN
$START

log '== mkdir .../d12; touch .../d12/f; chmod .../d12/f == test 12'
mkdir $DIR/d12
touch $DIR/d12/f
chmod 0666 $DIR/d12/f
chmod 0654 $DIR/d12/f
$CHECKSTAT -t file -p 0654 $DIR/d12/f || error
pass
$CLEAN
$START

log '== mkdir .../d13; creat .../d13/f;  .../d13/f; > .../d13/f == test 13'
mkdir $DIR/d13
dd if=/dev/zero of=$DIR/d13/f count=10
>  $DIR/d13/f
$CHECKSTAT -t file -s 0 $DIR/d13/f || error
pass
$CLEAN
$START

log '================================================== test 14'
mkdir $DIR/d14
touch $DIR/d14/f
rm $DIR/d14/f
$CHECKSTAT -a $DIR/d14/f || error
pass
$CLEAN
$START

log '================================================== test 15'
mkdir $DIR/d15
touch $DIR/d15/f
mv $DIR/d15/f $DIR/d15/f2
$CHECKSTAT -t file $DIR/d15/f2 || error
pass
$CLEAN
$START

log '================================================== test 16'
mkdir $DIR/d16
touch $DIR/d16/f
rm -rf $DIR/d16/f
$CHECKSTAT -a $DIR/d16/f || error
pass
$CLEAN
$START

log '== symlinks: create, remove (dangling and real) == test 17'
mkdir $DIR/d17
touch $DIR/d17/f
ln -s $DIR/d17/f $DIR/d17/l-exist
ln -s no-such-file $DIR/d17/l-dangle
ls -l $DIR/d17
$CHECKSTAT -l $DIR/d17/f $DIR/d17/l-exist || error
$CHECKSTAT -f -t f $DIR/d17/l-exist || error
$CHECKSTAT -l no-such-file $DIR/d17/l-dangle || error
$CHECKSTAT -fa $DIR/d17/l-dangle || error
rm -f $DIR/l-dangle
rm -f $DIR/l-exist
$CHECKSTAT -a $DIR/l-dangle || error
$CHECKSTAT -a $DIR/l-exist || error
pass
$CLEAN
$START

log "== touch .../f ; ls ... ========================= test 18"
touch $DIR/f
ls $DIR || error
pass
$CLEAN
$START

log "== touch .../f ; ls -l ... ====================== test 19"
touch $DIR/f
ls -l $DIR
rm $DIR/f
$CHECKSTAT -a $DIR/f || error
pass
$CLEAN
$START

log "== touch .../f ; ls -l ... ====================== test 20"
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
pass
$CLEAN
$START

log '== write to dangling link ======================== test 21'
mkdir $DIR/d21
[ -f $DIR/d21/dangle ] && rm -f $DIR/d21/dangle
ln -s dangle $DIR/d21/link
echo foo >> $DIR/d21/link
cat $DIR/d21/dangle
$CHECKSTAT -t link $DIR/d21/link || error
$CHECKSTAT -f -t file $DIR/d21/link || error
pass
$CLEAN
$START

log '== unpack tar archive as non-root user =========== test 22'
mkdir $DIR/d22
[ $UID -ne 0 ] && RUNAS=""
[ $UID -ne 0 ] && RUNAS_ID="$UID"
chown $RUNAS_ID $DIR/d22
$RUNAS tar cf - /etc/hosts /etc/sysconfig/network | $RUNAS tar xfC - $DIR/d22
ls -lR $DIR/d22/etc
$CHECKSTAT -t dir $DIR/d22/etc || error
$CHECKSTAT -u \#$RUNAS_ID $DIR/d22/etc || error
pass
$CLEAN
$START

log '== O_CREAT|O_EXCL in subdir ====================== test 23'
mkdir $DIR/d23
$TOEXCL $DIR/d23/f23
$TOEXCL -e $DIR/d23/f23 || error
pass
$CLEAN
$START

echo '== rename sanity ================================= test24'
echo '-- same directory rename'
log '-- test 24-R1: touch a ; rename a b'
mkdir $DIR/R1
touch $DIR/R1/f
mv $DIR/R1/f $DIR/R1/g
$CHECKSTAT -t file $DIR/R1/g || error
pass
$CLEAN
$START

log '-- test 24-R2: touch a b ; rename a b;'
mkdir $DIR/R2
touch $DIR/R2/{f,g}
mv $DIR/R2/f $DIR/R2/g
$CHECKSTAT -a $DIR/R2/f || error
$CHECKSTAT -t file $DIR/R2/g || error
pass
$CLEAN
$START

log '-- test 24-R3: mkdir a  ; rename a b;'
mkdir $DIR/R3
mkdir $DIR/R3/f
mv $DIR/R3/f $DIR/R3/g
$CHECKSTAT -a $DIR/R3/f || error
$CHECKSTAT -t dir $DIR/R3/g || error
pass
$CLEAN
$START

log '-- test 24-R4: mkdir a b ; rename a b;'
mkdir $DIR/R4
mkdir $DIR/R4/{f,g}
perl -e "rename \"$DIR/R4/f\", \"$DIR/R4/g\";"
$CHECKSTAT -a $DIR/R4/f || error
$CHECKSTAT -t dir $DIR/R4/g || error
pass
$CLEAN
$START

echo '-- cross directory renames --' 
log '-- test 24-R5: touch a ; rename a b'
mkdir $DIR/R5{a,b}
touch $DIR/R5a/f
mv $DIR/R5a/f $DIR/R5b/g
$CHECKSTAT -a $DIR/R5a/f || error
$CHECKSTAT -t file $DIR/R5b/g || error
pass
$CLEAN
$START

log '-- test 24-R6: touch a ; rename a b'
mkdir $DIR/R6{a,b}
touch $DIR/R6a/f $DIR/R6b/g
mv $DIR/R6a/f $DIR/R6b/g
$CHECKSTAT -a $DIR/R6a/f || error
$CHECKSTAT -t file $DIR/R6b/g || error
pass
$CLEAN
$START

log '-- test 24-R7: touch a ; rename a b'
mkdir $DIR/R7{a,b}
mkdir $DIR/R7a/f
mv $DIR/R7a/f $DIR/R7b/g
$CHECKSTAT -a $DIR/R7a/f || error
$CHECKSTAT -t dir $DIR/R7b/g || error
pass
$CLEAN
$START

log '-- test 24-R8: touch a ; rename a b'
mkdir $DIR/R8{a,b}
mkdir $DIR/R8a/f $DIR/R8b/g
perl -e "rename \"$DIR/R8a/f\", \"$DIR/R8b/g\";"
$CHECKSTAT -a $DIR/R8a/f || error
$CHECKSTAT -t dir $DIR/R8b/g || error
pass
$CLEAN
$START

echo "-- rename error cases"
log "-- test 24-R9 target error: touch f ; mkdir a ; rename f a"
mkdir $DIR/R9
mkdir $DIR/R9/a
touch $DIR/R9/f
perl -e "rename \"$DIR/R9/f\", \"$DIR/R9/a\";"
$CHECKSTAT -t file $DIR/R9/f || error
$CHECKSTAT -t dir  $DIR/R9/a || error
$CHECKSTAT -a file $DIR/R9/a/f || error
pass
$CLEAN
$START

log "--test 24-R10 source does not exist" 
mkdir $DIR/R10
perl -e "rename \"$DIR/R10/f\", \"$DIR/R10/g\"" 
$CHECKSTAT -t dir $DIR/R10 || error
$CHECKSTAT -a $DIR/R10/f || error
$CHECKSTAT -a $DIR/R10/g || error
pass
$CLEAN
$START

echo '== symlink sanity ================================ test25'
log "--test 25.1 create file in symlinked directory"
mkdir $DIR/d25
ln -s d25 $DIR/s25
touch $DIR/s25/foo
pass
$CLEAN
$START

log "--test 25.2 lookup file in symlinked directory"
$CHECKSTAT -t file $DIR/s25/foo
pass
$CLEAN
$START

log "--test 26 multiple component symlink"
mkdir $DIR/d26
mkdir $DIR/d26/d26-2
ln -s d26/d26-2 $DIR/s26
touch $DIR/s26/foo
pass
$CLEAN
$START

log "--test 26.1 multiple component symlink at the end of a lookup"
ln -s d26/d26-2/foo $DIR/s26-2
touch $DIR/s26-2
pass
$CLEAN
$START

log "--test 26.2 a chain of symlinks"
mkdir $DIR/d26.2
touch $DIR/d26.2/foo
ln -s d26.2 $DIR/s26.2-1
ln -s s26.2-1 $DIR/s26.2-2
ln -s s26.2-2 $DIR/s26.2-3
chmod 0666 $DIR/s26.2-3/foo
pass
$CLEAN
$START

# recursive symlinks (bug 439)
log "--test 26.3 create multiple component recursive symlink"
ln -s d26-3/foo $DIR/d26-3
pass
$CLEAN
$START

log "--test 26.3 unlink multiple component recursive symlink"
rm $DIR/d26-3
pass
$CLEAN
$START

echo '== stripe sanity ================================= test27'
log "--test 27.1 create one stripe"
mkdir $DIR/d27
$LSTRIPE $DIR/d27/f0 8192 0 1
$CHECKSTAT -t file $DIR/d27/f0
log "--test 27.2 write to one stripe file"
cp /etc/hosts $DIR/d27/f0
pass

log "--test 27.3 create two stripe file f01"
$LSTRIPE $DIR/d27/f01 8192 0 2
log "--test 27.4 write to two stripe file file f01"
dd if=/dev/zero of=$DIR/d27/f01 bs=4k count=4
pass

log "--test 27.5 create file with default settings"
$LSTRIPE $DIR/d27/fdef 0 -1 0
$CHECKSTAT -t file $DIR/d27/fdef
#dd if=/dev/zero of=$DIR/d27/fdef bs=4k count=4

log "--test 27.6 lstripe existing file (should return error)"
$LSTRIPE $DIR/d27/f12 8192 1 2
! $LSTRIPE $DIR/d27/f12 8192 1 2
$CHECKSTAT -t file $DIR/d27/f12
#dd if=/dev/zero of=$DIR/d27/f12 bs=4k count=4
pass


log "--test 27.7 lstripe with bad stripe size (should return error on LOV)"
$LSTRIPE $DIR/d27/fbad 100 1 2 || /bin/true
dd if=/dev/zero of=$DIR/d27/f12 bs=4k count=4
pass
$CLEAN
$START

log "--test 27.8 lfind "
$LFIND $DIR/d27
pass
$CLEAN
$START

log '== create/mknod/mkdir with bad file types ======== test28'
mkdir $DIR/d28
$CREATETEST $DIR/d28/ct || error
pass

log '== IT_GETATTR regression  ======================== test29'
mkdir $DIR/d29
touch $DIR/d29/foo
ls -l $DIR/d29
MDCDIR=${MDCDIR:-/proc/fs/lustre/ldlm/ldlm/MDC_*}
LOCKCOUNTORIG=`cat $MDCDIR/lock_count`
LOCKUNUSEDCOUNTORIG=`cat $MDCDIR/lock_unused_count`
ls -l $DIR/d29
LOCKCOUNTCURRENT=`cat $MDCDIR/lock_count`
LOCKUNUSEDCOUNTCURRENT=`cat $MDCDIR/lock_unused_count`
if [ $LOCKCOUNTCURRENT -gt $LOCKCOUNTORIG ] || [ $LOCKUNUSEDCOUNTCURRENT -gt $LOCKUNUSEDCOUNTORIG ]; then
    error
fi
pass
$CLEAN
$START

log '== run binary from Lustre (execve) =============== test30'
cp `which ls` $DIR
$DIR/ls /
$CLEAN
$START

log '== open-unlink file ============================== test31'
./openunlink $DIR/f31 $DIR/f31 || error
pass

log '== cleanup ============================================='
rm -r $DIR/[Rdfs][1-9]* $DIR/ls

echo '======================= finished ======================='
exit
