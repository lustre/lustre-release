#!/bin/bash

set -e

CHECKSTAT=${CHECKSTAT:-"./checkstat -v"}
MOUNT=${MOUNT:-/mnt/lustre}
export NAME=$NAME
clean() {
        echo -n "cln.."
        sh llmountcleanup.sh > /dev/null
}
CLEAN=${CLEAN:-clean}
start() {
        echo -n "mnt.."
        sh llrmount.sh > /dev/null
        echo -n "done"
}
START=${START:-start}

error () { 
    echo FAIL
    exit 1
}

pass() { 
    echo PASS
}

mount | grep $MOUNT || $START

echo '== touch .../f ; rm .../f ======================== test 0'
touch $MOUNT/f
$CHECKSTAT -t file $MOUNT/f || error 
rm $MOUNT/f
$CHECKSTAT -a $MOUNT/f || error
pass
$CLEAN
$START

echo '== mkdir .../d1; mkdir .../d1/d2 ================= test 1'
mkdir $MOUNT/d1
mkdir $MOUNT/d1/d2
$CHECKSTAT -t dir $MOUNT/d1/d2 || error
pass
$CLEAN
$START

echo '== rmdir .../d1/d2; rmdir .../d1 ================= test 1b'
rmdir $MOUNT/d1/d2
rmdir $MOUNT/d1
$CHECKSTAT -a $MOUNT/d1 || error
pass
$CLEAN
$START

echo '== mkdir .../d2; touch .../d2/f ================== test 2'
mkdir $MOUNT/d2
touch $MOUNT/d2/f
$CHECKSTAT -t file $MOUNT/d2/f || error
pass
$CLEAN
$START

echo '== rm -r .../d2; touch .../d2/f ================== test 2b'
rm -r $MOUNT/d2
$CHECKSTAT -a $MOUNT/d2 || error
pass
$CLEAN
$START

echo '== mkdir .../d3 ================================== test 3'
mkdir $MOUNT/d3
$CHECKSTAT -t dir $MOUNT/d3 || error
pass
$CLEAN
$START
echo '== touch .../d3/f ================================ test 3b'
touch $MOUNT/d3/f
$CHECKSTAT -t file $MOUNT/d3/f || error
pass
$CLEAN
$START
echo '== rm -r .../d3 ================================== test 3c'
rm -r $MOUNT/d3
$CHECKSTAT -a $MOUNT/d3 || error
pass
$CLEAN
$START

echo '== mkdir .../d4 ================================== test 4'
mkdir $MOUNT/d4
$CHECKSTAT -t dir $MOUNT/d4 || error
pass
$CLEAN
$START
echo '== mkdir .../d4/d2 =============================== test 4b'
mkdir $MOUNT/d4/d2
$CHECKSTAT -t dir $MOUNT/d4/d2 || error
pass
$CLEAN
$START

echo '== mkdir .../d5; mkdir .../d5/d2; chmod .../d5/d2 = test 5'
mkdir $MOUNT/d5
mkdir $MOUNT/d5/d2
chmod 0666 $MOUNT/d5/d2
$CHECKSTAT -t dir -p 0666 $MOUNT/d5/d2 || error
pass
$CLEAN
$START

echo '== touch .../f6; chmod .../f6 ==================== test 6'
touch $MOUNT/f6
chmod 0666 $MOUNT/f6
$CHECKSTAT -t file -p 0666 $MOUNT/f6 || error
pass
$CLEAN
$START

echo '== mkdir .../d7; mcreate .../d7/f; chmod .../d7/f = test 7'
mkdir $MOUNT/d7
./mcreate $MOUNT/d7/f
chmod 0666 $MOUNT/d7/f
$CHECKSTAT -t file -p 0666 $MOUNT/d7/f || error
pass
$CLEAN
$START

echo '== mkdir .../d8; touch .../d8/f; chmod .../d8/f == test 8'
mkdir $MOUNT/d8
touch $MOUNT/d8/f
chmod 0666 $MOUNT/d8/f
$CHECKSTAT -t file -p 0666 $MOUNT/d8/f || error
pass
$CLEAN
$START


echo '== mkdir .../d9 .../d9/d2 .../d9/d2/d3 =========== test 9'
mkdir $MOUNT/d9
mkdir $MOUNT/d9/d2
mkdir $MOUNT/d9/d2/d3
$CHECKSTAT -t dir $MOUNT/d9/d2/d3 || error
pass
$CLEAN
$START


echo '== mkdir .../d10 .../d10/d2; touch .../d10/d2/f = test 10'
mkdir $MOUNT/d10
mkdir $MOUNT/d10/d2
touch $MOUNT/d10/d2/f
$CHECKSTAT -t file $MOUNT/d10/d2/f || error
pass
$CLEAN
$START

echo '== mkdir .../d11 d11/d2; chmod .../d11/d2 ======= test 11'
mkdir $MOUNT/d11
mkdir $MOUNT/d11/d2
chmod 0666 $MOUNT/d11/d2
chmod 0555 $MOUNT/d11/d2
$CHECKSTAT -t dir -p 0555 $MOUNT/d11/d2 || error
pass
$CLEAN
$START

echo '== mkdir .../d12; touch .../d12/f; chmod .../d12/f == test 12'
mkdir $MOUNT/d12
touch $MOUNT/d12/f
chmod 0666 $MOUNT/d12/f
chmod 0555 $MOUNT/d12/f
$CHECKSTAT -t file -p 0555 $MOUNT/d12/f || error
pass
$CLEAN
$START

echo '== mkdir .../d13; cp /etc/passwd .../d13/f; > .../d13/f == test 13'
mkdir $MOUNT/d13
cp /etc/hosts $MOUNT/d13/f
>  $MOUNT/d13/f
$CHECKSTAT -t file -s 0 $MOUNT/d13/f || error
pass
$CLEAN
$START


echo '================================================== test 14'
mkdir $MOUNT/d14
touch $MOUNT/d14/f
rm $MOUNT/d14/f
$CHECKSTAT -a $MOUNT/d14/f || error
pass
$CLEAN
$START


echo '================================================== test 15'
mkdir $MOUNT/d15
touch $MOUNT/d15/f
mv $MOUNT/d15/f $MOUNT/d15/f2
$CHECKSTAT -t file $MOUNT/d15/f2 || error
pass
$CLEAN
$START

echo '================================================== test 16'
mkdir $MOUNT/d16
touch $MOUNT/d16/f
rm -rf $MOUNT/d16/f
$CHECKSTAT -a $MOUNT/d16/f || error
pass
$CLEAN
$START

echo '== symlinks: create, remove (dangling and real) == test 17'
mkdir $MOUNT/d17
touch $MOUNT/d17/f
ln -s $MOUNT/d17/f $MOUNT/d17/l-exist
ln -s no-such-file $MOUNT/d17/l-dangle
ls -l $MOUNT/d17
$CHECKSTAT -l $MOUNT/d17/f $MOUNT/d17/l-exist || error
$CHECKSTAT -f -t f $MOUNT/d17/l-exist || error
$CHECKSTAT -l no-such-file $MOUNT/d17/l-dangle || error
$CHECKSTAT -fa $MOUNT/d17/l-dangle || error
rm -f $MOUNT/l-dangle
rm -f $MOUNT/l-exist
$CHECKSTAT -a $MOUNT/l-dangle || error
$CHECKSTAT -a $MOUNT/l-exist || error
pass
$CLEAN
$START

echo "== touch .../f ; ls ... ========================= test 18"
touch $MOUNT/f
ls $MOUNT || error
pass
$CLEAN
$START

echo "== touch .../f ; ls -l ... ====================== test 19"
touch $MOUNT/f
ls -l $MOUNT
rm $MOUNT/f
$CHECKSTAT -a $MOUNT/f || error
pass
$CLEAN
$START

echo "== touch .../f ; ls -l ... ====================== test 20"
touch $MOUNT/f
rm $MOUNT/f
echo "1 done"
touch $MOUNT/f
rm $MOUNT/f
echo "2 done"
touch $MOUNT/f
rm $MOUNT/f
echo "3 done"
$CHECKSTAT -a $MOUNT/f || error
pass
$CLEAN
$START

echo '== write to dangling link ======================== test 21'
mkdir $MOUNT/d21
[ -f $MOUNT/d21/dangle ] && rm -f $MOUNT/d21/dangle
ln -s dangle $MOUNT/d21/link
echo foo >> $MOUNT/d21/link
cat $MOUNT/d21/dangle
$CHECKSTAT -t link $MOUNT/d21/link || error
$CHECKSTAT -f -t file $MOUNT/d21/link || error
pass
$CLEAN
$START

echo '== unpack tar archive as non-root user =========== test 22'
mkdir $MOUNT/d22
which sudo && chown 4711 $MOUNT/d22
SUDO=`which sudo 2> /dev/null` && SUDO="$SUDO -u #4711" || SUDO=""
$SUDO tar cf - /etc/hosts /etc/sysconfig/network | $SUDO tar xfC - $MOUNT/d22
ls -lR $MOUNT/d22/etc
$CHECKSTAT -t dir $MOUNT/d22/etc || error
[ -z "$SUDO" ] || $CHECKSTAT -u \#4711 $MOUNT/d22/etc || error
pass
$CLEAN
$START

echo '== O_CREAT|O_EXCL in subdir ====================== test 23'
mkdir $MOUNT/d23
./toexcl $MOUNT/d23/f23
./toexcl -e $MOUNT/d23/f23 || error
pass
$CLEAN
$START

echo '== rename sanity ================================= test24'
echo '-- same directory rename'
echo '-- test 24-R1: touch a ; rename a b'
mkdir $MOUNT/R1
touch $MOUNT/R1/f
mv $MOUNT/R1/f $MOUNT/R1/g
$CHECKSTAT -t file $MOUNT/R1/g || error
pass
$CLEAN
$START

echo '-- test 24-R2: touch a b ; rename a b;'
mkdir $MOUNT/R2
touch $MOUNT/R2/{f,g}
mv $MOUNT/R2/f $MOUNT/R2/g
$CHECKSTAT -a $MOUNT/R2/f || error
$CHECKSTAT -t file $MOUNT/R2/g || error
pass
$CLEAN
$START

echo '-- test 24-R3: mkdir a  ; rename a b;'
mkdir $MOUNT/R3
mkdir $MOUNT/R3/f
mv $MOUNT/R3/f $MOUNT/R3/g
$CHECKSTAT -a $MOUNT/R3/f || error
$CHECKSTAT -t dir $MOUNT/R3/g || error
pass
$CLEAN
$START

echo '-- test 24-R4: mkdir a b ; rename a b;'
mkdir $MOUNT/R4
mkdir $MOUNT/R4/{f,g}
perl -e "rename \"$MOUNT/R4/f\", \"$MOUNT/R4/g\";"
$CHECKSTAT -a $MOUNT/R4/f || error
$CHECKSTAT -t dir $MOUNT/R4/g || error
pass
$CLEAN
$START

echo '-- cross directory renames --' 
echo '-- test 24-R5: touch a ; rename a b'
mkdir $MOUNT/R5{a,b}
touch $MOUNT/R5a/f
mv $MOUNT/R5a/f $MOUNT/R5b/g
$CHECKSTAT -a $MOUNT/R5a/f || error
$CHECKSTAT -t file $MOUNT/R5b/g || error
pass
$CLEAN
$START

echo '-- test 24-R6: touch a ; rename a b'
mkdir $MOUNT/R6{a,b}
touch $MOUNT/R6a/f $MOUNT/R6b/g
mv $MOUNT/R6a/f $MOUNT/R6b/g
$CHECKSTAT -a $MOUNT/R6a/f || error
$CHECKSTAT -t file $MOUNT/R6b/g || error
pass
$CLEAN
$START

echo '-- test 24-R7: touch a ; rename a b'
mkdir $MOUNT/R7{a,b}
mkdir $MOUNT/R7a/f
mv $MOUNT/R7a/f $MOUNT/R7b/g
$CHECKSTAT -a $MOUNT/R7a/f || error
$CHECKSTAT -t dir $MOUNT/R7b/g || error
pass
$CLEAN
$START

echo '-- test 24-R8: touch a ; rename a b'
mkdir $MOUNT/R8{a,b}
mkdir $MOUNT/R8a/f $MOUNT/R8b/g
perl -e "rename \"$MOUNT/R8a/f\", \"$MOUNT/R8b/g\";"
$CHECKSTAT -a $MOUNT/R8a/f || error
$CHECKSTAT -t dir $MOUNT/R8b/g || error
pass
$CLEAN
$START

echo "-- rename error cases"
echo "-- test 24-R9 target error: touch f ; mkdir a ; rename f a"
mkdir $MOUNT/R9
mkdir $MOUNT/R9/a
touch $MOUNT/R9/f
perl -e "rename \"$MOUNT/R9/f\", \"$MOUNT/R9/a\";"
$CHECKSTAT -t file $MOUNT/R9/f || error
$CHECKSTAT -t dir  $MOUNT/R9/a || error
$CHECKSTAT -a file $MOUNT/R9/a/f || error
pass
$CLEAN
$START

echo "--test 24-R10 source does not exist" 
mkdir $MOUNT/R10
perl -e "rename \"$MOUNT/R10/f\", \"$MOUNT/R10/g\"" 
$CHECKSTAT -t dir $MOUNT/R10 || error
$CHECKSTAT -a $MOUNT/R10/f || error
$CHECKSTAT -a $MOUNT/R10/g || error
pass
$CLEAN
$START

echo '== symlink sanity ================================ test25'
echo "--test 25.1 create file in symlinked directory"
mkdir $MOUNT/d25
ln -s d25 $MOUNT/s25
touch $MOUNT/s25/foo
pass
$CLEAN
$START

echo "--test 25.2 lookup file in symlinked directory"
$CHECKSTAT -t file $MOUNT/s25/foo
pass
$CLEAN
$START

echo "--test 26 multiple component symlink"
mkdir $MOUNT/d26
mkdir $MOUNT/d26/d26-2
ln -s d26/d26-2 $MOUNT/s26
touch $MOUNT/s26/foo
pass
$CLEAN
$START

echo "--test 26.1 multiple component symlink at the end of a lookup"
ln -s d26/d26-2/foo $MOUNT/s26-2
touch $MOUNT/s26-2
pass
$CLEAN
$START

echo "--test 26.2 a chain of symlinks"
mkdir $MOUNT/d26.2
touch $MOUNT/d26.2/foo
ln -s d26.2 $MOUNT/s26.2-1
ln -s s26.2-1 $MOUNT/s26.2-2
ln -s s26.2-2 $MOUNT/s26.2-3
chmod 0666 $MOUNT/s26.2-3/foo
pass
$CLEAN
$START

echo '== stripe sanity ================================= test27'
echo "--test 26.1 create one stripe"
mkdir $MOUNT/d27
../utils/lstripe $MOUNT/d27/f0 4096 0 1
$CHECKSTAT -t file $MOUNT/d27/f0
echo "--test 26.2 write to one stripe file"
cp /etc/hosts $MOUNT/d27/f0
pass
$CLEAN
$START

echo "--test 26.3 create two stripes"
../utils/lstripe $MOUNT/d27/f01 4096 0 2
echo "--test 26.4 write to two stripe file"
cp /etc/hosts $MOUNT/d27/f01
pass
$CLEAN
$START

echo "--test 26.5 lstripe existing file (should return error)"
../utils/lstripe $MOUNT/d27/f12 4096 1 2
! ../utils/lstripe $MOUNT/d27/f12 4096 1 2
pass
$CLEAN
$START

echo "--test 26.6 lfind "
../utils/lfind $MOUNT/d27
pass
$CLEAN
$START


echo '== cleanup ============================================='
rm -r $MOUNT/[Rdfs][1-9]*

echo '======================= finished ======================='
exit
