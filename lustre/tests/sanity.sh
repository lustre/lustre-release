#!/bin/bash

set -e
MOUNT=${MOUNT:-/mnt/lustre}
export NAME=$NAME
clean() {
        echo -n "cleanup..."
        sh llmountcleanup.sh > /dev/null
}
CLEAN=${CLEAN:-clean}
start() {
        echo -n "mounting..."
        sh llrmount.sh > /dev/null
        echo -n "mounted"
}
START=${START:-start}

error () { 
    echo FAIL
    exit 1
}

pass() { 
    echo PASS
}

echo '== touch .../f ; rm .../f ======================== test 0'
touch $MOUNT/f
[ -f $MOUNT/f ] || error 
rm $MOUNT/f
[ ! -f $MOUNT/f ] || error
pass
$CLEAN
$START

echo '== mkdir .../d1; mkdir .../d1/d2 ================= test 1'
mkdir $MOUNT/d1
mkdir $MOUNT/d1/d2
[ -d $MOUNT/d1/d2 ] || error
pass
$CLEAN
$START

echo '== rmdir .../d1/d2; rmdir .../d1 ================= test 1b'
rmdir $MOUNT/d1/d2
rmdir $MOUNT/d1
[ ! -d $MOUNT/d1 ] || error
pass
$CLEAN
$START

echo '== mkdir .../d2; touch .../d2/f ================== test 2'
mkdir $MOUNT/d2
touch $MOUNT/d2/f
$CLEAN
$START

echo '== rm -r .../d2; touch .../d2/f ================== test 2b'
rm -r $MOUNT/d2
$CLEAN
$START

echo '== mkdir .../d3 ================================== test 3'
mkdir $MOUNT/d3
$CLEAN
$START
echo '== touch .../d3/f ================================ test 3b'
touch $MOUNT/d3/f
$CLEAN
$START
echo '== rm -r .../d3 ================================== test 3c'
rm -r $MOUNT/d3
$CLEAN
$START

echo '== mkdir .../d4 ================================== test 4'
mkdir $MOUNT/d4
$CLEAN
$START
echo '== mkdir .../d4/d2 =============================== test 4b'
mkdir $MOUNT/d4/d2
$CLEAN
$START

echo '== mkdir .../d5; mkdir .../d5/d2; chmod .../d5/d2 = test 5'
mkdir $MOUNT/d5
mkdir $MOUNT/d5/d2
chmod 0666 $MOUNT/d5/d2
$CLEAN
$START

echo '== touch .../f6; chmod .../f6 ==================== test 6'
touch $MOUNT/f6
chmod 0666 $MOUNT/f6
$CLEAN
$START

echo '== mkdir .../d7; mcreate .../d7/f; chmod .../d7/f = test 7'
mkdir $MOUNT/d7
./mcreate $MOUNT/d7/f
chmod 0666 $MOUNT/d7/f
$CLEAN
$START

echo '== mkdir .../d8; touch .../d8/f; chmod .../d8/f == test 8'
mkdir $MOUNT/d8
touch $MOUNT/d8/f
chmod 0666 $MOUNT/d8/f
$CLEAN
$START


echo '== mkdir .../d9; mkdir .../d9/d2; mkdir .../d9/d2/d3 == test 9'
mkdir $MOUNT/d9
mkdir $MOUNT/d9/d2
mkdir $MOUNT/d9/d2/d3
$CLEAN
$START


echo '== mkdir .../d10; mkdir .../d10/d2; touch .../d10/d2/f = test 10'
mkdir $MOUNT/d10
mkdir $MOUNT/d10/d2
touch $MOUNT/d10/d2/f
$CLEAN
$START

echo '=================================================== test 11'
mkdir $MOUNT/d11
mkdir $MOUNT/d11/d2
chmod 0666 $MOUNT/d11/d2
chmod 0555 $MOUNT/d11/d2
$CLEAN
$START

echo '=================================================== test 12'
mkdir $MOUNT/d12
touch $MOUNT/d12/f
chmod 0666 $MOUNT/d12/f
chmod 0555 $MOUNT/d12/f
$CLEAN
$START

echo '=================================================== test 13'
mkdir $MOUNT/d13
cp /etc/passwd $MOUNT/d13/f
>  $MOUNT/d13/f
$CLEAN
$START


echo '=================================================== test 14'
mkdir $MOUNT/d14
touch $MOUNT/d14/f
rm $MOUNT/d14/f
$CLEAN
$START


echo '=================================================== test 15'
mkdir $MOUNT/d15
touch $MOUNT/d15/f
mv $MOUNT/d15/f $MOUNT/d15/f2
$CLEAN
$START

echo '=================================================== test 16'
mkdir $MOUNT/d16
touch $MOUNT/d16/f
rm -rf $MOUNT/d16/f
$CLEAN
$START

echo '== symlinks: create, remove (dangling and real) === test 17'
mkdir $MOUNT/d17
touch $MOUNT/d17/f
ln -s $MOUNT/d17/f $MOUNT/d17/l-exist
ln -s no-such-file $MOUNT/d17/l-dangle
ls -l $MOUNT/d17
rm -f $MOUNT/l-dangle
rm -f $MOUNT/l-exist
$CLEAN
$START

echo "== touch $MOUNT/f ; ls $MOUNT ========== test 18"
touch $MOUNT/f
ls $MOUNT
$CLEAN
$START

echo "== touch $MOUNT/f ; ls -l $MOUNT ======= test 19"
touch $MOUNT/f
ls -l $MOUNT
rm $MOUNT/f
$CLEAN
$START

echo "== touch $MOUNT/f ; ls -l $MOUNT ======= test 20"
touch $MOUNT/f
rm $MOUNT/f
echo "1 done"
touch $MOUNT/f
rm $MOUNT/f
echo "2 done"
touch $MOUNT/f
rm $MOUNT/f
echo "3 done"
$CLEAN
$START

echo '== write to dangling link ======================= test 21'
mkdir $MOUNT/d21
ln -s dangle $MOUNT/d21/link
echo foo >> $MOUNT/d21/link
cat $MOUNT/d21/dangle
$CLEAN
$START

echo '== unpack tar archive as nonroot user =========== test 22'
mkdir $MOUNT/d22
which sudo && chown 4711 $MOUNT/d22
SUDO=`which sudo` && SUDO="$SUDO -u \#4711" || SUDO=""
$SUDO tar cf - /etc/hosts /etc/sysconfig/network | $SUDO tar xfC - $MOUNT/d22
ls -lR $MOUNT/d22/etc
$CLEAN
$START

echo '== O_CREAT|O_EXCL in subdir ===================== test 23'
mkdir $MOUNT/d23
./toexcl $MOUNT/d23/f23
./toexcl $MOUNT/d23/f23
$CLEAN
$START

echo '== rename sanity ============================= test24'
echo '-- same directory rename'
echo '-- test 24-R1: touch a ; rename a b'
mkdir $MOUNT/R1
touch $MOUNT/R1/f
mv $MOUNT/R1/f $MOUNT/R1/g
$CLEAN
$START

echo '-- test 24-R2: touch a b ; rename a b;'
mkdir $MOUNT/R2
touch $MOUNT/R2/{f,g}
mv $MOUNT/R2/f $MOUNT/R2/g
$CLEAN
$START

echo '-- test 24-R3: mkdir a  ; rename a b;'
mkdir $MOUNT/R3
mkdir $MOUNT/R3/f
mv $MOUNT/R3/f $MOUNT/R3/g
$CLEAN
$START

echo '-- test 24-R4: mkdir a b ; rename a b;'
mkdir $MOUNT/R4
mkdir $MOUNT/R4/{f,g}
perl -e "rename \"$MOUNT/R3/f\", \"$MOUNT/R3/g\";"
$CLEAN
$START

echo '-- cross directory renames --' 
echo '-- test 24-R5: touch a ; rename a b'
mkdir $MOUNT/R5{a,b}
touch $MOUNT/R5a/f
mv $MOUNT/R5a/f $MOUNT/R5b/g
$CLEAN
$START

echo '-- test 24-R6: touch a ; rename a b'
mkdir $MOUNT/R6{a,b}
touch $MOUNT/R6a/f $MOUNT/R6b/g
mv $MOUNT/R6a/f $MOUNT/R6b/g
$CLEAN
$START

echo '-- test 24-R7: touch a ; rename a b'
mkdir $MOUNT/R7{a,b}
mkdir $MOUNT/R7a/f
mv $MOUNT/R7a/f $MOUNT/R7b/g
$CLEAN
$START

echo '-- test 24-R8: touch a ; rename a b'
mkdir $MOUNT/R8{a,b}
mkdir $MOUNT/R8a/f $MOUNT/R8b/g
perl -e "rename \"$MOUNT/R8a/f\", \"$MOUNT/R8b/g\";"
$CLEAN
$START

echo "-- rename error cases"
echo "-- test 24-R9 target error: touch f ; mkdir a ; rename f a"
mkdir $MOUNT/R9
mkdir $MOUNT/R9/a
touch $MOUNT/R9/f
perl -e "rename \"$MOUNT/R9/f\", \"$MOUNT/R9/a\";"
$CLEAN
$START

echo "--test 24-R10 source does not exist" 
mkdir $MOUNT/R10
mv $MOUNT/R10/f $MOUNT/R10/g 
$CLEAN
$START

echo '======================= finished ======================='
exit
