#!/bin/bash

export NAME=$NAME
clean() {
        echo -n "cleanup..."
        sh llmountcleanup.sh > /dev/null
}
CLEAN=clean
start() {
        echo -n "mounting..."
        sh llrmount.sh > /dev/null
        echo -n "mounted"
}
START=start



echo '== touch .../f ; rm .../f ======================== test 0'
touch /mnt/lustre/f
rm /mnt/lustre/f
$CLEAN
$START

echo '== mkdir .../d1; mkdir .../d1/d2 ================= test 1'
mkdir /mnt/lustre/d1
mkdir /mnt/lustre/d1/d2
$CLEAN
$START

echo '== rmdir .../d1/d2; rmdir .../d1 ================= test 1b'
rmdir /mnt/lustre/d1/d2
rmdir /mnt/lustre/d1
$CLEAN
$START

echo '== mkdir .../d2; touch .../d2/f ================== test 2'
mkdir /mnt/lustre/d2
touch /mnt/lustre/d2/f
$CLEAN
$START

echo '== rm -r .../d2; touch .../d2/f ================== test 2b'
rm -r /mnt/lustre/d2
$CLEAN
$START

echo '== mkdir .../d3 ================================== test 3'
mkdir /mnt/lustre/d3
$CLEAN
$START
echo '== touch .../d3/f ================================ test 3b'
touch /mnt/lustre/d3/f
$CLEAN
$START
echo '== rm -r .../d3 ================================== test 3c'
rm -r /mnt/lustre/d3
$CLEAN
$START

echo '== mkdir .../d4 ================================== test 4'
mkdir /mnt/lustre/d4
$CLEAN
$START
echo '== mkdir .../d4/d2 =============================== test 4b'
mkdir /mnt/lustre/d4/d2
$CLEAN
$START

echo '== mkdir .../d5; mkdir .../d5/d2; chmod .../d5/d2 = test 5'
mkdir /mnt/lustre/d5
mkdir /mnt/lustre/d5/d2
chmod 0666 /mnt/lustre/d5/d2
$CLEAN
$START

echo '== touch .../f6; chmod .../f6 ==================== test 6'
touch /mnt/lustre/f6
chmod 0666 /mnt/lustre/f6
$CLEAN
$START

echo '== mkdir .../d7; mcreate .../d7/f; chmod .../d7/f = test 7'
mkdir /mnt/lustre/d7
./mcreate /mnt/lustre/d7/f
chmod 0666 /mnt/lustre/d7/f
$CLEAN
$START

echo '== mkdir .../d8; touch .../d8/f; chmod .../d8/f == test 8'
mkdir /mnt/lustre/d8
touch /mnt/lustre/d8/f
chmod 0666 /mnt/lustre/d8/f
$CLEAN
$START


echo '== mkdir .../d9; mkdir .../d9/d2; mkdir .../d9/d2/d3 == test 9'
mkdir /mnt/lustre/d9
mkdir /mnt/lustre/d9/d2
mkdir /mnt/lustre/d9/d2/d3
$CLEAN
$START


echo '== mkdir .../d10; mkdir .../d10/d2; touch .../d10/d2/f = test 10'
mkdir /mnt/lustre/d10
mkdir /mnt/lustre/d10/d2
touch /mnt/lustre/d10/d2/f
$CLEAN
$START

echo '=================================================== test 11'
mkdir /mnt/lustre/d11
mkdir /mnt/lustre/d11/d2
chmod 0666 /mnt/lustre/d11/d2
chmod 0555 /mnt/lustre/d11/d2
$CLEAN
$START

echo '=================================================== test 12'
mkdir /mnt/lustre/d12
touch /mnt/lustre/d12/f
chmod 0666 /mnt/lustre/d12/f
chmod 0555 /mnt/lustre/d12/f
$CLEAN
$START

echo '=================================================== test 13'
mkdir /mnt/lustre/d13
cp /etc/passwd /mnt/lustre/d13/f
>  /mnt/lustre/d13/f
$CLEAN
$START


echo '=================================================== test 14'
mkdir /mnt/lustre/d14
touch /mnt/lustre/d14/f
rm /mnt/lustre/d14/f
$CLEAN
$START


echo '=================================================== test 15'
mkdir /mnt/lustre/d15
touch /mnt/lustre/d15/f
mv /mnt/lustre/d15/f /mnt/lustre/d15/f2
$CLEAN
$START

echo '=================================================== test 16'
mkdir /mnt/lustre/d16
touch /mnt/lustre/d16/f
rm -rf /mnt/lustre/d16/f
$CLEAN
$START

echo '== symlinks: create, remove (dangling and real) === test 17'
mkdir /mnt/lustre/d17
touch /mnt/lustre/d17/f
ln -s /mnt/lustre/d17/f /mnt/lustre/d17/l-exist
ln -s no-such-file /mnt/lustre/d17/l-dangle
ls -l /mnt/lustre/d17
rm -f /mnt/lustre/l-dangle
rm -f /mnt/lustre/l-exist
$CLEAN
$START

echo '== touch /mnt/lustre/f ; ls /mnt/lustre ========== test 18'
touch /mnt/lustre/f
ls /mnt/lustre
$CLEAN
$START

echo '== touch /mnt/lustre/f ; ls -l /mnt/lustre ======= test 19'
touch /mnt/lustre/f
ls -l /mnt/lustre
rm /mnt/lustre/f
$CLEAN
$START

echo '== touch /mnt/lustre/f ; ls -l /mnt/lustre ======= test 20'
touch /mnt/lustre/f
rm /mnt/lustre/f
echo "1 done"
touch /mnt/lustre/f
rm /mnt/lustre/f
echo "2 done"
touch /mnt/lustre/f
rm /mnt/lustre/f
echo "3 done"
$CLEAN
$START

echo '== write to dangling link ======================= test 21'
mkdir /mnt/lustre/d21
ln -s dangle /mnt/lustre/d21/link
echo foo >> /mnt/lustre/d21/link
cat /mnt/lustre/d21/dangle
$CLEAN
$START

echo '== unpack tar archive as nonroot user =========== test 22'
mkdir /mnt/lustre/d22
chown 4711 /mnt/lustre/d22
sudo -u \#4711 tar cf - /etc/hosts /etc/sysconfig/network | tar xfC - /mnt/lustre/d22
ls -lR /mnt/lustre/d22/etc
$CLEAN
$START

echo '== O_CREAT|O_EXCL in subdir ===================== test 23'
mkdir /mnt/lustre/d23
./toexcl /mnt/lustre/d23/f23
./toexcl /mnt/lustre/d23/f23
$CLEAN
$START

echo '== rename sanity ============================= test24'
echo '-- same directory rename'
echo '-- test 24-R1: touch a ; rename a b'
mkdir /mnt/lustre/R1
touch /mnt/lustre/R1/f
mv /mnt/lustre/R1/f /mnt/lustre/R1/g
$CLEAN
$START

echo '-- test 24-R2: touch a b ; rename a b;'
mkdir /mnt/lustre/R2
touch /mnt/lustre/R2/{f,g}
mv /mnt/lustre/R2/f /mnt/lustre/R2/g
$CLEAN
$START

echo '-- test 24-R3: mkdir a  ; rename a b;'
mkdir /mnt/lustre/R3
mkdir /mnt/lustre/R3/f
mv /mnt/lustre/R3/f /mnt/lustre/R3/g
$CLEAN
$START

echo '-- test 24-R4: mkdir a b ; rename a b;'
mkdir /mnt/lustre/R4
mkdir /mnt/lustre/R4/{f,g}
perl -e 'rename "/mnt/lustre/R3/f", "/mnt/lustre/R3/g";'
$CLEAN
$START

echo '-- cross directory renames --' 
echo '-- test 24-R5: touch a ; rename a b'
mkdir /mnt/lustre/R5{a,b}
touch /mnt/lustre/R5a/f
mv /mnt/lustre/R5a/f /mnt/lustre/R5b/g
$CLEAN
$START

echo '-- test 24-R6: touch a ; rename a b'
mkdir /mnt/lustre/R6{a,b}
touch /mnt/lustre/R6a/f /mnt/lustre/R6b/g
mv /mnt/lustre/R6a/f /mnt/lustre/R6b/g
$CLEAN
$START

echo '-- test 24-R7: touch a ; rename a b'
mkdir /mnt/lustre/R7{a,b}
mkdir /mnt/lustre/R7a/f
mv /mnt/lustre/R7a/f /mnt/lustre/R7b/g
$CLEAN
$START

echo '-- test 24-R8: touch a ; rename a b'
mkdir /mnt/lustre/R8{a,b}
mkdir /mnt/lustre/R8a/f /mnt/lustre/R8b/g
perl -e 'rename "/mnt/lustre/R8a/f", "/mnt/lustre/R8b/g";'
$CLEAN
$START

echo "-- rename error cases"
echo "-- test 24-R9 target error: touch f ; mkdir a ; rename f a"
mkdir /mnt/lustre/R9
mkdir /mnt/lustre/R9/a
touch /mnt/lustre/R9/f
perl -e 'rename "/mnt/lustre/R9/f", "/mnt/lustre/R9/a";'
$CLEAN
$START

echo "--test 24-R10 source does not exist" 
mkdir /mnt/lustre/R10
mv /mnt/lustre/R10/f /mnt/lustre/R10/g 
$CLEAN
$START

echo '======================= finished ======================='
exit
