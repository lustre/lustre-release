#!/bin/bash

export NAME=$NAME
clean() {
        echo -n "cleanup..."
        sh llmountcleanup.sh > /dev/null
        dmesg | grep leaked | grep -v " 0 bytes" 
        dmesg | grep -i destruct
}
CLEAN=clean
start() {
        echo -n "mounting..."
        sh llrmount.sh > /dev/null
        echo -n "mounted"
        echo 0 > /proc/sys/portals/debug
}
START=start

echo '== touch .../f ; rm .../f ========== test 0'
touch /mnt/lustre/f
rm /mnt/lustre/f
$CLEAN
$START

echo '== mkdir .../d1; mkdir .../d1/d2 == test 1'
mkdir /mnt/lustre/d1
mkdir /mnt/lustre/d1/d2
$CLEAN
$START

echo '== mkdir .../d1; touch .../d1/f === test 2'
mkdir /mnt/lustre/d2
touch /mnt/lustre/d2/f
$CLEAN
$START

echo '== mkdir .../d3 =================== test 3'
mkdir /mnt/lustre/d3
$CLEAN
$START
echo '== touch .../d3/f ================= test 3b'
touch /mnt/lustre/d3/f
$CLEAN
$START

echo '== mkdir .../d4 =================== test 4'
mkdir /mnt/lustre/d4
$CLEAN
$START
echo '== mkdir .../d4/d2 ================ test 4b'
mkdir /mnt/lustre/d4/d2
$CLEAN
$START

echo '== mkdir .../d5; mkdir .../d5/d2; chmod .../d5/d2 == test 5'
mkdir /mnt/lustre/d5
mkdir /mnt/lustre/d5/d2
chmod 0666 /mnt/lustre/d5/d2
$CLEAN
$START

echo '== touch .../f6; chmod .../f6 ===== test 6'
touch /mnt/lustre/f6
chmod 0666 /mnt/lustre/f6
$CLEAN
$START

echo '== mkdir .../d7; mcreate .../d7/f; chmod .../d7/f == test 7'
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


echo '=============================== test 10'
mkdir /mnt/lustre/d10
mkdir /mnt/lustre/d10/d2
touch /mnt/lustre/d10/d2/f
$CLEAN
$START

echo '=============================== test 11'
mkdir /mnt/lustre/d11
mkdir /mnt/lustre/d11/d2
chmod 0666 /mnt/lustre/d11/d2
chmod 0555 /mnt/lustre/d11/d2
$CLEAN
$START

echo '=============================== test 12'
mkdir /mnt/lustre/d12
touch /mnt/lustre/d12/f
chmod 0666 /mnt/lustre/d12/f
chmod 0555 /mnt/lustre/d12/f
$CLEAN
$START

echo '=============================== test 13'
mkdir /mnt/lustre/d13
cp /etc/passwd /mnt/lustre/d13/f
>  /mnt/lustre/d13/f
$CLEAN
$START


echo '=============================== test 14'
mkdir /mnt/lustre/d14
touch /mnt/lustre/d14/f
rm /mnt/lustre/d14/f
$CLEAN
$START


echo '=============================== test 15'
mkdir /mnt/lustre/d15
touch /mnt/lustre/d15/f
mv /mnt/lustre/d15/f /mnt/lustre/d15/f2
$CLEAN
$START

echo '=============================== test 16'
mkdir /mnt/lustre/d16
touch /mnt/lustre/d16/f
rm -rf /mnt/lustre/d16/f
$CLEAN
$START

echo '====== symlinks: create, remove symlinks (dangling and real) =====' test 17
mkdir /mnt/lustre/d17
touch /mnt/lustre/d17/f
ln -s /mnt/lustre/d17/f /mnt/lustre/d17/l-exist
ln -s no-such-file /mnt/lustre/d17/l-dangle
ls -l /mnt/lustre/d17
rm -f /mnt/lustre/l-dangle
rm -f /mnt/lustre/l-exist
$CLEAN
$START

echo '==== touch /mnt/lustre/f ; ls /mnt/lustre ==== test 18'
touch /mnt/lustre/f
ls /mnt/lustre
$CLEAN
$START

echo '==== touch /mnt/lustre/f ; ls -l /mnt/lustre ==== test 19'
touch /mnt/lustre/f
ls -l /mnt/lustre
rm /mnt/lustre/f
$CLEAN
$START

echo '==== touch /mnt/lustre/f ; ls -l /mnt/lustre ==== test 20'
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

echo '==== write to dangling link ==== test 21'
mkdir /mnt/lustre/d21
ln -s dangle /mnt/lustre/d21/link
echo foo >> /mnt/lustre/d21/link
cat /mnt/lustre/d21/dangle
$CLEAN
$START

# echo '==== unpack tar archive as nonroot user ==== test 22'
echo please fix test 22
# mkdir /mnt/lustre/d22
# chown 4711 /mnt/lustre/d22
# (./setuid 4711 ; tar cf - /etc/hosts /etc/sysconfig/network | tar xfC - /mnt/lustre/d22 ; ./setuid 0)
# ls -lR /mnt/lustre/d22/etc
# $CLEAN
# $START

echo '==== O_CREAT|O_EXCL in subdir ==== test 23'
mkdir /mnt/lustre/d23
./toexcl /mnt/lustre/d23/f23
./toexcl /mnt/lustre/d23/f23
$CLEAN
$START

echo '=========== finished ==========='
exit
