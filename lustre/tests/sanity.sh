#!/bin/bash

#CLEAN=umount /mnt/lustre
#START=../utils/lconf --minlevel 70 local.xml
CLEAN="sh llmountcleanup.sh"
START="sh llmount.sh"



echo '==== touch /mnt/lustre/f ; rm /mnt/lustre/* ==== test 19'
touch /mnt/lustre/f
rm /mnt/lustre/*
$CLEAN
dmesg | grep -i destruct
$START


echo '=============================== test 1'
mkdir /mnt/lustre/d1
mkdir /mnt/lustre/d1/d2
$CLEAN
dmesg | grep -i destruct
$START


echo '=============================== test 2'
mkdir /mnt/lustre/d2
touch /mnt/lustre/d2/f
$CLEAN
dmesg | grep -i destruct
$START

echo '===============================' test 3
mkdir /mnt/lustre/d3
$CLEAN
$START
touch /mnt/lustre/d3/f
$CLEAN
dmesg | grep -i destruct
$START

echo '===============================' test 4
mkdir /mnt/lustre/d4
$CLEAN
$START
mkdir /mnt/lustre/d4/d2
$CLEAN
dmesg | grep -i destruct
$START

echo '===============================' test 5
mkdir /mnt/lustre/d5
mkdir /mnt/lustre/d5/d2
chmod 0666 /mnt/lustre/d5/d2
$CLEAN
dmesg | grep -i destruct
$START

echo '===============================' test 6
touch /mnt/lustre/f6
chmod 0666 /mnt/lustre/f6
$CLEAN
dmesg | grep -i destruct
$START

echo '===============================' test 7
mkdir /mnt/lustre/d7
./mcreate /mnt/lustre/d7/f
chmod 0666 /mnt/lustre/d7/f
$CLEAN
dmesg | grep -i destruct
$START

echo '===============================' test 8
mkdir /mnt/lustre/d8
touch /mnt/lustre/d8/f
chmod 0666 /mnt/lustre/d8/f
$CLEAN
dmesg | grep -i destruct
$START


echo '=============9=================' test 9
mkdir /mnt/lustre/d9
mkdir /mnt/lustre/d9/d2
mkdir /mnt/lustre/d9/d2/d3
$CLEAN
dmesg | grep -i destruct
$START


echo '===============================' test 10
mkdir /mnt/lustre/d10
mkdir /mnt/lustre/d10/d2
touch /mnt/lustre/d10/d2/f
$CLEAN
dmesg | grep -i destruct
$START

echo '===============================' test 11
mkdir /mnt/lustre/d11
mkdir /mnt/lustre/d11/d2
chmod 0666 /mnt/lustre/d11/d2
chmod 0555 /mnt/lustre/d11/d2
$CLEAN
dmesg | grep -i destruct
$START

echo '===============================' test 12
mkdir /mnt/lustre/d12
touch /mnt/lustre/d12/f
chmod 0666 /mnt/lustre/d12/f
chmod 0555 /mnt/lustre/d12/f
$CLEAN
dmesg | grep -i destruct
$START

echo '===============================' test 13
mkdir /mnt/lustre/d13
cp /etc/passwd /mnt/lustre/d13/f
>  /mnt/lustre/d13/f
$CLEAN
dmesg | grep -i destruct
$START


echo '===============================' test 14
mkdir /mnt/lustre/d14
touch /mnt/lustre/d14/f
rm /mnt/lustre/d14/f
$CLEAN
dmesg | grep -i destruct
$START


echo '===============================' test 15
mkdir /mnt/lustre/d15
touch /mnt/lustre/d15/f
mv /mnt/lustre/d15/f /mnt/lustre/d15/f2
$CLEAN
dmesg | grep -i destruct
$START

echo '===============================' test 16
mkdir /mnt/lustre/d16
touch /mnt/lustre/d16/f
rm -rf /mnt/lustre/d16/f
$CLEAN
dmesg | grep -i destruct
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
dmesg | grep -i destruct
$START

echo '==== touch /mnt/lustre/f ; ls /mnt/lustre ==== test 18'
touch /mnt/lustre/f
ls /mnt/lustre
$CLEAN
dmesg | grep -i destruct
$START

echo '==== touch /mnt/lustre/f ; ls -l /mnt/lustre ==== test 19'
touch /mnt/lustre/f
ls -l /mnt/lustre
$CLEAN
dmesg | grep -i destruct
$START

echo '==== touch /mnt/lustre/f ; ls -l /mnt/lustre ==== test 19'
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
dmesg | grep -i destruct
$START

exit
