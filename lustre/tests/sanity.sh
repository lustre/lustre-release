!/bin/bash

echo '=============================== test 1'
mkdir /mnt/lustre/d1
mkdir /mnt/lustre/d1/d2
umount /mnt/lustre
dmesg | grep -i destruct
../utils/lconf --start 70 local.xml

echo '=============================== test 2'
mkdir /mnt/lustre/d2
touch /mnt/lustre/d2/f
umount /mnt/lustre
dmesg | grep -i destruct
../utils/lconf --start 70 local.xml

echo '===============================' test 3
mkdir /mnt/lustre/d3
umount /mnt/lustre
../utils/lconf --start 70 local.xml
touch /mnt/lustre/d3/f
umount /mnt/lustre
dmesg | grep -i destruct
../utils/lconf --start 70 local.xml

echo '===============================' test 4
mkdir /mnt/lustre/d4
umount /mnt/lustre
../utils/lconf --start 70 local.xml
mkdir /mnt/lustre/d4/d2
umount /mnt/lustre
dmesg | grep -i destruct
../utils/lconf --start 70 local.xml

echo '===============================' test 5
mkdir /mnt/lustre/d5
mkdir /mnt/lustre/d5/d2
chmod 0666 /mnt/lustre/d5/d2
umount /mnt/lustre
dmesg | grep -i destruct
../utils/lconf --start 70 local.xml

echo '===============================' test 6
touch /mnt/lustre/f6
chmod 0666 /mnt/lustre/f6
umount /mnt/lustre
dmesg | grep -i destruct
../utils/lconf --start 70 local.xml

echo '===============================' test 7
mkdir /mnt/lustre/d7
./mcreate /mnt/lustre/d7/f
chmod 0666 /mnt/lustre/d7/f
umount /mnt/lustre
dmesg | grep -i destruct
../utils/lconf --start 70 local.xml

echo '===============================' test 8
mkdir /mnt/lustre/d8
touch /mnt/lustre/d8/f
chmod 0666 /mnt/lustre/d8/f
umount /mnt/lustre
dmesg | grep -i destruct
../utils/lconf --start 70 local.xml


echo '=============9=================' test 9
mkdir /mnt/lustre/d9
mkdir /mnt/lustre/d9/d2
mkdir /mnt/lustre/d9/d2/d3
umount /mnt/lustre
dmesg | grep -i destruct
../utils/lconf --start 70 local.xml


echo '===============================' test 10
mkdir /mnt/lustre/d10
mkdir /mnt/lustre/d10/d2
touch /mnt/lustre/d10/d2/f
umount /mnt/lustre
dmesg | grep -i destruct
../utils/lconf --start 70 local.xml

echo '===============================' test 11
mkdir /mnt/lustre/d11
mkdir /mnt/lustre/d11/d2
chmod 0666 /mnt/lustre/d11/d2
chmod 0555 /mnt/lustre/d11/d2
umount /mnt/lustre
dmesg | grep -i destruct
../utils/lconf --start 70 local.xml

echo '===============================' test 12
mkdir /mnt/lustre/d12
touch /mnt/lustre/d12/f
chmod 0666 /mnt/lustre/d12/f
chmod 0555 /mnt/lustre/d12/f
umount /mnt/lustre
dmesg | grep -i destruct
../utils/lconf --start 70 local.xml

echo '===============================' test 13
mkdir /mnt/lustre/d13
cp /etc/passwd /mnt/lustre/d13/f
>  /mnt/lustre/d13/f
umount /mnt/lustre
dmesg | grep -i destruct
../utils/lconf --start 70 local.xml

echo '===============================' test 14
mkdir /mnt/lustre/d14
touch /mnt/lustre/d14/f
rm /mnt/lustre/d14/f
umount /mnt/lustre
dmesg | grep -i destruct
../utils/lconf --start 70 local.xml

echo '===============================' test 15
mkdir /mnt/lustre/d15
touch /mnt/lustre/d15/f
mv /mnt/lustre/d15/f /mnt/lustre/d15/f2
umount /mnt/lustre
dmesg | grep -i destruct
../utils/lconf --start 70 local.xml

echo '===============================' test 16
mkdir /mnt/lustre/d16
touch /mnt/lustre/d16/f
rm -rf /mnt/lustre/d16/f
umount /mnt/lustre
dmesg | grep -i destruct
../utils/lconf --start 70 local.xml

echo '===============================' test 17
mkdir /mnt/lustre/d17
touch /mnt/lustre/d17/f
ln -s /mnt/lustre/d17/f /mnt/lustre/d17/l-exist
ln -s no-such-file /mnt/lustre/d17/l-dangle
ls -l /mnt/lustre/d17
rm -f /mnt/lustre/l-dangle
rm -f /mnt/lustre/l-exist
umount /mnt/lustre
dmesg | grep -i destruct
../utils/lconf --start 70 local.xml
