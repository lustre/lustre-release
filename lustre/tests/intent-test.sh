#!/bin/bash -x

OST=`../utils/obdctl name2dev OSCDEV`
MDS=`../utils/obdctl name2dev MDCDEV`

remount() {
    umount /mnt/lustre || exit -1
    debugctl clear
    mount -t lustre_lite -o ost=$OST,mds=$MDS none /mnt/lustre || exit -1
}

# Test mkdir
mkdir /mnt/lustre/dir
mkdir /mnt/lustre/dir2

# Test mkdir on existing directory
mkdir /mnt/lustre/dir

remount

# Test mkdir on existing directory with no locks already held
mkdir /mnt/lustre/dir

remount

# Use mknod to create a file
./mcreate /mnt/lustre/file
# ...on an existing file.
./mcreate /mnt/lustre/file

remount

# Use mknod to create a file with no locks already held
./mcreate /mnt/lustre/file

remount

ls -l /mnt/lustre/file

remount

cat /mnt/lustre/file
./mcreate /mnt/lustre/file2
cat /mnt/lustre/file2
./mcreate /mnt/lustre/file3

remount

./tchmod 777 /mnt/lustre/file3

remount

./mcreate /mnt/lustre/file4
./tchmod 777 /mnt/lustre/file4

remount

ls -l /mnt/lustre/file4
./tchmod 777 /mnt/lustre/file4

remount

cat /mnt/lustre/file4
./tchmod 777 /mnt/lustre/file4

remount

touch /mnt/lustre/file5
touch /mnt/lustre/file6
touch /mnt/lustre/file5

remount

touch /mnt/lustre/file5

remount

echo foo >> /mnt/lustre/file
cat /mnt/lustre/file

remount

cat /mnt/lustre/file

echo foo >> /mnt/lustre/iotest
echo bar >> /mnt/lustre/iotest
cat /mnt/lustre/iotest

remount

cat /mnt/lustre/iotest
echo baz >> /mnt/lustre/iotest

remount

ls /mnt/lustre

remount

mkdir /mnt/lustre/new
ls /mnt/lustre

remount

ls /mnt/lustre
mkdir /mnt/lustre/newer
ls /mnt/lustre

remount

cat /mnt/lustre/iotest
echo "Testing truncation..."
echo foo > /mnt/lustre/iotest
echo bar >> /mnt/lustre/iotest
cat  /mnt/lustre/iotest
echo "trucating to 4 bytes now..."
./truncate /mnt/lustre/iotest 4
cat  /mnt/lustre/iotest

remount

ls /mnt/lustre
rmdir /mnt/lustre/foo
