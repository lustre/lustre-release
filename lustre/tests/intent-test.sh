#!/bin/bash -x

MTPT=/mnt/lustre

remount() {
    umount $MTPT || exit -1
    debugctl clear
    mount -t lustre_lite -o osc=OSCDEV-UUID,mdc=MDCDEV-UUID none $MTPT
}

# Test mkdir
mkdir $MTPT/dir
mkdir $MTPT/dir2

# Test mkdir on existing directory
mkdir $MTPT/dir

remount

# Test mkdir on existing directory with no locks already held
mkdir $MTPT/dir

remount

# Use mknod to create a file
./mcreate $MTPT/file
# ...on an existing file.
./mcreate $MTPT/file

remount

# Use mknod to create a file with no locks already held
./mcreate $MTPT/file

remount

ls -l $MTPT/file

remount

cat $MTPT/file
./mcreate $MTPT/file2
cat $MTPT/file2
./mcreate $MTPT/file3

remount

./tchmod 777 $MTPT/file3

remount

./mcreate $MTPT/file4
./tchmod 777 $MTPT/file4

remount

ls -l $MTPT/file4
./tchmod 777 $MTPT/file4

remount

cat $MTPT/file4
./tchmod 777 $MTPT/file4

remount

touch $MTPT/file5
touch $MTPT/file6
touch $MTPT/file5

remount

touch $MTPT/file5

remount

echo foo >> $MTPT/file
cat $MTPT/file

remount

cat $MTPT/file

echo foo >> $MTPT/iotest
echo bar >> $MTPT/iotest
cat $MTPT/iotest

remount

cat $MTPT/iotest
echo baz >> $MTPT/iotest

remount

ls $MTPT

remount

mkdir $MTPT/new
ls $MTPT

remount

ls $MTPT
mkdir $MTPT/newer
ls $MTPT

remount

cat $MTPT/iotest
echo "Testing truncation..."
echo foo > $MTPT/iotest
echo bar >> $MTPT/iotest
cat  $MTPT/iotest
echo "trucating to 4 bytes now..."
./truncate $MTPT/iotest 4
cat  $MTPT/iotest

remount

ls $MTPT
rmdir $MTPT/foo
