#!/bin/bash

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

setup_opts "$@"

set -vx

MTPT1=/mnt/lustre1
MTPT2=/mnt/lustre2

remount() {
    umount $MTPT1 || exit -1
    umount $MTPT2 || exit -1
    debugctl clear
    setup_mount || fail "cannot remount /mnt/lustre"
}

fail() {
    echo "unexpected failure"
    exit -1
}

[ "`mount | grep $MTPT1`" ] || . llsetup.sh "$@" || exit -1

mkdir $MTPT1/dir1 || fail
echo "Next mkdir should fail"
mkdir $MTPT2/dir1 && fail
mkdir $MTPT2/dir2 || fail
echo "Next mkdirs should fail"
mkdir $MTPT1/dir2 && fail

remount

echo "Next 2 mkdir should fail"
mkdir $MTPT2/dir1 && fail
mkdir $MTPT1/dir2 && fail

./mcreate $MTPT2/file1
echo "Next mcreate should fail"
./mcreate $MTPT2/file1 && fail
./mcreate $MTPT2/file2 || fail
echo "Next mcreate should fail"
./mcreate $MTPT1/file2 && fail

remount

echo "Next 2 mcreates should fail"
./mcreate $MTPT2/file1 && fail
./mcreate $MTPT1/file2 && fail

rmdir $MTPT1/dir2 || fail
echo "Next rmdir should fail"
rmdir $MTPT2/dir2 && fail
rmdir $MTPT2/dir1 || fail

remount

echo "Next rpmdir should fail"

echo "File I/O: you should see increasing sequences of contiguous numbers"
echo 1 >> $MTPT1/file1
cat $MTPT2/file1
echo 2 >> $MTPT2/file1
cat $MTPT1/file1
echo 3 >> $MTPT2/file1
cat $MTPT1/file1
echo 4 >> $MTPT1/file1
cat $MTPT1/file1
