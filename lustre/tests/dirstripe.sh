#!/bin/sh

set -e

SRCDIR="/r/usr/src/lustre"
PATH=$SRCDIR:$SRCDIR/tests:$SRCDIR/utils:$PATH
DIR="/mnt/lustre"
LFS=${LFS:-lfs}
export NAME=${NAME:-lov}

if ! mount | grep -q $DIR; then
	echo -n "mnt.."
	sh llmount.sh > /dev/null || exit 10
	echo "done"
fi

cd $DIR

echo "===== test 1: no stripe info set on dir1====="
mkdir $DIR/dir1
cd $DIR/dir1
touch file1 file2 file3 file4 file5
cd $DIR
$LFS find -v $DIR/dir1

echo "===== test 2: set default stripe info on dir ====="
echo "===== lfs dsetstripe dir2 0 -1 0 ================="
mkdir $DIR/dir2
$LFS dsetstripe $DIR/dir2 0 -1 0
cd $DIR/dir2
touch file1 file2 file3 file4 file5
cd $DIR
$LFS find -v $DIR/dir2

echo "===== test 3(1): specific stripe info ====="
echo "===== lfs dsetstripe dir3_1 131072 0 2 ===="
mkdir $DIR/dir3_1
$LFS dsetstripe $DIR/dir3_1 131072 0 2
cd $DIR/dir3_1
touch file1 file2 file3 file4 file5
cd $DIR
$LFS find -v $DIR/dir3_1

echo "===== test 3(2): specific stripe info ====="
echo "===== lfs dsetstripe dir3_2 131072 1 4 ===="
mkdir $DIR/dir3_2
$LFS dsetstripe $DIR/dir3_2 131072 1 4
cd $DIR/dir3_2
touch file1 file2 file3 file4 file5
cd $DIR
$LFS find -v $DIR/dir3_2

echo "===== test 4: change stripe info to affect future files ====="
echo "===== lfs dsetstripe dir4 131072 0 1 --> file2 =============="
echo "===== lfs dsetstripe dir4 131072 1 3 --> file3 =============="
echo "===== lfs dsetstripe dir4 262144 -1 4 --> file4 ============="
echo "===== lfs dsetstripe dir4 0 -1 0 --> file5 =================="
mkdir $DIR/dir4
touch $DIR/dir4/file1
$LFS dsetstripe $DIR/dir4 131072 0 1
touch $DIR/dir4/file2
$LFS dsetstripe $DIR/dir4 131072 1 3
touch $DIR/dir4/file3
$LFS dsetstripe $DIR/dir4 262144 -1 4
touch $DIR/dir4/file4
$LFS dsetstripe $DIR/dir4 0 -1 0
touch $DIR/dir4/file5
$LFS find -v dir4

echo -n "cln.."
NAME=lov sh llmountcleanup.sh > /dev/null || exit 20
