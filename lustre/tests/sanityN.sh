#!/bin/bash

set -e

PATH=$PATH:.

CHECKSTAT=${CHECKSTAT:-"checkstat -v"}
MOUNT1=${MOUNT1:-/mnt/lustre1}
MOUNT2=${MOUNT2:-/mnt/lustre2}
export NAME=${NAME:-mount2}

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

mkdir -p $MOUNT2
mount | grep $MOUNT1 || sh llmount.sh

echo -n "test 1: check create on 2 mtpt's..."
touch $MOUNT1/f1
[ -f $MOUNT2/f1 ] || error
pass

echo "test 2: check attribute updates on 2 mtpt's..."
chmod 777 $MOUNT2/f1
$CHECKSTAT -t file -p 0777 $MOUNT1/f1 || error
pass

echo "test 2b: check cached attribute updates on 2 mtpt's..."
touch $MOUNT1/f2b
ls -l $MOUNT2/f2b
chmod 777 $MOUNT2/f2b
$CHECKSTAT -t file -p 0777 $MOUNT1/f2b || error
pass

echo "test 2c: check cached attribute updates on 2 mtpt's..."
touch $MOUNT1/f2c
ls -l $MOUNT2/f2c
chmod 777 $MOUNT1/f2c
$CHECKSTAT -t file -p 0777 $MOUNT2/f2c || error
pass

echo "test 3: check after remount attribute updates on 2 mtpt's..."
chmod a-x $MOUNT2/f1
$CLEAN
$START
$CHECKSTAT -t file -p 0666 $MOUNT1/f1 || error
pass

echo "test 4: unlink on one mountpoint removes file on other..."
rm $MOUNT2/f1
$CHECKSTAT -a $MOUNT1/f1 || error
pass

echo -n "test 5: symlink on one mtpt, readlink on another..."
( cd $MOUNT1 ; ln -s this/is/good lnk )

[ "this/is/good" = "`perl -e 'print readlink("/mnt/lustre2/lnk");'`" ] || error
pass

echo -n "test 6: fstat validation on multiple mount points..."
./multifstat $MOUNT1/f6 $MOUNT2/f6
pass

echo "test 9: remove of open file on other node..."
./openunlink $MOUNT1/f9 $MOUNT2/f9 || error
pass

echo -n "test 10: append of file with sub-page size on multiple mounts..."
MTPT=1
> $MOUNT2/f10
for C in a b c d e f g h i j k l; do
	MOUNT=`eval echo \\$MOUNT$MTPT`
	echo -n $C >> $MOUNT/f10
	[ "$MTPT" -eq 1 ] && MTPT=2 || MTPT=1
done
[ "`cat $MOUNT1/f10`" = "abcdefghijkl" ] && pass || error
	
echo -n "test 11: write of file with sub-page size on multiple mounts..."
MTPT=1
OFFSET=0
> $MOUNT2/f11
for C in a b c d e f g h i j k l; do
	MOUNT=`eval echo \\$MOUNT$MTPT`
	echo -n $C | dd of=$MOUNT/f11 bs=1 seek=$OFFSET count=1
	[ "$MTPT" -eq 1 ] && MTPT=2 || MTPT=1
	OFFSET=`expr $OFFSET + 1`
done
[ "`cat $MOUNT1/f11`" = "abcdefghijkl" ] && pass || error
	
rm -f $MOUNT1/f[0-9]* $MOUNT1/lnk

$CLEAN

exit
