#!/bin/bash

set -e
set -vx

export PATH=`dirname $0`/../utils:$PATH
LFS=${LFS:-lfs}
MOUNT=${MOUNT:-$1}
MOUNT=${MOUNT:-/mnt/lustre}
OOS=$MOUNT/oosfile
LOG=$TMP/oosfile
TMP=${TMP:-/tmp}

SUCCESS=1

rm -f $OOS

STRIPECOUNT=`cat /proc/fs/lustre/lov/*/activeobd | head -1`
ORIGFREE=`df | grep $MOUNT | awk '{ print $4 }'`
MAXFREE=${MAXFREE:-$((200000 * $STRIPECOUNT))}
if [ $ORIGFREE -gt $MAXFREE ]; then
	echo "skipping out-of-space test on $OSC"
	echo "reports ${ORIGFREE}kB free, more tham MAXFREE ${MAXFREE}kB"
	echo "increase $MAXFREE (or reduce test fs size) to proceed"
	exit 0
fi

export LANG=C LC_LANG=C # for "No space left on device" message

# make sure we stripe over all OSTs to avoid OOS on only a subset of OSTs
$LFS setstripe $OOS 65536 0 $STRIPECOUNT
if dd if=/dev/zero of=$OOS count=$(($ORIGFREE + 100)) bs=1k 2> $LOG; then
	echo "ERROR: dd did not fail"
	SUCCESS=0
fi

RECORDSOUT=`grep "records out" $LOG | cut -d + -f1`

if [ -z "`grep "No space left on device" $LOG`" ]; then
        echo "ERROR: dd not return ENOSPC"
	SUCCESS=0
fi

LEFTFREE=`df | grep $MOUNT | awk '{ print $4 }'`
if [ $(($ORIGFREE - $LEFTFREE)) -lt $RECORDSOUT ]; then
        echo "ERROR: space used by dd not equal to available space"
        SUCCESS=0
	echo "$ORIGFREE - $LEFTFREE $RECORDSOUT"
fi

if [ $LEFTFREE -gt $((100 * $STRIPECOUNT)) ]; then
	echo "ERROR: too much space left $LEFTFREE and -ENOSPC returned"
	SUCCESS=0
fi

FILESIZE=`ls -l $OOS | awk '{ print $5 }'`
if [ $RECORDSOUT -ne $(($FILESIZE / 1024)) ]; then
        echo "ERROR: blocks written by dd not equal to the size of file"
        SUCCESS=0
fi

if [ $SUCCESS -eq 1 ]; then
	echo "Success!"

	rm -f $OOS
	rm -f $LOG
fi
