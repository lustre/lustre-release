#!/bin/bash

set -e
set -vx

export NAME=${NAME:-local}
export OSTSIZE=10000

MOUNT=${MOUNT:-/mnt/lustre}
OOS=$MOUNT/oosfile
LOG=$TMP/oosfile
TMP=${TMP:-/tmp}

echo "mnt.."
sh llmount.sh
echo "done"

SUCCESS=1

ORIGFREE=`df | grep $MOUNT | awk '{ print $4}'`

export LANG=C LC_LANG=C # for "No space left on device" message

if dd if=/dev/zero of=$OOS count=$(($ORIGFREE + 16)) bs=1k 2> $LOG; then
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

if [ $LEFTFREE -gt 100 ]; then
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

	echo -e "\ncln.."
	sh llmountcleanup.sh
fi
