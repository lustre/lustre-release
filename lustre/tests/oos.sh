#!/bin/bash

export NAME=${NAME:-local}
export OSTSIZE=10000

MOUNT=${MOUNT:-/mnt/lustre}
TMP=${TMP:-/tmp}

echo "mnt.."
sh llmount.sh
echo "done"

SUCCESS=1

FREESPACE=`df |grep $MOUNT|tr -s ' '|cut -d ' ' -f4`

rm -f $TMP/oosfile
dd if=/dev/zero of=$MOUNT/oosfile count=$[$FREESPACE + 1] bs=1k 2>$TMP/oosfile

RECORDSOUT=`grep "records out" $TMP/oosfile|cut -d + -f1`

[ -z "`grep "No space left on device" $TMP/oosfile`" ] && \
        echo "failed:dd not return ENOSPC" && SUCCESS=0

REMAINEDFREE=`df |grep $MOUNT|tr -s ' '|cut -d ' ' -f4`
[ $[$FREESPACE - $REMAINEDFREE ] -lt $RECORDSOUT ] && \
        echo "failed:the space written by dd not equal to available space" && \
        SUCCESS=0 && echo "$FREESPACE - $REMAINEDFREE $RECORDSOUT"

[ $REMAINEDFREE -gt 100 ] && \
	echo "failed:too many space left $REMAINEDFREE and -ENOSPC returned" &&\
	SUCCESS=0

FILESIZE=`ls -l $MOUNT/oosfile|tr -s ' '|cut -d ' ' -f5`
[ $RECORDSOUT -ne $[$FILESIZE/1024] ] && \
        echo "failed:the space written by dd not equal to the size of file" && \
        SUCCESS=0

[ $SUCCESS -eq 1 ] && echo "Success!"

rm -f $MOUNT/oosfile*
rm -f $TMP/oosfile

echo ""
echo "cln.."
sh llmountcleanup.sh
