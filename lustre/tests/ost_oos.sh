#!/bin/bash

export NAME=${NAME:-local}
export OSTSIZE=10000

MOUNT=${MOUNT:-/mnt/lustre}

echo "mnt.."
sh llmount.sh
echo "done"
echo ""

SUCCESS=1

FREESPACE=`df |grep $MOUNT|tr -s ' '|cut -d ' ' -f4`

rm -f /tmp/oosfile
dd if=/dev/zero of=$MOUNT/oosfile count=$[$FREESPACE + 1] bs=1k 2>/tmp/oosfile

RECORDSOUT=`grep "records out" /tmp/oosfile|cut -d + -f1`

[ -z "`grep "No space left on device" /tmp/oosfile`" ] && \
        echo "failed:dd not return ENOSPC" && SUCCESS=0

[ $FREESPACE -lt $RECORDSOUT ] && \
        echo "failed:the space written by dd larger than available space" && \
        SUCCESS=0

FILESIZE=`ls -l $MOUNT/oosfile|tr -s ' '|cut -d ' ' -f5`
[ $RECORDSOUT -ne $[$FILESIZE/1024] ] && \
        echo "failed:the space written by dd not equal to the size of file" && \
        SUCCESS=0

[ $SUCCESS -eq 1 ] && echo "Success!"

rm -f $MOUNT/oosfile*
rm -f /tmp/oosfile

echo ""
echo "cln.."
sh llmountcleanup.sh
