#!/bin/bash
# this will cause debugfs to create the /tmp/debugfs.mark file once it has
# passed the MMP startup, then continue reading input until it is killed
MARKFILE=$(mktemp)
DEBUGFS=${DEBUGFS:-debugfs}
DEVICE=$1

rm -f $MARKFILE
echo "$DEBUGFS -w $DEVICE"
{ echo "dump_inode <2> $MARKFILE"; cat /dev/zero; } | $DEBUGFS -w $DEVICE &
debugfspid=$!
while [ ! -e $MARKFILE ]; do
        sleep 1
done
rm -f $MARKFILE
kill -9 $debugfspid
