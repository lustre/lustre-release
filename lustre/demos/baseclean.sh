#!/bin/sh
# Script to remove the loopback device and temp file created in newtest.sh
OBDDIR="`dirname $0`/.."

[ "$OBDDIR" = "./.." ] && OBDDIR=".."

. $OBDDIR/demos/config.sh


mount | grep $MNTOBD > /dev/null 2>&1
if [ x$? = x0 ]; then 
    echo "Stuff still mounted on $MNTOBD"
    exit 
fi

mount | grep $MNTSNAP > /dev/null 2>&1
if [ x$? = x0 ]; then 
    echo "Stuff still mounted on $MNTSNAP"
    exit 
fi

mount | grep $MNTSNAP > /dev/null 2>&1
if [ x$? = x0 ]; then 
    echo "Stuff still mounted on $MNTSNAP2"
    exit 
fi


[ "$LOOPDEV" ] && losetup -d $LOOPDEV
rmmod loop > /dev/null 2>&1

# [ "$TMPFILE" -a -f "$TMPFILE" ] && rm $TMPFILE

