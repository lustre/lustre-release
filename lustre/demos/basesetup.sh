#! /bin/sh
# Get the locations for the files from a single place to avoid confusion
OBDDIR="`dirname $0`/.."
[ "$OBDDIR" = "" ] && OBDDIR=".."
. $OBDDIR/demos/config.sh

#if [ "$TMPFILE" -a -f $TMPFILE ]; then 
#    echo "$TMPFILE exists; I'm unwilling to overwrite it." 1>&2
#    exit 1
#fi

# We assume the loop module will be installed by kerneld if required.
# If not, the following line should be uncommented.
#insmod loop

if [ "$LOOPDEV" -a "`losetup $LOOPDEV 2> /dev/null`" ]; then
    echo "It appears that $LOOPDEV is in use.  Unable to continue" 1>&2
    echo "You need to clean up $LOOPDEV (via cleanup.sh),"
    echo "or you can change which device is used in demos/config.sh" 1>&2
    exit 2
fi

# Ensure that we have the correct devices for OBD to work
[ ! -c /dev/obd0 ] && mknod /dev/obd0 c $OBDMAJ 0
[ ! -c /dev/obd1 ] && mknod /dev/obd1 c $OBDMAJ 1
[ ! -c /dev/obd2 ] && mknod /dev/obd2 c $OBDMAJ 2

[ "$TMPFILE" ] && dd if=/dev/zero of=$TMPFILE bs=1k count=10k

[ "$LOOPDEV" ] && losetup $LOOPDEV $TMPFILE
if [ "$BASEDEV" ]; then
    mke2fs -b 4096 $BASEDEV
else
    echo "\$BASEDEV not defined in demos/config.sh.  Please fix!"
    exit 1
fi
