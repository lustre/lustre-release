#! /bin/sh
# Get the locations for the files from a single place to avoid confusion
#
# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution
OBDDIR="`dirname $0`/.."

# source config info
. $OBDDIR/demos/config.sh

insmod obdclass
insmod obdext2
insmod obdfs

# module configuration
if [ "$MODCONF" -a -f $MODCONF ]; then
    if [ -z "`grep -i "alias  *char-major-$OBDMAJ  *obdclass" $MODCONF`" ]; then
	if [ -d /etc/modutils ]; then
	    # Debian-style modules configuration.
	    echo "alias char-major-${OBDMAJ} obdclass" > /etc/modutils/obd
	    update-modules
	else
	    echo "alias char-major-${OBDMAJ} obdclass" >>$MODCONF
	fi
    fi
fi


# temp file
if [ "$LOOPDEV" -a "$TMPFILE" -a -f $TMPFILE ]; then 
    echo "$TMPFILE exists; I'm unwilling to overwrite it.  Remove [N/y]?" 1>&2
    rm -i $TMPFILE
    [ -f $TMPFILE ] && exit 1
fi
[ "$TMPFILE" ] && dd if=/dev/zero of=$TMPFILE bs=1k count=$TMPSIZE


# loop device
if [ "$LOOPDEV" ]; then
    insmod loop > /dev/null 2>&1
    if [ -a "`losetup $LOOPDEV 2> /dev/null`" ]; then
	echo "It appears that $LOOPDEV is in use.  Unable to continue" 1>&2
	echo "You need to clean up $LOOPDEV (via cleanup.sh),"
	echo "or you can change which device is used in demos/config.sh" 1>&2
	# undo previous
	[ "$TMPFILE" ] && rm $TMPFILE
	exit 2
    fi
    losetup $LOOPDEV $TMPFILE
fi

# Ensure that we have the correct devices for OBD to work
[ ! -c /dev/obd0 ] && mknod /dev/obd0 c $OBDMAJ 0
[ ! -c /dev/obd1 ] && mknod /dev/obd1 c $OBDMAJ 1
[ ! -c /dev/obd2 ] && mknod /dev/obd2 c $OBDMAJ 2


if [ "$BASEDEV" ]; then
    mke2fs -r 0 -b 4096 $BASEDEV
else
    echo "\$BASEDEV not defined in demos/config.sh.  Please fix!"
    [ "$LOOPDEV" ] && losetup -d $LOOPDEV 
    [ "$TMPFILE" ] && rm $TMPFILE
    exit 3
fi
