#! /bin/bash
# Utility script for cleaning up a simple OBDFS mounted filesystem
#
# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

OBDDIR="`dirname $0`/.."
. $OBDDIR/demos/config.sh

umount $MNTOBD
mount | grep "$MNTOBD " > /dev/null 2>&1
if [ x$? = x0 ]; then 
    echo "Stuff still mounted on $MNTOBD; clean up first."
    exit 
fi

rmmod obdfs

$OBDDIR/class/obdcontrol -f << EOF
device /dev/obd2
cleanup
detach
device /dev/obd0
cleanup
detach
quit
EOF

rmmod obdsnap
rmmod obdext2
rmmod obdclass

rm $SNAPTABLE
$OBDDIR/demos/baseclean.sh
