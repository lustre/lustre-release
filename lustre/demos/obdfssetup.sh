#! /bin/bash
# Utility script for configuring a simple OBDFS mount
#
# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

OBDDIR="`dirname $0`/.."
.  $OBDDIR/demos/config.sh

$OBDDIR/demos/basesetup.sh

if [ x$? != x0 ]; then 
    echo "Error running basesetup.sh"
    exit 4;
fi

#insmod $OBDDIR/class/obdclass.o
#insmod $OBDDIR/ext2obd/obdext2.o
#insmod $OBDDIR/obdfs/obdfs.o

plog log "ATTACHING device 0 SETUP $BASEDEV"
$OBDDIR/utils/obdctl << EOF
device 0
# attach obdfilter
# setup $BASEDEV reiserfs
attach obdext2
setup $BASEDEV
quit
EOF

[ ! -d "$MNTOBD" ] &&  mkdir $MNTOBD
plog mount -t obdfs -odevice=/dev/obd0 none $MNTOBD
