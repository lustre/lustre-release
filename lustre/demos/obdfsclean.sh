#!/bin/sh
# Utility script for cleaning up a simple OBDFS mounted filesystem
#
# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

OBDDIR="`dirname $0`/.."
. $OBDDIR/demos/config.sh

plog umount $MNTOBD
#killall pupdated	# stop the OBDFS flush daemon
plog rmmod obdfs

plog log "CLEANUP/DETACH"
$OBDDIR/class/obdcontrol -f << EOF
device /dev/obd0
cleanup
detach
quit
EOF

plog rmmod obdext2
plog rmmod obdclass

$OBDDIR/demos/baseclean.sh
