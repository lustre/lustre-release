#!/bin/sh
# Utility script for cleaning up a third snapshot created by setup3.sh
#
# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

OBDDIR="`dirname $0`/.."
. $OBDDIR/demos/config.sh

plog umount $MNTSNAP2

plog log "CLEANUP /dev/obd3"
$OBDDIR/class/obdcontrol -f << EOF
device /dev/obd3
cleanup
detach
quit
EOF

$OBDDIR/demos/snapclean.sh
