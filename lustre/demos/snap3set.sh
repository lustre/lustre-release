#!/bin/sh
# Utility script for creating a third snapshot.
OBDDIR="`dirname $0`/.."
[ "$OBDDIR" = "" ] && OBDDIR=".."
. $OBDDIR/demos/config.sh

[ ! -d $MNTSNAP/lost+found ] && $OBDDIR/demos/snapsetup.sh

$OBDDIR/demos/snaptest.sh

sync
sleep 5 # let syslog logs get written 

plog log "CREATING /dev/obd3 snapshot"
$OBDDIR/class/obdcontrol -f << EOF
snaptable
$SNAPTABLE
a
3
now
q
y
snapset 0 $SNAPTABLE
device /dev/obd3
attach snap_obd 0 3 0
setup
quit
EOF

[ ! -d "$MNTSNAP2" ] && mkdir $MNTSNAP2
plog mount -t obdfs -oro,device=/dev/obd3 /dev/obd3 $MNTSNAP2
