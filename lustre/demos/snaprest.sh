#!/bin/sh
# Utility script to test restoring a previous snapshot.  This will destroy
# the "current" snapshot and restore the old one in its place.
OBDDIR="`dirname $0`/.."
[ "$OBDDIR" = "" ] && OBDDIR=".."
. $OBDDIR/demos/config.sh

[ ! -d $MNTSNAP/lost+found ] && echo "need to run snapsetup.sh first" && exit 1

plog umount $MNTSNAP
plog umount $MNTOBD

sync
sleep 1
rm $SNAPTABLE
plog log "STARTING snaprestore"
$OBDDIR/class/obdcontrol -f << EOF
snaptable
$SNAPTABLE
a
1
now
a
2
current
q
y
snapset 0 $SNAPTABLE
device /dev/obd2
connect
snaprestore 1
disconnect
EOF
plog log "COMPLETE snaprestore"

plog mount -t obdfs -odevice=/dev/obd1 /dev/obd1 $MNTOBD
