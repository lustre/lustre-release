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
plog log "STARTING snaprestore"
# To do a snapshot restore at this time, we need to do several steps.  In
# the future, this should all be wrapped into the snaprestore function.
# - we reverse the current and restored entries in the snapshot table
# - we proceed to delete the previous current snapshot
# - we unconfigure the previous current snapshot
# - we delete the previous current snapshot from the table and load it
$OBDDIR/class/obdcontrol -f << EOF
XXX need to reverse current/restored entries here!!!
snapset 0 $SNAPTABLE
device /dev/obd2
connect
snaprestore 1
device /dev/obd1
cleanup
detach
snaptable
$SNAPTABLE
d
1
q
y
snapset 0 $SNAPTABLE
EOF
plog log "COMPLETE snaprestore"

plog mount -t obdfs -odevice=/dev/obd1 /dev/obd1 $MNTOBD
