#!/bin/sh
# Utility script to test restoring a previous snapshot.  This will destroy
# the "current" snapshot and restore the old one in its place.
OBDDIR="`dirname $0`/.."
. $OBDDIR/demos/config.sh

[ ! -d $MNTSNAP/lost+found ] && echo "need to run snapsetup.sh first" && exit 1

plog umount $MNTSNAP
plog umount $MNTOBD

mount | grep "$MNTOBD " > /dev/null 2>&1
if [ x$? = x0 ]; then 
    echo "Stuff still mounted on $MNTOBD; clean up first."
    exit 
fi

mount | grep "$MNTSNAP " > /dev/null 2>&1
if [ x$? = x0 ]; then 
    echo "Stuff still mounted on $MNTSNAP; clean up first."
    exit 
fi

sync
plog log "STARTING snaprestore"


$OBDDIR/class/obdcontrol -f << EOF
device /dev/obd1
cleanup
detach
device /dev/obd2
connect
snaprestore 2 $SNAPTABLE 0
quit
EOF

plog log "COMPLETE snaprestore"

plog mount -t obdfs -odevice=/dev/obd2 none $MNTOBD
