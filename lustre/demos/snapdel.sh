#!/bin/sh
# Utility script to test deleting a snapshot that has been previously
# created as the setup.sh script does.
OBDDIR="`dirname $0`/.."
. $OBDDIR/demos/config.sh

[ ! -d $MNTSNAP/lost+found ] && echo "need to run obdsetup.sh first" && exit 1
[ ! -f $MNTOBD/hosts ] && $OBDDIR/demos/snaptest.sh

plog umount $MNTSNAP
plog umount $MNTOBD

sync
sleep 1
plog log "STARTING snapdelete"
$OBDDIR/class/obdcontrol -f << EOF
device /dev/obd2
connect
snapdelete
disconnect
cleanup
detach
snaptable
$SNAPTABLE
d
2
q
y
snapset 0 $SNAPTABLE
EOF
plog log "COMPLETE snapdelete"
plog mount -t obdfs -odevice=/dev/obd1 none $MNTOBD
