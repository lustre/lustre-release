#! /bin/bash
# Utility script for configuring a simple OBDFS mount

OBDDIR="`dirname $0`/.."
[ "$OBDDIR" = "" ] && OBDDIR=".."
. $OBDDIR/demos/basesetup.sh

insmod $OBDDIR/class/obdclass.o
insmod $OBDDIR/ext2obd/obdext2.o
insmod $OBDDIR/obdfs/obdfs.o

plog log "CREATING /dev/obd0"
$OBDDIR/class/obdcontrol -f << EOF
attach ext2_obd $BASEDEV
setup
quit
EOF
[ ! -d $MNTOBD ] && mkdir $MNTOBD
plog mount -t obdfs -odevice=/dev/obd0 /dev/obd0 $MNTOBD
