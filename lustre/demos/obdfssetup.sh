#! /bin/bash
# Utility script for configuring a simple OBDFS mount

OBDDIR="`dirname $0`/.."
[ "$OBDDIR" = "./.." ] && OBDDIR=".."

.  $OBDDIR/demos/config.sh

$OBDDIR/demos/basesetup.sh

if [ x$? != x0 ]; then 
    echo "Errors in basesetup"
    exit 4;
fi

insmod $OBDDIR/class/obdclass.o
insmod $OBDDIR/ext2obd/obdext2.o
insmod $OBDDIR/obdfs/obdfs.o

plog log "ATTACHING /dev/obd0"
$OBDDIR/class/obdcontrol -f << EOF
attach ext2_obd 
setup $BASEDEV
quit
EOF

plog mount -t obdfs -odevice=/dev/obd0 none $MNTOBD
