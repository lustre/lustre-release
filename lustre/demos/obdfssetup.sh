#! /bin/bash
# Utility script for configuring a simple OBDFS mount
OBDDIR="`dirname $0`/.."
.  $OBDDIR/demos/config.sh

$OBDDIR/demos/basesetup.sh
#losetup /dev/loop0 /tmp/obdfs.tmpfile

if [ x$? != x0 ]; then 
    echo "Error running basesetup.sh"
    exit 4;
fi

insmod $OBDDIR/class/obdclass.o
insmod $OBDDIR/ext2obd/obdext2.o
insmod $OBDDIR/obdfs/obdfs.o

plog log "ATTACHING /dev/obd0, SETUP $BASEDEV"
$OBDDIR/class/obdcontrol -f << EOF
attach ext2_obd 
setup $BASEDEV
quit
EOF

[ ! -d "$MNTOBD" ] &&  mkdir $MNTOBD
plog mount -t obdfs -odevice=/dev/obd0 none $MNTOBD
