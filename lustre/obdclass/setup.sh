#! /bin/bash

insmod loop
losetup /dev/loop0 /tmp/fs
insmod obdclass.o
insmod ../ext2obd/obdext2.o
insmod ../obdfs/obdfs.o
./obdcontrol -f << EOF
attach ext2_obd
setup
quit
EOF
mount -t obdfs /dev/obd0 /mnt/obd
