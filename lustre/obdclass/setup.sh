#! /bin/bash

insmod loop
losetup /dev/loop0 /tmp/fs
insmod obdclass.o
insmod obdsim.o
insmod ../obdfs/obdfs.o
./obdcontrol -f << EOF
attach sim_obd
setup
quit
EOF
mount -t obdfs /dev/obd0 /mnt/obd
