#! /bin/bash
insmod loop
losetup /dev/loop0 /tmp/fs
insmod ../class/obdclass.o
insmod ../ext2obd/obdext2.o
insmod ../obdfs/obdfs.o

echo "NEW OBDFS setup..." >> /var/log/messages

./obdcontrol -f << EOF
attach ext2_obd
setup
quit
EOF
echo "NEW OBDFS mount..." >> /var/log/messages
mount -t obdfs -odevice=/dev/obd0 /dev/obd0 /mnt/obd
echo "NEW OBDFS usage..." >> /var/log/messages
