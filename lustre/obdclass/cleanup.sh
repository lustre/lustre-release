#!/bin/sh

umount /mnt/obd
rmmod obdfs

./obdcontrol -f << EOF
cleanup
quit
EOF

rmmod obdext2
rmmod obdclass

