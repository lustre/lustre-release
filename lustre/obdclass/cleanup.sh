#!/bin/sh

umount /mnt/obd
rmmod obdfs

./obdcontrol -f << EOF
cleanup
quit
EOF

rmmod obdsim
rmmod obdclass

