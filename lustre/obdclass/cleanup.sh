#!/bin/sh

umount /mnt/obd
rmmod obdfs

./obdcontrol -f << EOF
cleanup
detach
quit
EOF

rmmod obdext2
rmmod obdclass
[ "`lsmod | grep loop`" ] && rmmod loop
