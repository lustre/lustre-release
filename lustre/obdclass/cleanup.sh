#!/bin/sh

umount /mnt/obd
rmmod obdfs

../class/obdcontrol -f << EOF
cleanup
detach
quit
EOF

rmmod obdext2
rmmod obdclass
[ "`lsmod | grep loop`" ] && rmmod loop
