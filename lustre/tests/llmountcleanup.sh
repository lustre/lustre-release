#!/bin/sh
LOOP0=/dev/loop0
LOOP1=/dev/loop1

if [ ! -e $LOOP0 ]; then
    echo $LOOP0 'doesnt exist: (not) using devfs?' 
    exit
fi

umount /mnt/obd

rmmod llight
rmmod mdc
/usr/src/obd/utils/obdctl <<EOF
device 3
cleanup
detach
device 2
cleanup
detach
device 1
cleanup
detach
device 0
cleanup
detach
quit
EOF
rmmod mds
rmmod osc
rmmod ost
rmmod obdext2
rmmod obdclass
rmmod ptlrpc
/usr/src/portals/linux/utils/ptlctl <<EOF
setup tcp localhost 1234
disconnect self
disconnect mds
EOF
rmmod ksocknal
killall acceptor
rmmod portals

losetup -d $LOOP0
losetup -d $LOOP1