#!/bin/sh

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

umount /mnt/obd

rmmod llight
rmmod mdc

$R/usr/src/obd/utils/obdctl <<EOF
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

rmmod obdecho
rmmod mds
rmmod osc
rmmod ost
rmmod obdext2
rmmod ptlrpc
rmmod obdclass

$R/usr/src/portals/linux/utils/ptlctl <<EOF
setup tcp
disconnect localhost
del_uuid self
del_uuid mds
del_uuid ost
quit
EOF

rmmod ksocknal
killall acceptor
rmmod portals

losetup -d ${LOOP}0
losetup -d ${LOOP}1