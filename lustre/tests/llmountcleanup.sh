#!/bin/sh

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

umount /mnt/obd

rmmod llight
rmmod mdc

$OBDCTL <<EOF
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
rmmod ldlm
rmmod ptlrpc
rmmod obdclass

$PTLCTL <<EOF
setup tcp
disconnect
del_uuid self
del_uuid mds
del_uuid ost
quit
EOF

rmmod kqswnal
rmmod ksocknal
killall acceptor
rmmod portals

losetup -d ${LOOP}0
losetup -d ${LOOP}1
losetup -d ${LOOP}2
