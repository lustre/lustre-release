#!/bin/sh

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

umount /mnt/lustre

killall acceptor
rmmod llite
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
rmmod obdfilter
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
del_uuid ldlm
quit
EOF

rmmod kqswnal
rmmod ksocknal
rmmod portals

losetup -d ${LOOP}0
losetup -d ${LOOP}1
losetup -d ${LOOP}2
