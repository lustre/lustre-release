#!/bin/sh

SRCDIR="`dirname $0`/"
. $SRCDIR/common.sh

rmmod llite
rmmod mdc

$OBDCTL <<EOF
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

$PTLCTL <<EOF
setup tcp
disconnect localhost
del_uuid self
del_uuid mds
EOF

losetup -d ${LOOP}0

killall acceptor
rmmod ksocknal
rmmod portals
