#!/bin/sh

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

rmmod llight
rmmod mdc

$R/usr/src/obd/utils/obdctl <<EOF
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

$R/usr/src/portals/linux/utils/ptlctl <<EOF
setup tcp
disconnect localhost
del_uuid self
del_uuid mds
EOF

losetup -d ${LOOP}0

killall acceptor
rmmod ksocknal
rmmod portals
