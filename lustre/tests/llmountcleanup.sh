#!/bin/sh

SRCDIR="`dirname $0`/"
. $SRCDIR/common.sh

$DBGCTL get_debug > /tmp/debug.1

if mount | grep '/mnt/lustre'; then
	umount /mnt/lustre || fail "cannot unmount"
fi

killall acceptor
rmmod llite
rmmod mdc

$OBDCTL <<EOF
name2dev OSCDEV
cleanup
detach
name2dev LDLMDEV
cleanup
detach
name2dev RPCDEV
cleanup
detach
name2dev OSTDEV
cleanup
detach
name2dev OBDDEV
cleanup
detach
name2dev MDSDEV
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
rmmod extN

$DBGCTL get_debug > /tmp/debug.2

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
exit 0
