#!/bin/sh

SRCDIR="`dirname $0`/"
. $SRCDIR/common.sh

TIME=`date +'%s'`

$DBGCTL debug_kernel /tmp/debug.1.$TIME 1

if mount | grep '/mnt/lustre'; then
	umount /mnt/lustre || fail "cannot unmount"
fi

killall acceptor
rmmod llite

$OBDCTL <<EOF
name2dev MDCDEV
cleanup
detach
name2dev OSCDEV
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
name2dev LDLMDEV
cleanup
detach
name2dev RPCDEV
cleanup
detach
quit
EOF

rmmod lov
rmmod obdecho
rmmod mds_extN
rmmod mds_ext3
rmmod mds_ext2
rmmod mds
rmmod mdc
rmmod osc
rmmod ost
rmmod obdfilter
rmmod obdext2
rmmod ldlm
rmmod ptlrpc
rmmod obdclass
rmmod extN

$DBGCTL debug_kernel /tmp/debug.2.$TIME 1

$PTLCTL <<EOF
setup tcp
disconnect
del_uuid self
del_uuid localhost
del_uuid localhost
del_uuid localhost
quit
EOF

rmmod kqswnal
rmmod ksocknal

$DBGCTL debug_kernel /tmp/debug.3.$TIME 1

rmmod portals

losetup -d ${LOOP}0
losetup -d ${LOOP}1
losetup -d ${LOOP}2
exit 0
