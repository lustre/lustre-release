#!/bin/sh
export PATH=/sbin:/usr/sbin:$PATH

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

NETWORK=tcp
LOCALHOST=dev5
SERVER=dev4
PORT=1234

setup_portals
setup_lustre

$OBDCTL <<EOF
device 0
attach ptlrpc RPCDEV
setup
device 1
attach ldlm LDLMDEV
setup
device 2
attach osc OSCDEV
setup -1
quit
EOF

mount -t lustre_lite -o device=2 none /mnt/lustre
