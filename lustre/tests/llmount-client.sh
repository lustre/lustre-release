#!/bin/sh
SRCDIR="`dirname $0`/"
. $SRCDIR/common.sh

export DEBUG_WAIT=yes
. $SRCDIR/llsetup.sh $SRCDIR/net-client.cfg $SRCDIR/ldlm.cfg $SRCDIR/client-mount.cfg || exit 2

debug_client_on
#debug_client_off
