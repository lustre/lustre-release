#!/bin/sh

SRCDIR="`dirname $0`/"
. $SRCDIR/common.sh

export DEBUG_WAIT=yes
. $SRCDIR/llrsetup.sh $SRCDIR/net-local.cfg $SRCDIR/client-mount.cfg $SRCDIR/mds.cfg $SRCDIR/obdext2.cfg $SRCDIR/ldlm.cfg || exit 2

debug_client_on
#debug_client_off
