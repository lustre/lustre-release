#!/bin/sh

SRCDIR="`dirname $0`/"
. $SRCDIR/common.sh

export DEBUG_WAIT=yes
. $SRCDIR/llsetup.sh $SRCDIR/net-local.cfg $SRCDIR/mds.cfg $SRCDIR/obdfilter.cfg $SRCDIR/client-mount.cfg $SRCDIR/ldlm.cfg || exit 2

debug_client_on
#debug_client_off
