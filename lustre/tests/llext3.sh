#!/bin/sh

SRCDIR="`dirname $0`/"
. $SRCDIR/common.sh

export DEBUG_WAIT=yes
. $SRCDIR/llsetup.sh $SRCDIR/net-local.cfg $SRCDIR/client-mount.cfg $SRCDIR/mds.cfg $SRCDIR/obdext2.cfg

debug_client_on
