#!/bin/sh

SRCDIR="`dirname $0`/"
. $SRCDIR/common.sh

. $SRCDIR/llcleanup.sh $SRCDIR/net-local.cfg $SRCDIR/mds.cfg $SRCDIR/obdfilter.cfg $SRCDIR/client-mount.cfg $SRCDIR/ldlm.cfg || exit 2