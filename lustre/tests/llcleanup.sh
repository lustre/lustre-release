#!/bin/sh

SRCDIR="`dirname $0`/"
[ -f $SRCDIR/common.sh ] || SRCDIR="/lib/lustre"

. $SRCDIR/common.sh

setup_opts "$@"

TIME=`date +'%s'`

$DBGCTL debug_kernel /tmp/debug.1.$TIME
cleanup_client
$DBGCTL debug_kernel /tmp/debug.2.$TIME
cleanup_server

cleanup_ldlm
cleanup_lustre
cleanup_portals
