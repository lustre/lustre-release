#!/bin/sh

SRCDIR="`dirname $0`/"
. $SRCDIR/common.sh

setup_opts "$@"

$DBGCTL debug_kernel /tmp/debug.1
cleanup_client
$DBGCTL debug_kernel /tmp/debug.2
cleanup_server

$DBGCTL debug_kernel /tmp/debug.3
cleanup_ldlm
$DBGCTL debug_kernel /tmp/debug.4
cleanup_lustre
$DBGCTL debug_kernel /tmp/debug.5
cleanup_portals
