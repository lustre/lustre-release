#!/bin/sh

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

setup_opts "$@"

$DBGCTL get_debug > /tmp/debug.1
cleanup_client
$DBGCTL get_debug > /tmp/debug.2
cleanup_server

$DBGCTL get_debug > /tmp/debug.3
cleanup_lustre
$DBGCTL get_debug > /tmp/debug.4
cleanup_portals
