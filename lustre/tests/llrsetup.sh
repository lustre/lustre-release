#!/bin/sh

SRCDIR="`dirname $0`/"
. $SRCDIR/common.sh

setup_opts "$@"

setup_portals
setup_lustre
setup_ldlm

setup_server old_fs
setup_client
