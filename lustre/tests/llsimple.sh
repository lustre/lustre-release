#!/bin/sh

SRCDIR="`dirname $0`/"
[ -f $SRCDIR/common.sh ] || SRCDIR="/lib/lustre"

. $SRCDIR/common.sh

setup_opts "$@"

setup_portals || exit $?
setup_lustre || exit $?
