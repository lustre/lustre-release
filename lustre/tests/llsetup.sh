#!/bin/sh

SRCDIR="`dirname $0`/"
. $SRCDIR/common.sh

setup_opts "$@"

setup_portals || exit $?
setup_lustre || exit $?
setup_ldlm || exit $?

setup_server new_fs || exit $?
setup_client || exit $?
