#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#
# lustre/tests/llmount.sh
#
# Create a simple lustre filesystem and client for
# testing
#

usage() {
	less -F <<EOF
Usage: ${0##*/} [options]
Helper for creating, formatting, and mounting a simple lustre filesystem.
	-S, --server-only   Do not setup up a client
	-n, --no-format     Do not reformat the test filesystem
	-s, --skip-setup    Do not setup the test filesystem
	-l, --load-modules  Load the lustre modules
	-h, --help          This help

Environment variables
See lustre/tests/cfg/local.sh to see more variables.
	FSTYPE    ldiskfs,zfs  Type of backing filesystem
	MDSCOUNT  number       Number of MDS
	OSSCOUNT  number       Number of OSS
	MOUNTOPT  string       Options passed to client mount command

Example usage:
Create a simple lustre filesystem.

	./llmount.sh --server-only

Create a ZFS backed lustre filesystem with a client.

	FSTYPE=zfs ./llmount.sh

EOF
	exit
}

setup_client=true

# Replace long option with corresponding short option
for arg in "$@"; do
	shift
	case "$arg" in
		--server-only) set -- "$@" '-S';;
		--no-format) set -- "$@" '-n';;
		--skip-setup) set -- "$@" '-s';;
		--load-modules) set -- "$@" '-l';;
		--help) set -- "$@" '-h';;
		*) set -- "$@" "$arg";;
	esac
done

while getopts "Snslh" opt
do
	case "$opt" in
		S) setup_client=false;;
		n) NOFORMAT=true;;
		s) NOSETUP=true;;
		l) LOAD=true;;
		h|\?) usage;;
	esac
done

LUSTRE=${LUSTRE:-$(dirname "$0")/..}
. "$LUSTRE/tests/test-framework.sh"
init_test_env "$@"

[ -n "$LOAD" ] && load_modules && exit 0
[ -z "$NOFORMAT" ] && formatall

if $setup_client; then
	[ -z "$NOSETUP" ] && setupall
else
	[ -z "$NOSETUP" ] && setupall server_only
fi
