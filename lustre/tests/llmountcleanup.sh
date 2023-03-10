#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#
# lustre/tests/llmountcleanup.sh
#
# Destroy the lustre filesystem and client created by
# llmount.sh
#

usage() {
	less -F <<EOF
Usage: ${0##*/}
Destroy the lustre filesystem and client created by llmount.sh
	-h, --help          This help

EOF
	exit
}

# Replace long option with corresponding short option
for arg in "$@"; do
	shift
	case "$arg" in
		--help) set -- "$@" '-h';;
		*) set -- "$@" "$arg";;
	esac
done

while getopts "h" opt
do
	case "$opt" in
		h|\?) usage;;
	esac
done

LUSTRE=${LUSTRE:-$(dirname "$0")/..}
. "$LUSTRE/tests/test-framework.sh"
init_test_env "$@"

cleanupall -f
