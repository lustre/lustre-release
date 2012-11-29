#!/bin/sh

# NOTE: Please avoid bashisms (bash specific syntax) in this script

# enable execution tracing
set -x

error()
{
	rc=$?
	echo "$1 failed (rc=$rc).  Aborting."
	exit 1
}

aclocal -I $PWD/config || error "aclocal"
autoheader || error "autoheader"
automake -a -c -W no-portability || error "automake"
autoconf || error "autoconf"
