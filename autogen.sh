#!/bin/sh

# NOTE: Please avoid bashisms (bash specific syntax) in this script

set -e
pw="$PWD"
for dir in libcfs lnet lustre snmp ; do
	ACLOCAL_FLAGS="$ACLOCAL_FLAGS -I $pw/$dir/autoconf"
done

libtoolize -q
aclocal -I $pw/config $ACLOCAL_FLAGS
autoheader
automake -a -c
autoconf
