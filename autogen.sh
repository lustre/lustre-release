#!/bin/sh

# NOTE: Please avoid bashisms (bash specific syntax) in this script

set -e

for dir in libcfs lnet lustre snmp ; do
	ACLOCAL_FLAGS="$ACLOCAL_FLAGS -I $PWD/$dir/autoconf"
done

libtoolize -q
aclocal -I $PWD/config $ACLOCAL_FLAGS
autoheader
automake -a -c
autoconf
