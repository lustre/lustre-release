#!/bin/bash

#
# This script is to generate lib lustre library as a whole. It will leave
# two files on current directory: liblustre.a and liblustre.so.
# Integrate them into Makefile.am later
#

AR=/usr/bin/ar
LD=/usr/bin/ld

CWD=`pwd`

LUS=$CWD/../
PTL=$LUS/portals
SYSIO=$LUS/../libsysio

TMP=/tmp/llib_tmp

LLLIBS="$LUS/liblustre/libllite.a \
	$SYSIO/src/libsysio.a \
	$SYSIO/dev/stdfd/libsysio_stdfd.a \
	$SYSIO/drivers/native/libsysio_native.a \
	$LUS/lov/liblov.a \
	$LUS/osc/libosc.a \
	$LUS/ldlm/libldlm.a \
	$LUS/ptlrpc/libptlrpc.a \
	$LUS/obdclass/liblustreclass.a \
	$LUS/mdc/libmdc.a \
        $PTL/unals/libtcpnal.a  \
        $PTL/portals/libportals.a \
	$PTL/utils/libptlctl.a"

rm -rf $TMP
mkdir -p $TMP

i=0
for lib in $LLLIBS; do
	mkdir $TMP/$i
	cd $TMP/$i
	$AR x $lib
	i=$(($i+1))
done

cd $TMP

# static lib
ar -r $CWD/liblustre.a `find . -type f`

# shared lib
$LD -shared -o $CWD/liblustre.so -init __liblustre_setup_ -fini __liblustre_cleanup_ \
	`find . -type f` -lpthread -lreadline -lncurses 

cd $CWD
