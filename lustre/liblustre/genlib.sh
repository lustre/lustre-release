#!/bin/bash
#set -xv
set -e

#
# This script is to generate lib lustre library as a whole. It will leave
# two files on current directory: liblustre.a and liblustre.so.
#
# Most concern here is the libraries linking order
#
# FIXME: How to do this cleanly use makefile?
#

# see http://osdir.com/ml/gmane.comp.gnu.binutils.bugs/2006-01/msg00016.php
ppc64_CPU=`uname -p`
if [ "x${ppc64_CPU}" = "xppc64" ]; then
	LD="$CC -m64"
else
	LD=$CC
fi

CWD=`pwd`

SYSIO=$1
LIBS=$2
LND_LIBS=$3
PTHREAD_LIBS=$4
CAP_LIBS=$5
ZLIB=$6

if [ ! -f $SYSIO/lib/libsysio.a ]; then
  echo "ERROR: $SYSIO/lib/libsysio.a dosen't exist"
  exit 1
fi

# do cleanup at first
rm -f liblustre.so

ALL_OBJS=

build_obj_list() {
  _objs=`$AR -t $1/$2`
  for _lib in $_objs; do
    ALL_OBJS=$ALL_OBJS"$1/$_lib ";
  done;
}

#
# special treatment for libsysio
#
sysio_tmp=$CWD/sysio_tmp_`date +%s`
rm -rf $sysio_tmp
build_sysio_obj_list() {
  _objs=`$AR -t $1`
  mkdir -p $sysio_tmp
  cd $sysio_tmp
  $AR -x $1
  cd ..
  for _lib in $_objs; do
    ALL_OBJS=$ALL_OBJS"$sysio_tmp/$_lib ";
  done
}

# lustre components libs
build_obj_list . libllite.a
build_obj_list ../lov liblov.a
build_obj_list ../obdecho libobdecho.a
build_obj_list ../osc libosc.a
build_obj_list ../lmv liblmv.a
build_obj_list ../mdc libmdc.a
build_obj_list ../fid libfid.a
build_obj_list ../fld libfld.a
build_obj_list ../mgc libmgc.a
build_obj_list ../ptlrpc libptlrpc.a
build_obj_list ../obdclass liblustreclass.a

# lnet components libs
build_obj_list ../../lnet/utils libuptlctl.a
build_obj_list ../../libcfs/libcfs libcfs.a
build_obj_list ../../libcfs/libcfs libcfsutil.a
if $(echo "$LND_LIBS" | grep "socklnd" >/dev/null) ; then
	build_obj_list ../../lnet/ulnds/socklnd libsocklnd.a
fi
build_obj_list ../../lnet/lnet liblnet.a

# create static lib lsupport
rm -f $CWD/liblsupport.a
$AR -cru $CWD/liblsupport.a $ALL_OBJS
$RANLIB $CWD/liblsupport.a

# if libsysio is already in our LIBS we don't need to link against it here
if $(echo "$LIBS" | grep -v -- "-lsysio" >/dev/null) ; then
	build_sysio_obj_list $SYSIO/lib/libsysio.a
fi

# create static lib lustre
rm -f $CWD/liblustre.a
$AR -cru $CWD/liblustre.a $ALL_OBJS
$RANLIB $CWD/liblustre.a

# create shared lib lustre
rm -f $CWD/liblustre.so
OS=`uname`
if test x$OS = xAIX; then
	$LD $LDFLAGS -shared -o $CWD/liblustre.so $ALL_OBJS -lpthread -Xlinker -bnoipath ../../libsyscall.so
else
# using -nostdlib on Ubuntu causes errors such as:
#./llite_lib.o: In function `liblustre_process_log':
#/home/brian/rpm/BUILD/lustre-1.8.2.50/lustre/liblustre/llite_lib.c:234: undefined reference to `__stack_chk_fail_local'
# due to the use of SSP
#$LD -shared -nostdlib -o $CWD/liblustre.so $ALL_OBJS $CAP_LIBS $PTHREAD_LIBS $ZLIB
	$LD $LDFLAGS -shared -o $CWD/liblustre.so $ALL_OBJS $CAP_LIBS $PTHREAD_LIBS $ZLIB
fi

rm -rf $sysio_tmp
