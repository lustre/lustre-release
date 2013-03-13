#!/bin/bash
#set -xv
set -e

CWD=`pwd`

LIBS=$1
LND_LIBS=$2
PTHREAD_LIBS=$3

# do cleanup at first
rm -f liblst.so

ALL_OBJS=

build_obj_list() {
  _objs=`$AR -t $1/$2`
  for _lib in $_objs; do
    ALL_OBJS=$ALL_OBJS"$1/$_lib ";
  done;
}

# lnet components libs
build_obj_list ../../libcfs/libcfs libcfs.a
build_obj_list ../../libcfs/libcfs libcfsutil.a
if $(echo "$LND_LIBS" | grep "socklnd" >/dev/null) ; then
	build_obj_list ../../lnet/ulnds/socklnd libsocklnd.a
fi
build_obj_list ../../lnet/lnet liblnet.a
build_obj_list ../../lnet/selftest libselftest.a

# create static lib lustre
rm -f $CWD/liblst.a
$AR -cru $CWD/liblst.a $ALL_OBJS
$RANLIB $CWD/liblst.a
