#!/bin/bash
#set -xv

#
# This script is to generate lib lustre library as a whole. It will leave
# two files on current directory: liblustre.a and liblustre.so.
# Integrate them into Makefile.am later
#

AR=/usr/bin/ar
LD=/usr/bin/ld
RANLIB=/usr/bin/ranlib

CWD=`pwd`

SYSIO=$1

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
build_sysio_obj_list() {
  _objs=`$AR -t $1`
  mkdir -p $sysio_tmp
  $AR -x $1
  mv $_objs $sysio_tmp
  for _lib in $_objs; do
    ALL_OBJS=$ALL_OBJS"$sysio_tmp/$_lib ";
  done
}

# lustre components libs
build_obj_list . libllite.a
build_obj_list ../lov liblov.a
build_obj_list ../obdecho libobdecho.a
build_obj_list ../osc libosc.a
build_obj_list ../mdc libmdc.a
build_obj_list ../ptlrpc libptlrpc.a
build_obj_list ../obdclass liblustreclass.a
build_obj_list ../lvfs liblvfs.a

# portals components libs
build_obj_list ../portals/utils libuptlctl.a
build_obj_list ../portals/unals libtcpnal.a
build_obj_list ../portals/portals libportals.a

# create static lib lsupport
rm -f $CWD/liblsupport.a
$AR -cru $CWD/liblsupport.a $ALL_OBJS
$RANLIB $CWD/liblsupport.a

# libsysio components libs
build_sysio_obj_list $SYSIO/lib/libsysio.a

# create static lib lustre
rm -f $CWD/liblustre.a
$AR -cru $CWD/liblustre.a $ALL_OBJS
$RANLIB $CWD/liblustre.a

# create shared lib lustre
rm -f $CWD/liblustre.so
$LD -shared -o $CWD/liblustre.so -init __liblustre_setup_ -fini __liblustre_cleanup_ \
	$ALL_OBJS -lpthread

rm -rf $sysio_tmp
