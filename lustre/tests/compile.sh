#!/bin/sh
set -evx

MOUNT=${MOUNT:-/mnt/lustre}
DIR=${DIR:-$MOUNT}
SRC=${SRC:-`dirname $0`/../..}
export CC=${CC:-gcc}
while date; do
	for i in lustre; do
		TGT=$DIR/$i
		[ -d $TGT ] || cp -av $SRC/$i/ $TGT
		make -C $TGT clean
		make -C $TGT -j2
		make -C $TGT clean
	done
done
