#!/bin/sh
set -evx

MNT=${MNT:-/mnt/lustre}
DIR=${DIR:-$MNT}
SRC=${SRC:-`dirname $0`/../..}
while date; do
	for i in portals lustre; do
		TGT=$DIR/$i
		[ -d $TGT ] || cp -av $SRC/$i/ $TGT
		make -C $TGT clean
		make -C $TGT -j2
		make -C $TGT clean
	done
done
