#!/bin/bash

DIR=$1
MAX=$2

MDTCOUNT=${MDSCOUNT:-$(lfs df $DIR 2> /dev/null | grep -c MDT)}
while /bin/true ; do
	remote_dir=$((RANDOM % MAX))
	file=$((RANDOM % MAX))
	mdt_idx=$((RANDOM % MDTCOUNT))
	mkdir -p $DIR
	lfs mkdir -i$mdt_idx -c$MDTCOUNT $DIR/$remote_dir 2> /dev/null
	echo "abcd" > $DIR/$remote_dir/$file 2> /dev/null
	$LFS getdirstripe $DIR/$remote_dir 2> /dev/null
done
