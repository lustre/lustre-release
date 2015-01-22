#!/bin/bash

DIR=$1
MAX=$2

MDTCOUNT=${MDSCOUNT:-$($LFS df $DIR 2> /dev/null | grep -c MDT)}
while /bin/true ; do
	remote_dir=$((RANDOM % MAX))
	file=$((RANDOM % MAX))
	mdt_idx=$((RANDOM % MDTCOUNT))
	# stripe_count in range [1,MDTCOUNT]
	# $LFS mkdir treats stripe_count 0 and 1 the same
	stripe_count=$(((RANDOM % MDTCOUNT) + 1))
	mkdir -p $DIR 2> /dev/null
	$LFS mkdir -i$mdt_idx -c$stripe_count $DIR/$remote_dir 2> /dev/null
	touch $DIR/$remote_dir/$file 2> /dev/null
	$LFS getdirstripe $DIR/$remote_dir > /dev/null 2>&1
done
