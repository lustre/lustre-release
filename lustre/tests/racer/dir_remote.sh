#!/bin/bash
trap 'kill $(jobs -p)' EXIT

DIR=$1
MAX=$2

MDTCOUNT=${MDSCOUNT:-$($LFS df $DIR 2> /dev/null | grep -c MDT)}
while /bin/true ; do
	remote_dir=$((RANDOM % MAX))
	file=$((RANDOM % MAX))
	mdt_idx=$((RANDOM % MDTCOUNT))

	if $RACER_ENABLE_STRIPED_DIRS; then
		# stripe_count in range [1,MDTCOUNT]
		# $LFS mkdir treats stripe_count 0 and 1 the same
		stripe_count_opt="-c$((RANDOM % MDTCOUNT + 1))"
	else
		stripe_count_opt=""
	fi

	$LFS mkdir -i$mdt_idx $stripe_count_opt $DIR/$remote_dir 2> /dev/null
	touch $DIR/$remote_dir/$file 2> /dev/null
	$LFS getdirstripe $DIR/$remote_dir > /dev/null 2>&1
done
