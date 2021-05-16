#!/bin/bash
trap 'kill $(jobs -p)' EXIT

DIR=$1
MAX=$2

MDTCOUNT=${MDSCOUNT:-$($LFS df $DIR 2> /dev/null | grep -c MDT)}
while /bin/true ; do
	migrate_dir=$((RANDOM % MAX))
	file=$((RANDOM % MAX))
	mdt_idx=$((RANDOM % MDTCOUNT))

	(( $RACER_MIGRATE_STRIPE_MAX > 1 )) &&
		mdt_count=$((RANDOM % RACER_MIGRATE_STRIPE_MAX + 1)) ||
		mdt_count=1

	mkdir -p $DIR/$migrate_dir 2> /dev/null
	eval touch $DIR/$migrate_dir/{$file..$MAX} 2> /dev/null
	$LFS migrate -m$mdt_idx -c$mdt_count $DIR/$migrate_dir 2> /dev/null
	$LFS getdirstripe $DIR/$migrate_dir > /dev/null 2>&1
done
