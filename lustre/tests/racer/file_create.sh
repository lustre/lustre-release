#!/bin/bash
trap 'kill $(jobs -p)' EXIT

DIR=$1
MAX=$2
MAX_MB=${RACER_MAX_MB:-8}

OSTCOUNT=${OSTCOUNT:-$($LFS df $DIR 2> /dev/null | grep -c OST)}

while /bin/true; do
	file=$((RANDOM % MAX))
	# $RANDOM is between 0 and 32767, and we want $blockcount in 64kB units
	blockcount=$((RANDOM * MAX_MB / 32 / 64))
	stripecount=$((RANDOM % (OSTCOUNT + 1)))
	[ $OSTCOUNT -gt 0 ] &&
		$LFS setstripe -c $stripecount $DIR/$file 2> /dev/null
	dd if=/dev/zero of=$DIR/$file bs=64k count=$blockcount 2> /dev/null
done

