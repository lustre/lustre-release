#!/bin/bash

DIR=$1
MAX=$2
MAX_MB=256

# disable until LU-2523 and LU-2789 are fixed
[ -z "$RACER_SETSTRIPE" ] && RACER_SETSTRIPE=false
OSTCOUNT=${OSTCOUNT:-$(lfs df $DIR 2> /dev/null | grep -c OST)}

while /bin/true ; do 
	file=$((RANDOM % MAX))
	SIZE=$((RANDOM * MAX_MB / 32))
	echo "file_create: FILE=$DIR/$file SIZE=$SIZE"
	[ $OSTCOUNT -gt 0 ] && $RACER_SETSTRIPE &&
		lfs setstripe -c $((RANDOM % OSTCOUNT)) $DIR/$file 2> /dev/null
	dd if=/dev/zero of=$DIR/$file bs=1k count=$SIZE 2> /dev/null
done

