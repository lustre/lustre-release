#!/usr/bin/bash
trap 'kill $(jobs -p)' EXIT

org_LANG=$LANG
export LANG=C

DIR=$1
MAX=$2
PROG=/bin/sleep

while /bin/true ; do
	file=$((RANDOM % MAX))
	cp -p $PROG $DIR/$file > /dev/null 2>&1
	# bound the exec'd copy: racer may corrupt it into a hang/spin, and once
	# orphaned it would hold this pipe (and the fs) open forever (LU-15248)
	timeout -s KILL 5 $DIR/$file 0.$((RANDOM % 5 + 1)) 2> /dev/null
	sleep $((RANDOM % 3))
done 2>&1 | grep -E -v "Segmentation fault|Bus error|Killed"

export LANG=$org_LANG
