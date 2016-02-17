#!/bin/bash
trap 'kill $(jobs -p)' EXIT

DIR=$1
MAX=$2
PROG=/bin/sleep

while /bin/true ; do
    file=$((RANDOM % MAX))
    cp $PROG $DIR/$file > /dev/null 2>&1
    $DIR/$file 0.$((RANDOM % 5 + 1)) 2> /dev/null
    sleep $((RANDOM % 3))
done

