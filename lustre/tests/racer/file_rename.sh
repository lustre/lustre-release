#!/bin/bash
trap 'kill $(jobs -p)' EXIT

DIR=$1
MAX=$2

while /bin/true ; do
    file=$((RANDOM % MAX))
    new_file=$((RANDOM % MAX))
    mv $DIR/$file $DIR/$new_file 2> /dev/null
done
