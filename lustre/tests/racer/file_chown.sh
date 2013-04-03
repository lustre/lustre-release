#!/bin/bash

DIR=$1
MAX=$2

while true; do
	file=$DIR/$((RANDOM % MAX))
	chown $RANDOM:$RANDOM $file 2> /dev/null
done
