#!/bin/bash

DIR=$1
MAX=$2

while true; do
	file=$DIR/$((RANDOM % MAX))
	attr=user.$((RANDOM % MAX))
	value=$RANDOM$RANDOM$RANDOM$RANDOM$RANDOM$RANDOM$RANDOM$RANDOM$RANDOM
	setfattr -n $attr -v $value $file 2> /dev/null
done
