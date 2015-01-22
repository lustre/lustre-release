#!/bin/bash

DIR=$1
MAX=$2

MCREATE=${MCREATE:-$LUSTRE/tests/mcreate}

while true; do
	file=$DIR/$((RANDOM % MAX))
	$MCREATE $file 2> /dev/null
done
