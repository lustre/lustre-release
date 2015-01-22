#!/bin/bash

DIR=$1
MAX=$2

TRUNCATE=${TRUNCATE:-$LUSTRE/tests/truncate}

while true; do
	file=$DIR/$((RANDOM % MAX))
	$TRUNCATE $file $RANDOM 2> /dev/null
done
