#!/bin/bash

DIR=$1
MAX=$2

while true; do
	file=$DIR/$((RANDOM % MAX))
	getfattr -d -m- $file &> /dev/null
done
