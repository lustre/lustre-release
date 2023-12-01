#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#
# lustre/tests/racer/file_fallocate.sh
#
# Test fallocate calls when running under racer.sh
#

trap 'kill $(jobs -p)' EXIT

DIR=$1
MAX=$2

FALLOCATE=$(which fallocate)

while true; do
	keep_size=""
	length=$RANDOM
	offset=$RANDOM
	punch=""
	file=$DIR/$((RANDOM % MAX))

	# Select 'punch' switch randomly
	if (( length % 2 == 0 )); then
		# Punch implies 'keep_size'
		punch="-p"
	elif (( offset % 2 == 0 )) ; then
		# Select 'keep_size' switch randomly
		keep_size="-n"
	fi

	$FALLOCATE $punch $keep_size -o $offset -l $length $file 2> /dev/null
done
