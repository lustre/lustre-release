#!/bin/bash
#
# This file is provided under a dual BSD/GPLv2 license.  When using or
# redistributing this file, you may do so under either license.
#
# GPL LICENSE SUMMARY
#
# Copyright(c) 2016 Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# Contact Information:
# Cong Xu, cong.xu@intel.com
#
# BSD LICENSE
#
# Copyright(c) 2016 Intel Corporation.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in
# the documentation and/or other materials provided with the
# distribution.
# * Neither the name of Intel Corporation nor the names of its
# contributors may be used to endorse or promote products derived
# from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.




function usage() {
	cat << EOF
Usage: $0 [-i] [-x] [-y] [-t]
	-i  path to LIOProf rpc tracing logs
	-x  lowest Lustre Client [IB IP Address]
	-y  highest Lustre Client [IB IP Address]
	-t  Type of Operation Code (OPC) (OST_READ 3, OST_WRITE 4)
EOF
	exit 0
}


while getopts ":i:x:y:t:" o; do
	case "${o}" in
		i)
			i=${OPTARG};;
		x)
			x=${OPTARG};;
		y)
			y=${OPTARG};;
		t)
			t=${OPTARG};;
		*)
			usage;;
	esac
done
shift $((OPTIND-1))

if [ -z "${i}" ] || [ -z "${x}" ] || [ -z "${y}" ] || [ -z "${t}" ]; then
	usage
fi


# Cluster Name
cluster_name=$(cut -d- -f1 <<<"${x}")

# Lustre Clients
CLIENT_PRE=$(cut -d. -f 1-3 <<<"${x}")
CLIENT_MIN=$(cut -d. -f4 <<<"${x}")
CLIENT_MAX=$(cut -d. -f4 <<<"${y}")

# Type of Operation Code (OPC) (Defined in lustre/include/lustre/lustre_idl.h)
OPC_TYPE=${t}

# Input directory
IN_PUT=${i}

# Output directory
OUT_PUT=${i}-out
rm -rf $OUT_PUT
mkdir -p $OUT_PUT

for f in ${IN_PUT}/*
do
	echo "Processing ${f}"
	for ((c = $CLIENT_MIN; c <= $CLIENT_MAX; c = c + 1))
	do
		ip=${CLIENT_PRE}.$c
		CUR_OST=$(echo "${f}" | rev | cut -d'/' -f1 | rev)

		cat ${f} | grep "Handling RPC pname" | grep "ll_ost_io" | \
		grep o2ib:${OPC_TYPE} | grep ${ip} | \
		awk 'BEGIN{FS=":"}{print $4}' | sort -n | \
		awk 'BEGIN {count = 0; line = 0; FS="."} {
			if (NR == 1) {curval = $1};
			if($1 <= curval) {
				count = count + 1;
			} else {
				print line "\t" count;
				curval = curval + 1;
				line = line + 1;
				count = 1;
				while(curval < $1) {
					print line "\t" 0;
					curval = curval + 1;
					line = line + 1;
				}
			}
		} END {
			print line "\t" count;
		}' \
		> ${OUT_PUT}/$CUR_OST-Client-$c &
	done
done

# Wait for completion
wait


# If the lines of the files are different, fill the end of files with zeros to
# guarantee all the files have the same number of lines.

# Get max line
MAX_LINE=-1
for f in ${OUT_PUT}/*
do
	LINE=$(wc -l < ${f})
	if [ "$MAX_LINE" -lt "$LINE" ]
	then
		MAX_LINE=${LINE}
	fi
done

# Append zeros
for f in  ${OUT_PUT}/*
do
	LINE=$(wc -l < ${f})
	for ((i = $LINE; i < $MAX_LINE; i = i + 1))
	do
		printf  "0\t0\n" >> ${f} &
	done
done
