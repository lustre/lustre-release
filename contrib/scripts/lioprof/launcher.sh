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
Usage: $0 [-a] [-d] [-l] [-h] [-m] [-n] [-o] [-u]
	-a  command to launch application
	-d  shared nfs directory to store LIOProf logs
	-l  lowest Lustre OSS node [Hostname]
	-h  highest Lustre OSS node [Hostname]
	-m  lowest Lustre Client [Hostname]
	-n  highest Lustre Client [Hostname]
	-o  use Obdfilter-survey to measure Lustre bandwidth
	-u  user name
EOF
	exit 0
}


while getopts ":a:d:l:h:m:n:ou:" arg; do
	case "${arg}" in
		a)
			a=${OPTARG};;
		d)
			d=${OPTARG};;
		l)
			l=${OPTARG};;
		h)
			h=${OPTARG};;
		m)
			m=${OPTARG};;
		n)
			n=${OPTARG};;
		o)
			o="Obdfilter-survey";;
		u)
			u=${OPTARG};;
		*)
			usage;;
	esac
done
shift $((OPTIND-1))

if [ -n "${o}" ]; then
	# Launch OBDfilter-survey to measure Lustre bandwidth
	if [ -n "${a}" ] || [ -z "${d}" ] || [ -z "${l}" ] || [ -z "${h}" ] \
		|| [ -z "${u}" ]; then
		usage
	fi
else
	# Launch application
	if [ -z "${a}" ] || [ -z "${d}" ] || [ -z "${l}" ] || [ -z "${h}" ] \
		|| [ -z "${m}" ] || [ -z "${n}" ] || [ -z "${u}" ]; then
		usage
	fi
fi


# Cluster Name
cluster_name=$(cut -d- -f1 <<<"${l}")

# Lustre OSS Nodes
OSS_MIN=$(cut -d- -f2 <<<"${l}")
OSS_MAX=$(cut -d- -f2 <<<"${h}")

# Lustre Clients
CLIENT_MIN=$(cut -d- -f2 <<<"${m}")
CLIENT_MAX=$(cut -d- -f2 <<<"${n}")

# Input user name
USER_NAME=${u}

# Commands information
mpi_cmd=mpirun
pdsh_cmd=/usr/bin/pdsh

# Job ID (Based on job time)
job_id=job-`date +%s`
echo "Launch" ${job_id}


if [ -n "${o}" ]; then
	# OBDfilter-survey (Obtain maximum available bandwidth of Lustre)
	echo "Running OBDfilter-survey in the background"

	HOMEOBDFILTER=${d}/${job_id}/obdfilter
	sudo -u ${USER_NAME} mkdir -p $HOMEOBDFILTER
	sudo -u ${USER_NAME} chmod 777 -R ${d}/${job_id}
	${pdsh_cmd} -R ssh -w $cluster_name-[$OSS_MIN-$OSS_MAX] " \
		size=65536 nobjlo=1 nobjhi=2 thrlo=32 thrhi=64 \
		obdfilter-survey > ${HOMEOBDFILTER}/\`hostname -s\` & \
	"
	exit 0
fi


# rpc and brw logs directories
LOCALRPC=/lioprof_loc/${job_id}/rpc
LOCALBRW=/lioprof_loc/${job_id}/brw
LOCALIOSTAT=/lioprof_loc/${job_id}/iostat

HOMERPC=${d}/${job_id}/rpc
HOMEBRW=${d}/${job_id}/brw
HOMEIOSTAT=${d}/${job_id}/iostat

# Create logs directories
${pdsh_cmd} -R ssh -w $cluster_name-[$OSS_MIN-$OSS_MAX] " \
	mkdir -p ${LOCALRPC} ${LOCALBRW} ${LOCALIOSTAT}; \
	"

# Change log directories permissions
sudo -u ${USER_NAME} mkdir -p ${HOMERPC} ${HOMEBRW} ${HOMEIOSTAT}
sudo -u ${USER_NAME} chmod 777 -R ${d}/${job_id}

# Enable RPC Tracing
${pdsh_cmd} -R ssh -w $cluster_name-[$OSS_MIN-$OSS_MAX] \
	"lctl set_param debug=rpctrace"

# Evaluate Performance

# Clear Lustre cache
${pdsh_cmd} -R ssh -w $cluster_name-[$OSS_MIN-$CLIENT_MAX] " \
	echo 3 > /proc/sys/vm/drop_caches; echo 0 > /proc/sys/vm/drop_caches;
"

# Start RPC log service and brw_stats
${pdsh_cmd} -R ssh -w $cluster_name-[$OSS_MIN-$OSS_MAX] " \
	echo > /proc/fs/lustre/obdfilter/*/brw_stats; \
	lctl clear; lctl debug_daemon start ${LOCALRPC}/rpc.log 1024; \
	"

# Start iostat
${pdsh_cmd} -R ssh -w $cluster_name-[$OSS_MIN-$OSS_MAX] " \
	iostat 1 > ${LOCALIOSTAT}/iostat.log&
	"
sleep 2

######################## Launch Application ########################
${a} > ${d}/${job_id}/job-output
sleep 2
####################################################################

# Collect Lustre RPC and btw_stats logs
${pdsh_cmd} -R ssh -w $cluster_name-[$CLIENT_MIN-$CLIENT_MAX] " \
	lctl set_param ldlm.namespaces.*.lru_size=clear
	"
sleep 5
${pdsh_cmd} -R ssh -w $cluster_name-[$OSS_MIN-$OSS_MAX] " \
	lctl debug_daemon stop; \
	cat /proc/fs/lustre/obdfilter/*/brw_stats > \
			${HOMEBRW}/brw-\`hostname -s\`; \
	lctl debug_file ${LOCALRPC}/rpc.log ${HOMERPC}/rpc-\`hostname -s\`; \
"

# Stop iostat and collect data
${pdsh_cmd} -R ssh -w $cluster_name-[$OSS_MIN-$OSS_MAX] " \
	pkill iostat; cp -r ${LOCALIOSTAT}/iostat.log \
	${HOMEIOSTAT}/iostat-\`hostname -s\` \
"

# Change log file mode
sleep 1
sudo -u root chmod 755 -R ${HOMERPC}/* ${HOMEBRW}/* ${HOMEIOSTAT}/*

###################################################################
#### Warning! Pay much more attention to rm commands with root ####
###################################################################
# Clear local history logs
sleep 2
LOCAL_LIOPROF=/lioprof_loc
${pdsh_cmd} -R ssh -w $cluster_name-[$OSS_MIN-$OSS_MAX] " \
	pkill iostat; \
	rm -rf ${LOCAL_LIOPROF}; \
"
