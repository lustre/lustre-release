#!/bin/bash
#
# gen_hb_config.sh - script for generating the Heartbeat HA software's
#		     configuration files
#
###############################################################################

# Usage
usage() {
	cat >&2 <<EOF

Usage:  `basename $0` <-r HBver> <-n hostnames> <-d target device>
		      <-c heartbeat channels> <-s service address>
		      [-o heartbeat options] [-v]

	-r HBver		the version of Heartbeat software
                        	The Heartbeat software versions which are curr-
				ently supported are: hbv1 (Heartbeat version 1) 
				and hbv2 (Heartbeat version 2).
	-n hostnames            the nodenames of the primary node and its fail-
				overs
                        	Multiple nodenames are separated by colon (:)
                        	delimeter. The first one is the nodename of the 
				primary node, the others are failover nodenames.
	-d target device        the target device name and type
                        	The name and type are separated by colon (:)
                        	delimeter. The type values are: mgs, mdt, ost or
				mgs_mdt.
	-c heartbeat channels   the methods and devices to send/rcv heartbeats on
	-s service address      the IP address to failover
	-o heartbeat options    a "catchall" for other heartbeat configuration 
				options
	-v			verbose mode
				Causes `basename $0` to print debugging messages
             			about its progress.
EOF
	exit 1
}

# Global variables
SCRIPT_PATH=$"./"
SCRIPT_VERIFY_SRVIP=${SCRIPT_PATH}$"verify_serviceIP.sh"

LUSTRE_SRV_SCRIPT=$"lustre" 		# service script for lustre
MON_SRV_SCRIPT=$"mon"			# service script for mon
LUSTRE_MON_SCRIPT=$"simple.health_check.monitor"
LUSTRE_ALERT_SCRIPT=$"fail_lustre.alert"
CIB_GEN_SCRIPT=$"/usr/lib/heartbeat/cts/haresources2cib.py"

TMP_DIR=$"/tmp/heartbeat/"		# temporary directory
HACF_TEMP=${TMP_DIR}$"ha.cf.temp"
AUTHKEYS_TEMP=${TMP_DIR}$"authkeys.temp"
MONCF_TEMP=${TMP_DIR}$"mon.cf.temp"

HA_DIR=$"/etc/ha.d/"			# Heartbeat configuration directory
MON_DIR=$"/etc/mon/"			# mon configuration directory
CIB_DIR=$"/var/lib/heartbeat/crm/"	# cib.xml directory

HBVER_HBV1=$"hbv1"			# Heartbeat version 1
HBVER_HBV2=$"hbv2"			# Heartbeat version 2

declare -a NODE_NAMES			# node names in the failover group

# Get and check the positional parameters
while getopts "r:n:d:c:s:o:v" OPTION; do
	case $OPTION in
	r) 
		HBVER_OPT=$OPTARG
		if [ "${HBVER_OPT}" != "${HBVER_HBV1}" ] \
		&& [ "${HBVER_OPT}" != "${HBVER_HBV2}" ]; then
			echo >&2 $"`basename $0`: Invalid Heartbeat software" \
				  "version - ${HBVER_OPT}!"
			usage
		fi
		;;
        n)
		HOSTNAME_OPT=$OPTARG 
		HOSTNAME_NUM=`echo ${HOSTNAME_OPT} | awk -F":" '{print NF}'`
		if [ ${HOSTNAME_NUM} -lt 2 ]; then
			echo >&2 $"`basename $0`: Lack failover nodenames!"
			usage
		fi
		;;
        d)
		DEVICE_OPT=$OPTARG 
		TARGET_DEV=`echo ${DEVICE_OPT} | awk -F":" '{print $1}'`
		TARGET_TYPE=`echo ${DEVICE_OPT} | awk -F":" '{print $2}'`
		if [ -z "${TARGET_TYPE}" ]; then
			echo >&2 $"`basename $0`: Lack target device type!"
			usage
		fi
		if [ "${TARGET_TYPE}" != "mgs" ]&&[ "${TARGET_TYPE}" != "mdt" ]\
		&&[ "${TARGET_TYPE}" != "ost" ]&&[ "${TARGET_TYPE}" != "mgs_mdt" ]
		then
			echo >&2 $"`basename $0`: Invalid target device type" \
				  "- ${TARGET_TYPE}!"
			usage
		fi
		;;
        c)
		HBCHANNEL_OPT=$OPTARG 
		HBCHANNEL_OPT=`echo "${HBCHANNEL_OPT}" | sed 's/^"//' \
			       | sed 's/"$//'`
		if [ "${HBCHANNEL_OPT}" = "${HBCHANNEL_OPT#*serial*}" ] \
   		&& [ "${HBCHANNEL_OPT}" = "${HBCHANNEL_OPT#*bcast*}" ] \
   		&& [ "${HBCHANNEL_OPT}" = "${HBCHANNEL_OPT#*ucast*}" ] \
   		&& [ "${HBCHANNEL_OPT}" = "${HBCHANNEL_OPT#*mcast*}" ]; then
			echo >&2 $"`basename $0`: Invalid Heartbeat channel" \
				  "- ${HBCHANNEL_OPT}!"
			usage
		fi
		;;
        s)
		SRVADDR_OPT=$OPTARG 
		;;
        o)
		HBOPT_OPT=$OPTARG 
		HBOPT_OPT=`echo "${HBOPT_OPT}" | sed 's/^"//' | sed 's/"$//'`
		;;
	v) 
		VERBOSE_OPT=$"yes"
		;;
        ?) 
		usage 
	esac
done

# Check the required parameters
if [ -z "${HBVER_OPT}" ]; then
	echo >&2 $"`basename $0`: Lack -r option!"
	usage
fi

if [ -z "${HOSTNAME_OPT}" ]; then
	echo >&2 $"`basename $0`: Lack -n option!"
	usage
fi

if [ -z "${DEVICE_OPT}" ]; then
	echo >&2 $"`basename $0`: Lack -d option!"
	usage
fi

if [ -z "${HBCHANNEL_OPT}" ]; then
	echo >&2 $"`basename $0`: Lack -c option!"
	usage
fi

if [ -z "${SRVADDR_OPT}" ]; then
	echo >&2 $"`basename $0`: Lack -s option!"
	usage
fi

if [ "${HBVER_OPT}" = "${HBVER_HBV1}" -a ${HOSTNAME_NUM} -gt 2 ]; then
	echo >&2 $"`basename $0`: Heartbeat version 1 can only support 2 nodes!"
	usage
fi

# Output verbose informations
verbose_output() {
	if [ "${VERBOSE_OPT}" = "yes" ]; then
		echo "`basename $0`: $*"
	fi
	return 0
}

# Check service IP address
PRIM_NODENAME=`echo ${HOSTNAME_OPT} | awk -F":" '{print $1}'`
verbose_output "Verifying service IP ${SRVADDR_OPT} and real IP" \
	       "of host ${PRIM_NODENAME} are in the same subnet..."
if ! ${SCRIPT_VERIFY_SRVIP} ${SRVADDR_OPT} ${PRIM_NODENAME}; then
	exit 1
fi
verbose_output "OK"

# get_nodenames
#
# Get all the node names in this failover group
get_nodenames() {
	declare -i idx
	local nodename_str nodename

	nodename_str=`echo ${HOSTNAME_OPT}|awk '{split($HOSTNAME_OPT, a, ":")}\
		      END {for (i in a) print a[i]}'`
	idx=0
	for nodename in ${nodename_str}
        do
		NODE_NAMES[idx]=${nodename}
		idx=$idx+1
        done

	return 0
}

# stop_heartbeat
#
# Run pdsh command to stop each node's heartbeat service
stop_heartbeat() {
	declare -i idx
	local nodename_str=${PRIM_NODENAME}

	for ((idx = 1; idx < ${#NODE_NAMES[@]}; idx++)); do
		nodename_str=${nodename_str}$","${NODE_NAMES[idx]}
	done

	${PDSH} -w ${nodename_str} /sbin/service heartbeat stop
	if [ $? -ne 0 ]; then
		echo >&2 "`basename $0`: stop_heartbeat() error:"\
			 "Fail to execute pdsh command!"
		return 1
	fi

	return 0
}

# create_template
#
# Create the templates for ha.cf, authkeys and mon.cf files
create_template() {
	/bin/mkdir -p ${TMP_DIR}

	# Create the template for ha.cf
	if [ "${HBVER_OPT}" = "${HBVER_HBV1}" ]; then
		cat >${HACF_TEMP} <<EOF
debugfile /var/log/ha-debug
logfile /var/log/ha-log
logfacility     local0
keepalive 2
deadtime 15
warntime 10
initdead 120

EOF
	elif [ "${HBVER_OPT}" = "${HBVER_HBV2}" ]; then
		cat >${HACF_TEMP} <<EOF
logfacility     daemon
use_logd        yes
keepalive 2
deadtime 15
warntime 10
initdead 120

EOF
	fi

	# Create the template for authkeys
	if [ ! -s ${AUTHKEYS_TEMP} ]; then
		cat >${AUTHKEYS_TEMP} <<EOF
auth 1
1 sha1 HelloLustre!
EOF
	fi

	# Create the template for mon.cf 
	if [ ! -s ${MONCF_TEMP} ]; then
		cat >${MONCF_TEMP} <<EOF
cfbasedir   = /etc/mon
alertdir   = /usr/lib/mon/alert.d
mondir     = /usr/lib/mon/mon.d
statedir    = /usr/lib/mon/state.d
logdir    = /usr/lib/mon/log.d
dtlogfile    = /usr/lib/mon/log.d/downtime.log
maxprocs    = 20
histlength  = 100
randstart   = 60s

authtype = getpwnam

EOF
	fi

	return 0
}

# gen_udpport
#
# Generate the UDP port number for Heartbeat bcast/ucast communication
# The default value for udpport option in ha.cf is 694. If there are multiple 
# bcast failover groups on the same subnet, this value should be different for 
# each of the failover groups.
gen_udpport() {
	local port_file
	declare -i default_port=694
	declare -i dynamic_port=49152
	declare -i port=0
	declare -i tmp_port
	declare -i idx

	UDPPORT_PRIMNODE=${TMP_DIR}$"udpport."${PRIM_NODENAME}

	if [ -s ${UDPPORT_PRIMNODE} ]; then
		cat ${UDPPORT_PRIMNODE}
		return 0
	fi

	# Get the current maximum UDP port number in the cluster
	for port_file in `ls ${TMP_DIR}udpport.*`
	do
		if [ $? -ne 0 ]; then
			break
		fi
		tmp_port=$(cat ${port_file})
		if [ $? -ne 0 ]; then
			break
		fi
		
		if [ ${tmp_port} -gt ${port} ]; then
			port=${tmp_port}
		fi
	done

	# Generate and check a new UDP port number
	if [ ${port} -eq 0 ]; then
		port=${default_port}
	elif [ ${port} -eq ${default_port} ]; then
		port=${dynamic_port}
	else
		port=${port}+1
		if [ ${port} -gt 65535 ]; then
			echo >&2 $"`basename $0`: Invalid UDP port" \
				  "- ${port}!"
			return 1
		fi
	fi

        # Add the UDP port number into each failover node's udpport file
        for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
                UDPPORT_NODE=${TMP_DIR}$"udpport."${NODE_NAMES[idx]}
		echo ${port} > ${UDPPORT_NODE}
        done

	echo ${port}
	return 0
}

# create_hacf
#
# Create the ha.cf file and scp it to the primary node's /etc/ha.d/
create_hacf() {
	HACF_PRIMNODE=${TMP_DIR}$"ha.cf."${PRIM_NODENAME}

	declare -i idx

	if [ -s ${HACF_PRIMNODE} ]; then
		# The ha.cf file for the primary node has already existed.
		verbose_output "${HACF_PRIMNODE} already exists."
		return 0
	fi

	/bin/cp -f ${HACF_TEMP} ${HACF_PRIMNODE}

	if [ "${HBCHANNEL_OPT}" != "${HBCHANNEL_OPT#*bcast*}" ] \
	|| [ "${HBCHANNEL_OPT}" != "${HBCHANNEL_OPT#*ucast*}" ]; then
		UDPPORT_OPT=$(gen_udpport)
		if [ $? -ne 0 ]; then
			return 1
		fi	
		echo "udpport ${UDPPORT_OPT}" >> ${HACF_PRIMNODE}
	fi

	if [ "${HBCHANNEL_OPT}" != "${HBCHANNEL_OPT#*serial*}" ]; then
		echo "baud    19200" >> ${HACF_PRIMNODE}
	fi

	echo ${HBCHANNEL_OPT} | awk '{split($HBCHANNEL_OPT, a, ":")} \
	END {for (i in a) print a[i]}' >> ${HACF_PRIMNODE}

        for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
		echo "node    ${NODE_NAMES[idx]}" >> ${HACF_PRIMNODE}
        done

	echo ${HBOPT_OPT} | awk '{split($HBOPT_OPT, a, ":")} \
	END {for (i in a) print a[i]}' >> ${HACF_PRIMNODE}

	# scp ha.cf file to the primary node's /etc/ha.d/
	scp ${HACF_PRIMNODE} ${PRIM_NODENAME}:${HA_DIR}ha.cf
	if [ $? -ne 0 ]; then
		echo >&2 "`basename $0`: Fail to scp ha.cf file to" \
			 "node ${PRIM_NODENAME}!"
		return 1
	fi

	return 0
}

# add_resgrp
#
# Add the resource group line into the haresources file
add_resgrp() {
	declare -i idx

	echo "${PRIM_NODENAME} ${SRVADDR_OPT} "\
	     "${LUSTRE_SRV_SCRIPT}::${TARGET_TYPE}::${TARGET_DEV} "\
	     "${MON_SRV_SCRIPT}" >> ${HARES_PRIMNODE}

        for ((idx = 1; idx < ${#NODE_NAMES[@]}; idx++)); do
		HARES_NODE=${TMP_DIR}$"haresources."${NODE_NAMES[idx]}
		/bin/cp -f ${HARES_PRIMNODE} ${HARES_NODE}
        done

	return 0
}

# create_haresources
#
# Create the haresources file and scp it to the each node's /etc/ha.d/
create_haresources() {
	HARES_PRIMNODE=${TMP_DIR}$"haresources."${PRIM_NODENAME}
	declare -i idx

	if [ -s ${HARES_PRIMNODE} ]; then
		# The haresources file for the primary node has already existed
		verbose_output "${HARES_PRIMNODE} already exists."
		
		if [ -z "`grep ${SRVADDR_OPT} ${HARES_PRIMNODE}`" ]; then
			# Service IP does not exist in the haresources file
			# Add the resource group line into the haresources file
			if ! add_resgrp; then
				echo >&2 "`basename $0`: add_resgrp() error!"
				return 1
			fi
		fi
	else 	# The haresources file for the primary node does not exist
		# Add the resource group line into the haresources file
		if ! add_resgrp; then
			echo >&2 "`basename $0`: add_resgrp() error!"
			return 1
		fi

	fi

	# Add the primary node name into all the nodes' node files
	for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
		NODEFILE_NODE=${TMP_DIR}$"nodefile."${NODE_NAMES[idx]}
		touch ${NODEFILE_NODE}

		if [ -z "`grep ${PRIM_NODENAME} ${NODEFILE_NODE}`" ]; then
			echo ${PRIM_NODENAME} >> ${NODEFILE_NODE}
		fi
	done

	# Check whether all the nodes in the failover group are in the node file
	# If they are, then we can scp the haresources file to all the nodes;
	# Else return 0
	NODEFILE_PRIMNODE=${TMP_DIR}$"nodefile."${PRIM_NODENAME}
	for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
		if [ -z "`grep ${NODE_NAMES[idx]} ${NODEFILE_PRIMNODE}`" ]; then
			verbose_output "INFO: not have the information of node"\
				       "${NODE_NAMES[idx]}. The haresources"\
				       "file is incompleted."
			return 0
		fi
	done

	# All the nodes in the failover group are in the node file, then we can
	# scp the haresources file 

	# Generate the cib.xml file
	if [ "${HBVER_OPT}" = "${HBVER_HBV2}" ]; then
		CIB_PRIMNODE=${TMP_DIR}$"cib.xml."${PRIM_NODENAME}
		python ${CIB_GEN_SCRIPT} ${HARES_PRIMNODE} > ${CIB_PRIMNODE}
		if [ $? -ne 0 ]; then
			echo >&2 "`basename $0`: Fail to generate cib.xml file"\
				 "for node ${PRIM_NODENAME}!"
			return 1
		fi
	fi

	# scp the haresources file or cib.xml file
	for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
		if [ "${HBVER_OPT}" = "${HBVER_HBV2}" ]; then
			scp ${CIB_PRIMNODE} ${NODE_NAMES[idx]}:${CIB_DIR}cib.xml
		else
			scp ${HARES_PRIMNODE} ${NODE_NAMES[idx]}:${HA_DIR}haresources
		fi

		if [ $? -ne 0 ]; then
			echo >&2 "`basename $0`: Fail to scp haresources file"\
				 "to node ${NODE_NAMES[idx]}!"
			return 1
		fi
	done

	return 0
}

# create_authkeys
#
# Create the authkeys file and scp it to the each node's /etc/ha.d/
create_authkeys() {
	AUTHKEYS_PRIMNODE=${TMP_DIR}$"authkeys."${PRIM_NODENAME}
	declare -i idx

	if [ -e ${AUTHKEYS_PRIMNODE} ]; then
		verbose_output "${AUTHKEYS_PRIMNODE} already exists."
		return 0
	fi

	# scp the authkeys file to all the nodes
	for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
		touch ${TMP_DIR}$"authkeys."${NODE_NAMES[idx]}
		scp ${AUTHKEYS_TEMP} ${NODE_NAMES[idx]}:${HA_DIR}authkeys
		if [ $? -ne 0 ]; then
			echo >&2 "`basename $0`: Fail to scp authkeys file"\
				 "to node ${NODE_NAMES[idx]}!"
			return 1
		fi
	done

	return 0
}

# create_moncf
#
# Create the mon.cf file and scp it to the each node's /etc/mon/
create_moncf() {
	MONCF_PRIMNODE=${TMP_DIR}$"mon.cf."${PRIM_NODENAME}
	declare -i idx
	local hostgroup_str=$"hostgroup ${TARGET_TYPE}-group"

	if [ -e ${MONCF_PRIMNODE} ]; then
		verbose_output "${MONCF_PRIMNODE} already exists."
		return 0
	fi

	/bin/cp -f ${MONCF_TEMP} ${MONCF_PRIMNODE}

	for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
		hostgroup_str=${hostgroup_str}$" "${NODE_NAMES[idx]}
	done

	echo ${hostgroup_str} >> ${MONCF_PRIMNODE}

	cat >>${MONCF_PRIMNODE} <<EOF

watch ${TARGET_TYPE}-group
    service ${LUSTRE_SRV_SCRIPT}
        description Lustre health check
        interval 1m
        monitor ${LUSTRE_MON_SCRIPT} -o ${TARGET_TYPE}
        period wd {Sat-Sun}
            alert ${LUSTRE_ALERT_SCRIPT}

EOF
	# scp the mon.cf file to all the nodes
	for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
		touch ${TMP_DIR}$"mon.cf."${NODE_NAMES[idx]}
		scp ${MONCF_PRIMNODE} ${NODE_NAMES[idx]}:${MON_DIR}mon.cf
		if [ $? -ne 0 ]; then
			echo >&2 "`basename $0`: Fail to scp mon.cf file"\
				 "to node ${NODE_NAMES[idx]}!"
			return 1
		fi
	done

	return 0
}

# generate_config
#
# Generate the configuration files for Heartbeat and scp them to all the nodes
generate_config() {
	if ! create_template; then
		return 1
	fi

	verbose_output "Creating and remote copying ha.cf file to host" \
		       "${PRIM_NODENAME}..."
	if ! create_hacf; then
		return 1
	fi
	verbose_output "OK"

	if [ "${HBVER_OPT}" = "${HBVER_HBV1}" ]; then
		verbose_output "Creating and remote copying haresources file"\
			       "to ${PRIM_NODENAME} failover group hosts..."
	else
		verbose_output "Creating and remote copying cib.xml file"\
			       "to ${PRIM_NODENAME} failover group hosts..."
	fi

	if ! create_haresources; then
		return 1
	fi
	verbose_output "OK"

	verbose_output "Creating and remote copying authkeys file to" \
		       "${PRIM_NODENAME} failover group hosts..."
	if ! create_authkeys; then
		return 1
	fi
	verbose_output "OK"

	verbose_output "Creating and remote copying mon.cf file to" \
		       "${PRIM_NODENAME} failover group hosts..."
	if ! create_moncf; then
		return 1
	fi
	verbose_output "OK"

	return 0
}

# Main flow
# Get all the node names
if ! get_nodenames; then
	exit 1
fi

# Stop heartbeat services
verbose_output "Stopping heartbeat service in the ${PRIM_NODENAME}"\
	       "failover group hosts..."
if ! stop_heartbeat; then
	exit 1
fi
verbose_output "OK"

# Generate configuration files
if ! generate_config; then
	exit 1
fi

exit 0
