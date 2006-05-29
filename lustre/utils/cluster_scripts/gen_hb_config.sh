#!/bin/bash
#
# gen_hb_config.sh - script for generating the Heartbeat HA software's
#		     configuration files
#
###############################################################################

# Usage
usage() {
	cat >&2 <<EOF

Usage:  `basename $0` <-r HBver> <-n hostnames> <-c heartbeat channels> 
		      [-s service address] [-o heartbeat options] [-v] 
		      <-d target device> [-d target device...]

	-r HBver		the version of Heartbeat software
                        	The Heartbeat software versions which are curr-
				ently supported are: hbv1 (Heartbeat version 1) 
				and hbv2 (Heartbeat version 2).
	-n hostnames            the nodenames of the primary node and its fail-
				overs
                        	Multiple nodenames are separated by colon (:)
                        	delimeter. The first one is the nodename of the 
				primary node, the others are failover nodenames.
	-c heartbeat channels   the methods and devices to send/rcv heartbeats on
				Multiple channels are separated by colon (:)
				delimeter.
	-s service address      the IP address to failover, required by hbv1
	-o heartbeat options    a "catchall" for other heartbeat configuration 
				options
				Multiple options are separated by colon (:)
				delimeter.
	-v			verbose mode
	-d target device        the target device name and mount point
                        	The device name and mount point are separated by
				colon (:) delimeter. 

EOF
	exit 1
}

#****************************** Global variables ******************************#
# Scripts to be called
SCRIPTS_PATH=${CLUSTER_SCRIPTS_PATH:-"."}
SCRIPT_VERIFY_SRVIP=${SCRIPTS_PATH}/verify_serviceIP.sh
SCRIPT_GEN_MONCF=${SCRIPTS_PATH}/mon_cf.generator.sh	# create mon.cf file

# Remote command
REMOTE=${REMOTE:-"ssh -x -q"}

# Lustre utilities path
CMD_PATH=${CMD_PATH:-"/usr/sbin"}
TUNEFS=${TUNEFS:-"$CMD_PATH/tunefs.lustre"}

# Heartbeat tools
HB_TOOLS_PATH=${HB_TOOLS_PATH:-"/usr/lib/heartbeat"}	# Heartbeat tools path
CIB_GEN_SCRIPT=${HB_TOOLS_PATH}/haresources2cib.py

# Configuration directories
HA_DIR=${HA_DIR:-"/etc/ha.d"}		# Heartbeat configuration directory
MON_DIR=${MON_DIR:-"/etc/mon"}		# mon configuration directory
CIB_DIR=${CIB_DIR:-"/var/lib/heartbeat/crm"}	# cib.xml directory

# Service directories and names
INIT_DIR=${INIT_DIR:-"/etc/init.d"}
HARES_DIR=${HARES_DIR:-"${HA_DIR}/resource.d"}		# Heartbeat resources
LUSTRE_SRV=${LUSTRE_SRV:-"${INIT_DIR}/lustre"}		# service script for lustre
LUSTRE_RESMON_SCRIPT=${LUSTRE_RESMON_SCRIPT:-"${HARES_DIR}/lustre-resource-monitor"}

TMP_DIR="/tmp/heartbeat"		# temporary directory
HACF_TEMP=${TMP_DIR}/ha.cf.temp
AUTHKEYS_TEMP=${TMP_DIR}/authkeys.temp

HBVER_HBV1="hbv1"			# Heartbeat version 1
HBVER_HBV2="hbv2"			# Heartbeat version 2

declare -a NODE_NAMES			# node names in the failover group

# Lustre target device names, service names and mount points
declare -a TARGET_DEVNAMES TARGET_SRVNAMES TARGET_MNTPNTS
declare -i TARGET_NUM=0			# number of targets


# Get and check the positional parameters
VERBOSE_OUTPUT=false
while getopts "r:n:c:s:o:vd:" OPTION; do
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
		PRIM_NODENAME=`echo ${HOSTNAME_OPT} | awk -F":" '{print $1}'`
		if [ -z "${PRIM_NODENAME}" ]; then
			echo >&2 $"`basename $0`: Missing primary nodename!"
			usage
		fi
		HOSTNAME_NUM=`echo ${HOSTNAME_OPT} | awk -F":" '{print NF}'`
		if [ ${HOSTNAME_NUM} -lt 2 ]; then
			echo >&2 $"`basename $0`: Missing failover nodenames!"
			usage
		fi
		if [ "${HBVER_OPT}" = "${HBVER_HBV1}" -a ${HOSTNAME_NUM} -gt 2 ]
		then
			echo >&2 $"`basename $0`: Heartbeat version 1 can" \
				  "only support 2 nodes!"
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
				  "- \"${HBCHANNEL_OPT}\"!"
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
		VERBOSE_OUTPUT=true
		;;
        d)
		DEVICE_OPT=$OPTARG 
		TARGET_DEVNAMES[TARGET_NUM]=`echo ${DEVICE_OPT}|awk -F: '{print $1}'`
		TARGET_MNTPNTS[TARGET_NUM]=`echo ${DEVICE_OPT}|awk -F: '{print $2}'`
		if [ -z "${TARGET_DEVNAMES[TARGET_NUM]}" ]; then
			echo >&2 $"`basename $0`: Missing target device name!"
			usage
		fi
		if [ -z "${TARGET_MNTPNTS[TARGET_NUM]}" ]; then
			echo >&2 $"`basename $0`: Missing mount point for target"\
				  "${TARGET_DEVNAMES[TARGET_NUM]}!"
			usage
		fi
		TARGET_NUM=$(( TARGET_NUM + 1 ))
		;;
        ?) 
		usage 
	esac
done

# Check the required parameters
if [ -z "${HBVER_OPT}" ]; then
	echo >&2 $"`basename $0`: Missing -r option!"
	usage
fi

if [ -z "${HOSTNAME_OPT}" ]; then
	echo >&2 $"`basename $0`: Missing -n option!"
	usage
fi

if [ -z "${HBCHANNEL_OPT}" ]; then
	echo >&2 $"`basename $0`: Missing -c option!"
	usage
fi

if [ "${HBVER_OPT}" = "${HBVER_HBV1}" -a -z "${SRVADDR_OPT}" ]; then
	echo >&2 $"`basename $0`: Missing -s option!"
	usage
fi

if [ -z "${DEVICE_OPT}" ]; then
	echo >&2 $"`basename $0`: Missing -d option!"
	usage
fi

# Output verbose informations
verbose_output() {
	if ${VERBOSE_OUTPUT}; then
		echo "`basename $0`: $*"
	fi
	return 0
}

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

# check_srvIPaddr
#
# Check service IP address in this failover group
check_srvIPaddr() {
	declare -i idx

	for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
		# Check service IP address
	    	verbose_output "Verifying service IP ${SRVADDR_OPT} and" \
	    	           "real IP of host ${NODE_NAMES[idx]} are in the" \
			   "same subnet..."
	    	if ! ${SCRIPT_VERIFY_SRVIP} ${SRVADDR_OPT} ${NODE_NAMES[idx]}
	    	then
	      		return 1
	    	fi
	    	verbose_output "OK"
	done

	return 0
}

# stop_heartbeat
#
# Run remote command to stop each node's heartbeat service
stop_heartbeat() {
	declare -i idx
	local ret_str

	for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
		ret_str=`${REMOTE} ${NODE_NAMES[idx]} \
			"/sbin/service heartbeat stop" 2>&1`
		if [ $? -ne 0 ]; then
			echo >&2 "`basename $0`: stop_heartbeat() error:"\
				 "from host ${NODE_NAMES[idx]} - $ret_str!"
		fi
	done

	return 0
}

# get_srvname hostname target_devname
#
# Get the lustre target server name from the node @hostname
get_srvname() {
	local host_name=$1
	local target_devname=$2
	local target_srvname=
	local ret_str

	# Execute remote command to get the target server name
	ret_str=`${REMOTE} ${host_name} \
		"${TUNEFS} --print ${target_devname} | grep Target:" 2>&1`
	if [ $? -ne 0 ]; then
		echo "`basename $0`: get_srvname() error:" \
		     "from host ${host_name} - ${ret_str}"
		return 1
	fi

	if [ "${ret_str}" != "${ret_str#*Target: }" ]; then
		ret_str=${ret_str#*Target: }
		target_srvname=`echo ${ret_str} | awk '{print $1}'`
	fi
	
	if [ -z "${target_srvname}" ]; then
		echo "`basename $0`: get_srvname() error: Cannot get the"\
		     "server name of target ${target_devname} in ${host_name}!"
		return 1
	fi

	echo ${target_srvname}
	return 0
} 

# create_service
#
# Create service symlinks from /etc/init.d/lustre for Lustre targets
create_service() {
	declare -i i
	local srv_dir
	local command ret_str

	# Initialize the TARGET_SRVNAMES array
	unset TARGET_SRVNAMES

	# Get Lustre target service names
	for ((i = 0; i < ${#TARGET_DEVNAMES[@]}; i++)); do
		TARGET_SRVNAMES[i]=$(get_srvname ${PRIM_NODENAME} \
				     ${TARGET_DEVNAMES[i]})
		if [ $? -ne 0 ]; then
			echo >&2 "${TARGET_SRVNAMES[i]}"
			return 1
		fi
	done

	[ "${HBVER_OPT}" = "${HBVER_HBV1}" ] && srv_dir=${HARES_DIR} \
	|| srv_dir=${INIT_DIR}

	# Construct remote command
	command=":"
	for ((i = 0; i < ${#TARGET_SRVNAMES[@]}; i++)); do
		command=${command}";ln -s -f ${LUSTRE_SRV} ${srv_dir}/${TARGET_SRVNAMES[i]}"
		if [ "${HBVER_OPT}" = "${HBVER_HBV1}" ]; then
			command=${command}";/bin/cp -f ${LUSTRE_RESMON_SCRIPT} ${HARES_DIR}/${TARGET_SRVNAMES[i]}-mon"
		fi
	done

	# Execute remote command to create symlinks
	for ((i = 0; i < ${#NODE_NAMES[@]}; i++)); do
		ret_str=`${REMOTE} ${NODE_NAMES[i]} "${command}" 2>&1`
		if [ $? -ne 0 ]; then
			echo >&2 "`basename $0`: create_service() error:" \
		     		 "from host ${NODE_NAMES[i]} - ${ret_str}"
			return 1
		fi
	done

	return 0
}

# create_template
#
# Create the templates for ha.cf and authkeys files
create_template() {
	/bin/mkdir -p ${TMP_DIR}

	# Create the template for ha.cf
	if [ "${HBVER_OPT}" = "${HBVER_HBV1}" ]; then
		cat >${HACF_TEMP} <<EOF
debugfile /var/log/ha-debug
logfile /var/log/ha-log
logfacility     local0
keepalive 2
deadtime 30
initdead 120

EOF
	elif [ "${HBVER_OPT}" = "${HBVER_HBV2}" ]; then
		cat >${HACF_TEMP} <<EOF
use_logd        yes
keepalive 1
deadtime 10
initdead 60

EOF
	fi

	# Create the template for authkeys
	if [ ! -s ${AUTHKEYS_TEMP} ]; then
		cat >${AUTHKEYS_TEMP} <<EOF
auth 1
1 sha1 HelloLustre!
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

	UDPPORT_PRIMNODE=${TMP_DIR}$"/udpport."${PRIM_NODENAME}

	if [ -s ${UDPPORT_PRIMNODE} ]; then
		cat ${UDPPORT_PRIMNODE}
		return 0
	fi

	# Get the current maximum UDP port number in the cluster
	for port_file in `ls ${TMP_DIR}/udpport.* 2>/dev/null`
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
                UDPPORT_NODE=${TMP_DIR}$"/udpport."${NODE_NAMES[idx]}
		echo ${port} > ${UDPPORT_NODE}
        done

	echo ${port}
	return 0
}

# create_hacf
#
# Create the ha.cf file and scp it to each node's /etc/ha.d/
create_hacf() {
	HACF_PRIMNODE=${TMP_DIR}$"/ha.cf."${PRIM_NODENAME}

	declare -i idx

	if [ -e ${HACF_PRIMNODE} ]; then
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

	# Disable automatic failbacks
	echo "auto_failback off" >> ${HACF_PRIMNODE}

	[ "${HBVER_OPT}" = "${HBVER_HBV2}" ] && echo "crm yes" >> ${HACF_PRIMNODE}

        for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
		echo "node    ${NODE_NAMES[idx]}" >> ${HACF_PRIMNODE}
        done

	echo ${HBOPT_OPT} | awk '{split($HBOPT_OPT, a, ":")} \
	END {for (i in a) print a[i]}' >> ${HACF_PRIMNODE}

	# scp ha.cf file to all the nodes
	for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
		touch ${TMP_DIR}$"/ha.cf."${NODE_NAMES[idx]}
		scp ${HACF_PRIMNODE} ${NODE_NAMES[idx]}:${HA_DIR}/ha.cf
		if [ $? -ne 0 ]; then
			echo >&2 "`basename $0`: Failed to scp ha.cf file"\
				 "to node ${NODE_NAMES[idx]}!"
			return 1
		fi
	done

	return 0
}

# create_haresources
#
# Create the haresources file and scp it to the each node's /etc/ha.d/
create_haresources() {
	HARES_PRIMNODE=${TMP_DIR}$"/haresources."${PRIM_NODENAME}
	declare -i idx
	local res_line

	if [ -s ${HARES_PRIMNODE} ]; then
		# The haresources file for the primary node has already existed
		if [ -n "`/bin/grep ${TARGET_SRVNAMES[0]} ${HARES_PRIMNODE}`" ]; then
			verbose_output "${HARES_PRIMNODE} already exists."
			return 0
		fi
	fi
		
	# Add the resource group line into the haresources file
	res_line=${PRIM_NODENAME}" "${SRVADDR_OPT}
	for ((idx = 0; idx < ${#TARGET_SRVNAMES[@]}; idx++)); do
		res_line=${res_line}" "${TARGET_SRVNAMES[idx]}::${TARGET_DEVNAMES[idx]}::${TARGET_MNTPNTS[idx]}
			
		if [ "${HBVER_OPT}" = "${HBVER_HBV1}" ]; then
			res_line=${res_line}" "${TARGET_SRVNAMES[idx]}"-mon"
		fi
	done
	echo "${res_line}" >> ${HARES_PRIMNODE}

	# Generate the cib.xml file
	if [ "${HBVER_OPT}" = "${HBVER_HBV2}" ]; then
		# Add group haclient and user hacluster
		[ -z "`grep haclient /etc/group`" ] && groupadd haclient
		[ -z "`grep hacluster /etc/passwd`" ] && useradd -g haclient hacluster

		CIB_PRIMNODE=${TMP_DIR}$"/cib.xml."${PRIM_NODENAME}
		python ${CIB_GEN_SCRIPT} --stdout -c ${HACF_PRIMNODE} \
		${HARES_PRIMNODE} > ${CIB_PRIMNODE}
		if [ $? -ne 0 ]; then
			echo >&2 "`basename $0`: Failed to generate cib.xml file"\
				 "for node ${PRIM_NODENAME}!"
			return 1
		fi
	fi

	# scp the haresources file or cib.xml file
	for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
		if [ "${PRIM_NODENAME}" != "${NODE_NAMES[idx]}" ]; then
			/bin/cp -f ${HARES_PRIMNODE} \
			${TMP_DIR}$"/haresources."${NODE_NAMES[idx]}
		fi

		scp ${HARES_PRIMNODE} ${NODE_NAMES[idx]}:${HA_DIR}/haresources
		if [ $? -ne 0 ]; then
			echo >&2 "`basename $0`: Failed to scp haresources file"\
				 "to node ${NODE_NAMES[idx]}!"
			return 1
		fi

		if [ "${HBVER_OPT}" = "${HBVER_HBV2}" ]; then
			scp ${CIB_PRIMNODE} ${NODE_NAMES[idx]}:${CIB_DIR}/cib.xml
			if [ $? -ne 0 ]; then
				echo >&2 "`basename $0`: Failed to scp cib.xml"\
				 	 "file to node ${NODE_NAMES[idx]}!"
				return 1
			fi
		fi
	done

	return 0
}

# create_authkeys
#
# Create the authkeys file and scp it to the each node's /etc/ha.d/
create_authkeys() {
	AUTHKEYS_PRIMNODE=${TMP_DIR}$"/authkeys."${PRIM_NODENAME}
	declare -i idx

	if [ -e ${AUTHKEYS_PRIMNODE} ]; then
		verbose_output "${AUTHKEYS_PRIMNODE} already exists."
		return 0
	fi

	# scp the authkeys file to all the nodes
	chmod 600 ${AUTHKEYS_TEMP}
	for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
		touch ${TMP_DIR}$"/authkeys."${NODE_NAMES[idx]}
		scp -p ${AUTHKEYS_TEMP} ${NODE_NAMES[idx]}:${HA_DIR}/authkeys
		if [ $? -ne 0 ]; then
			echo >&2 "`basename $0`: Failed to scp authkeys file"\
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
	MONCF_PRIMNODE=${TMP_DIR}$"/mon.cf."${PRIM_NODENAME}
	local srv_name params=
	declare -i idx
	declare -a OLD_TARGET_SRVNAMES		# targets in other nodes 
						# in this failover group
	# Initialize the OLD_TARGET_SRVNAMES array
	unset OLD_TARGET_SRVNAMES

	if [ -s ${MONCF_PRIMNODE} ]; then
		if [ -n "`/bin/grep ${TARGET_SRVNAMES[0]} ${MONCF_PRIMNODE}`" ]
		then
			verbose_output "${MONCF_PRIMNODE} already exists."
			return 0
		else
			# Get the Lustre target service names 
			# from the previous mon.cf file
			idx=0
			for srv_name in `grep hostgroup ${MONCF_PRIMNODE}\
					|awk '$2 ~ /-mon/ {print $2}'|xargs`
			do
				OLD_TARGET_SRVNAMES[idx]=`echo ${srv_name}\
							  |sed 's/-mon//g'`
				idx=$(( idx + 1 ))
			done
		fi
	fi

	# Construct the parameters to mon.cf generation script
	for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
		params=${params}" -n "${NODE_NAMES[idx]}
	done

	for ((idx = 0; idx < ${#OLD_TARGET_SRVNAMES[@]}; idx++)); do
		params=${params}" -o "${OLD_TARGET_SRVNAMES[idx]}
	done

	for ((idx = 0; idx < ${#TARGET_SRVNAMES[@]}; idx++)); do
		params=${params}" -o "${TARGET_SRVNAMES[idx]}
	done

	${SCRIPT_GEN_MONCF} ${params}
	if [ $? -ne 0 ]; then
		echo >&2 "`basename $0`: Failed to generate mon.cf file"\
			 "by using ${SCRIPT_GEN_MONCF}!"
		return 1
	fi

	/bin/mv *-mon.cfg ${MONCF_PRIMNODE}

	# scp the mon.cf file to all the nodes
	for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
		if [ "${PRIM_NODENAME}" != "${NODE_NAMES[idx]}" ]; then
			/bin/cp -f ${MONCF_PRIMNODE} \
			${TMP_DIR}$"/mon.cf."${NODE_NAMES[idx]}
		fi

		scp ${MONCF_PRIMNODE} ${NODE_NAMES[idx]}:${MON_DIR}/mon.cf
		if [ $? -ne 0 ]; then
			echo >&2 "`basename $0`: Failed to scp mon.cf file"\
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
	# Create symlinks for Lustre services
	verbose_output "Creating symlinks for lustre target services in"\
		       "${PRIM_NODENAME} failover group hosts..." 
	if ! create_service; then
		return 1
	fi
	verbose_output "OK"
	
	if ! create_template; then
		return 1
	fi

	verbose_output "Creating and remote copying ha.cf file to"\
		       "${PRIM_NODENAME} failover group hosts..." 
	if ! create_hacf; then
		return 1
	fi
	verbose_output "OK"

	verbose_output "Creating and remote copying haresources file"\
		       "to ${PRIM_NODENAME} failover group hosts..."
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

	if [ "${HBVER_OPT}" = "${HBVER_HBV1}" ]; then
		verbose_output "Creating and remote copying mon.cf file to" \
				"${PRIM_NODENAME} failover group hosts..."
		if ! create_moncf; then
			return 1
		fi
		verbose_output "OK"
	fi

	return 0
}

# Main flow
# Get all the node names
if ! get_nodenames; then
	exit 1
fi

# Check service IP address
if [ "${HBVER_OPT}" = "${HBVER_HBV1}" ] && ! check_srvIPaddr; then
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
