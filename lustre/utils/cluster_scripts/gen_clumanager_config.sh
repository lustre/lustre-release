#!/bin/bash
#
# gen_clumanager_config.sh - script for generating the Red Hat's Cluster Manager
#		     	     HA software's configuration files
#
################################################################################

# Usage
usage() {
	cat >&2 <<EOF

Usage:  `basename $0` <-n hostnames> <-d target device> <-s service addresses> 
		      [-c heartbeat channels] [-o heartbeat options] [-v]

	-n hostnames            the nodenames of the primary node and its fail-
				overs
                        	Multiple nodenames are separated by colon (:)
                        	delimeter. The first one is the nodename of the 
				primary node, the others are failover nodenames.
	-d target device        the target device name and type
                        	The name and type are separated by colon (:)
                        	delimeter. The type values are: mgs, mdt, ost or
				mgs_mdt.
	-s service addresses    the IP addresses to failover
				Multiple addresses are separated by colon (:)
				delimeter.
	-c heartbeat channels   the methods to send/rcv heartbeats on
				The default method is multicast, and multicast_
				ipaddress is "225.0.0.11".
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

LUSTRE_SRV_SCRIPT=$"/etc/rc.d/init.d/lustre"	# service script for lustre

TMP_DIR=$"/tmp/clumanager/"		# temporary directory
CLUMGR_DIR=$"/etc/"			# CluManager configuration directory

CONFIG_CMD=$"redhat-config-cluster-cmd"

declare -a NODE_NAMES			# node names in the failover group
declare -a SRV_IPADDRS			# service IP addresses

# Get and check the positional parameters
while getopts "n:d:s:c:o:v" OPTION; do
	case $OPTION in
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
        s)
		SRVADDR_OPT=$OPTARG 
		;;
        c)
		HBCHANNEL_OPT=$OPTARG
		HBCHANNEL_OPT=`echo "${HBCHANNEL_OPT}" | sed 's/^"//' \
                               | sed 's/"$//'` 
		if [ -n "${HBCHANNEL_OPT}" ] \
   		&& [ "${HBCHANNEL_OPT}" = "${HBCHANNEL_OPT#*broadcast*}" ] \
   		&& [ "${HBCHANNEL_OPT}" = "${HBCHANNEL_OPT#*multicast*}" ]; then
			echo >&2 $"`basename $0`: Invalid Heartbeat channel" \
				  "- ${HBCHANNEL_OPT}!"
			usage
		fi
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
if [ -z "${HOSTNAME_OPT}" ]; then
	echo >&2 $"`basename $0`: Lack -n option!"
	usage
fi

if [ -z "${DEVICE_OPT}" ]; then
	echo >&2 $"`basename $0`: Lack -d option!"
	usage
fi

if [ -z "${SRVADDR_OPT}" ]; then
	echo >&2 $"`basename $0`: Lack -s option!"
	usage
fi

# Output verbose informations
verbose_output() {
	if [ "${VERBOSE_OPT}" = "yes" ]; then
		echo "`basename $0`: $*"
	fi
	return 0
}

# get_check_srvIPaddrs
#
# Get and check all the service IP addresses in this failover group
get_check_srvIPaddrs() {
	PRIM_NODENAME=`echo ${HOSTNAME_OPT} | awk -F":" '{print $1}'`

	declare -i idx
	local srvIPaddr_str srvIPaddr

	srvIPaddr_str=`echo ${SRVADDR_OPT}|awk '{split($SRVADDR_OPT, a, ":")}\
		      END {for (i in a) print a[i]}'`
	idx=0
	for srvIPaddr in ${srvIPaddr_str}
        do
		SRV_IPADDRS[idx]=${srvIPaddr}
		idx=$idx+1
        done

	for ((idx = 0; idx < ${#SRV_IPADDRS[@]}; idx++)); do
		# Check service IP address
		verbose_output "Verifying service IP ${SRV_IPADDRS[idx]} and" \
	       		       "real IP of host ${PRIM_NODENAME} are in the" \
			       "same subnet..."
		if ! ${SCRIPT_VERIFY_SRVIP} ${SRV_IPADDRS[idx]} ${PRIM_NODENAME}
		then
			return 1
		fi
		verbose_output "OK"
	done

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

# stop_clumanager
#
# Run pdsh command to stop each node's clumanager service
stop_clumanager() {
	declare -i idx
	local nodename_str=${PRIM_NODENAME}

	for ((idx = 1; idx < ${#NODE_NAMES[@]}; idx++)); do
		nodename_str=${nodename_str}$","${NODE_NAMES[idx]}
	done

	${PDSH} -w ${nodename_str} /sbin/service clumanager stop
	if [ $? -ne 0 ]; then
		echo >&2 "`basename $0`: stop_clumanager() error:"\
			 "Fail to execute pdsh command!"
		return 1
	fi

	return 0
}

# check_retval retval
#
# Check the return value of redhat-config-cluster-cmd
check_retval() {
	if [ $1 -ne 0 ]; then
		echo >&2 "`basename $0`: Fail to run ${CONFIG_CMD}!"
		return 1
	fi

	return 0
}

# gen_cluster_xml
#
# Run redhat-config-cluster-cmd to create the cluster.xml file
gen_cluster_xml() {
	declare -i idx
	local mcast_IPaddr
	local hbopt_str hbopt

	# Run redhat-config-cluster-cmd to generate cluster.xml
	# Add clumembd tag
   	if [ "${HBCHANNEL_OPT}" != "${HBCHANNEL_OPT#*broadcast*}" ]; then
		${CONFIG_CMD} --clumembd --broadcast=yes
		if ! check_retval $?; then
			return 1
		fi
	elif [ "${HBCHANNEL_OPT}" != "${HBCHANNEL_OPT#*multicast*}" ]; then
		mcast_IPaddr=`echo ${HBCHANNEL_OPT} | awk '{print $2}'`
		if [ -n "${mcast_IPaddr}" ]; then
			${CONFIG_CMD} --clumembd --multicast=yes\
				      --multicast_ipaddress=${mcast_IPaddr}
			if ! check_retval $?; then
				return 1
			fi
		fi
	fi

	# Add cluster tag
	${CONFIG_CMD} --cluster --name='${TARGET_TYPE} failover group'
	if ! check_retval $?; then
		return 1
	fi

	# Add member tag
	for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
		${CONFIG_CMD} --add_member --name=${NODE_NAMES[idx]}
		if ! check_retval $?; then
			return 1
		fi
	done

	# Add failoverdomain tag
	${CONFIG_CMD} --add_failoverdomain --name=${TARGET_TYPE}-domain
	if ! check_retval $?; then
		return 1
	fi

	for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
		${CONFIG_CMD} --failoverdomain=${TARGET_TYPE}-domain\
			--add_failoverdomainnode --name=${NODE_NAMES[idx]}
		if ! check_retval $?; then
			return 1
		fi
	done

	# Add service tag
	${CONFIG_CMD} --add_service --name=${TARGET_TYPE}-service
	if ! check_retval $?; then
		return 1
	fi

	${CONFIG_CMD} --service=${TARGET_TYPE}-service \
		--userscript=${LUSTRE_SRV_SCRIPT}
	if ! check_retval $?; then
		return 1
	fi

	${CONFIG_CMD} --service=${TARGET_TYPE}-service \
		--failoverdomain=${TARGET_TYPE}-domain
	if ! check_retval $?; then
		return 1
	fi

	for ((idx = 0; idx < ${#SRV_IPADDRS[@]}; idx++)); do
		${CONFIG_CMD} --service=mgs-service \
			--add_service_ipaddress --ipaddress=${SRV_IPADDRS[idx]}
		if ! check_retval $?; then
			return 1
		fi
	done

	# Add other tags
	if [ -n "${HBOPT_OPT}"]; then
		hbopt_str=`echo ${HBOPT_OPT}|awk '{split($HBOPT_OPT, a, ":")}\
		      	  END {for (i in a) print a[i]}'`
		idx=0
		for hbopt in ${hbopt_str}
        	do
			${CONFIG_CMD} ${hbopt}
			if ! check_retval $?; then
				return 1
			fi
			idx=$idx+1
        	done
	fi

	return 0
}

# create_config
#
# Create the cluster.xml file and scp it to the each node's /etc/
create_config() {
	CONFIG_PRIMNODE=${TMP_DIR}$"cluster.xml."${PRIM_NODENAME}
	declare -i idx

	if [ -e ${CONFIG_PRIMNODE} ]; then
		verbose_output "${CONFIG_PRIMNODE} already exists."
		return 0
	fi

	# Run redhat-config-cluster-cmd to generate cluster.xml
	verbose_output "Creating cluster.xml file for" \
		       "${PRIM_NODENAME} failover group hosts..."
	if ! gen_cluster_xml; then
		return 1
	fi
	verbose_output "OK"

	/bin/cp -f ${CLUMGR_DIR}cluster.xml ${CONFIG_PRIMNODE}

	# scp the cluster.xml file to all the nodes
	verbose_output "Remote copying cluster.xml file to" \
		       "${PRIM_NODENAME} failover group hosts..."
	for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
		touch ${TMP_DIR}$"cluster.xml."${NODE_NAMES[idx]}
		scp ${CONFIG_PRIMNODE} ${NODE_NAMES[idx]}:${CLUMGR_DIR}cluster.xml
		if [ $? -ne 0 ]; then
			echo >&2 "`basename $0`: Fail to scp cluster.xml file"\
				 "to node ${NODE_NAMES[idx]}!"
			return 1
		fi
	done
	verbose_output "OK"

	return 0
}

# Main flow
# Get and check all the service IP addresses
if ! get_check_srvIPaddrs; then
	exit 1
fi

# Get all the node names
if ! get_nodenames; then
	exit 1
fi

# Stop clumanager services
verbose_output "Stopping clumanager service in the ${PRIM_NODENAME}"\
	       "failover group hosts..."
if ! stop_clumanager; then
	exit 1
fi
verbose_output "OK"

# Generate configuration files
if ! create_config; then
	exit 1
fi

exit 0
