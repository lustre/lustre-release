#!/bin/bash
#
# lc_cluman.sh - script for generating the Red Hat Cluster Manager
#		 HA software's configuration files
#
################################################################################

# Usage
usage() {
	cat >&2 <<EOF

Usage:  `basename $0` <-n hostnames> <-s service addresses> 
		      [-c heartbeat channel] [-o heartbeat options] [-v]
		      <-d target device> [-d target device...]

	-n hostnames            the nodenames of the primary node and its fail-
				overs
                        	Multiple nodenames are separated by colon (:)
                        	delimeter. The first one is the nodename of the 
				primary node, the others are failover nodenames.
	-s service addresses    the IP addresses to failover
				Multiple addresses are separated by colon (:)
				delimeter.
	-c heartbeat channel	the method to send/rcv heartbeats on
				The default method is multicast, and multicast_
				ipaddress is "225.0.0.11".
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
SCRIPTS_PATH=${CLUSTER_SCRIPTS_PATH:-"/usr/local/sbin"}
SCRIPT_VERIFY_SRVIP=${SCRIPTS_PATH}/lc_servip.sh

# Remote command
REMOTE=${REMOTE:-"ssh -x -q"}

# Lustre utilities path
CMD_PATH=${CMD_PATH:-"/usr/sbin"}
TUNEFS=${TUNEFS:-"$CMD_PATH/tunefs.lustre"}

# CluManager tools
CLUMAN_TOOLS_PATH=${CLUMAN_TOOLS_PATH:-"/usr/sbin"}
CONFIG_CMD=${CONFIG_CMD:-"${CLUMAN_TOOLS_PATH}/redhat-config-cluster-cmd"}

# Configuration directory
CLUMAN_DIR="/etc"			# CluManager configuration directory

# Service directory and name
INIT_DIR=${INIT_DIR:-"/etc/init.d"}
LUSTRE_SRV=${LUSTRE_SRV:-"${INIT_DIR}/lustre"}	# service script for lustre

TMP_DIR="/tmp/clumanager"		# temporary directory

declare -a NODE_NAMES			# node names in the failover group
declare -a SRV_IPADDRS			# service IP addresses

# Lustre target device names, service names and mount points
declare -a TARGET_DEVNAMES TARGET_SRVNAMES TARGET_MNTPNTS
declare -i TARGET_NUM=0			# number of targets

# Get and check the positional parameters
VERBOSE_OUTPUT=false
while getopts "n:s:c:o:vd:" OPTION; do
	case $OPTION in
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
if [ -z "${HOSTNAME_OPT}" ]; then
	echo >&2 $"`basename $0`: Missing -n option!"
	usage
fi

if [ -z "${SRVADDR_OPT}" ]; then
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

# get_check_srvIPaddrs
#
# Get and check all the service IP addresses in this failover group
get_check_srvIPaddrs() {
	declare -i idx
	declare -i i
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
	  for ((i = 0; i < ${#NODE_NAMES[@]}; i++)); do
	    # Check service IP address
	    verbose_output "Verifying service IP ${SRV_IPADDRS[idx]} and" \
	    	           "real IP of host ${NODE_NAMES[i]} are in the" \
			   "same subnet..."
	    if ! ${SCRIPT_VERIFY_SRVIP} ${SRV_IPADDRS[idx]} ${NODE_NAMES[i]}
	    then
	      return 1
	    fi
	    verbose_output "OK"
	  done
	done

	return 0
}

# stop_clumanager
#
# Run remote command to stop each node's clumanager service
stop_clumanager() {
	declare -i idx
	local ret_str

	for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
		ret_str=`${REMOTE} ${NODE_NAMES[idx]} \
			"/sbin/service clumanager stop" 2>&1`
		if [ $? -ne 0 ]; then
			echo >&2 "`basename $0`: stop_clumanager() error:"\
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
		"${TUNEFS} --print --verbose ${target_devname} | grep Target:" 2>&1`
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

	# Construct remote command
	command=":"
	for ((i = 0; i < ${#TARGET_SRVNAMES[@]}; i++)); do
		command=${command}";ln -s -f ${LUSTRE_SRV} ${INIT_DIR}/${TARGET_SRVNAMES[i]}"
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

# check_retval retval
#
# Check the return value of redhat-config-cluster-cmd
check_retval() {
	if [ $1 -ne 0 ]; then
		echo >&2 "`basename $0`: Failed to run ${CONFIG_CMD}!"
		return 1
	fi

	return 0
}

# add_services
#
# Add service tags into the cluster.xml file
add_services() {
	declare -i idx
	declare -i i

	# Add service tag
	for ((i = 0; i < ${#TARGET_SRVNAMES[@]}; i++)); do
		${CONFIG_CMD} --add_service --name=${TARGET_SRVNAMES[i]}
		if ! check_retval $?; then
			return 1
		fi

		${CONFIG_CMD} --service=${TARGET_SRVNAMES[i]} \
			      --userscript=${INIT_DIR}/${TARGET_SRVNAMES[i]}
		if ! check_retval $?; then
			return 1
		fi

		for ((idx = 0; idx < ${#SRV_IPADDRS[@]}; idx++)); do
			${CONFIG_CMD} --service=${TARGET_SRVNAMES[i]} \
			--add_service_ipaddress --ipaddress=${SRV_IPADDRS[idx]}
			if ! check_retval $?; then
				return 1
			fi
		done

		${CONFIG_CMD} --service=${TARGET_SRVNAMES[i]} \
			      --device=${TARGET_DEVNAMES[i]} \
			      --mount \
			      --mountpoint=${TARGET_MNTPNTS[i]} \
			      --fstype=lustre
		if ! check_retval $?; then
			return 1
		fi
	done

	return 0
}

# gen_cluster_xml
#
# Run redhat-config-cluster-cmd to create the cluster.xml file
gen_cluster_xml() {
	declare -i idx
	declare -i i
	local mcast_IPaddr
	local node_names
	local hbopt_str hbopt

	[ -e "${CLUMAN_DIR}/cluster.xml" ] && \
	/bin/mv ${CLUMAN_DIR}/cluster.xml ${CLUMAN_DIR}/cluster.xml.old

	# Run redhat-config-cluster-cmd to generate cluster.xml
	# Add clumembd tag
   	if [ "${HBCHANNEL_OPT}" != "${HBCHANNEL_OPT#*broadcast*}" ]; then
		${CONFIG_CMD} --clumembd --broadcast=yes
		${CONFIG_CMD} --clumembd --multicast=no
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
	node_names=
	for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
		node_names=${node_names}"${NODE_NAMES[idx]} "
	done

	${CONFIG_CMD} --cluster --name="${node_names}failover group"
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

	# Add service tag
	if ! add_services; then
		return 1
	fi

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
	CONFIG_PRIMNODE=${TMP_DIR}$"/cluster.xml."${PRIM_NODENAME}
	declare -i idx

	# Create symlinks for Lustre services
	verbose_output "Creating symlinks for lustre target services in"\
	       	"${PRIM_NODENAME} failover group hosts..." 
	if ! create_service; then
		return 1
	fi
	verbose_output "OK"

	if [ -s ${CONFIG_PRIMNODE} ]; then
		if [ -n "`/bin/grep ${TARGET_SRVNAMES[0]} ${CONFIG_PRIMNODE}`" ]
		then
			verbose_output "${CONFIG_PRIMNODE} already exists."
			return 0
		else
			/bin/cp -f ${CONFIG_PRIMNODE} ${CLUMAN_DIR}/cluster.xml 

			# Add services into the cluster.xml file
			if ! add_services; then
				return 1
			fi
		fi
	else
		# Run redhat-config-cluster-cmd to generate cluster.xml
		verbose_output "Creating cluster.xml file for" \
			       "${PRIM_NODENAME} failover group hosts..."
		if ! gen_cluster_xml; then
			return 1
		fi
		verbose_output "OK"
	fi

	/bin/cp -f ${CLUMAN_DIR}/cluster.xml ${CONFIG_PRIMNODE}

	# scp the cluster.xml file to all the nodes
	verbose_output "Remote copying cluster.xml file to" \
		       "${PRIM_NODENAME} failover group hosts..."
	for ((idx = 0; idx < ${#NODE_NAMES[@]}; idx++)); do
		if [ "${PRIM_NODENAME}" != "${NODE_NAMES[idx]}" ]; then
			/bin/cp -f ${CONFIG_PRIMNODE} \
			${TMP_DIR}$"/cluster.xml."${NODE_NAMES[idx]}
		fi

		scp ${CONFIG_PRIMNODE} ${NODE_NAMES[idx]}:${CLUMAN_DIR}/cluster.xml
		if [ $? -ne 0 ]; then
			echo >&2 "`basename $0`: Failed to scp cluster.xml file"\
				 "to node ${NODE_NAMES[idx]}!"
			return 1
		fi
	done
	verbose_output "OK"

	return 0
}

# Main flow
# Get all the node names
if ! get_nodenames; then
	exit 1
fi

# Get and check all the service IP addresses
if ! get_check_srvIPaddrs; then
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
