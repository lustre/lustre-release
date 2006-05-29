#!/bin/bash
#
# gen_cluster_config.sh - generate a csv file from a running lustre cluster
#
# This script is used to collect lustre target informations and HA software
# configurations in a lustre cluster to generate a csv file. In reverse, the
# csv file could be parsed by cluster_config.sh to configure multiple lustre
# servers in parallel.
#
# This script should be run on the MGS node.
#
################################################################################

# Usage
usage() {
	cat >&2 <<EOF

Usage:	`basename $0` [-t HAtype] [-h] [-v] [-f csv_filename]

	This script is used to collect lustre target informations and HA software
	configurations from a running lustre cluster to generate a csv file. It 
	should be run on the MGS node.

	-t HAtype	collect High-Availability software configurations
			The argument following -t is used to indicate the High-
			Availability software type. The HA software types which 
			are currently supported are: hbv1 (Heartbeat v1), hbv2 
			(Heartbeat v2) and cluman (CluManager).
	-h		help
	-v		verbose mode
	-f csv_filename	designate a name for the csv file
			Default is cluster_config.csv.

EOF
	exit 1
}

#**************************** Global variables ****************************#
# csv file
CSV_FILE=${CSV_FILE:-"cluster_config.csv"}

# Remote command
REMOTE=${REMOTE:-"ssh -x -q"}
#REMOTE=${REMOTE:-"pdsh -R ssh -w"}

# Command path
CMD_PATH=${CMD_PATH:-"/usr/sbin"}
TUNEFS=${TUNEFS:-"$CMD_PATH/tunefs.lustre"}

# Lustre proc files
LUSTRE_PROC=${LUSTRE_PROC:-"/proc/fs/lustre"}
LUSTRE_PROC_DEVICES=${LUSTRE_PROC}/devices

LNET_PROC=${LNET_PROC:-"/proc/sys/lnet"}
LNET_PROC_PEERS=${LNET_PROC}/peers

# Default network module options
DEFAULT_MOD_OPTS=${DEFAULT_MOD_OPTS:-"options lnet networks=tcp"}
START_MARKER=${START_MARKER:-"# start lustre config"}
END_MARKER=${END_MARKER:-"# end lustre config"}

# Variables of HA software
HATYPE_HBV1="hbv1"			# Heartbeat version 1
HATYPE_HBV2="hbv2"			# Heartbeat version 2
HATYPE_CLUMGR="cluman"			# Cluster Manager

HA_DIR=${HA_DIR:-"/etc/ha.d"}		# Heartbeat configuration directory
CIB_DIR=${CIB_DIR:-"/var/lib/heartbeat/crm"}   # cib.xml directory
HA_CF=${HA_DIR}/ha.cf			# ha.cf file
HA_RES=${HA_DIR}/haresources		# haresources file
HA_CIB=${CIB_DIR}/cib.xml

CLUMAN_DIR=${CLUMAN_DIR:-"/etc"}	# CluManager configuration directory
CLUMAN_CONFIG=${CLUMAN_DIR}/cluster.xml

# Lustre target obd device types
MGS_TYPE=${MGS_TYPE:-"mgs"}
MDT_TYPE=${MDT_TYPE:-"mds"}
OST_TYPE=${OST_TYPE:-"obdfilter"}

# The obd name of MGS target server
MGS_SVNAME=${MGS_SVNAME:-"MGS"}		

# Hostnames of the lustre cluster nodes
declare -a HOST_NAMES			
MGS_HOSTNAME=${MGS_HOSTNAME:-"`hostname`"} # Hostname of the MGS node

# Configs of lustre targets in one cluster node
declare -a TARGET_CONFIGS		
declare -a TARGET_SVNAMES TARGET_DEVNAMES TARGET_DEVSIZES TARGET_MNTPNTS
declare -a TARGET_DEVTYPES TARGET_FSNAMES TARGET_MGSNIDS TARGET_INDEXES
declare -a TARGET_FMTOPTS TARGET_MKFSOPTS TARGET_MNTOPTS TARGET_FAILNIDS
declare -a HA_CONFIGS

# Lustre target service types
let "LDD_F_SV_TYPE_MDT = 0x0001"
let "LDD_F_SV_TYPE_OST = 0x0002"
let "LDD_F_SV_TYPE_MGS = 0x0004"

# Permanent mount options for ext3 or ldiskfs
ALWAYS_MNTOPTS=${ALWAYS_MNTOPTS:-"errors=remount-ro"}
MDT_MGS_ALWAYS_MNTOPTS=${MDT_MGS_ALWAYS_MNTOPTS:-",iopen_nopriv,user_xattr"}
OST_ALWAYS_MNTOPTS=${OST_ALWAYS_MNTOPTS:-",asyncdel"}

# User-settable parameter keys
PARAM_MGSNODE=${PARAM_MGSNODE:-"mgsnode="}
PARAM_FAILNODE=${PARAM_FAILNODE:-"failnode="}

# Block size
L_BLOCK_SIZE=4096


# Get and check the positional parameters
VERBOSE_OUTPUT=false
while getopts "t:hvf:" OPTION; do
	case $OPTION in
	t) 
		HATYPE_OPT=$OPTARG
		if [ "${HATYPE_OPT}" != "${HATYPE_HBV1}" ] \
		&& [ "${HATYPE_OPT}" != "${HATYPE_HBV2}" ] \
		&& [ "${HATYPE_OPT}" != "${HATYPE_CLUMGR}" ]; then
			echo >&2 "`basename $0`: Invalid HA software type" \
				 "- ${HATYPE_OPT}!"
			usage
		fi
		;;
	h)	usage;;
	v) 	VERBOSE_OUTPUT=true;;
	f)	CSV_FILE=$OPTARG;;
        ?) 	usage 
	esac
done

# Output verbose informations
verbose_output() {
	if ${VERBOSE_OUTPUT}; then
		echo "`basename $0`: $*"
	fi
	return 0
}

# Verify the local host is the MGS node
mgs_node() {
	if [ ! -e ${LUSTRE_PROC_DEVICES} ]; then
		echo >&2 "`basename $0`: error: ${LUSTRE_PROC_DEVICES} does" \
			 "not exist. Lustre kernel modules may not be loaded!"
		return 1
	fi

	if [ -z "`cat ${LUSTRE_PROC_DEVICES}`" ]; then
		echo >&2 "`basename $0`: error: ${LUSTRE_PROC_DEVICES} is" \
			 "empty. Lustre services may not be started!"
		return 1
	fi

	if [ -z "`grep ${MGS_TYPE} ${LUSTRE_PROC_DEVICES}`" ]; then
		echo >&2 "`basename $0`: error: This node is not a MGS node." \
                         "The script should be run on the MGS node!"
		return 1
	fi

	return 0
}

# Check whether the reomte command is pdsh
is_pdsh() {
	if [ "${REMOTE}" = "${REMOTE#pdsh}" ]; then
		return 1
	fi

	return 0
}

# remote_error fn_name host_addr ret_str
# Verify the return result from remote command
remote_error() {
	local fn_name host_addr ret_str

	fn_name=$1
	shift
	host_addr=$1
	shift
	ret_str=$*

	if [ "${ret_str}" != "${ret_str#*connect:*}" ]; then
		echo "`basename $0`: ${fn_name}() error: remote error:" \
		     "${ret_str}"
		return 0
	fi

	if [ -z "${ret_str}" ]; then
		echo "`basename $0`: ${fn_name}() error: remote error:" \
		     "No results from remote!" \
		     "Check network connectivity between the local host"\
		     "and ${host_addr}!"
		return 0
	fi

	return 1
}

# nid2hostname nid
# Convert @nid to hostname of the lustre cluster node
nid2hostname() {
	local nid=$1
	local host_name=
	local addr nettype ip_addr
	local ret_str

	addr=${nid%@*}
	nettype=${nid#*@}
	if [ -z "${addr}" ]; then
		echo "`basename $0`: nid2hostname() error:" \
		     "Invalid nid - \"${nid}\"!"
		return 1
	fi
		
	case "${nettype}" in
	lo*)	host_name=`hostname`;;
	elan*)	# QsNet
	  # FIXME: Parse the /etc/elanhosts configuration file to
	  # convert ElanID to hostname
	  ;;
	gm*)	# Myrinet
	  # FIXME: Use /usr/sbin/gmlndnid to find the hostname of
	  # the specified GM Global node ID 
	  ;;
	ptl*)	# Portals
	  # FIXME: Convert portal ID to hostname
	  ;;
	*)	# tcp, o2ib, cib, openib, iib, vib, ra
	  ip_addr=${addr}

	  # Execute remote command to get the host name
	  ret_str=`${REMOTE} ${ip_addr} "hostname" 2>&1`
	  if [ $? -ne 0 -a -n "${ret_str}" ]; then
		echo "`basename $0`: nid2hostname() error:" \
		     "remote command error: ${ret_str}"
		return 1
	  fi
	  remote_error "nid2hostname" ${ip_addr} "${ret_str}" && return 1

	  if is_pdsh; then
	  	host_name=`echo ${ret_str} | awk '{print $2}'`
	  else
	  	host_name=`echo ${ret_str} | awk '{print $1}'`
	  fi
	  ;;
	esac

	echo ${host_name}
	return 0
}

# get_hostnames
# Get lustre cluster node names
get_hostnames() {
	declare -a HOST_NIDS
	declare -i idx		# Index of HOST_NIDS array
	declare -i i		# Index of HOST_NAMES array

	if ! mgs_node; then
		return 1
	fi

	if [ ! -e ${LNET_PROC_PEERS} ]; then
		echo >&2 "`basename $0`: error: ${LNET_PROC_PEERS} does not" \
                         "exist. LNET kernel modules may not be loaded" \
			 "or LNET network may not be up!"
		return 1
	fi

	HOST_NAMES[0]=${MGS_HOSTNAME} # MGS node
	HOST_NIDS[0]=${HOST_NAMES[0]}

	# Get the nids of the nodes which have contacted MGS
	idx=1
	for nid in `cat ${LNET_PROC_PEERS} | awk '{print $1}'`; do
		if [ "${nid}" = "nid" ]; then
			continue
		fi

		HOST_NIDS[idx]=${nid}
		let "idx += 1"
	done

	if [ ${idx} -eq 1 ]; then
		verbose_output "Only one node running in the lustre cluster." \
			       "It's ${HOST_NAMES[0]}."
		return 0		
	fi

	# Get the hostnames of the nodes
	for ((idx = 1, i = 1; idx < ${#HOST_NIDS[@]}; idx++, i++)); do
		if [ -z "${HOST_NIDS[idx]}" ]; then
			echo >&2 "`basename $0`: get_hostnames() error:" \
				 "Invalid nid - \"${HOST_NIDS[idx]}\"!"
			return 1
		fi

		HOST_NAMES[i]=$(nid2hostname ${HOST_NIDS[idx]})
		if [ $? -ne 0 ]; then
			echo >&2 "${HOST_NAMES[i]}"
			return 1
		fi

		if [ "${HOST_NAMES[i]}" = "${HOST_NAMES[0]}" ]; then
			let "i -= 1"
		fi
	done

	return 0
}

#*************************** Network module options ***************************#

# get_module_opts hostname
# Get the network module options from the node @hostname 
get_module_opts() {
	local host_name=$1
	local ret_str
	local MODULE_CONF KERNEL_VER
	local ret_line line find_options

	MODULE_OPTS=${DEFAULT_MOD_OPTS}

	# Execute remote command to get the kernel version
	ret_str=`${REMOTE} ${host_name} "uname -r" 2>&1`
	if [ $? -ne 0 -a -n "${ret_str}" ]; then
		echo >&2 "`basename $0`: get_module_opts() error:" \
			 "remote command error: ${ret_str}"
		return 1
	fi
	remote_error "get_module_opts" ${host_name} "${ret_str}" && return 1

	if is_pdsh; then
		KERNEL_VER=`echo ${ret_str} | awk '{print $2}'`
	else
		KERNEL_VER=`echo ${ret_str} | awk '{print $1}'`
	fi

	# Get the module configuration file name
	if [ "${KERNEL_VER:0:3}" = "2.4" ]; then
        	MODULE_CONF=/etc/modules.conf
	else
        	MODULE_CONF=/etc/modprobe.conf
	fi

	# Execute remote command to get the lustre network module options
	find_options=false
	while read -r ret_line; do
		if is_pdsh; then
                	set -- ${ret_line}
			shift
			line="$*"
		else
			line="${ret_line}"
		fi

		if [ "${line}" = "${START_MARKER}" ]; then
			find_options=true
			MODULE_OPTS=
			continue
		fi	

		if ${find_options}; then
			if [ "${line}" = "${END_MARKER}" ]; then
				break
			fi 

			if [ -z "${MODULE_OPTS}" ]; then
				MODULE_OPTS=${line}
			else
				MODULE_OPTS=${MODULE_OPTS}$" \n "${line}
			fi
		fi
        done < <(${REMOTE} ${host_name} "cat ${MODULE_CONF}")

	if [ -z "${MODULE_OPTS}" ]; then
		MODULE_OPTS=${DEFAULT_MOD_OPTS}
	fi

	return 0
}

#************************ HA software configurations ************************#
# is_ha_target hostname target_svname
# Check whether the target service @target_svname was made to be high-available
is_ha_target() {
	local host_name=$1
	local target_svname=$2
	local res_file
	local ret_str

	case "${HATYPE_OPT}" in
	"${HATYPE_HBV1}")	res_file=${HA_RES};;
	"${HATYPE_HBV2}")	res_file=${HA_CIB};;
	"${HATYPE_CLUMGR}")	res_file=${CLUMAN_CONFIG};;
	esac

	# Execute remote command to check the resource file
	ret_str=`${REMOTE} ${host_name} \
		"grep ${target_svname} ${res_file}" 2>&1`
	if [ $? -ne 0 -a -n "${ret_str}" ]; then
		echo >&2 "`basename $0`: is_ha_target() error:" \
			 "remote command error: ${ret_str}"
		return 1
	fi

	[ "${ret_str}" = "${ret_str#*${target_svname}*}" ] && return 1

	return 0
}

# get_hb_configs hostname
# Get the Heartbeat configurations from the node @hostname
get_hb_configs() {
	local host_name=$1
	local ret_line line
	declare -i i

	unset HA_CONFIGS
	HB_CHANNELS=
	SRV_IPADDRS=
	HB_OPTIONS=

	# Execute remote command to get the configs of Heartbeat channels, etc
	while read -r ret_line; do
		if is_pdsh; then
                	set -- ${ret_line}
			shift
			line="$*"
		else
			line="${ret_line}"
		fi

                # Get rid of the comment line
                [ -z "`echo \"${line}\"|egrep -v \"^#\"`" ] && continue

		if [ "${line}" != "${line#*serial*}" ] \
		|| [ "${line}" != "${line#*cast*}" ]; then
			if [ -z "${HB_CHANNELS}" ]; then
				HB_CHANNELS=${line}
			else
				HB_CHANNELS=${HB_CHANNELS}:${line}
			fi
		fi

		if [ "${line}" != "${line#*stonith*}" ] \
		|| [ "${line}" != "${line#*ping*}" ] \
		|| [ "${line}" != "${line#*respawn*}" ] \
		|| [ "${line}" != "${line#*apiauth*}" ] \
		|| [ "${line}" != "${line#*compression*}" ]; then
			if [ -z "${HB_OPTIONS}" ]; then
				HB_OPTIONS=${line}
			else
				HB_OPTIONS=${HB_OPTIONS}:${line}
			fi
		fi
        done < <(${REMOTE} ${host_name} "cat ${HA_CF}")

	if [ -z "${HB_CHANNELS}" ]; then
		echo >&2 "`basename $0`: get_hb_configs() error:" \
			 "There are no heartbeat channel configs in ${HA_CF}" \
			 "of host ${host_name} or ${HA_CF} does not exist!"
		return 0
	fi

	# Execute remote command to get Heartbeat service address
	if [ "${HATYPE_OPT}" = "${HATYPE_HBV1}" ]; then
		while read -r ret_line; do
			if is_pdsh; then
                		set -- ${ret_line}
				shift
				line="$*"
			else
				line="${ret_line}"
			fi

			# Get rid of the empty line
                	[ -z "`echo ${line}|awk '/[[:alnum:]]/ {print $0}'`" ]\
                        && continue

                	# Get rid of the comment line
                	[ -z "`echo \"${line}\"|egrep -v \"^#\"`" ] && continue

			SRV_IPADDRS=`echo ${line} | awk '{print $2}'`
			[ -n "${SRV_IPADDRS}" ] && break
        	done < <(${REMOTE} ${host_name} "cat ${HA_RES}")
	
		if [ -z "${SRV_IPADDRS}" ]; then
			echo >&2 "`basename $0`: get_hb_configs() error: There"\
			 	 "are no service address in ${HA_RES} of host"\
			 	 "${host_name} or ${HA_RES} does not exist!"
			return 0
		fi
	fi

	# Construct HA configuration items 
	for ((i = 0; i < ${#TARGET_DEVNAMES[@]}; i++)); do
		[ -z "${TARGET_DEVNAMES[i]}" ] && continue

		# Execute remote command to check whether this target service 
		# was made to be high-available
		if is_ha_target ${host_name} ${TARGET_SVNAMES[i]}; then
			HA_CONFIGS[i]=${HB_CHANNELS},${SRV_IPADDRS},${HB_OPTIONS}
		fi
	done

	return 0
}

# get_cluman_configs hostname
# Get the CluManager configurations from the node @hostname
get_cluman_configs() {
	local host_name=$1
	unset HA_CONFIGS

	# FIXME: Get CluManager configurations
	return 0
}

# get_ha_configs hostname
# Get the HA software configurations from the node @hostname
get_ha_configs() {
	local host_name=$1

	unset HA_CONFIGS

	if [ -z "${HATYPE_OPT}" ]; then
		return 0
	fi

	verbose_output "Collecting HA software configurations from host $1..."

	case "${HATYPE_OPT}" in
	"${HATYPE_HBV1}" | "${HATYPE_HBV2}") # Heartbeat
		if ! get_hb_configs ${host_name}; then
			return 1
		fi
		;;
	"${HATYPE_CLUMGR}") # CluManager
		if ! get_cluman_configs ${host_name}; then
			return 1
		fi
		;;
	esac

	verbose_output "OK"
	return 0
}

#*********************** Lustre targets configurations ***********************#

# get_svnames hostname
# Get the lustre target server obd names from the node @hostname
get_svnames(){
	declare -i i
	local host_name=$1
	local ret_line line

        # Initialize the TARGET_SVNAMES array
	unset TARGET_SVNAMES
	
	# Execute remote command to the node @hostname and figure out what
	# lustre services are running.
	i=0
	while read -r ret_line; do
		if is_pdsh; then
                	set -- ${ret_line}
			shift
			line="$*"
		else
			line="${ret_line}"
		fi

		if [ -z "`echo ${line} | grep ${MGS_TYPE}`" ] \
		&& [ -z "`echo ${line} | grep ${MDT_TYPE}`" ] \
		&& [ -z "`echo ${line} | grep ${OST_TYPE}`" ]; then
			continue
		fi

		# Get target server name
		TARGET_SVNAMES[i]=`echo ${line} | awk '{print $4}'`
		if [ -n "${TARGET_SVNAMES[i]}" ]; then
			let "i += 1"
		else
			echo >&2 "`basename $0`: get_svnames() error: Invalid"\
			      "line in ${host_name}'s ${LUSTRE_PROC_DEVICES}"\
			      "- \"${line}\"!"
			return 1
		fi
        done < <(${REMOTE} ${host_name} "cat ${LUSTRE_PROC_DEVICES}")

	if [ $i -eq 0 ]; then
		verbose_output "There are no lustre services running" \
			       "on the node ${host_name}!"
	fi

	return 0
} 

# is_loopdev devname
# Check whether a device @devname is a loop device or not
is_loopdev() {
	local devname=$1

	if [ -z "${devname}" ] || \
	[ -z "`echo ${devname}|awk '/\/dev\/loop[[:digit:]]/ {print $0}'`" ]
	then
		return 1
	fi

	return 0
}

# get_devname hostname svname
# Get the device name of lustre target @svname from node @hostname
get_devname() {
	local host_name=$1
	local target_svname=$2
	local target_devname=
	local ret_str
	local target_type target_obdtype mntdev_file

	if [ "${target_svname}" = "${MGS_SVNAME}" ]; then
		# Execute remote command to get the device name of mgs target
		ret_str=`${REMOTE} ${host_name} \
			"/sbin/findfs LABEL=${target_svname}" 2>&1`
		if [ $? -ne 0 -a -n "${ret_str}" ]; then
			if [ "${ret_str}" = "${ret_str#*Unable to resolve*}" ]
			then
				echo "`basename $0`: get_devname() error:" \
			     	     "remote command error: ${ret_str}"
				return 1
			fi
		fi

		if [ "${ret_str}" = "${ret_str#*Unable to resolve*}" ]; then
			if is_pdsh; then
				target_devname=`echo ${ret_str} | awk '{print $2}'`
			else
				target_devname=`echo ${ret_str} | awk '{print $1}'`
			fi
		fi
	else	# Execute remote command to get the device name of mdt/ost target
		target_type=`echo ${target_svname} | cut -d - -f 2`
		target_obdtype=${target_type:0:3}_TYPE
		
		mntdev_file=${LUSTRE_PROC}/${!target_obdtype}/${target_svname}/mntdev

		ret_str=`${REMOTE} ${host_name} "cat ${mntdev_file}" 2>&1`
		if [ $? -ne 0 -a -n "${ret_str}" ]; then
			echo "`basename $0`: get_devname() error:" \
			     "remote command error: ${ret_str}"
			return 1
		fi

		if [ "${ret_str}" != "${ret_str#*No such file*}" ]; then
			echo "`basename $0`: get_devname() error:"\
			     "${mntdev_file} does not exist in ${host_name}!"
			return 1
		else
			if is_pdsh; then
				target_devname=`echo ${ret_str} | awk '{print $2}'`
			else
				target_devname=`echo ${ret_str} | awk '{print $1}'`
			fi
		fi
	fi

	echo ${target_devname}
	return 0
}

# get_devsize hostname target_devname 
# Get the device size (KB) of @target_devname from node @hostname
get_devsize() {
	local host_name=$1
	local target_devname=$2
	local target_devsize=
	local ret_str

	# Execute remote command to get the device size
	ret_str=`${REMOTE} ${host_name} \
		"/sbin/blockdev --getsize ${target_devname}" 2>&1`
	if [ $? -ne 0 -a -n "${ret_str}" ]; then
		echo "`basename $0`: get_devsize() error:" \
		     "remote command error: ${ret_str}"
		return 1
	fi

	if is_pdsh; then
		target_devsize=`echo ${ret_str} | awk '{print $2}'`
	else
		target_devsize=`echo ${ret_str} | awk '{print $1}'`
	fi
	
	if [ -z "`echo ${target_devsize}|awk '/^[[:digit:]]/ {print $0}'`" ]
	then
		echo "`basename $0`: get_devsize() error: can't" \
		"get device size of ${target_devname} in ${host_name}!"
		return 1
	fi

	let " target_devsize /= 2"

	echo ${target_devsize}
	return 0
}

# get_realdevname hostname loop_dev
# Get the real device name of loop device @loop_dev from node @hostname
get_realdevname() {
	local host_name=$1
	local loop_dev=$2
	local target_devname=
	local ret_str

	# Execute remote command to get the real device name
	ret_str=`${REMOTE} ${host_name} \
		"/sbin/losetup ${loop_dev}" 2>&1`
	if [ $? -ne 0 -a -n "${ret_str}" ]; then
		echo "`basename $0`: get_realdevname() error:" \
		     "remote command error: ${ret_str}"
		return 1
	fi

	if is_pdsh; then
		target_devname=`echo ${ret_str} | awk '{print $4}' \
				| sed 's/^(//' | sed 's/)$//'`
	else
		target_devname=`echo ${ret_str} | awk '{print $3}' \
				| sed 's/^(//' | sed 's/)$//'`
	fi

	if [ "${ret_str}" != "${ret_str#*No such*}" ] \
	|| [ -z "${target_devname}" ]; then
		echo "`basename $0`: get_realdevname() error: can't" \
		"get info on device ${loop_dev} in ${host_name}!"
		return 1
	fi

	echo ${target_devname}
	return 0
}

# get_mntpnt hostname target_devname
# Get the lustre target mount point from the node @hostname
get_mntpnt(){
	local host_name=$1
	local target_devname=$2
	local mnt_point=
	local ret_str

	# Execute remote command to get the mount point
	ret_str=`${REMOTE} ${host_name} \
		"cat /etc/mtab | grep ${target_devname}" 2>&1`
	if [ $? -ne 0 -a -n "${ret_str}" ]; then
		echo "`basename $0`: get_mntpnt() error:" \
		     "remote command error: ${ret_str}"
		return 1
	fi

	if is_pdsh; then
		mnt_point=`echo ${ret_str} | awk '{print $3}'`
	else
		mnt_point=`echo ${ret_str} | awk '{print $2}'`
	fi
	
	if [ -z "${mnt_point}" ]; then
		echo "`basename $0`: get_mntpnt() error: can't" \
		"get the mount point of ${target_devname} in ${host_name}!"
		return 1
	fi

	echo ${mnt_point}
	return 0
}

# get_devnames hostname
# Get the lustre target device names, mount points
# and loop device sizes from the node @hostname
get_devnames(){
	declare -i i
	local host_name=$1
	local ret_line line

        # Initialize the arrays
	unset TARGET_DEVNAMES
	unset TARGET_DEVSIZES
	unset TARGET_MNTPNTS

	for ((i = 0; i < ${#TARGET_SVNAMES[@]}; i++)); do
		TARGET_DEVNAMES[i]=$(get_devname ${host_name} \
				     ${TARGET_SVNAMES[i]})
		if [ $? -ne 0 ]; then
			echo >&2 "${TARGET_DEVNAMES[i]}"
			return 1
		fi

		if [ -z "${TARGET_DEVNAMES[i]}" ]; then
			if [ "${TARGET_SVNAMES[i]}" = "${MGS_SVNAME}" ]; then
				verbose_output "There exists combo mgs/mdt"\
					       "target in ${host_name}."
				continue
			else
				echo >&2 "`basename $0`: get_devname() error:"\
			      		 "No device corresponding to target" \
					 "${TARGET_SVNAMES[i]} in ${host_name}!"
				return 1
			fi
		fi

		# Get the mount point of the target
		TARGET_MNTPNTS[i]=$(get_mntpnt ${host_name} \
				     ${TARGET_DEVNAMES[i]})
		if [ $? -ne 0 ]; then
			echo >&2 "${TARGET_MNTPNTS[i]}"
			return 1
		fi

		# The target device is a loop device?
		if [ -n "${TARGET_DEVNAMES[i]}" ] \
		&& is_loopdev ${TARGET_DEVNAMES[i]}; then 
			# Get the device size
			TARGET_DEVSIZES[i]=$(get_devsize ${host_name} \
					     ${TARGET_DEVNAMES[i]})
			if [ $? -ne 0 ]; then
				echo >&2 "${TARGET_DEVSIZES[i]}"
				return 1
			fi

			# Get the real device name
			TARGET_DEVNAMES[i]=$(get_realdevname ${host_name} \
					     ${TARGET_DEVNAMES[i]})
			if [ $? -ne 0 ]; then
				echo >&2 "${TARGET_DEVNAMES[i]}"
				return 1
			fi
		fi
        done

	return 0
}

# is_target target_svtype ldd_flags
# Check the service type of a lustre target
is_target() {
	case "$1" in
	"mdt") let "ret = $2 & LDD_F_SV_TYPE_MDT";;
	"ost") let "ret = $2 & LDD_F_SV_TYPE_OST";;
	"mgs") let "ret = $2 & LDD_F_SV_TYPE_MGS";;
	"*") 
		echo >&2 "`basename $0`: is_target() error: Invalid" \
		"target service type - \"$1\"!"
		return 1
		;;
	esac

	if [ ${ret} -eq 0 ]; then
		return 1
	fi

	return 0
}

# get_devtype ldd_flags
# Get the service type of a lustre target from @ldd_flags
get_devtype() {
	local target_devtype=

	if [ -z "${flags}" ]; then
		echo "`basename $0`: get_devtype() error: Invalid" \
			"ldd_flags - it's value is null!"
		return 1
	fi

	if is_target "mgs" $1; then
		if is_target "mdt" $1; then
			target_devtype="mgs|mdt"
		else
			target_devtype="mgs"
		fi
	elif is_target "mdt" $1; then
		target_devtype="mdt"
	elif is_target "ost" $1; then
		target_devtype="ost"
	else
		echo "`basename $0`: get_devtype() error: Invalid" \
		"ldd_flags - \"$1\"!"
		return 1
	fi

	echo ${target_devtype}
	return 0
}

# get_mntopts ldd_mount_opts
# Get the user-specified lustre target mount options from @ldd_mount_opts
get_mntopts() {
	local mount_opts=
	local ldd_mount_opts=$1

	mount_opts="${ldd_mount_opts#${ALWAYS_MNTOPTS}}"
	mount_opts="${mount_opts#${MDT_MGS_ALWAYS_MNTOPTS}}"
	mount_opts="${mount_opts#${OST_ALWAYS_MNTOPTS}}"
	mount_opts="`echo \"${mount_opts}\" | sed 's/^,//'`"

	[ "${mount_opts}" != "${mount_opts#*,*}" ] && echo "\""${mount_opts}"\"" \
	|| echo ${mount_opts}

	return 0
}

# get_mgsnids ldd_params
# Get the mgs nids of lustre target from @ldd_params
get_mgsnids() {
	local mgs_nids=
	local param=
	local ldd_params="$*"

	for param in ${ldd_params}; do
		if [ -n "`echo ${param}|awk '/mgsnode=/ {print $0}'`" ]; then
			if [ -n "${mgs_nids}" ]; then
				mgs_nids=${mgs_nids}:`echo ${param#${PARAM_MGSNODE}}`
			else
				mgs_nids=`echo ${param#${PARAM_MGSNODE}}`
			fi
		fi
	done

	[ "${mgs_nids}" != "${mgs_nids#*,*}" ] && echo "\""${mgs_nids}"\"" || echo ${mgs_nids}

	return 0
}

# ip2hostname nids
# Convert IP addresses in @nids into hostnames
ip2hostname() {
	local orig_nids=$1
	local nids=
	local nid nids_str
	local nettype

        nids_str=`echo ${orig_nids}|awk '{split($orig_nids, a, ",")}\
		  END {for (i in a) print a[i]}'`
        for nid in ${nids_str}; do
		nettype=${nid#*@}

		case "${nettype}" in
		lo* | elan* | gm* | ptl*) ;;
		*)
			nid=$(nid2hostname ${nid})
			if [ $? -ne 0 ]; then
				echo "${nid}"
				return 1
			fi
			
			nid=${nid}@${nettype}
	  		;;
		esac

		if [ -z "${nids}" ]; then
			nids=${nid}
		else
			nids=${nids},${nid}
		fi
        done

	echo ${nids}
	return 0
}

# get_failnids ldd_params
# Get the failover nids of lustre target from @ldd_params
get_failnids() {
	local fail_nids=	# failover nids in one failover node
	local all_fail_nids=	# failover nids in all failover nodes
				# of this target
	local param=
	local ldd_params="$*"

	for param in ${ldd_params}; do
		if [ -n "`echo ${param}|awk '/failnode=/ {print $0}'`" ]; then
			fail_nids=`echo ${param#${PARAM_FAILNODE}}`
			fail_nids=$(ip2hostname ${fail_nids})
			if [ $? -ne 0 ]; then
				echo >&2 "${fail_nids}"
				return 1
			fi

			if [ -n "${all_fail_nids}" ]; then
				all_fail_nids=${all_fail_nids}:${fail_nids}
			else
				all_fail_nids=${fail_nids}
			fi
		fi
	done

	[ "${all_fail_nids}" != "${all_fail_nids#*,*}" ] \
	&& echo "\""${all_fail_nids}"\"" || echo ${all_fail_nids}

	return 0
}

# get_fmtopts target_devname hostname ldd_params
# Get other format options of the lustre target @target_devname from @ldd_params
get_fmtopts() {
	local target_devname=$1
	local host_name=$2
	shift
	shift
	local ldd_params="$*"
	local param= 
	local fmt_opts=

	for param in ${ldd_params}; do
		[ -n "`echo ${param}|awk '/mgsnode=/ {print $0}'`" ] && continue
		[ -n "`echo ${param}|awk '/failnode=/ {print $0}'`" ] && continue

		if [ -n "${param}" ]; then
			if [ -n "${fmt_opts}" ]; then
				fmt_opts=${fmt_opts}" "${param}
			else
				fmt_opts=${param}
			fi
		fi
	done

	echo ${fmt_opts}
	return 0
}

# get_ldds hostname
# Get the lustre target disk data from the node @hostname
get_ldds(){
	declare -i i
	local host_name=$1
	local ret_line line
	local flags mnt_opts params

        # Initialize the arrays
	unset TARGET_DEVTYPES TARGET_FSNAMES TARGET_MGSNIDS TARGET_INDEXES
	unset TARGET_FMTOPTS  TARGET_MNTOPTS TARGET_FAILNIDS
	
	# Get lustre target device type, fsname, index, etc.
	# from MOUNT_DATA_FILE. Using tunefs.lustre to read it.
	for ((i = 0; i < ${#TARGET_DEVNAMES[@]}; i++)); do
		flags=
		mnt_opts=
		params=
		[ -z "${TARGET_DEVNAMES[i]}" ] && continue

		# Execute remote command to read MOUNT_DATA_FILE
		while read -r ret_line; do
			if is_pdsh; then
                		set -- ${ret_line}
				shift
				line="$*"
			else
				line="${ret_line}"
			fi

			if [ -n "`echo ${line}|awk '/Index:/ {print $0}'`" ]; then
				TARGET_INDEXES[i]=`echo ${line}|awk '{print $2}'`
				continue
			fi

			if [ -n "`echo ${line}|awk '/Lustre FS:/ {print $0}'`" ]; then
				TARGET_FSNAMES[i]=`echo ${line}|awk '{print $3}'`
				continue
			fi
			
			if [ -n "`echo ${line}|awk '/Flags:/ {print $0}'`" ]; then
				flags=`echo ${line}|awk '{print $2}'`
				continue
			fi

			if [ -n "`echo ${line}|awk '/Persistent mount opts:/ {print $0}'`" ]; then
				mnt_opts=`echo ${line}|awk '{print $0}'`
				mnt_opts=`echo ${mnt_opts#Persistent mount opts: }`
				continue
			fi

			if [ -n "`echo ${line}|awk '/Parameters:/ {print $0}'`" ]; then
				params=`echo ${line}|awk '{print $0}'`
				params=`echo ${params#Parameters:}`
				break
			fi
        	done < <(${REMOTE} ${host_name} "${TUNEFS} --print ${TARGET_DEVNAMES[i]} 2>/dev/null")

		if [ -z "${flags}" ]; then
			echo >&2 "`basename $0`: get_ldds() error: Invalid" \
				 "ldd_flags of target ${TARGET_DEVNAMES[i]}" \
				 "in host ${host_name} - it's value is null!"\
				 "Check ${TUNEFS} command!"
			return 1
		fi
		
		if [ "${TARGET_INDEXES[i]}" = "unassigned" ] \
		|| is_target "mgs" ${flags}; then
			TARGET_INDEXES[i]=
		fi

		[ "${TARGET_FSNAMES[i]}" = "lustre" ] && TARGET_FSNAMES[i]=

		# Get the lustre target service type
		TARGET_DEVTYPES[i]=$(get_devtype ${flags})
		if [ $? -ne 0 ]; then
			echo >&2 "${TARGET_DEVTYPES[i]} From device" \
			"${TARGET_DEVNAMES[i]} in host ${host_name}!"
			return 1
		fi

		# Get the lustre target mount options
		TARGET_MNTOPTS[i]=$(get_mntopts "${mnt_opts}")

		# Get mgs nids of the lustre target
		TARGET_MGSNIDS[i]=$(get_mgsnids "${params}")

		# Get failover nids of the lustre target
		TARGET_FAILNIDS[i]=$(get_failnids "${params}")
		if [ $? -ne 0 ]; then
			echo >&2 "${TARGET_FAILNIDS[i]} From device" \
			"${TARGET_DEVNAMES[i]} in host ${host_name}!"
			return 1
		fi

		# Get other format options of the lustre target
		TARGET_FMTOPTS[i]=$(get_fmtopts ${TARGET_DEVNAMES[i]} ${host_name} "${params}")
		if [ $? -ne 0 ]; then
			echo >&2 "${TARGET_FMTOPTS[i]}"
			return 1
		fi

		if [ -n "${TARGET_DEVSIZES[i]}" ]; then
			if [ -n "${TARGET_FMTOPTS[i]}" ]; then
				TARGET_FMTOPTS[i]="--device-size=${TARGET_DEVSIZES[i]} ""${TARGET_FMTOPTS[i]}"
			else
				TARGET_FMTOPTS[i]="--device-size=${TARGET_DEVSIZES[i]}"
			fi
		fi

		if [ "${TARGET_FMTOPTS[i]}" != "${TARGET_FMTOPTS[i]#*,*}" ]; then
			TARGET_FMTOPTS[i]="\""${TARGET_FMTOPTS[i]}"\""
		fi
        done

	return 0
}

# get_journalsize target_devname hostname
# Get the journal size of lustre target @target_devname from @hostname
get_journalsize() {
	local target_devname=$1
	local host_name=$2
	local journal_inode= 
	local journal_size=
	local ret_str

	# Execute remote command to get the journal inode number
	ret_str=`${REMOTE} ${host_name} "/sbin/debugfs -R 'stats -h' \
		 ${target_devname} | grep 'Journal inode:'" 2>&1`
	if [ $? -ne 0 -a -n "${ret_str}" ]; then
		echo "`basename $0`: get_journalsize() error:" \
		     "remote command error: ${ret_str}"
		return 1
	fi

	ret_str=${ret_str#${ret_str%Journal inode:*}}
	journal_inode=`echo ${ret_str} | awk '{print $3}'`
	if [ -z "`echo ${journal_inode}|awk '/^[[:digit:]]/ {print $0}'`" ]
	then
		echo "`basename $0`: get_journalsize() error: can't" \
		"get journal inode of ${target_devname} in ${host_name}!"
		return 1
	fi

	# Execute remote command to get the journal size
	ret_str=`${REMOTE} ${host_name} "/sbin/debugfs -R \
		'stat <${journal_inode}>' ${target_devname}|grep '^User:'" 2>&1`
	if [ $? -ne 0 -a -n "${ret_str}" ]; then
		echo "`basename $0`: get_journalsize() error:" \
		     "remote command error: ${ret_str}"
		return 1
	fi

	ret_str=${ret_str#${ret_str%User:*}}
	journal_size=`echo ${ret_str} | awk '{print $6}'`
	if [ -z "`echo ${journal_size}|awk '/^[[:digit:]]/ {print $0}'`" ]
	then
		echo "`basename $0`: get_journalsize() error: can't" \
		"get journal size of ${target_devname} in ${host_name}!"
		return 1
	fi

	let "journal_size /= 1024*1024" # MB

	echo ${journal_size}
	return 0
}

# get_defaultjournalsize target_devsize
# Calculate the default journal size from target device size @target_devsize
get_defaultjournalsize() {
	declare -i target_devsize=$1
	declare -i journal_size=0 
	declare -i max_size base_size 

	let "base_size = 1024*1024"
	if [ ${target_devsize} -gt ${base_size} ]; then  # 1GB
		let "journal_size = target_devsize / 102400"
		let "journal_size *= 4"
	fi

	let "max_size = 102400 * L_BLOCK_SIZE"
	let "max_size >>= 20" # 400MB

	if [ ${journal_size} -gt ${max_size} ]; then
		let "journal_size = max_size"
	fi

	echo ${journal_size}
	return 0
}

# get_J_opt hostname target_devname target_devsize
# Get the mkfs -J option of lustre target @target_devname 
# from the node @hostname
get_J_opt() {
	local host_name=$1
	local target_devname=$2
	local target_devsize=$3
	local journal_size=
	local default_journal_size=
	local journal_opt=

	# Get the real journal size of lustre target
	journal_size=$(get_journalsize ${target_devname} ${host_name})
	if [ $? -ne 0 ]; then
		echo "${journal_size}"
		return 1
	fi

	# Get the default journal size of lustre target
	default_journal_size=$(get_defaultjournalsize ${target_devsize})
	if [ "${default_journal_size}" = "0" ]; then
		let "default_journal_size = L_BLOCK_SIZE/1024"
	fi

	if [ "${journal_size}" != "${default_journal_size}" ]; then
		journal_opt="-J size=${journal_size}"
	fi
		
	echo ${journal_opt}
	return 0
}

# get_ratio target_devname hostname
# Get the bytes/inode ratio of lustre target @target_devname from @hostname
get_ratio() {
	local target_devname=$1
	local host_name=$2
	local inode_count= 
	local block_count=
	local ratio=
	local ret_str

	# Execute remote command to get the inode count
	ret_str=`${REMOTE} ${host_name} "/sbin/debugfs -R 'stats -h' \
		 ${target_devname} | grep 'Inode count:'" 2>&1`
	if [ $? -ne 0 -a -n "${ret_str}" ]; then
		echo "`basename $0`: get_ratio() error:" \
		     "remote command error: ${ret_str}"
		return 1
	fi

	ret_str=${ret_str#${ret_str%Inode count:*}}
	inode_count=`echo ${ret_str} | awk '{print $3}'`
	if [ -z "`echo ${inode_count}|awk '/^[[:digit:]]/ {print $0}'`" ]
	then
		echo "`basename $0`: get_ratio() error: can't" \
		"get inode count of ${target_devname} in ${host_name}!"
		return 1
	fi

	# Execute remote command to get the block count
	ret_str=`${REMOTE} ${host_name} "/sbin/debugfs -R 'stats -h' \
		 ${target_devname} | grep 'Block count:'" 2>&1`
	if [ $? -ne 0 -a -n "${ret_str}" ]; then
		echo "`basename $0`: get_ratio() error:" \
		     "remote command error: ${ret_str}"
		return 1
	fi

	ret_str=${ret_str#${ret_str%Block count:*}}
	block_count=`echo ${ret_str} | awk '{print $3}'`
	if [ -z "`echo ${block_count}|awk '/^[[:digit:]]/ {print $0}'`" ]
	then
		echo "`basename $0`: get_ratio() error: can't" \
		"get block count of ${target_devname} in ${host_name}!"
		return 1
	fi

	let "ratio = block_count*L_BLOCK_SIZE/inode_count"

	echo ${ratio}
	return 0
}

# get_default_ratio target_devtype target_devsize
# Calculate the default bytes/inode ratio from target type @target_devtype
get_default_ratio() {
	local target_devtype=$1
	declare -i target_devsize=$2
	local ratio=

	case "${target_devtype}" in
	"mdt" | "mgs|mdt" | "mdt|mgs")
		ratio=4096;;
	"ost")
		[ ${target_devsize} -gt 1000000 ] && ratio=16384;;
	esac

	[ -z "${ratio}" ] && ratio=${L_BLOCK_SIZE}

	echo ${ratio}
	return 0
}

# get_i_opt hostname target_devname target_devtype target_devsize
# Get the mkfs -i option of lustre target @target_devname 
# from the node @hostname
get_i_opt() {
	local host_name=$1
	local target_devname=$2
	local target_devtype=$3
	local target_devsize=$4
	local ratio=
	local default_ratio=
	local ratio_opt=

	# Get the real bytes/inode ratio of lustre target
	ratio=$(get_ratio ${target_devname} ${host_name})
	if [ $? -ne 0 ]; then
		echo "${ratio}"
		return 1
	fi

	# Get the default bytes/inode ratio of lustre target
	default_ratio=$(get_default_ratio ${target_devtype} ${target_devsize})

	if [ "${ratio}" != "${default_ratio}" ]; then
		ratio_opt="-i ${ratio}"
	fi
		
	echo ${ratio_opt}
	return 0
}

# get_isize target_devname hostname
# Get the inode size of lustre target @target_devname from @hostname
get_isize() {
	local target_devname=$1
	local host_name=$2
	local inode_size= 
	local ret_str

	# Execute remote command to get the inode size 
	ret_str=`${REMOTE} ${host_name} "/sbin/debugfs -R 'stats -h' \
		 ${target_devname} | grep 'Inode size:'" 2>&1`
	if [ $? -ne 0 -a -n "${ret_str}" ]; then
		echo "`basename $0`: get_isize() error:" \
		     "remote command error: ${ret_str}"
		return 1
	fi

	ret_str=${ret_str#${ret_str%Inode size:*}}
	inode_size=`echo ${ret_str} | awk '{print $3}'`
	if [ -z "`echo ${inode_size}|awk '/^[[:digit:]]/ {print $0}'`" ]
	then
		echo "`basename $0`: get_isize() error: can't" \
		"get inode size of ${target_devname} in ${host_name}!"
		return 1
	fi

	echo ${inode_size}
	return 0
}

# get_default_isize target_devtype
# Calculate the default inode size of lustre target type @target_devtype
get_default_isize() {
	local target_devtype=$1
	local inode_size=

	case "${target_devtype}" in
	"mdt" | "mgs|mdt" | "mdt|mgs")
		# FIXME: How to get the value of "--stripe-count-hint=#N" option
		inode_size=512;;
	"ost")
		inode_size=256;;
	esac

	[ -z "${inode_size}" ] && inode_size=128

	echo ${inode_size}
	return 0
}

# get_I_opt hostname target_devname target_devtype
# Get the mkfs -I option of lustre target @target_devname 
# from the node @hostname
get_I_opt() {
	local host_name=$1
	local target_devname=$2
	local target_devtype=$3
	local isize=
	local default_isize=
	local isize_opt=

	# Get the real inode size of lustre target
	isize=$(get_isize ${target_devname} ${host_name})
	if [ $? -ne 0 ]; then
		echo "${isize}"
		return 1
	fi

	# Get the default inode size of lustre target
	default_isize=$(get_default_isize ${target_devtype})

	if [ "${isize}" != "${default_isize}" ]; then
		isize_opt="-I ${isize}"
	fi
		
	echo ${isize_opt}
	return 0
}

# get_mkfsopts hostname
# Get the mkfs options of lustre targets from the node @hostname
get_mkfsopts(){
	declare -i i
	local host_name=$1
	local journal_opt
	local ratio_opt
	local inode_size_opt

        # Initialize the arrays
	unset TARGET_MKFSOPTS
	
	# FIXME: Get other mkfs options of ext3/ldiskfs besides -J, -i and -I
	for ((i = 0; i < ${#TARGET_DEVNAMES[@]}; i++)); do
		journal_opt=
		ratio_opt=
		inode_size_opt=

		[ -z "${TARGET_DEVNAMES[i]}" ] && continue

		if [ -z "${TARGET_DEVSIZES[i]}" ]; then
			# Get the device size
			TARGET_DEVSIZES[i]=$(get_devsize ${host_name} \
				         ${TARGET_DEVNAMES[i]})
			if [ $? -ne 0 ]; then
				echo >&2 "${TARGET_DEVSIZES[i]}"
				return 1
			fi
		fi

		# Get the journal option
		journal_opt=$(get_J_opt ${host_name} ${TARGET_DEVNAMES[i]} \
			      ${TARGET_DEVSIZES[i]})
		if [ $? -ne 0 ]; then
			echo >&2 "${journal_opt}"
			return 1
		fi

		if [ -n "${journal_opt}" ]; then
			if [ -z "${TARGET_MKFSOPTS[i]}" ]; then
				TARGET_MKFSOPTS[i]="${journal_opt}"
			else
				TARGET_MKFSOPTS[i]=${TARGET_MKFSOPTS[i]}" ${journal_opt}"
			fi
		fi
		
		# Get the bytes-per-inode ratio option
		ratio_opt=$(get_i_opt ${host_name} ${TARGET_DEVNAMES[i]} \
			    ${TARGET_DEVTYPES[i]} ${TARGET_DEVSIZES[i]})
		if [ $? -ne 0 ]; then
			echo >&2 "${ratio_opt}"
			return 1
		fi

		if [ -n "${ratio_opt}" ]; then
			if [ -z "${TARGET_MKFSOPTS[i]}" ]; then
				TARGET_MKFSOPTS[i]="${ratio_opt}"
			else
				TARGET_MKFSOPTS[i]=${TARGET_MKFSOPTS[i]}" ${ratio_opt}"
			fi
		fi

		# Get the inode size option
		inode_size_opt=$(get_I_opt ${host_name} ${TARGET_DEVNAMES[i]} \
				 ${TARGET_DEVTYPES[i]})
		if [ $? -ne 0 ]; then
			echo >&2 "${inode_size_opt}"
			return 1
		fi

		if [ -n "${inode_size_opt}" ]; then
			if [ -z "${TARGET_MKFSOPTS[i]}" ]; then
				TARGET_MKFSOPTS[i]="${inode_size_opt}"
			else
				TARGET_MKFSOPTS[i]=${TARGET_MKFSOPTS[i]}" ${inode_size_opt}"
			fi
		fi

		if [ "${TARGET_MKFSOPTS[i]}" != "${TARGET_MKFSOPTS[i]#*,*}" ]; then
			TARGET_MKFSOPTS[i]="\""${TARGET_MKFSOPTS[i]}"\""
		fi
	done
	return 0
}

# get_target_configs hostname
# Get the lustre target informations from the node @hostname
get_target_configs() {
	declare -i i
	local host_name=$1
	local ret_line line

        # Initialize the arrays
	unset TARGET_CONFIGS

	# Get lustre target server names
	if ! get_svnames ${host_name}; then
		return 1
	fi

	# Get lustre target device names, mount points and loop device sizes
	if ! get_devnames ${host_name}; then
		return 1
	fi

	# Get lustre target device type, fsname, index, etc.
	if ! get_ldds ${host_name}; then
		return 1
	fi

	# Get mkfs options of lustre targets
	if ! get_mkfsopts ${host_name}; then
		return 1
	fi

	# Construct lustre target configs
	for ((i = 0; i < ${#TARGET_DEVNAMES[@]}; i++)); do
		[ -z "${TARGET_DEVNAMES[i]}" ] && continue
		TARGET_CONFIGS[i]=${TARGET_DEVNAMES[i]},${TARGET_MNTPNTS[i]},${TARGET_DEVTYPES[i]},${TARGET_FSNAMES[i]},${TARGET_MGSNIDS[i]},${TARGET_INDEXES[i]},${TARGET_FMTOPTS[i]},${TARGET_MKFSOPTS[i]},${TARGET_MNTOPTS[i]},${TARGET_FAILNIDS[i]}
	done

	return 0
}

# get_configs hostname
# Get all the informations needed to generate a csv file from 
# the node @hostname
get_configs() {
	# Check the hostname
	if [ -z "$1" ]; then
		echo >&2 "`basename $0`: get_configs() error:" \
			 "Missing hostname!"
		return 1
	fi

	# Get network module options
	verbose_output ""
	verbose_output "Collecting network module options from host $1..."
	if ! get_module_opts $1; then
		return 1
	fi
	verbose_output "OK"

	# Get lustre target informations
	verbose_output "Collecting Lustre targets informations from host $1..."
	if ! get_target_configs $1; then
		return 1
	fi
	verbose_output "OK"

	# Get HA software configurations
	if ! get_ha_configs $1; then
		return 1
	fi

	return 0
}


# Generate the csv file from the lustre cluster
gen_csvfile() {
	declare -i idx
	declare -i i
	local line

	# Get lustre cluster node names
	verbose_output "Collecting Lustre cluster node names..."
	if ! get_hostnames; then
		return 1
	fi
	verbose_output "OK"

	: > ${CSV_FILE}

	for ((idx = 0; idx < ${#HOST_NAMES[@]}; idx++)); do
		# Collect informations
		if ! get_configs ${HOST_NAMES[idx]}; then
			rm -f ${CSV_FILE}
			return 1
		fi

		# Append informations to the csv file
		for ((i = 0; i < ${#TARGET_DEVNAMES[@]}; i++)); do
			[ -z "${TARGET_DEVNAMES[i]}" ] && continue

			if [ -z "${HA_CONFIGS[i]}" ]; then
				line=${HOST_NAMES[idx]},${MODULE_OPTS},${TARGET_CONFIGS[i]}
			else
				line=${HOST_NAMES[idx]},${MODULE_OPTS},${TARGET_CONFIGS[i]},${HA_CONFIGS[i]}
			fi
			verbose_output "Informations of target ${TARGET_DEVNAMES[i]}" \
				       "in host ${HOST_NAMES[idx]} are as follows:"
			verbose_output "${line}"
			echo "" >> ${CSV_FILE}
			echo "${line}" >> ${CSV_FILE}
		done
    	done

	return 0
}

# Main flow
echo "`basename $0`: ******** Generate csv file -- ${CSV_FILE} START ********"
if ! gen_csvfile; then
	exit 1
fi
echo "`basename $0`: ******** Generate csv file -- ${CSV_FILE} OK **********"

exit 0
