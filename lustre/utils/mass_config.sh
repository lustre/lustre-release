#!/bin/bash
#
# mass_config.sh - spreadsheet parsing for massive parallel config
#
# This script is used to parse each line of a spreadsheet (csv file) and 
# execute remote pdsh commands to format (mkfs.lustre) every Lustre target 
# that will be part of the Lustre cluster.
# 
# In addition, it can also verify the network connectivity and hostnames in 
# the cluster and produce High-Availability software configurations according 
# to the csv file.
#
################################################################################

# Usage
usage() {
	cat >&2 <<EOF

Usage:	`basename $0` [-t HAtype] [-n] [-f] [-h] [-v] <csv file>

	-t HAtype	produce High-Availability software configurations

			The argument following -t is used to indicate the High-
			Availability software type. The HA software types which 
			are currently supported are: hbv1 (Heartbeat v1), hbv2 
			(Heartbeat v2) and clumanager (CluManager).

	-n		don't verify network connectivity and hostnames in the 
			cluster
	-f		format the Lustre targets using --reformat option
	-h		show the format of csv file and some samples
	-v		verbose mode
			Causes `basename $0` to print debugging messages
             		about its progress.
	csv file	a spreadsheet that contains configuration parameters
                        (separated by commas) for each target in a Lustre cl-
                        uster
EOF
	exit 1
}

# Samples 
sample() {
	cat >&2 <<EOF

Each line in the csv file represents one Lustre target.
The format of it is:
hostname,networks,device name,device type,fsname/poolname,mgmtnid,index,
format options,mkfs options,mount options,failovers,heartbeat channels,
service address,heartbeat options

Sample 1 for csv file (without HA software configuration options):
-------------------------------------------------------------------------------
mgs-node,options lnet networks=tcp,/r/tmp/mgmt,mgs,,,,--device-size=10240,
-J size=4,,,,,

ost-node,options lnet 'networks="tcp,elan"' \n options ost 'numthreads=23',
/r/tmp/ost,ost,,mgs-node@tcp0,,--device-size=10240,-J size=4,"extents,mballoc",
,,,

mdt-node,options lnet networks=tcp,/r/tmp/mdt,mdt,,mgs-node1@tcp,,--device-size
=10240,-J size=4,,,,,
-------------------------------------------------------------------------------

Sample 2 for csv file (with Heartbeat version 1 configuration options):
-------------------------------------------------------------------------------
mgs-node1,options lnet networks=tcp,/r/tmp/mgmt,mgs,,,,--device-size=10240,-J
size=4,,mgs-node2@tcp0,serial /dev/ttyS0:bcast eth1,192.168.1.170,auto_failback
off:ping 192.168.1.169:respawn hacluster /usr/lib/heartbeat/ipfail

mgs-node2,options lnet networks=tcp,/r/tmp/mgmt,mgs,,,,--device-size=10240,-J
size=4,,mgs-node1@tcp0,serial /dev/ttyS1:bcast eth1,192.168.1.170,auto_failback
off:ping 192.168.1.169:respawn hacluster /usr/lib/heartbeat/ipfail

ost-node1,options lnet networks=tcp,/r/tmp/ost,ost,,"mgs-node1@tcp0,mgs-node2
@tcp0",,--device-size=10240,-J size=4,"extents,mballoc",ost-node2@tcp0,bcast
eth1,192.168.1.171,auto_failback on

ost-node2,options lnet networks=tcp,/r/tmp/ost,ost,,"mgs-node1@tcp0,mgs-node2
@tcp0",,--device-size=10240,-J size=4,"extents,mballoc",ost-node1@tcp0,bcast
eth1,192.168.1.172,auto_failback on

mdt-node1,options lnet networks=tcp,/r/tmp/mdt,mdt,,"mgs-node1@tcp0,mgs-node2
@tcp0",,--device-size=10240,-J size=4,,mdt-node2@tcp0,bcast eth1,192.168.1.173,
auto_failback off

mdt-node2,options lnet networks=tcp,/r/tmp/mdt,mdt,,"mgs-node1@tcp0,mgs-node2
@tcp0",,--device-size=10240,-J size=4,,mdt-node1@tcp0,bcast eth1,192.168.1.173,
auto_failback off
-------------------------------------------------------------------------------

Sample 3 for csv file (with Heartbeat version 2 configuration options):
-------------------------------------------------------------------------------
mgs-node1,options lnet networks=tcp,/r/tmp/mgmt,mgs|mdt,,,,--device-size=10240,
,,mgs-node2@tcp0,bcast eth1,192.168.1.170,auto_failback off

mgs-node2,options lnet networks=tcp,/r/tmp/mgmt,mgs|mdt,,,,--device-size=10240,
,,mgs-node1@tcp0,bcast eth1,192.168.1.170,auto_failback off

ost-node1,options lnet networks=tcp,/r/tmp/ost,ost,,"mgs-node1@tcp0,mgs-node2
@tcp0",,--device-size=10240,,,ost-node2@tcp0,bcast eth1,192.168.1.171,
auto_failback on:crm yes

ost-node2,options lnet networks=tcp,/r/tmp/ost,ost,,"mgs-node1@tcp0,mgs-node2
@tcp0",,--device-size=10240,,,ost-node1@tcp0,bcast eth1,192.168.1.172,
auto_failback on:crm yes
-------------------------------------------------------------------------------

Sample 4 for csv file (with Red Hat's Cluster Manager configuration options):
-------------------------------------------------------------------------------
mgs-node1,options lnet networks=tcp,/r/tmp/mgmt,mgs,,,,--device-size=10240,
,,mgs-node2@tcp0,broadcast,192.168.1.170,--clumembd --interval=1000000
--tko_count=20

mgs-node2,options lnet networks=tcp,/r/tmp/mgmt,mgs,,,,--device-size=10240,
,,mgs-node1@tcp0,broadcast,192.168.1.170,--clumembd --interval=1000000
--tko_count=20

ost-node1,options lnet networks=tcp,/r/tmp/ost,ost,,"mgs-node1@tcp0,mgs-node2
@tcp0",,--device-size=10240,,,ost-node2@tcp0,,192.168.1.171:192.168.1.172,

ost-node2,options lnet networks=tcp,/r/tmp/ost,ost,,"mgs-node1@tcp0,mgs-node2
@tcp0",,--device-size=10240,,,ost-node1@tcp0,,192.168.1.171:192.168.1.172,

mdt-node1,options lnet networks=tcp,/r/tmp/mdt,mdt,,"mgs-node1@tcp0,mgs-node2
@tcp0",,--device-size=10240,,,mdt-node2@tcp0,multicast 225.0.0.12,192.168.1.173,

mdt-node2,options lnet networks=tcp,/r/tmp/mdt,mdt,,"mgs-node1@tcp0,mgs-node2
@tcp0",,--device-size=10240,,,mdt-node1@tcp0,multicast 225.0.0.12,192.168.1.173,
-------------------------------------------------------------------------------

EOF
	exit 1
}

# Global variables
# Some scripts to be called
SCRIPTS_PATH=$"./"
ADD_LNET_OPTIONS=${SCRIPTS_PATH}$"add_lnet_options.sh"
VERIFY_CLUSTER_NET=${SCRIPTS_PATH}$"verify_cluster_net.sh"
GEN_HB_CONFIG=${SCRIPTS_PATH}$"gen_hb_config.sh"
GEN_CLUMGR_CONFIG=${SCRIPTS_PATH}$"gen_clumanager_config.sh"

HATYPE_HBV1=$"hbv1"			# Heartbeat version 1
HATYPE_HBV2=$"hbv2"			# Heartbeat version 2
HATYPE_CLUMGR=$"clumanager"		# Cluster Manager

HB_TMP_DIR=$"/tmp/heartbeat/"		# Temporary directory
CLUMGR_TMP_DIR=$"/tmp/clumanager/"
TMP_DIRS=$"${HB_TMP_DIR} ${CLUMGR_TMP_DIR}"

declare -a CONFIG_ITEM			# fields in each line of the csv file
declare -a NODE_NAMES			# node names in the failover group

# Get and check the positional parameters
while getopts "t:nfhv" OPTION; do
	case $OPTION in
	t) 
		HATYPE_OPT=$OPTARG
		if [ "${HATYPE_OPT}" != "${HATYPE_HBV1}" ] \
		&& [ "${HATYPE_OPT}" != "${HATYPE_HBV2}" ] \
		&& [ "${HATYPE_OPT}" != "${HATYPE_CLUMGR}" ]; then
			echo >&2 $"`basename $0`: Invalid HA software type" \
				  "- ${HATYPE_OPT}!"
			usage
		fi
		;;
        n) 
		VERIFY_CONNECT=$"no"
		;;
        f) 
		REFORMAT_OPTION=$"--reformat "
		;;
        h) 
		sample	
		;;
	v) 
		VERBOSE_OPT=$" -v"
		;;
        ?) 
		usage 
	esac
done

# Toss out the parameters we've already processed
shift  `expr $OPTIND - 1`

# Here we expect the csv file
if [ $# -eq 0 ]; then
	echo >&2 $"`basename $0`: Lack csv file!"
	usage
fi

# Output verbose informations
verbose_output() {
	if [ -n "${VERBOSE_OPT}" ]; then
		echo "`basename $0`: $*"
	fi
	return 0
}

# Check the csv file
check_file() {
        # Check argument
        if [ $# -eq 0 ]; then
                echo >&2 $"`basename $0`: check_file() error: Lack argument"\
			  "for function check_file()!"
                return 1
        fi

	CSV_FILE=$1
	if [ ! -s ${CSV_FILE} ]; then
                echo >&2 $"`basename $0`: check_file() error: ${CSV_FILE}"\
			  "does not exist or is empty!"
                return 1
        fi

        return 0
}

# Parse a line in the csv file
parse_line() {
        # Check argument
        if [ $# -eq 0 ]; then
                echo >&2 $"`basename $0`: parse_line() error: Lack argument"\
			  "for function parse_line()!"
                return 1
        fi

	declare -i i=0
	declare -i length=0 
	declare -i idx=0
	declare -i s_quote_flag=0 
	declare -i d_quote_flag=0
	local TMP_LETTER LINE
 
	LINE=$*

	# Initialize the CONFIG_ITEM array
	for ((i = 0; i < ${#CONFIG_ITEM[@]}; i++)); do
        	CONFIG_ITEM[i]=$""
    	done

	# Get the length of the line
        length=${#LINE}

	i=0
	while [ ${idx} -lt ${length} ]; do
		# Get a letter from the line
		TMP_LETTER=${LINE:${idx}:1}

		case "${TMP_LETTER}" in
		",")
                       	if [ ${s_quote_flag} -eq 1 ] || [ ${d_quote_flag} -eq 1 ]; then
                               	CONFIG_ITEM[i]=${CONFIG_ITEM[i]}${TMP_LETTER}
                       	else
				i=$i+1
                       	fi
               		idx=${idx}+1
			continue
			;;
		"'")
                       	if [ ${s_quote_flag} -eq 0 ]; then
                               	s_quote_flag=1
                       	else
                               	s_quote_flag=0
                       	fi
			;;
		"\"")
                       	if [ ${d_quote_flag} -eq 0 ]; then
                               	d_quote_flag=1
                       	else
                               	d_quote_flag=0
                       	fi

                       	if [ ${i} -eq 1 ]; then
                		CONFIG_ITEM[i]=${CONFIG_ITEM[i]}$"\\"${TMP_LETTER}
                		idx=${idx}+1
				continue
			fi
			;;
		"")
               		idx=${idx}+1
			continue
			;;
		*)
			;;
		esac
                CONFIG_ITEM[i]=${CONFIG_ITEM[i]}${TMP_LETTER}
                idx=${idx}+1
       	done
	return 0
}

# Check the elements required for OSTs, MDTs and MGS
#
# When formatting an OST, the following elements: hostname, networks,
# device name, device type and mgmtnid, cannot have null value.
#
# When formatting an MDT or MGS, the following elements: hostname,
# networks, device name and device type, cannot have null value.
check_element() {
        # Check hostname, networks, device name and device type
        if [ -z "${HOST_NAME}" ]||[ -z "${NETWORKS}" ]||[ -z "${DEVICE_NAME}" ]\
	   ||[ -z "${DEVICE_TYPE}" ]; then
                echo >&2 $"`basename $0`: check_element() error: Some required"\
			  "element has null value! Check hostname, networks,"\
			  "device name and device type!"
                return 1
        fi

        # Check mgmtnid
        if [ "${DEVICE_TYPE}" = "ost" ]&&[ -z "${MGMT_NID}" ]; then
                echo >&2 $"`basename $0`: check_element() error: OST's mgmtnid"\
			  "element has null value!"
                return 1
        fi

        return 0
}

# Check the elements required for HA configuration
check_ha_element() {
	if [ -z "${HATYPE_OPT}" ]; then
		return 0
	fi

	# Check service IP element
	if [ -z "${SRV_IPADDRS}" ]; then
                echo >&2 $"`basename $0`: check_ha_element() error: Service IP"\
			  "element has null value!"
                return 1
        fi

	# Check heartbeat channel element
	if [ "${HATYPE_OPT}" != "${HATYPE_CLUMGR}" -a -z "${HB_CHANNELS}" ]
	then
                echo >&2 $"`basename $0`: check_ha_element() error: Heartbeat"\
			  "channel element has null value!"
                return 1
        fi

	return 0
}

# Check the number of MGS.
# There should be no more than one MGS specified in the entire csv file.
check_mgs() {
	# Check the number of explicit MGS
	if [ "${DEVICE_TYPE#*mgs*}" != "${DEVICE_TYPE}" ]; then	
		if [ "${EXP_MGS}" = "${HOST_NAME}" ]; then
			echo >&2 $"`basename $0`: check_mgs() error: More than"\
				  "one explicit MGS in the csv file!"
			return 1
		fi

		if [ -z "${EXP_MGS}" ]; then
			EXP_MGS=${HOST_NAME}
		fi

		if [ "${EXP_MGS}" != "${HOST_NAME}" ] \
		&& [ "${FAILOVERS#*$EXP_MGS*}" = "${FAILOVERS}" ]; then
			echo >&2 $"`basename $0`: check_mgs() error: More than"\
				  "one explicit MGS in the csv file!"
			return 1
		fi
	fi

	# Check the number of implicit MGS
        if [ "${DEVICE_TYPE}" = "mdt" ]&&[ -z "${MGMT_NID}" ]; then
		if [ "${IMP_MGS}" = "${HOST_NAME}" ]; then
			echo >&2 $"`basename $0`: check_mgs() error: More than"\
				  "one implicit MGS in the csv file!"
			return 1
		fi

		if [ -z "${IMP_MGS}" ]; then
			IMP_MGS=${HOST_NAME}
		fi

		if [ "${IMP_MGS}" != "${HOST_NAME}" ] \
		&& [ "${FAILOVERS#*$IMP_MGS*}" = "${FAILOVERS}" ]; then
			echo >&2 $"`basename $0`: check_mgs() error: More than"\
				  "one implicit MGS in the csv file!"
			return 1
		fi
	fi

	if [ -n "${EXP_MGS}" -a -n "${IMP_MGS}" ]; then
		echo >&2 $"`basename $0`: check_mgs() error: More than one"\
			  "MGS in the csv file!"
		return 1
	fi
	
	return 0
}

# Construct the command line of mkfs.lustre
construct_mkfs_cmdline() {
	MKFS_CMD=$"mkfs.lustre "${REFORMAT_OPTION}

	case "${DEVICE_TYPE}" in
	"ost")
		MKFS_CMD=${MKFS_CMD}$"--ost "
		;;
	"mdt")
		MKFS_CMD=${MKFS_CMD}$"--mdt "
		;;
	"mgs")
		MKFS_CMD=${MKFS_CMD}$"--mgmt "
		;;
	"mdt|mgs")
		MKFS_CMD=${MKFS_CMD}$"--mdt --mgmt "
		;;
	"mgs|mdt")
		MKFS_CMD=${MKFS_CMD}$"--mdt --mgmt "
		;;
	*)
		echo >&2 $"`basename $0`: construct_mkfs_cmdline() error:"\
			  "Invalid device type - \"${DEVICE_TYPE}\""
		return 1
		;;
	esac

	if [ -n "${FS_NAME}" ]; then
		MKFS_CMD=${MKFS_CMD}$"--fsname="${FS_NAME}$" "
	fi

	if [ -n "${MGMT_NID}" ]; then
		MGMT_NID=`echo "${MGMT_NID}" | sed 's/^"//' | sed 's/"$//'`
		MKFS_CMD=${MKFS_CMD}$"--mgmtnid="${MGMT_NID}$" "
	fi

	if [ -n "${INDEX}" ]; then
		MKFS_CMD=${MKFS_CMD}$"--index="${INDEX}$" "
	fi

	if [ -n "${FORMAT_OPTIONS}" ]; then
		FORMAT_OPTIONS=`echo "${FORMAT_OPTIONS}" | sed 's/^"//' | sed 's/"$//'`
		MKFS_CMD=${MKFS_CMD}${FORMAT_OPTIONS}$" "
	fi

	if [ -n "${MKFS_OPTIONS}" ]; then
		MKFS_OPTIONS=`echo "${MKFS_OPTIONS}" | sed 's/^"//' | sed 's/"$//'`
		MKFS_CMD=${MKFS_CMD}$"--mkfsoptions="$"\""${MKFS_OPTIONS}$"\""$" "
	fi

	if [ -n "${MOUNT_OPTIONS}" ]; then
		MOUNT_OPTIONS=`echo "${MOUNT_OPTIONS}" | sed 's/^"//' | sed 's/"$//'`
		MKFS_CMD=${MKFS_CMD}$"--mountfsoptions="$"\""${MOUNT_OPTIONS}$"\""$" "
	fi

	if [ -n "${FAILOVERS}" ]; then
		FAILOVERS=`echo "${FAILOVERS}" | sed 's/^"//' | sed 's/"$//'`
		MKFS_CMD=${MKFS_CMD}$"--failover="${FAILOVERS}$" "
	fi

	MKFS_CMD=${MKFS_CMD}${DEVICE_NAME}
	return 0
} 

# Get all the node names in this failover group
get_nodenames() {
        declare -i idx
        local failover_nids failover_nid

	NODE_NAMES[0]=${HOST_NAME}

        failover_nids=`echo ${FAILOVERS}|awk '{split($FAILOVERS, a, ",")}\
                      	END {for (i in a) print a[i]}'`

	idx=1
        for failover_nid in ${failover_nids}
        do
                NODE_NAMES[idx]=${failover_nid%@*}
                idx=$idx+1
        done

        return 0
}

# Produce HA software's configuration files
gen_ha_config() {
        local  cmd_line
        declare -i idx

	if [ -z "${HATYPE_OPT}" ]; then
		return 0
	fi

	# Prepare parameters
	# Hostnames option
	HOSTNAME_OPT=${HOST_NAME}

	if ! get_nodenames; then
		return 1
	fi

        for ((idx = 1; idx < ${#NODE_NAMES[@]}; idx++)); do
                HOSTNAME_OPT=${HOSTNAME_OPT}$":"${NODE_NAMES[idx]}
        done

	# Target device option
	TARGET_TYPE=${DEVICE_TYPE}
	if [ "${TARGET_TYPE}" = "mdt|mgs" -o "${TARGET_TYPE}" = "mgs|mdt" ]
	then
		TARGET_TYPE=$"mgs_mdt"
	fi
	TARGET_OPT=${DEVICE_NAME}:${TARGET_TYPE}

	# Service IP address option
	SRVADDR_OPT=${SRV_IPADDRS}

	# Heartbeat channels option
	HBCHANNEL_OPT=$"\""${HB_CHANNELS}$"\""

	# Heartbeat options option
	HBOPT_OPT=$"\""${HB_OPTIONS}$"\""

	# Construct the generation script command line
	case "${HATYPE_OPT}" in
	"${HATYPE_HBV1}"|"${HATYPE_HBV2}")	# Heartbeat 
		cmd_line=${GEN_HB_CONFIG}$" -r ${HATYPE_OPT} -n ${HOSTNAME_OPT}"
		cmd_line=${cmd_line}$" -d ${TARGET_OPT} -c ${HBCHANNEL_OPT}"
		cmd_line=${cmd_line}$" -s ${SRVADDR_OPT}"${VERBOSE_OPT}

		if [ -n "${HB_OPTIONS}" ]; then
			cmd_line=${cmd_line}$" -o ${HBOPT_OPT}"
		fi
		;;
        "${HATYPE_CLUMGR}") 			# CluManager
		cmd_line=${GEN_CLUMGR_CONFIG}$" -n ${HOSTNAME_OPT}"
		cmd_line=${cmd_line}$" -d ${TARGET_OPT} -s ${SRVADDR_OPT}"
		cmd_line=${cmd_line}${VERBOSE_OPT}

		if [ -n "${HBCHANNEL_OPT}" ]; then
			cmd_line=${cmd_line}$" -c ${HBCHANNEL_OPT}"
		fi

		if [ -n "${HB_OPTIONS}" ]; then
			cmd_line=${cmd_line}$" -o ${HBOPT_OPT}"
		fi
		;;
	esac
	
	# Execute script to generate HA software's configuration files
	verbose_output "${cmd_line}"
	eval $(echo "${cmd_line}")
	if [ $? -ne 0 ]; then
		return 1
	fi
	
	return 0
}

# Execute pdsh commands to add lnet options lines to remote nodes'
# modprobe.conf/modules.conf and format(mkfs.lustre) Lustre targets
#
# If -t option exists, then also to produce the HA software's 
# configuration files
mass_config() {
	# Check argument
        if [ $# -eq 0 ]; then
                echo >&2 $"`basename $0`: mass_config() error: Lack argument"\
			  "for function mass_config()!"
                return 1
        fi

        CSV_FILE=$1
	local LINE COMMAND
	declare -a PDSH_PID 
	declare -a PDSH_CMD 
	declare -i line_num=1
	declare -i pid_num=0

	while read -r LINE; do
		# Get rid of the empty line
		if [ -z "`echo ${LINE} | awk '/[[:alnum:]]/{print $0}'`" ]; then
			line_num=${line_num}+1
			continue
		fi

		# Get rid of the comment line
		if [ -z "`echo \"${LINE}\" | egrep -v \"([[:space:]]|^)#\"`" ]; then
			line_num=${line_num}+1
			continue
		fi

		# Parse the config line into CONFIG_ITEM
		if ! parse_line $LINE; then
			return 1	
		fi

		HOST_NAME=${CONFIG_ITEM[0]}
		NETWORKS=${CONFIG_ITEM[1]}
		DEVICE_NAME=${CONFIG_ITEM[2]}
		DEVICE_TYPE=${CONFIG_ITEM[3]}
		FS_NAME=${CONFIG_ITEM[4]}
		MGMT_NID=${CONFIG_ITEM[5]}
		INDEX=${CONFIG_ITEM[6]}
		FORMAT_OPTIONS=${CONFIG_ITEM[7]}
		MKFS_OPTIONS=${CONFIG_ITEM[8]}
		MOUNT_OPTIONS=${CONFIG_ITEM[9]}
		FAILOVERS=${CONFIG_ITEM[10]}

		HB_CHANNELS=${CONFIG_ITEM[11]}
		SRV_IPADDRS=${CONFIG_ITEM[12]}
		HB_OPTIONS=${CONFIG_ITEM[13]}

		# Check some required elements for formatting target
		if ! check_element; then
			echo >&2 $"`basename $0`: check_element() error:"\
				  "Occurred on line ${line_num} in ${CSV_FILE}"
			return 1	
		fi
		
		# Check the number of MGS
		if ! check_mgs; then
			echo >&2 $"`basename $0`: check_mgs() error:"\
				  "Occurred on line ${line_num} in ${CSV_FILE}"
			return 1
		fi
		
		# Construct the command line of mkfs.lustre
		if ! construct_mkfs_cmdline; then
			echo >&2 $"`basename $0`: construct_mkfs_cmdline() error:"\
				  "Occurred on line ${line_num} in ${CSV_FILE}"
			return 1	
		fi

		# Produce HA software's configuration files
		if ! gen_ha_config; then
			return 1
		fi

		# Execute pdsh command to add lnet options lines to modprobe.conf/modules.conf
		verbose_output "Adding lnet options to ${HOST_NAME}..."
		COMMAND=$"echo \"${NETWORKS}\"|${ADD_LNET_OPTIONS}"
		pdsh -w ${HOST_NAME} ${COMMAND} >&2 &
		PDSH_PID[${pid_num}]=$!
		PDSH_CMD[${pid_num}]="pdsh -w ${HOST_NAME} ${COMMAND}"
		pid_num=${pid_num}+1

		# Execute pdsh command to format Lustre target
		verbose_output "Formatting Lustre target on ${HOST_NAME}..."
		verbose_output "Format command line is: ${MKFS_CMD}"
		pdsh -w ${HOST_NAME} ${MKFS_CMD} >&2 &  
		PDSH_PID[${pid_num}]=$!
		PDSH_CMD[${pid_num}]="pdsh -w ${HOST_NAME} ${MKFS_CMD}"
		pid_num=${pid_num}+1

		line_num=${line_num}+1
	done < ${CSV_FILE}

	# Wait for the exit status of the background pdsh command
	verbose_output "Waiting for the return of the pdsh command..."
	for ((pid_num = 0; pid_num < ${#PDSH_PID[@]}; pid_num++)); do
		wait ${PDSH_PID[${pid_num}]}
		if [ $? -ne 0 ]; then
			echo >&2 "`basename $0`: mass_config() error:"\
				 "Fail to execute \"${PDSH_CMD[${pid_num}]}\"!"
		fi
	done	

	rm -rf ${TMP_DIRS}
	return 0
}

# Main flow
# Check the csv file
if ! check_file $1; then
	exit 1	
fi

if [ "${VERIFY_CONNECT}" != "no" ]; then
# Check the network connectivity and hostnames
	verbose_output "Checking the network connectivity and hostnames..."
	if ! ${VERIFY_CLUSTER_NET} ${VERBOSE_OPT} ${CSV_FILE}; then
		exit 1
	fi
	verbose_output "Check the network connectivity and hostnames OK!"
fi

# Configure the Lustre cluster
verbose_output "******** Lustre cluster configuration START ********"
if ! mass_config ${CSV_FILE}; then
	rm -rf ${TMP_DIRS}
	exit 1
fi
verbose_output "******** Lustre cluster configuration END **********"

exit 0
