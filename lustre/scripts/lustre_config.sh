#!/bin/bash
#
# lustre_config.sh - format and set up multiple lustre servers from a csv file
#
# This script is used to parse each line of a spreadsheet (csv file) and 
# execute remote commands to format (mkfs.lustre) every Lustre target 
# that will be part of the Lustre cluster.
# 
# In addition, it can also verify the network connectivity and hostnames in 
# the cluster and produce High-Availability software configurations for
# Heartbeat or CluManager.
#
################################################################################

# Usage
usage() {
	cat >&2 <<EOF

Usage:	`basename $0` [-t HAtype] [-n] [-f] [-m] [-h] [-v] <csv file>

	This script is used to format and set up multiple lustre servers from a
	csv file.

	-h		help and examples
	-t HAtype	produce High-Availability software configurations

			The argument following -t is used to indicate the High-
			Availability software type. The HA software types which 
			are currently supported are: hbv1 (Heartbeat v1), hbv2 
			(Heartbeat v2) and cluman (CluManager).
	-n		no net - don't verify network connectivity and 
	                hostnames in the cluster
	-f		force-format the Lustre targets using --reformat option
	-m		modify /etc/fstab to add the new Lustre targets
	-v		verbose mode
	csv file	a spreadsheet that contains configuration parameters
                        (separated by commas) for each target in a Lustre cl-
                        uster

EOF
	exit 1
}

# Samples 
sample() {
	cat <<EOF

This script is used to parse each line of a spreadsheet (csv file) and 
execute remote commands to format (mkfs.lustre) every Lustre target 
that will be part of the Lustre cluster.

It can also optionally: 
 * verify the network connectivity and hostnames in the cluster
 * modify /etc/modprobe.conf to add Lustre networking info
 * add the Lustre server info to /etc/fstab
 * produce configurations for Heartbeat or CluManager.

Each line in the csv file represents one Lustre target. The format is:
hostname,module_opts,device name,mount point,device type,fsname,mgs nids,index,
format options,mkfs options,mount options,failover nids,heartbeat channels,
service address,heartbeat options

Items left blank will be set to defaults.

Example 1 - Simple, without HA software configuration options:
-------------------------------------------------------------------------------
# combo mdt/mgs
lustre-mgs,options lnet networks=tcp,/tmp/mgs,/mnt/mgs,mgs|mdt,,,,--device-size=10240

# ost0
lustre-ost,options lnet networks=tcp,/tmp/ost0,/mnt/ost0,ost,,lustre-mgs@tcp0,,--device-size=10240

# ost1
lustre-ost,options lnet networks=tcp,/tmp/ost1,/mnt/ost1,ost,,lustre-mgs@tcp0,,--device-size=10240
-------------------------------------------------------------------------------

Example 2 - Separate MGS/MDT, two networks interfaces:
-------------------------------------------------------------------------------
# mgs
lustre-mgs1,options lnet 'networks="tcp,elan"',/tmp/mgs,/mnt/mgs,mgs,,,,--device-size=10240,-J size=4,,"lustre-mgs2,2@elan"

# mdt
lustre-mdt1,options lnet 'networks="tcp,elan"',/tmp/mdt,/mnt/mdt,mdt,lustre2,"lustre-mgs1,1@elan:lustre-mgs2,2@elan",,--device-size=10240,-J size=4,,lustre-mdt2

# ost
lustre-ost1,options lnet 'networks="tcp,elan"',/tmp/ost,/mnt/ost,ost,lustre2,"lustre-mgs1,1@elan:lustre-mgs2,2@elan",,--device-size=10240,-J size=4,"extents,mballoc",lustre-ost2
-------------------------------------------------------------------------------

Example 3 - with Heartbeat version 1 configuration options:
-------------------------------------------------------------------------------
# mgs
lustre-mgs1,options lnet networks=tcp,/tmp/mgs,/mnt/mgs,mgs,,,,--device-size=10240,,,lustre-mgs2,serial /dev/ttyS0:bcast eth1,192.168.1.170,ping 192.168.1.169:respawn hacluster /usr/lib/heartbeat/ipfail

# mdt
lustre-mdt1,options lnet networks=tcp,/tmp/mdt,/mnt/mdt,mdt,,"lustre-mgs1:lustre-mgs2",,--device-size=10240,,,lustre-mdt2,bcast eth1,192.168.1.173

# ost
lustre-ost1,options lnet networks=tcp,/tmp/ost,/mnt/ost,ost,,"lustre-mgs1:lustre-mgs2",,--device-size=10240,,,lustre-ost2,bcast eth1,192.168.1.171
-------------------------------------------------------------------------------

Example 4 - with Heartbeat version 2 configuration options:
-------------------------------------------------------------------------------
# combo mdt/mgs
lustre-mgs1,options lnet networks=tcp,/tmp/mgs,/mnt/mgs,mgs|mdt,,,,--device-size=10240,,,"lustre-mgs2:lustre-mgs3",bcast eth1

# ost1
lustre-ost1,options lnet networks=tcp,/tmp/ost1,/mnt/ost1,ost,,"lustre-mgs1:lustre-mgs2:lustre-mgs3",,--device-size=10240,,,lustre-ost2,bcast eth2

# ost2
lustre-ost2,options lnet networks=tcp,/tmp/ost2,/mnt/ost2,ost,,"lustre-mgs1:lustre-mgs2:lustre-mgs3",,--device-size=10240,,,lustre-ost1,bcast eth2
-------------------------------------------------------------------------------

Example 5 - with Red Hat Cluster Manager configuration options:
-------------------------------------------------------------------------------
# mgs
lustre-mgs1,options lnet networks=tcp,/dev/sda,/mnt/mgs,mgs,,,,,,,lustre-mgs2,broadcast,192.168.1.170,--clumembd --interval=1000000 --tko_count=20

# mdt
lustre-mdt1,options lnet networks=tcp,/dev/sdb,/mnt/mdt,mdt,,"lustre-mgs1:lustre-mgs2",,,,,lustre-mdt2,multicast 225.0.0.12,192.168.1.173

# ost
lustre-ost1,options lnet networks=tcp,/dev/sdb,/mnt/ost,ost,,"lustre-mgs1:lustre-mgs2",,,,,lustre-ost2,,192.168.1.171:192.168.1.172
-------------------------------------------------------------------------------

Example 6 - with combo mgs/mdt failover pair and ost failover pair:
-------------------------------------------------------------------------------
# combo mgs/mdt
lustre-mgs1,options lnet networks=tcp,/tmp/mgs,/mnt/mgs,mgs|mdt,,,,--quiet --device-size=10240,,,lustre-mgs2@tcp0

# combo mgs/mdt backup (--noformat)
lustre-mgs2,options lnet networks=tcp,/tmp/mgs,/mnt/mgs,mgs|mdt,,,,--quiet --device-size=10240 --noformat,,,lustre-mgs1@tcp0

# ost
lustre-ost1,options lnet networks=tcp,/tmp/ost1,/mnt/ost1,ost,,"lustre-mgs1@tcp0:lustre-mgs2@tcp0",,--quiet --device-size=10240,,,lustre-ost2@tcp0

# ost backup (--noformat) (note different device name)
lustre-ost2,options lnet networks=tcp,/tmp/ost2,/mnt/ost2,ost,,"lustre-mgs1@tcp0:lustre-mgs2@tcp0",,--quiet --device-size=10240 --noformat,,,lustre-ost1@tcp0
-------------------------------------------------------------------------------

EOF
	exit 0
}

#***************************** Global variables *****************************#
# Remote command 
REMOTE=${REMOTE:-"ssh -x -q"}
#REMOTE=${REMOTE:-"pdsh -S -R ssh -w"}
export REMOTE

# Command path
CMD_PATH=${CMD_PATH:-"/usr/sbin"}
MKFS=${MKFS:-"$CMD_PATH/mkfs.lustre"}
LCTL=${LCTL:-"$CMD_PATH/lctl"}

EXPORT_PATH=${EXPORT_PATH:-"PATH=\$PATH:/sbin:/usr/sbin;"}

# Some scripts to be called
SCRIPTS_PATH=${CLUSTER_SCRIPTS_PATH:-"/usr/local/sbin"}
MODULE_CONFIG=${SCRIPTS_PATH}/lc_modprobe.sh
VERIFY_CLUSTER_NET=${SCRIPTS_PATH}/lc_net.sh
GEN_HB_CONFIG=${SCRIPTS_PATH}/lc_hb.sh
GEN_CLUMGR_CONFIG=${SCRIPTS_PATH}/lc_cluman.sh

# Variables of HA software
HATYPE_HBV1="hbv1"			# Heartbeat version 1
HATYPE_HBV2="hbv2"			# Heartbeat version 2
HATYPE_CLUMGR="cluman"			# Cluster Manager

HB_TMP_DIR="/tmp/heartbeat"		# Temporary directory
CLUMGR_TMP_DIR="/tmp/clumanager"
TMP_DIRS="${HB_TMP_DIR} ${CLUMGR_TMP_DIR}"

FS_TYPE=${FS_TYPE:-"lustre"}		# filesystem type

declare -a MGS_NODENAME			# node names of the MGS servers
declare -a MGS_IDX			# indexes of MGSs in the global arrays
declare -i MGS_NUM			# number of MGS servers in the cluster
declare -i INIT_IDX

declare -a CONFIG_ITEM			# items in each line of the csv file
declare -a NODE_NAMES			# node names in the failover group
declare -a TARGET_OPTS			# target services in one failover group

# All the items in the csv file
declare -a HOST_NAME MODULE_OPTS DEVICE_NAME MOUNT_POINT DEVICE_TYPE FS_NAME
declare -a MGS_NIDS INDEX FORMAT_OPTIONS MKFS_OPTIONS MOUNT_OPTIONS FAILOVERS
declare -a HB_CHANNELS SRV_IPADDRS HB_OPTIONS


VERIFY_CONNECT=true
MODIFY_FSTAB=false
# Get and check the positional parameters
while getopts "t:nfmhv" OPTION; do
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
		VERIFY_CONNECT=false
		;;
        f) 
		REFORMAT_OPTION=$"--reformat "
		;;
	m)
		MODIFY_FSTAB=true
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
	echo >&2 $"`basename $0`: Missing csv file!"
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
                echo >&2 $"`basename $0`: check_file() error: Missing argument"\
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
                echo >&2 $"`basename $0`: parse_line() error: Missing argument"\
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
	unset CONFIG_ITEM

	# Get the length of the line
        length=${#LINE}

	i=0
	while [ ${idx} -lt ${length} ]; do
		# Get a letter from the line
		TMP_LETTER=${LINE:${idx}:1}

		case "${TMP_LETTER}" in
		",")
			if [ ${s_quote_flag} -eq 1 -o ${d_quote_flag} -eq 1 ]
			then
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

# Check the items required for OSTs, MDTs and MGS
#
# When formatting an OST, the following items: hostname, module_opts,
# device name, device type and mgs nids, cannot have null value.
#
# When formatting an MDT or MGS, the following items: hostname,
# module_opts, device name and device type, cannot have null value.
check_item() {
        # Check argument
        if [ $# -eq 0 ]; then
                echo >&2 $"`basename $0`: check_item() error: Missing argument"\
			  "for function check_item()!"
                return 1
        fi

	declare -i i=$1

        # Check hostname, module_opts, device name and device type
	if [ -z "${HOST_NAME[i]}" ]||[ -z "${MODULE_OPTS[i]}" ]\
	||[ -z "${DEVICE_NAME[i]}" ]||[ -z "${DEVICE_TYPE[i]}" ]; then
                echo >&2 $"`basename $0`: check_item() error: Some required"\
			  "item has null value! Check hostname, module_opts,"\
			  "device name and device type!"
                return 1
        fi

        # Check mgs nids
        if [ "${DEVICE_TYPE[i]}" = "ost" ]&&[ -z "${MGS_NIDS[i]}" ]; then
                echo >&2 $"`basename $0`: check_item() error: OST's mgs nids"\
			  "item has null value!"
                return 1
        fi

	# Check mount point
	if ${MODIFY_FSTAB} && [ -z "${MOUNT_POINT[i]}" ]; then
		echo >&2 $"`basename $0`: check_item() error: mount"\
		"point item of target ${DEVICE_NAME[i]} has null value!"
		return 1
	fi

        return 0
}

# Check the items required for HA configuration
check_ha_item() {
	if [ -z "${HATYPE_OPT}" ]; then
		return 0
	fi

        # Check argument
        if [ $# -eq 0 ]; then
                echo >&2 $"`basename $0`: check_ha_item() error: Missing"\
			  "argument for function check_ha_item()!"
                return 1
        fi

	declare -i i=$1

	[ -z "${HB_CHANNELS[i]}" ] && [ -z "${SRV_IPADDRS[i]}" ] \
	&& [ -z "${HB_OPTIONS[i]}" ] && return 0

	# Check mount point
	if [ -z "${MOUNT_POINT[i]}" ]; then
		echo >&2 $"`basename $0`: check_ha_item() error: mount"\
		"point item of target ${DEVICE_NAME[i]} has null value!"
		return 1
	fi

	# Check failover nodes
	if [ -z "${FAILOVERS[i]}" ]; then
		echo >&2 $"`basename $0`: check_ha_item() error:"\
		"failover item of host ${HOST_NAME[i]} has null value!"
		return 1
	fi

	# Check service IP item
	if [ "${HATYPE_OPT}" = "${HATYPE_HBV1}" -a -z "${SRV_IPADDRS[i]}" ]
	then
                echo >&2 $"`basename $0`: check_ha_item() error:"\
		"service IP item of host ${HOST_NAME[i]} has null value!"
                return 1
        fi

	# Check heartbeat channel item
	if [ "${HATYPE_OPT}" != "${HATYPE_CLUMGR}" -a -z "${HB_CHANNELS[i]}" ]
	then
                echo >&2 $"`basename $0`: check_ha_item() error: Heartbeat"\
		"channel item of host ${HOST_NAME[i]} has null value!"
                return 1
        fi

	return 0
}

# Get the number of MGS nodes in the cluster
get_mgs_num() {
	INIT_IDX=0
	MGS_NUM=${#MGS_NODENAME[@]}
	[ -z "${MGS_NODENAME[0]}" ] && let "INIT_IDX += 1" \
	&& let "MGS_NUM += 1"
}

# is_mgs_node hostname
# Verify whether @hostname is a MGS node
is_mgs_node() {
	local host_name=$1
	declare -i i

	get_mgs_num
	for ((i = ${INIT_IDX}; i < ${MGS_NUM}; i++)); do
		[ "${MGS_NODENAME[i]}" = "${host_name}" ] && return 0
	done

	return 1
}

# Check whether the MGS nodes are in the same failover group
check_mgs_group() {
	declare -i i
	declare -i j
	declare -i idx
	local mgs_node

	get_mgs_num
	for ((i = ${INIT_IDX}; i < ${MGS_NUM}; i++)); do
		mgs_node=${MGS_NODENAME[i]}
		for ((j = ${INIT_IDX}; j < ${MGS_NUM}; j++)); do
		  [ "${MGS_NODENAME[j]}" = "${mgs_node}" ] && continue 1

		  idx=${MGS_IDX[j]}
		  if [ "${FAILOVERS[idx]#*$mgs_node*}" = "${FAILOVERS[idx]}" ]
		  then
			echo >&2 $"`basename $0`: check_mgs_group() error:"\
			"MGS node ${mgs_node} is not in the ${HOST_NAME[idx]}"\
			"failover group!"
			return 1
		  fi
		done
	done

	return 0
}

# Get and check MGS servers.
# There should be no more than one MGS specified in the entire csv file.
check_mgs() {
	declare -i i
	declare -i j
	declare -i exp_idx	# Index of explicit MGS servers
	declare -i imp_idx	# Index of implicit MGS servers
	local is_exp_mgs is_imp_mgs
	local mgs_node

	# Initialize the MGS_NODENAME and MGS_IDX arrays
	unset MGS_NODENAME
	unset MGS_IDX

	exp_idx=1
	imp_idx=1
	for ((i = 0; i < ${#HOST_NAME[@]}; i++)); do
		is_exp_mgs=false
		is_imp_mgs=false

		# Check whether this node is an explicit MGS node 
		# or an implicit one
		if [ "${DEVICE_TYPE[i]#*mgs*}" != "${DEVICE_TYPE[i]}" ]; then
			verbose_output "Explicit MGS target" \
			"${DEVICE_NAME[i]} in host ${HOST_NAME[i]}."
			is_exp_mgs=true
		fi

		if [ "${DEVICE_TYPE[i]}" = "mdt" -a -z "${MGS_NIDS[i]}" ]; then
			verbose_output "Implicit MGS target" \
			"${DEVICE_NAME[i]} in host ${HOST_NAME[i]}."
			is_imp_mgs=true
		fi

		# Get and check MGS servers
		if ${is_exp_mgs} || ${is_imp_mgs}; then
			# Check whether more than one MGS target in one MGS node
			if is_mgs_node ${HOST_NAME[i]}; then
				echo >&2 $"`basename $0`: check_mgs() error:"\
			  	"More than one MGS target in the same node -"\
				"\"${HOST_NAME[i]}\"!"
				return 1
			fi

			# Get and check primary MGS server and backup MGS server		
			if [ "${FORMAT_OPTIONS[i]}" = "${FORMAT_OPTIONS[i]#*noformat*}" ]
			then
				# Primary MGS server
				if [ -z "${MGS_NODENAME[0]}" ]; then
					if [ "${is_exp_mgs}" = "true" -a ${imp_idx} -gt 1 ] \
					|| [ "${is_imp_mgs}" = "true" -a ${exp_idx} -gt 1 ]; then
						echo >&2 $"`basename $0`: check_mgs() error:"\
				  		"There exist both explicit and implicit MGS"\
						"targets in the csv file!"
						return 1
					fi
					MGS_NODENAME[0]=${HOST_NAME[i]}
					MGS_IDX[0]=$i
				else
					mgs_node=${MGS_NODENAME[0]}
					if [ "${FAILOVERS[i]#*$mgs_node*}" = "${FAILOVERS[i]}" ]
					then
						echo >&2 $"`basename $0`: check_mgs() error:"\
				  		"More than one primary MGS nodes in the csv" \
						"file - ${MGS_NODENAME[0]} and ${HOST_NAME[i]}!"
					else
						echo >&2 $"`basename $0`: check_mgs() error:"\
				  		"MGS nodes ${MGS_NODENAME[0]} and ${HOST_NAME[i]}"\
						"are failover pair, one of them should use"\
						"\"--noformat\" in the format options item!"
					fi
					return 1
				fi
			else	# Backup MGS server
				if [ "${is_exp_mgs}" = "true" -a ${imp_idx} -gt 1 ] \
				|| [ "${is_imp_mgs}" = "true" -a ${exp_idx} -gt 1 ]; then
					echo >&2 $"`basename $0`: check_mgs() error:"\
					"There exist both explicit and implicit MGS"\
					"targets in the csv file!"
					return 1
				fi

				if ${is_exp_mgs}; then # Explicit MGS
					MGS_NODENAME[exp_idx]=${HOST_NAME[i]}
					MGS_IDX[exp_idx]=$i
					exp_idx=$(( exp_idx + 1 ))
				else	# Implicit MGS
					MGS_NODENAME[imp_idx]=${HOST_NAME[i]}
					MGS_IDX[imp_idx]=$i
					imp_idx=$(( imp_idx + 1 ))
				fi
			fi
		fi #End of "if ${is_exp_mgs} || ${is_imp_mgs}"
	done

	# Check whether the MGS nodes are in the same failover group
	if ! check_mgs_group; then
		return 1
	fi

	return 0
}

# Construct the command line of mkfs.lustre
construct_mkfs_cmdline() {
        # Check argument
        if [ $# -eq 0 ]; then
                echo >&2 $"`basename $0`: construct_mkfs_cmdline() error:"\
			  "Missing argument for function"\
			  "construct_mkfs_cmdline()!"
                return 1
        fi

	declare -i i=$1

	MKFS_CMD=${MKFS}$" "
	MKFS_CMD=${MKFS_CMD}${REFORMAT_OPTION}

	case "${DEVICE_TYPE[i]}" in
	"ost")
		MKFS_CMD=${MKFS_CMD}$"--ost "
		;;
	"mdt")
		MKFS_CMD=${MKFS_CMD}$"--mdt "
		;;
	"mgs")
		MKFS_CMD=${MKFS_CMD}$"--mgs "
		;;
	"mdt|mgs" | "mgs|mdt")
		MKFS_CMD=${MKFS_CMD}$"--mdt --mgs "
		;;
	*)
		echo >&2 $"`basename $0`: construct_mkfs_cmdline() error:"\
			  "Invalid device type - \"${DEVICE_TYPE[i]}\"!"
		return 1
		;;
	esac

	if [ -n "${FS_NAME[i]}" ]; then
		MKFS_CMD=${MKFS_CMD}$"--fsname="${FS_NAME[i]}$" "
	fi

	if [ -n "${MGS_NIDS[i]}" ]; then
		MGS_NIDS[i]=`echo "${MGS_NIDS[i]}" | sed 's/^"//' | sed 's/"$//'`
		MKFS_CMD=${MKFS_CMD}$"--mgsnode="${MGS_NIDS[i]}$" "
	fi

	if [ -n "${INDEX[i]}" ]; then
		MKFS_CMD=${MKFS_CMD}$"--index="${INDEX[i]}$" "
	fi

	if [ -n "${FORMAT_OPTIONS[i]}" ]; then
		FORMAT_OPTIONS[i]=`echo "${FORMAT_OPTIONS[i]}" | sed 's/^"//' | sed 's/"$//'`
		MKFS_CMD=${MKFS_CMD}${FORMAT_OPTIONS[i]}$" "
	fi

	if [ -n "${MKFS_OPTIONS[i]}" ]; then
		MKFS_OPTIONS[i]=`echo "${MKFS_OPTIONS[i]}" | sed 's/^"//' | sed 's/"$//'`
		MKFS_CMD=${MKFS_CMD}$"--mkfsoptions="$"\""${MKFS_OPTIONS[i]}$"\""$" "
	fi

	if [ -n "${MOUNT_OPTIONS[i]}" ]; then
		MOUNT_OPTIONS[i]=`echo "${MOUNT_OPTIONS[i]}" | sed 's/^"//' | sed 's/"$//'`
		MKFS_CMD=${MKFS_CMD}$"--mountfsoptions="$"\""${MOUNT_OPTIONS[i]}$"\""$" "
	fi

	if [ -n "${FAILOVERS[i]}" ]; then
		FAILOVERS[i]=`echo "${FAILOVERS[i]}" | sed 's/^"//' | sed 's/"$//'`
		MKFS_CMD=${MKFS_CMD}$"--failnode="${FAILOVERS[i]}$" "
	fi

	MKFS_CMD=${MKFS_CMD}${DEVICE_NAME[i]}
	return 0
} 

# Get all the node names in this failover group
get_nodenames() {
        # Check argument
        if [ $# -eq 0 ]; then
                echo >&2 $"`basename $0`: get_nodenames() error: Missing"\
			  "argument for function get_nodenames()!"
                return 1
        fi

	declare -i i=$1
	declare -i idx
	local nids_str failover_nids failover_nid first_nid

	# Initialize the NODE_NAMES array
	unset NODE_NAMES

	NODE_NAMES[0]=${HOST_NAME[i]}

	idx=0
	nids_str=${FAILOVERS[i]}
	failover_nids=`echo ${nids_str}|awk '{split($nids_str, a, ":")}\
                      	END {for (idx in a) print a[idx]}'`

	# FIXME: Suppose the first nid of one failover node contains node name
	idx=1
	for failover_nid in ${failover_nids}
	do
		first_nid=`echo ${failover_nid} | awk -F, '{print $1}'`
                NODE_NAMES[idx]=${first_nid%@*}
                idx=$idx+1
	done

	return 0
}

# Verify whether the format line has HA items
is_ha_line() {
	declare -i i=$1

	if [ "${HATYPE_OPT}" != "${HATYPE_CLUMGR}" ]; then
		[ -n "${HB_CHANNELS[i]}" ] && return 0
	else
		[ -n "${SRV_IPADDRS[i]}" ] && return 0
	fi

	return 1
}

# Produce HA software's configuration files
gen_ha_config() {
	declare -i i=$1
	declare -i idx
	local  cmd_line

	# Prepare parameters
	# Hostnames option
	HOSTNAME_OPT=${HOST_NAME[i]}

	if ! get_nodenames $i; then
		return 1
	fi

        for ((idx = 1; idx < ${#NODE_NAMES[@]}; idx++)); do
                HOSTNAME_OPT=${HOSTNAME_OPT}$":"${NODE_NAMES[idx]}
        done

	# Service IP address option
	SRVADDR_OPT=${SRV_IPADDRS[i]}

	# Heartbeat channels option
	HBCHANNEL_OPT=$"\""${HB_CHANNELS[i]}$"\""

	# Heartbeat options option
	HBOPT_OPT=$"\""${HB_OPTIONS[i]}$"\""

	# Target devices option
	DEVICE_OPT=" -d "${TARGET_OPTS[0]}
        for ((idx = 1; idx < ${#TARGET_OPTS[@]}; idx++)); do
                DEVICE_OPT=${DEVICE_OPT}" -d "${TARGET_OPTS[idx]}
        done

	# Construct the generation script command line
	case "${HATYPE_OPT}" in
	"${HATYPE_HBV1}"|"${HATYPE_HBV2}")	# Heartbeat 
		cmd_line=${GEN_HB_CONFIG}$" -r ${HATYPE_OPT} -n ${HOSTNAME_OPT}"
		cmd_line=${cmd_line}$" -c ${HBCHANNEL_OPT}"${DEVICE_OPT}${VERBOSE_OPT}

		if [ -n "${SRV_IPADDRS[i]}" ]; then
			cmd_line=${cmd_line}$" -s ${SRVADDR_OPT}"
		fi

		if [ -n "${HB_OPTIONS[i]}" ]; then
			cmd_line=${cmd_line}$" -o ${HBOPT_OPT}"
		fi
		;;
        "${HATYPE_CLUMGR}") 			# CluManager
		cmd_line=${GEN_CLUMGR_CONFIG}$" -n ${HOSTNAME_OPT}"
		cmd_line=${cmd_line}$" -s ${SRVADDR_OPT}"${DEVICE_OPT}${VERBOSE_OPT}

		if [ -n "${HBCHANNEL_OPT}" ]; then
			cmd_line=${cmd_line}$" -c ${HBCHANNEL_OPT}"
		fi

		if [ -n "${HB_OPTIONS[i]}" ]; then
			cmd_line=${cmd_line}$" -o ${HBOPT_OPT}"
		fi
		;;
	esac
	
	# Execute script to generate HA software's configuration files
	verbose_output "Generating HA software's configurations in"\
		       "${HOST_NAME[i]} failover group..."
	verbose_output "${cmd_line}"
	eval $(echo "${cmd_line}")
	if [ $? -ne 0 ]; then
		return 1
	fi
	verbose_output "Generate HA software's configurations in"\
		       "${HOST_NAME[i]} failover group OK"
	
	return 0
}

# Configure HA software
config_ha() {
	if [ -z "${HATYPE_OPT}" ]; then
		return 0
	fi

	declare -i i j k
	declare -i prim_idx	# Index for PRIM_HOSTNAMES array
	declare -i target_idx	# Index for TARGET_OPTS and HOST_INDEX arrays

	declare -a PRIM_HOSTNAMES	# Primary hostnames in all the failover
					# groups in the lustre cluster
	declare -a HOST_INDEX		# Indices for the same node in all the 
					# format lines in the csv file
	local prim_host

	# Initialize the PRIM_HOSTNAMES array
	prim_idx=0
	unset PRIM_HOSTNAMES

	# Get failover groups and generate HA configuration files
	for ((i = 0; i < ${#HOST_NAME[@]}; i++)); do
		prim_host=${HOST_NAME[i]}

		for ((j = 0; j < ${#PRIM_HOSTNAMES[@]}; j++)); do
			[ "${prim_host}" = "${PRIM_HOSTNAMES[j]}" ] && continue 2
		done

		target_idx=0
		unset HOST_INDEX
		unset TARGET_OPTS
		for ((k = 0; k < ${#HOST_NAME[@]}; k++)); do
			if [ "${prim_host}" = "${HOST_NAME[k]}" ] && is_ha_line "${k}"
			then
				HOST_INDEX[target_idx]=$k
				TARGET_OPTS[target_idx]=${DEVICE_NAME[k]}:${MOUNT_POINT[k]}
				target_idx=$(( target_idx + 1 ))
			fi
		done

		if [ ${#TARGET_OPTS[@]} -ne 0 ]; then
			PRIM_HOSTNAMES[prim_idx]=${prim_host}
			prim_idx=$(( prim_idx + 1 ))

			if ! gen_ha_config ${HOST_INDEX[0]}; then
				return 1
			fi
		fi
	done

	if [ ${#PRIM_HOSTNAMES[@]} -eq 0 ]; then
		verbose_output "There are no HA configuration items in the"\
		"csv file. No HA configuration files are generated!"
	fi

	rm -rf ${TMP_DIRS}
	return 0
}


# Get all the items in the csv file and do some checks.
get_items() {
	# Check argument
        if [ $# -eq 0 ]; then
                echo >&2 $"`basename $0`: get_items() error: Missing argument"\
			  "for function get_items()!"
                return 1
        fi

        CSV_FILE=$1
	local LINE
	declare -i line_num=0
	declare -i idx=0

	while read -r LINE; do
		line_num=${line_num}+1
		# verbose_output "Parsing line ${line_num}: $LINE"

		# Get rid of the empty line
		if [ -z "`echo ${LINE}|awk '/[[:alnum:]]/ {print $0}'`" ]; then
			continue
		fi

		# Get rid of the comment line
		if [ -z "`echo \"${LINE}\" | egrep -v \"([[:space:]]|^)#\"`" ]
		then
			continue
		fi

		# Parse the config line into CONFIG_ITEM
		if ! parse_line $LINE; then
			echo >&2 $"`basename $0`: parse_line() error: Occurred"\
				  "on line ${line_num} in ${CSV_FILE}: $LINE"
			return 1	
		fi

		HOST_NAME[idx]=${CONFIG_ITEM[0]}
		MODULE_OPTS[idx]=${CONFIG_ITEM[1]}
		DEVICE_NAME[idx]=${CONFIG_ITEM[2]}
		MOUNT_POINT[idx]=${CONFIG_ITEM[3]}
		DEVICE_TYPE[idx]=${CONFIG_ITEM[4]}
		FS_NAME[idx]=${CONFIG_ITEM[5]}
		MGS_NIDS[idx]=${CONFIG_ITEM[6]}
		INDEX[idx]=${CONFIG_ITEM[7]}
		FORMAT_OPTIONS[idx]=${CONFIG_ITEM[8]}
		MKFS_OPTIONS[idx]=${CONFIG_ITEM[9]}
		MOUNT_OPTIONS[idx]=${CONFIG_ITEM[10]}
		FAILOVERS[idx]=${CONFIG_ITEM[11]}

		HB_CHANNELS[idx]=${CONFIG_ITEM[12]}
		SRV_IPADDRS[idx]=${CONFIG_ITEM[13]}
		HB_OPTIONS[idx]=${CONFIG_ITEM[14]}

		# Check some required items for formatting target
		if ! check_item $idx; then
			echo >&2 $"`basename $0`: check_item() error:"\
				  "Occurred on line ${line_num} in ${CSV_FILE}."
			return 1	
		fi

		# Check the items required for HA configuration
		if ! check_ha_item $idx; then
			echo >&2 $"`basename $0`: check_ha_item() error:"\
				  "Occurred on line ${line_num} in ${CSV_FILE}."
			return 1	
		fi
		
		idx=${idx}+1
	done < ${CSV_FILE}

	return 0
}

# check_lnet_connect hostname_index mgs_hostname
# Check whether the target node can contact the MGS node @mgs_hostname
# If @mgs_hostname is null, then it means the primary MGS node
check_lnet_connect() {
	declare -i i=$1
	declare -i idx=0
	local mgs_node=$2

	local COMMAND RET_STR
	local mgs_prim_nids all_nids all_nids_str 	
	local nids
	local nids_str=
	local mgs_nids mgs_nid 
	local ping_mgs

	# Execute remote command to check that 
	# this node can contact the MGS node
	verbose_output "Checking lnet connectivity between" \
		       "${HOST_NAME[i]} and the MGS node ${mgs_node}"
	all_nids=${MGS_NIDS[i]}
	mgs_prim_nids=`echo ${all_nids} | awk -F: '{print $1}'`
	all_nids_str=`echo ${all_nids} | awk '{split($all_nids, a, ":")}\
		       END {for (idx in a) print a[idx]}'`

	if [ -z "${mgs_node}" ]; then
		nids_str=${mgs_prim_nids}	# nids of primary MGS node
	else
		for nids in ${all_nids_str}; do
			# FIXME: Suppose the MGS nids contain the node name
			[ "${nids}" != "${nids#*$mgs_node*}" ] && nids_str=${nids}
		done
	fi

	if [ -z "${nids_str}" ]; then
                echo >&2 $"`basename $0`: check_lnet_connect() error:"\
			  "Check the mgs nids item of host ${HOST_NAME[i]}!"\
			  "Missing nids of the MGS node ${mgs_node}!"
                return 1
	fi

	idx=0
	mgs_nids=`echo ${nids_str} | awk '{split($nids_str, a, ",")}\
		       END {for (idx in a) print a[idx]}'`

	ping_mgs=false
	for mgs_nid in ${mgs_nids}
	do
		COMMAND=$"${LCTL} ping ${mgs_nid} 5 || echo failed 2>&1"
		RET_STR=`${REMOTE} ${HOST_NAME[i]} "${COMMAND}" 2>&1`
		if [ $? -eq 0 -a "${RET_STR}" = "${RET_STR#*failed*}" ]
		then
			# This node can contact the MGS node
			verbose_output "${HOST_NAME[i]} can contact the MGS" \
                         	       "node ${mgs_node} by using nid" \
				       "\"${mgs_nid}\"!"
			ping_mgs=true
			break
        	fi
	done

	if ! ${ping_mgs}; then
                echo >&2 "`basename $0`: check_lnet_connect() error:" \
                         "${HOST_NAME[i]} cannot contact the MGS node"\
			 "${mgs_node} through lnet networks!"\
			 "Check ${LCTL} command!"
                return 1
	fi

	return 0
}

# Start lnet network in the cluster node and check that 
# this node can contact the MGS node
check_lnet() {
	if ! ${VERIFY_CONNECT}; then
		return 0
	fi

        # Check argument
        if [ $# -eq 0 ]; then
                echo >&2 $"`basename $0`: check_lnet() error: Missing"\
			  "argument for function check_lnet()!"
                return 1
        fi

	declare -i i=$1
	declare -i j
	local COMMAND RET_STR

	# Execute remote command to start lnet network
	verbose_output "Starting lnet network in ${HOST_NAME[i]}"
	COMMAND=$"modprobe lnet; ${LCTL} network up 2>&1"
        RET_STR=`${REMOTE} ${HOST_NAME[i]} "${COMMAND}" 2>&1`
        if [ $? -ne 0 -o "${RET_STR}" = "${RET_STR#*LNET configured*}" ]
	then
                echo >&2 "`basename $0`: check_lnet() error: remote" \
                         "${HOST_NAME[i]} error: ${RET_STR}"
                return 1
        fi

	if is_mgs_node ${HOST_NAME[i]}; then
		return 0
	fi

	# Execute remote command to check that 
	# this node can contact the MGS node
	for ((j = 0; j < ${MGS_NUM}; j++)); do
		if ! check_lnet_connect $i ${MGS_NODENAME[j]}; then
			return 1
		fi
	done

	return 0
}

# Start lnet network in the MGS node
start_mgs_lnet() {
	declare -i i
	declare -i idx
	local COMMAND

	if [ -z "${MGS_NODENAME[0]}" -a  -z "${MGS_NODENAME[1]}" ]; then
		verbose_output "There is no MGS target in the ${CSV_FILE} file."
		return 0
	fi

	for ((i = ${INIT_IDX}; i < ${MGS_NUM}; i++)); do
		# Execute remote command to add lnet options lines to 
		# the MGS node's modprobe.conf/modules.conf
		idx=${MGS_IDX[i]}
		COMMAND=$"echo \"${MODULE_OPTS[${idx}]}\"|${MODULE_CONFIG}"
		verbose_output "Adding lnet module options to ${MGS_NODENAME[i]}"
		${REMOTE} ${MGS_NODENAME[i]} "${COMMAND}" >&2 
		if [ $? -ne 0 ]; then
               		echo >&2 "`basename $0`: start_mgs_lnet() error:"\
				 "Failed to execute remote command to" \
				 "add module options to ${MGS_NODENAME[i]}!"\
				 "Check ${MODULE_CONFIG}!"
               		return 1
        	fi

		# Start lnet network in the MGS node
		if ! check_lnet ${idx}; then
			return 1	
		fi
	done

	return 0
}

# Execute remote command to add lnet options lines to remote nodes'
# modprobe.conf/modules.conf and format(mkfs.lustre) Lustre targets
mass_config() {
	local COMMAND
	declare -a REMOTE_PID 
	declare -a REMOTE_CMD 
	declare -i pid_num=0
	declare -i i=0

	# Start lnet network in the MGS node
	if ! start_mgs_lnet; then
		return 1	
	fi

	for ((i = 0; i < ${#HOST_NAME[@]}; i++)); do
		# Construct the command line of mkfs.lustre
		if ! construct_mkfs_cmdline $i; then
			return 1	
		fi

		if ! is_mgs_node ${HOST_NAME[i]}; then
			# Execute remote command to add lnet options lines to 
			# modprobe.conf/modules.conf
			COMMAND=$"echo \"${MODULE_OPTS[i]}\"|${MODULE_CONFIG}"
			verbose_output "Adding lnet module options to" \
				       "${HOST_NAME[i]}"
			${REMOTE} ${HOST_NAME[i]} "${COMMAND}" >&2 
			if [ $? -ne 0 ]; then
                		echo >&2 "`basename $0`: mass_config() error:"\
					 "Failed to execute remote command to"\
					 "add module options to ${HOST_NAME[i]}!"
                		return 1
        		fi

			# Check lnet networks
			if ! check_lnet $i; then
				return 1	
			fi
		fi

		# Execute remote command to format Lustre target
		verbose_output "Formatting Lustre target ${DEVICE_NAME[i]}"\
			       "on ${HOST_NAME[i]}..."
		verbose_output "Format command line is: ${MKFS_CMD}"
		REMOTE_CMD[${pid_num}]="${REMOTE} ${HOST_NAME[i]} ${MKFS_CMD}"
		${REMOTE} ${HOST_NAME[i]} "(${EXPORT_PATH} ${MKFS_CMD})" >&2 &  
		REMOTE_PID[${pid_num}]=$!
		pid_num=${pid_num}+1
		sleep 1
	done

	# Wait for the exit status of the background remote command
	verbose_output "Waiting for the return of the remote command..."
	fail_exit_status=false
	for ((pid_num = 0; pid_num < ${#REMOTE_PID[@]}; pid_num++)); do
		wait ${REMOTE_PID[${pid_num}]}
		if [ $? -ne 0 ]; then
			echo >&2 "`basename $0`: mass_config() error: Failed"\
				 "to execute \"${REMOTE_CMD[${pid_num}]}\"!"
			fail_exit_status=true
		fi
	done

	if ${fail_exit_status}; then
		return 1
	fi	

	verbose_output "All the Lustre targets are formatted successfully!"
	return 0
}

# get_mntopts hostname device_name failovers
# Construct the mount options of Lustre target @device_name in host @hostname
get_mntopts() {
	local host_name=$1
	local device_name=$2
	local failovers=$3
	local mnt_opts=
	local ret_str

	[ -n "${failovers}" ] && mnt_opts=defaults,noauto || mnt_opts=defaults

	# Execute remote command to check whether the device
	# is a block device or not
	ret_str=`${REMOTE} ${host_name} \
		"[ -b ${device_name} ] && echo block || echo loop" 2>&1`
	if [ $? -ne 0 -a -n "${ret_str}" ]; then
		echo "`basename $0`: get_mntopts() error:" \
		     "remote command error: ${ret_str}"
		return 1
	fi

	if [ -z "${ret_str}" ]; then
		echo "`basename $0`: get_mntopts() error: remote error:" \
                     "No results from remote!" \
                     "Check network connectivity between the local host"\
                     "and ${host_name}!"
		return 1
	fi

	[ "${ret_str}" != "${ret_str#*loop}" ] && mnt_opts=${mnt_opts},loop

	echo ${mnt_opts}
	return 0
}

# Execute remote command to modify /etc/fstab to add the new Lustre targets
modify_fstab() {
	declare -i i
	local mntent mntopts device_name
	local COMMAND

	if ! ${MODIFY_FSTAB}; then
		return 0	
	fi

	for ((i = 0; i < ${#HOST_NAME[@]}; i++)); do
		verbose_output "Modify /etc/fstab of host ${HOST_NAME[i]}"\
			       "to add Lustre target ${DEVICE_NAME[i]}"
		mntent=${DEVICE_NAME[i]}"\t\t"${MOUNT_POINT[i]}"\t\t"${FS_TYPE}
		mntopts=$(get_mntopts ${HOST_NAME[i]} ${DEVICE_NAME[i]}\
			  ${FAILOVERS[i]})
		if [ $? -ne 0 ]; then
			echo >&2 "${mntopts}"
			return 1
		fi

		mntent=${mntent}"\t"${mntopts}"\t"0" "0

		# Execute remote command to modify /etc/fstab
		device_name=${DEVICE_NAME[i]//\//\\/}
		COMMAND="(sed -i \"/${device_name}/d\" /etc/fstab; \
			 echo -e \"${mntent}\" >> /etc/fstab)"
		${REMOTE} ${HOST_NAME[i]} "${COMMAND}" >&2
		if [ $? -ne 0 ]; then
                	echo >&2 "`basename $0`: modify_fstab() error:"\
				 "Failed to execute remote command to"\
				 "modify /etc/fstab of host ${HOST_NAME[i]}"\
				 "to add Lustre target ${DEVICE_NAME[i]}!"
                	return 1
        	fi
	done

	return 0
}

# Main flow
# Check the csv file
if ! check_file $1; then
	exit 1	
fi

if ${VERIFY_CONNECT}; then
# Check the network connectivity and hostnames
	echo "`basename $0`: Checking the cluster network connectivity"\
	     "and hostnames..."
	if ! ${VERIFY_CLUSTER_NET} ${VERBOSE_OPT} ${CSV_FILE}; then
		exit 1
	fi
	echo "`basename $0`: Check the cluster network connectivity"\
	     "and hostnames OK!"
	echo
fi

# Configure the Lustre cluster
echo "`basename $0`: ******** Lustre cluster configuration START ********"
if ! get_items ${CSV_FILE}; then
	exit 1
fi

if ! check_mgs; then
	exit 1
fi

if ! mass_config; then
	exit 1
fi

if ! modify_fstab; then
	exit 1
fi

# Produce HA software's configuration files
if ! config_ha; then
	rm -rf ${TMP_DIRS}
	exit 1
fi

echo "`basename $0`: ******** Lustre cluster configuration END **********"

exit 0
