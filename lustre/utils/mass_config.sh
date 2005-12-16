#!/bin/bash
#
# mass_config.sh - spreadsheet parsing for massive parallel config
#
########################################################################

# Usage
usage() {
	echo -e >&2 $"\nUsage: `basename $0` <csv file>"
	cat >&2 <<EOF

Each line in the csv file represents one Lustre target.
The format of it is:
hostname,networks,device name,device type,fsname/poolname,mgmtnid,index,format options,mkfs options,mount options,failovers

Sample 1 for csv file:
lustre-mgs,options lnet networks=tcp,/r/tmp/mgmt,mgs,,,,--device_size 10240,-J size=4,,lustre-mgs@tcp0
lustre-ost,options lnet networks=tcp,/r/tmp/ost1,ost,lustre1,lustre-mgs@tcp0,0001,--device_size 10240,-J size=4,"extents,mballoc",lustre-mgs@tcp0
lustre-mdt,options lnet networks=tcp,/r/tmp/mdt1,mdt,lustre1,lustre-mgs@tcp0,0001,--device_size 10240,-J size=4,,lustre-mgs@tcp0

Sample 2 for csv file:
lustre-mgs,options lnet 'networks="tcp,elan"' \n options ost 'numthreads=23',/dev/sda,mgs,,,,,,,
lustre-ost,options lnet networks=tcp,/dev/sda,ost,,lustre-mgs@tcp0,,,,,
lustre-mdt,options lnet networks=tcp,/dev/sda,mdt,,lustre-mgs@tcp0,,,,,

EOF
	exit 1
}

# Check argument
if [ $# -eq 0 ]; then
	usage
fi

# Check the csv file
check_file() {
        # Check argument
        if [ $# -eq 0 ]; then
                echo >&2 $"check_file() error: Lack argument for function check_file()!"
                return 1
        fi

	CSV_FILE=$1
	if [ ! -s ${CSV_FILE} ]; then
                echo >&2 $"check_file() error: ${CSV_FILE} does not exist or is empty!"
                return 1
        fi

        return 0
}

# Parse a line in the csv file
parse_line() {
        # Check argument
        if [ $# -eq 0 ]; then
                echo >&2 $"parse_line() error: Lack argument for function parse_line()!"
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
                echo >&2 $"check_element() error: Some required element has null value!"
                echo >&2 $"check_element() info:  Check hostname, networks, device name and device type!"
                return 1
        fi

        # Check mgmtnid
        if [ "${DEVICE_TYPE}" == "ost" ]&&[ -z "${MGMT_NID}" ]; then
                echo >&2 $"check_element() error: OST's mgmtnid element has null value!"
                return 1
        fi

        return 0
}

# Check the number of MGS.
# There should be no more than one MGS specified in the entire csv file.
check_mgs() {
	# Check the number of explicit MGS
	if [ "${DEVICE_TYPE#*mgs*}" != "${DEVICE_TYPE}" ]; then	
		ex_mgs_count=${ex_mgs_count}+1
	fi

	if [ ${ex_mgs_count} -gt 1 ]; then
		echo >&2 $"check_mgs() error: More than one explicit MGS in the csv file!"
		return 1
	fi

	# Check the number of implicit MGS
        if [ "${DEVICE_TYPE}" == "mdt" ]&&[ -z "${MGMT_NID}" ]; then
		im_mgs_count=${im_mgs_count}+1
	fi

	if [ `expr ${im_mgs_count} + ${ex_mgs_count}` -gt 1 ]; then
		echo >&2 $"check_mgs() error: More than one MGS in the csv file!"
		return 1
	fi
	
	return 0
}

# Construct the command line of mkfs.lustre
construct_mkfs_cmdline() {
	MKFS_CMD=$"mkfs.lustre "

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
		echo >&2 $"construct_mkfs_cmdline() error: Invalid device type - \"${DEVICE_TYPE}\""
		return 1
		;;
	esac

	if [ -n "${FS_NAME}" ]; then
		MKFS_CMD=${MKFS_CMD}$"--fsname="${FS_NAME}$" "
	fi

	if [ -n "${MGMT_NID}" ]; then
		MKFS_CMD=${MKFS_CMD}$"--mgmtnid="${MGMT_NID}$" "
	fi

	if [ -n "${INDEX}" ]; then
		MKFS_CMD=${MKFS_CMD}$"--index="${INDEX}$" "
	fi

	if [ -n "${FORMAT_OPTIONS}" ]; then
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
		MKFS_CMD=${MKFS_CMD}$"--failover="${FAILOVERS}$" "
	fi

	MKFS_CMD=${MKFS_CMD}${DEVICE_NAME}
	return 0
} 

# Execute pdsh commands to add lnet options lines to remote nodes'
# modprobe.conf/modules.conf and format(mkfs.lustre) Lustre targets
mass_config() {
	# Check argument
        if [ $# -eq 0 ]; then
                echo >&2 $"mass_config() error: Lack argument for function mass_config()!"
                return 1
        fi

        CSV_FILE=$1
	local LINE COMMAND
	declare -a CONFIG_ITEM
	declare -a PDSH_PID 
	declare -a PDSH_CMD 
	declare -i ex_mgs_count=0
	declare -i im_mgs_count=0
	declare -i line_num=1
	declare -i pid_num=0

	ADD_LNET_OPTIONS=$"/usr/bin/add_lnet_options.sh"

	while read -r LINE; do
		# Get rid of the empty line
		if [ -z "`echo ${LINE} | awk '/[[:alnum:]]/{print $0}'`" ]; then
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

		# Check some required elements
		if ! check_element; then
			echo >&2 $"check_element() error: Occurred on line ${line_num}."
			return 1	
		fi
		
		# Check the number of MGS
		if ! check_mgs; then
			echo >&2 $"check_mgs() error: Occurred on line ${line_num}."
			return 1
		fi

		# Execute pdsh command to add lnet options lines to modprobe.conf/modules.conf
		COMMAND=$"echo \"${NETWORKS}\"|${ADD_LNET_OPTIONS}"
		pdsh -w ${HOST_NAME} ${COMMAND} >&2 &
		PDSH_PID[${pid_num}]=$!
		PDSH_CMD[${pid_num}]="pdsh -w ${HOST_NAME} ${COMMAND}"
		pid_num=${pid_num}+1

		# Construct the command line of mkfs.lustre
		if ! construct_mkfs_cmdline; then
			echo >&2 $"construct_mkfs_cmdline() error: Occurred on line ${line_num}."
			return 1	
		fi

		# Execute pdsh command to format Lustre target
		pdsh -w ${HOST_NAME} ${MKFS_CMD} >&2 &  
		PDSH_PID[${pid_num}]=$!
		PDSH_CMD[${pid_num}]="pdsh -w ${HOST_NAME} ${MKFS_CMD}"
		pid_num=${pid_num}+1

		line_num=${line_num}+1
	done < ${CSV_FILE}

	# Wait for the exit status of the background pdsh command
	echo "Waiting......"
	for ((pid_num = 0; pid_num < ${#PDSH_PID[@]}; pid_num++)); do
		wait ${PDSH_PID[${pid_num}]}
		if [ $? -ne 0 ]; then
			echo >&2 "mass_config() error: Fail to execute \"${PDSH_CMD[${pid_num}]}\"!"
		fi
	done	

	return 0
}

# Main flow
if ! check_file $1; then
	exit 1	
fi

if ! mass_config ${CSV_FILE}; then
	exit 1
fi
exit 0
