#!/bin/bash
#
# verify_cluster_net.sh - script for Lustre cluster network verification
#
###############################################################################

# Usage
usage() {
	cat >&2 <<EOF

Usage:	`basename $0` [-v] <csv file>

	-v		verbose mode
	csv file	a spreadsheet that contains configuration parameters 
			(separated by commas) for each target in a Lustre cl-
			uster, the first field of each line is the host name 
			of the cluster node

EOF
	exit 1
}

# Get and check the positional parameters
while getopts "v" OPTION; do
	case $OPTION in
	v) 
		VERBOSE_OPT=$"yes"
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

# Global variables
CSV_FILE=$1
declare -a HOST_NAMES
declare -a HOST_IPADDRS

# Output verbose informations
verbose_output() {
	if [ "${VERBOSE_OPT}" = "yes" ]; then
		echo "`basename $0`: $*"
	fi
	return 0
}

# Check the csv file
check_file() {
	if [ ! -s ${CSV_FILE} ]; then
                echo >&2 $"`basename $0`: check_file() error: ${CSV_FILE}" \
			  "does not exist or is empty!"
                return 1
        fi

        return 0
}

# Get the host names from the csv file
get_hostnames() {
	local NAME CHECK_STR
	declare -i i

	# Initialize the HOST_NAMES array
	for ((i = 0; i < ${#HOST_NAMES[@]}; i++)); do
        	HOST_NAMES[i]=$""
    	done

	CHECK_STR=`egrep -v "([[:space:]]|^)#" ${CSV_FILE} | awk -F, \
		  '/[[:alnum:]]/{if ($1 !~/[[:alnum:]]/) print $0}'`
	if [ -n "${CHECK_STR}" ]; then
                echo >&2 $"`basename $0`: get_hostnames() error: Lack hostname"\
			  "field in the line - ${CHECK_STR}"
		return 1
	fi

	i=0
	for NAME in `egrep -v "([[:space:]]|^)#" ${CSV_FILE}\
		    | awk -F, '/[[:alnum:]]/{print $1}'`
	do
		HOST_NAMES[i]=${NAME}
		i=$i+1
	done

	return 0
}

# Check whether the host name matches the name in the local /etc/hosts table
# and whether the IP address according to the host name is correct
local_check() {
	# Check argument
        if [ $# -ne 2 ]; then
                echo >&2 $"`basename $0`: local_check() error: Lack argument" \
			  "for function local_check()!"
                return 1
        fi

	local RET_STR REAL_NAME

	# Get the IP address according to the host name from /etc/hosts table
	# of the current host 
	HOST_IPADDRS[$2]=`egrep "[[:space:]]$1([[:space:]]|$)" /etc/hosts \
		     | awk '{print $1}'`
	if [ -z "${HOST_IPADDRS[$2]}" ]; then
		echo >&2 "`basename $0`: local_cleck() error: $1 does not" \
			 "exist in the local /etc/hosts table!"
		return 1
	fi

	if [ ${#HOST_IPADDRS[$2]} -gt 15 ]; then
		echo >&2 "`basename $0`: local_cleck() error: More than one" \
			 "IP address line according to $1 in the local" \
			 "/etc/hosts table!"
		return 1
	fi

	# Execute pdsh command to get the real host name
	RET_STR=`pdsh -w ${HOST_IPADDRS[$2]} hostname 2>&1`
	if [ $? -ne 0 ] || [ "${RET_STR}" != "${RET_STR#*connect:*}" ]; then
		echo >&2 "`basename $0`: local_cleck() error: pdsh error:" \
			 "${RET_STR}"
		return 1
	fi

	if [ -z "${RET_STR}" ]; then
		echo >&2 "`basename $0`: local_cleck() error: pdsh error:" \
			 "Nothing get from pdsh! Check the network connectivity"\
			 "between the local host and ${HOST_IPADDRS[$2]}" \
			 "or check the two hosts' rcmd module!"
		return 1
	fi

	REAL_NAME=`echo ${RET_STR} | awk '{print $2}'`
	if [ "$1" != "${REAL_NAME}" ]; then
		echo >&2 "`basename $0`: local_cleck() error: The real hostname"\
			 "according to ${HOST_IPADDRS[$2]} is ${REAL_NAME}," \
			 "not $1! Check the local /etc/hosts table!"
		return 1
	fi

	return 0
}

# Check whether the correct host name and IP address pair matches 
# the one in the remote /etc/hosts tables
remote_check() {
	# Check argument
        if [ $# -ne 2 ]; then
                echo >&2 $"`basename $0`: remote_check() error: Lack argument"\
			  "for function remote_check()!"
                return 1
        fi

	declare -i i
	local RET_STR COMMAND IP_ADDR

	COMMAND=$"egrep \"[[:space:]]$1([[:space:]]|$)\" /etc/hosts"

	# Execute pdsh command to check remote /etc/hosts tables
	for ((i = 0; i < ${#HOST_NAMES[@]}; i++)); do
		RET_STR=`pdsh -w ${HOST_NAMES[i]} ${COMMAND} 2>&1`
		if [ $? -ne 0 ] || [ "${RET_STR}" != "${RET_STR#*connect:*}" ]
		then
			echo >&2 "`basename $0`: remote_check() error:" \
				 "pdsh error: ${RET_STR}"
			return 1
		fi

		IP_ADDR=`echo ${RET_STR} | awk '{print $2}'`
		if [ -z "${IP_ADDR}" ]; then
			echo >&2 "`basename $0`: remote_check() error:" \
				 "$1 does not exist in the ${HOST_NAMES[i]}'s"\
				 "/etc/hosts table!"
			return 1
		fi

		if [ "${IP_ADDR}" != "${HOST_IPADDRS[$2]}" ]; then
			echo >&2 "`basename $0`: remote_check() error:" \
				 "IP address ${IP_ADDR} of $1 in the" \
				 "${HOST_NAMES[i]}'s /etc/hosts is incorrect!"
			return 1
		fi
		
    	done

	return 0
}

# Verify forward and reverse network connectivity of the Lustre cluster
network_check () {
	# Check argument
        if [ $# -eq 0 ]; then
                echo >&2 $"`basename $0`: network_check() error: Lack argument" \
			  "for function network_check()!"
                return 1
        fi

	declare -i i
	local RET_STR COMMAND REAL_NAME

	# Execute pdsh command to check network connectivity
	for ((i = 0; i < ${#HOST_NAMES[@]}; i++)); do
		COMMAND=$"pdsh -w ${HOST_NAMES[i]} hostname"
		RET_STR=`pdsh -w $1 ${COMMAND} 2>&1`
		if [ $? -ne 0 ] || [ "${RET_STR}" != "${RET_STR#*connect:*}" ]
		then
			echo >&2 "`basename $0`: network_check() error:" \
				 "pdsh error: ${RET_STR}"
			return 1
		fi

		if [ -z "${RET_STR}" ]; then
			echo >&2 "`basename $0`: network_check() error:" \
				 "pdsh error: Nothing get from pdsh! Check" \
				 "the network connectivity between $1 and" \
				 "${HOST_NAMES[i]} or the two hosts' rcmd module!"
			return 1
		fi

		REAL_NAME=`echo ${RET_STR} | awk '{print $3}'`
		if [ "${HOST_NAMES[i]}" != "${REAL_NAME}" ]; then
			echo >&2 "`basename $0`: network_check() error:" \
				 "${RET_STR}"
			return 1
		fi
    	done

	return 0
}

# Verify forward and reverse network connectivity of the Lustre cluster,
# and that hostnames match the names in the /etc/hosts tables.
network_verify() {
	declare -i i

	# Initialize the HOST_IPADDRS array
	for ((i = 0; i < ${#HOST_IPADDRS[@]}; i++)); do
        	HOST_IPADDRS[i]=$""
    	done

	# Get all the host names from the csv file
	if ! get_hostnames; then
		return 1
	fi

	# Check whether all the host names match the names in 
	# all the /etc/hosts tables of the Lustre cluster
	for ((i = 0; i < ${#HOST_NAMES[@]}; i++)); do
		verbose_output "Verifying IP address of host" \
			       "${HOST_NAMES[i]} in the local /etc/hosts..."
		if ! local_check ${HOST_NAMES[i]} $i; then
			return 1
		fi
		verbose_output "OK"
	done

	for ((i = 0; i < ${#HOST_NAMES[@]}; i++)); do
		verbose_output "Verifying IP address of host" \
			       "${HOST_NAMES[i]} in the remote /etc/hosts..."
		if ! remote_check ${HOST_NAMES[i]} $i; then
			return 1
		fi
		verbose_output "OK"
	done

	# Verify network connectivity of the Lustre cluster
	for ((i = 0; i < ${#HOST_NAMES[@]}; i++)); do
		verbose_output "Verifying network connectivity of host" \
			       "${HOST_NAMES[i]} to other hosts..."
		if ! network_check ${HOST_NAMES[i]}; then
			return 1
		fi
		verbose_output "OK"
	done

	return 0
}

# Main flow
if ! check_file; then
	exit 1	
fi

if ! network_verify; then
	exit 1	
fi

exit 0
