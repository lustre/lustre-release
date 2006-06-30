#
# vim:expandtab:shiftwidth=4:softtabstop=4:tabstop=4:
#
# lc_common.sh - This file contains functions to be used by most or all
#                Lustre cluster config scripts.
#
################################################################################

# Remote command 
REMOTE=${REMOTE:-"ssh -x -q"}
#REMOTE=${REMOTE:-"pdsh -S -R ssh -w"}
export REMOTE

# Lustre utilities
CMD_PATH=${CMD_PATH:-"/usr/sbin"}
MKFS=${MKFS:-"$CMD_PATH/mkfs.lustre"}
TUNEFS=${TUNEFS:-"$CMD_PATH/tunefs.lustre"}
LCTL=${LCTL:-"$CMD_PATH/lctl"}

EXPORT_PATH=${EXPORT_PATH:-"PATH=\$PATH:/sbin:/usr/sbin;"}

# Some scripts to be called
SCRIPTS_PATH=${CLUSTER_SCRIPTS_PATH:-"$(cd `dirname $0`; echo $PWD)"}
MODULE_CONFIG=${SCRIPTS_PATH}/lc_modprobe.sh
VERIFY_CLUSTER_NET=${SCRIPTS_PATH}/lc_net.sh
GEN_HB_CONFIG=${SCRIPTS_PATH}/lc_hb.sh
GEN_CLUMGR_CONFIG=${SCRIPTS_PATH}/lc_cluman.sh
SCRIPT_VERIFY_SRVIP=${SCRIPTS_PATH}/lc_servip.sh
SCRIPT_GEN_MONCF=${SCRIPTS_PATH}/lc_mon.sh

# Variables of HA software
HBVER_HBV1="hbv1"                   # Heartbeat version 1
HBVER_HBV2="hbv2"                   # Heartbeat version 2
HATYPE_CLUMGR="cluman"              # Cluster Manager

# Configuration directories and files
HA_DIR=${HA_DIR:-"/etc/ha.d"}		# Heartbeat configuration directory
MON_DIR=${MON_DIR:-"/etc/mon"}		# mon configuration directory
CIB_DIR=${CIB_DIR:-"/var/lib/heartbeat/crm"}	# cib.xml directory

HA_CF=${HA_DIR}/ha.cf               # ha.cf file
HA_RES=${HA_DIR}/haresources        # haresources file
HA_CIB=${CIB_DIR}/cib.xml

CLUMAN_DIR="/etc"			        # CluManager configuration directory
CLUMAN_CONFIG=${CLUMAN_DIR}/cluster.xml

CLUMAN_TOOLS_PATH=${CLUMAN_TOOLS_PATH:-"/usr/sbin"}	# CluManager tools
CONFIG_CMD=${CONFIG_CMD:-"${CLUMAN_TOOLS_PATH}/redhat-config-cluster-cmd"}

HB_TMP_DIR="/tmp/heartbeat"         # Temporary directory
CLUMGR_TMP_DIR="/tmp/clumanager"
TMP_DIRS="${HB_TMP_DIR} ${CLUMGR_TMP_DIR}"

FS_TYPE=${FS_TYPE:-"lustre"}        # Lustre filesystem type
FILE_SUFFIX=${FILE_SUFFIX:-".lustre"}	# Suffix of the generated config files

declare -a CONFIG_ITEM              # Items in each line of the csv file

# verbose_output string
# Output verbose information $string
verbose_output() {
    if ${VERBOSE_OUTPUT}; then
        echo "`basename $0`: $*"
    fi
    return 0
}

# Check whether the reomte command is pdsh
is_pdsh() {
    if [ "${REMOTE}" = "${REMOTE#*pdsh}" ]; then
        return 1
    fi

    return 0
}

# check_file csv_file
# Check the file $csv_file
check_file() {
    # Check argument
    if [ $# -eq 0 ]; then
        echo >&2 "`basename $0`: check_file() error: Missing csv file!"
        return 1
    fi

    CSV_FILE=$1
    if [ ! -s ${CSV_FILE} ]; then
        echo >&2 "`basename $0`: check_file() error: ${CSV_FILE}"\
                 "does not exist or is empty!"
        return 1
    fi

    return 0
}

# parse_line line
# Parse a line in the csv file
parse_line() {
    # Check argument
    if [ $# -eq 0 ]; then
        echo >&2 "`basename $0`: parse_line() error: Missing argument!"
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
                CONFIG_ITEM[i]=${CONFIG_ITEM[i]}"\\"${TMP_LETTER}
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

# fcanon name
# If $name is a symbolic link, then display it's value
fcanon() {
    local NAME=$1

    if [ -h "$NAME" ]; then
        readlink -f "$NAME"
    else
        echo "$NAME"
    fi
}
