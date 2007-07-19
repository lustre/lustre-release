#!/bin/sh

#########################################################################
# gather_stats_everywhere:
# script on a selection of nodes and collect all the results into a single
# tar ball
#
# Copyright (c) 2007 - Cluster File Systems, Inc.
#########################################################################
error() {
	echo "$0: $@"
	exit 1
}

usage() {
	printf $"Usage: gather_stats_everywhere [-help] config_file [start|stop|cleanup] <log_name>\n"
	if [ x$1 = x-h ]
	then
		 printf $"
The distribution script will run on a single node.  It is parameterised 
with a set of target node names.  It may assume ssh/scp to these node 
names works without requiring a password.  It will run in 2 modes...

gather_stats_everywhere config_file start

...will copy the script to /tmp everywhere described in
config_file running on all the target hosts.  And...

gather_stats_everywhere config_file stop log_name

...will stop script running on all the hosts it started on and collect 
all the individual stats files into a single compressed tarball if the log_name is
provided.

The config file is just a list of shell variable assignments that can be
customised. 

Serveral variables must be set in the config file

Targets: the nodes where run the script.
"
		 exit 0
	else
	 	 exit 1
	fi
}

options=`getopt -o h --long help:: -- "$@"`

if [ $? -ne 0 ]
then 
	usage
fi

eval set -- "$options"

while true
do
	case "$1" in
		-h)
			usage -h ;;
		--help)
			usage -h ;;
	        --)
			shift
			break ;;
	esac
done

if [ $# != 2 -a $# != 3 ] ; then
       	usage
fi

CONFIG=$1
OPTION=$2
shift
shift

GLOBAL_TIMESTAMP=""

if [ ! -r $CONFIG ]; then
	error "Config_file: $CONFIG does not exist "
fi

. $CONFIG

if [ -z "$SCRIPT" ]; then
       	error "SCRIPT in ${CONFIG} is empty"
fi	

if [ -z "$TARGETS" ]; then
       	error "TARGETS in ${CONFIG} is empty"
fi

#check nodes accessiable 
Check_nodes_avaible() {
       	local NODES_NOT_AVAIBLE=""

	for TARGET in $TARGETS; do
       		if ! ping -c 1 -w 3 $TARGET > /dev/null; then 
			 NODES_NOT_AVAIBLE=$NODES_NOT_AVAIBLE$TARGET
		fi
       	done
	if [ -z "$NODES_NOT_AVAIBLE" ]; then
		return 0
	else
		echo "Nodes ${NODES_NOT_AVAIBLE} not respond to ping"
		return 1
	fi
}

if ! Check_nodes_avaible;  then 
	error "not all the nodes are availble"
fi

Check_nodes_are_clean() {
	local NODES_NO_CLEAN=""

	# check whether there are running threads on the targets
	for TARGET in $TARGETS; do
		ps_str=`$DSH $TARGET "ps aux | grep -v grep | grep ${SCRIPT}-${TARGET}"`
		if [ -n "$ps_str" ]; then
		       	NODES_NO_CLEAN=${NODES_NO_CLEAN}$TARGET
		fi
	done

	if [ -n "$NODES_NO_CLEAN" ]; then
		return 1 
	fi

	return 0 
}

copy_target_script() {
	local target=$1

	#copy alex's run scripts to the target
	copy_cmd="$DCP $SCRIPT ${USER}${target}:$TMP/${SCRIPT}-${target}"
	${copy_cmd} 1>/dev/null 2>&1 
        if [ ${PIPESTATUS[0]} != 0 ]; then
		echo "copy command failed: ${copy_cmd}" 2>&1
		return 1
	else
		echo "$SCRIPT copied to ${USER}${target} (into $TMP)"
		return 0
	fi
}

start_target_script() {
	local target=$1

	if ! copy_target_script $target; then
		echo "copy_target_script $target failed." 2>&1
		return 1
	fi

	#run the script on the target
	$DSH ${USER}${target} "VMSTAT_INTERVAL=${VMSTAT_INTERVAL} \
		      SDIO_INTERVAL=${SDIO_INTERVAL} \
		      SERVICE_INTERVAL=${SERVICE_INTERVAL} \
		      BRW_INTERVAL=${BRW_INTERVAL} 	   \
		      JBD_INTERVAL=${JBD_INTERVAL}	   \
		      IO_INTERVAL=${IO_INTERVAL}	   \
		      MBALLOC_INTERVAL=${MBALLOC_INTERVAL} \
		      sh ${TMP}/${SCRIPT}-${target} start  \
		      1> /dev/null 2>/dev/null </dev/null"

	if [ ${PIPESTATUS[0]} != 0 ]; then
		echo "Start the ${SCRIPT} on ${target} failed"
		return 1
	else	
		echo "Start the ${SCRIPT} on ${target} success"
		return 0
	fi
}

stop_target_script() {
	local target=$1

	#stop the target script first
	$DSH ${USER}${target} "sh ${TMP}/${SCRIPT}-${target} stop" 1>/dev/null 2>&1
	if [ ${PIPESTATUS[0]} != 0 ]; then
		echo  "stop the collecting stats script on ${target} failed"
		return 1 
	else	
		echo  "stop the collecting stats script on ${target} success"
	fi

	#remove those tmp file
	$DSH ${USER}${target} "rm -rf $TMP/${SCRIPT}-${target}" 1>/dev/null 2>&1
	echo "cleanup ${target} tmp file after stop "
    	return 0
}

generate_timestamp() {
	if [ "X${GLOBAL_TIMESTAMP}" = "X" ]
	then
		export GLOBAL_TIMESTAMP=`date +%F-%H.%M.%S`
		echo "Global Timestamp Created: ${GLOBAL_TIMESTAMP}"
	fi
}

fetch_target_log() {
	generate_timestamp
	local target=$1
	local date=${GLOBAL_TIMESTAMP}
	local target_log_name="stats-${target}-${date}"

	echo "Getting log: ${target_log_name}.tar.gz from ${target}"
	$DSH ${USER}${target} "sh ${TMP}/${SCRIPT}-${target} fetch " \
		      > $TMP/${target_log_name}.tar.gz
	echo "Got log: ${target_log_name}.tar.gz from ${target}"

	echo "Moving $TMP/${target_log_name}.tar.gz to $TMP/$log_name"
	mv $TMP/${target_log_name}.tar.gz $TMP/$log_name
}

fetch_log() {
	generate_timestamp
	local log_name=${GLOBAL_TIMESTAMP}
	local stat_tar_name=$1
	local -a pids_array
	local -a clients_array

	if ! mkdir -p $TMP/$log_name ; then
		error "can not mkdir $log_name"
	fi

    	#retrive the log_tarball from remote nodes background 
        local n=0
	for TARGET in $TARGETS; do
		(fetch_target_log ${TARGET}) & 
		pids_array[$n]=$!
		clients_array[$n]=$TARGET
	        let n=$n+1
	done
	local num_pids=$n

	#Waiting log fetch finished
	for ((n=0; $n < $num_pids; n++)); do
		wait ${pids_array[$n]}
	done

	#compress the log tarball
	cmd="$TAR ${stat_tar_name} $TMP/${log_name}"
	echo "Creating compressed tar file ${stat_tar_name} from log files in  $TMP/${log_name}"
	${cmd} 1>/dev/null 2>&1 
       	if [ ${PIPESTATUS[0]} == 0 ]; then
		echo "removing temporary directory $TMP/${log_name}"
		rm -rf $TMP/${log_name}
	else
		echo "Compressed logfiles are in $TMP/${stat_tar_name}"
	fi
}

stop_targets_script() {
	local -a pids_array
	local -a clients_array
	local n=0
	for TARGET in $TARGETS; do
		(stop_target_script ${TARGET}) &
		pids_array[$n]=$!
		clients_array[$n]=$TARGET
	        let n=$n+1
	done
	local num_pids=$n
	
	#Waiting log fetch finished
	for ((n=0; $n < $num_pids; n++)); do
		if ! wait ${pids_array[$n]}; then
			echo "${clients_array[$n]}: can not stop stats collect"
		fi
	done
}

gather_start() {
	local -a pids_array
	local -a clients_array
	local n=0
	
	#check whether the collect scripts already start in some targets 
	if ! Check_nodes_are_clean ; then
		error "$SCRIPT already running in some targets, please cleanup first"
	fi
	
	for TARGET in $TARGETS; do
		(start_target_script ${TARGET}) &
		pids_array[$n]=$!
		clients_array[$n]=$TARGET
	        let n=$n+1
	done
	local num_pids=$n

	local RC=0	
	#Waiting log fetch finished
	for ((n=0; $n < $num_pids; n++)); do
		if ! wait ${pids_array[$n]}; then
			echo "${clients_array[$n]}: can not start stats collect"
			let RC=$RC+1
		fi
	done

	if [ $RC != 0 ]; then
		stop_targets_script
	fi
}

gather_stop() {
	if Check_nodes_are_clean ; then
		exit 0
	fi
	log=$1

	if [ -n "$log" ]; then
		fetch_log $log
	fi
	stop_targets_script
}

get_end_line_num()
{
	local log_name=$1

	ln=`grep -n snapshot_time ${log_name}  | awk -F":" '{ln=$1;} END{print ln;}'`
	total_ln=`wc ${log_name} | awk '{print $1}'`			

	local endlen=$((${total_ln} - ${ln}))
	echo $endlen
}

get_csv()
{
	local logdir=$1
	local statf=$2

	local statf_name=`basename ${statf}`
	type_name=`echo ${statf_name} | awk -F "." '{print $3}'`
	stat_name=`head -n 1 ${statf} | awk '{print $4}'`
	stat_type=`head -n 1 ${statf} | awk '{print $1}'`

	#currently, it can only analyse client application log
	if [ "$stat_type" != "client" ]; then
		error "can not analyse ${statf} ......."
	fi

	#create the header
	echo "${node_name}_${type_name}, ${stat_name}" \
			>> $logdir/analyse_${type_name}.csv

	#get total stats collection
	end_len=`get_end_line_num ${statf}`
	if [ $end_len != 1 -a $end_len != 0 ]; then
		if [ "$type_name" != "osc-rpc_stats" ]; then
			tail -n $end_len ${statf} | awk '{print $1 "," $2}' \
				>> $logdir/analyse_${type_name}.csv
		else
			tail -n $end_len ${statf} |		 	\
			awk  '/^[[:digit:]]/{print $1","$2","$6} 	\
			      /^page/{print "page per rpc,read,write"}  \
			      /^rpcs/{print "rpcs,read,write"}		\
			      /^offset/{print "offset, read,write"}' 	\
			>> $logdir/analyse_${type_name}.csv
		fi
	fi
}

gather_analyse()
{
	local log_tarball=$1
	local option=$2

	#validating option
	if [ -z "$log_tarball" -o -r "$option" ]; then
		usage;
	fi

	if [ ! -r $log_tarball ]; then
		error " not exist $log_tarball "
	fi

	shift

	local date=`date +%F-%H-%M`
	local logdir="analyse-${date}" 

	mkdir -p ${TMP}/${logdir}
	mkdir -p ${TMP}/${logdir}/tmp

	$UNTAR $log_tarball -C ${TMP}/${logdir}/tmp 1>/dev/null 2>&1
	for log_file in `find $TMP/$logdir/tmp`; do
		if test -f $log_file; then
			#get the node name
			local file_name=`basename ${log_file}`
			node_name=`echo ${file_name} | awk -F "-" '{print $2}'`
			echo "analysing the sublog ...$log_file"
			mkdir -p ${TMP}/${logdir}/${node_name}
			mkdir -p ${TMP}/${logdir}/${node_name}/tmp

			$UNTAR $log_file -C ${TMP}/${logdir}/${node_name}/tmp 1>/dev/null 2>&1
			for statf in `find ${TMP}/${logdir}/${node_name}/tmp`; do
				if test -f $statf ; then
					if [ "$option" == "csv" ]; then
						get_csv "$TMP/$logdir/${node_name}" "$statf"
					fi
				fi
			done
			rm -rf ${TMP}/${logdir}/${node_name}/tmp
		fi
	done

	rm -rf ${TMP}/${logdir}/tmp
	$TAR ${TMP}/${logdir}.tar.gz ${TMP}/${logdir} 1>/dev/null 2>&1

	echo "create analysed tarball ${TMP}/${logdir}.tar.gz"
}

case $OPTION in
	start) gather_start ;;
	stop)  gather_stop $@;;
	analyse) gather_analyse $@;;
	*) error "Unknown option ${OPTION}"
esac
