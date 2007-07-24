#TARGETS: the Node set we will do the script 
PERCH_BIG_FS_MDS_LIST="nid00135"
PERCH_BIG_FS_OST_LIST="nid00128 nid00131 nid00136 nid00139 nid00008 nid00011 nid00012"
export TARGETS="${PERCH_BIG_FS_MDS_LIST} ${PERCH_BIG_FS_OST_LIST}" 

#script var 
#case $TARGET in
#	oss*)     
#		VMSTAT_INTERVAL=0 
#		SERVICE_INTERVAL=2 
#		SDIO_INTERVAL=0  
#	;;
#	client*)  ALEX_SCRIPT_CLIENT_VAR1="hello!"
#	;;
#esac

#FIXME: diff these parameters according to client/MDS/OSS 
VMSTAT_INTERVAL=${VMSTAT_INTERVAL:-1} 
SERVICE_INTERVAL=${SERVICE_INTERVAL:-0}
SDIO_INTERVAL=${SDIO_INTERVAL:-0}
BRW_INTERVAL=${BRW_INTERVAL:-0}
MBALLOC_INTERVAL=${MBALLOC_INTERVAL:-0}
IO_INTERVAL=${IO_INTERVAL:-1}
JBD_INTERVAL=${JBD_INTERVAL:-1}

#some environment var
TMP=${TMP:-"/tmp"}
SCRIPT=${SCRIPT:-"lstats.sh"}
#Remote ssh script
DSH=${DSH:-ssh}
DCP=${DCP:-scp}
USER=""
TAR=${TAR:-tar -zcvf}

