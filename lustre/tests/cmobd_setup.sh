#!/bin/bash

LCTL=${LCTL:-"../utils/lctl"}
CACHE_OST_UUID=${CACHE_OST_UUID:-"OST_localhost_UUID"}
MASTER_UUID=${MASTER_UUID:-"uml2_UUID"}
MASTER_HOST=${MASTER_HOST:-"uml2"}
MASTER_OST_UUID=${MASTER_OST_UUID:-"OST_uml2_UUID"}
MASTER_IP=${MASTER_IP:-"192.168.0.3"}
MASTER_OSC=${MASTER_OSC:-"master_osc"}
MASTER_LOV=${MASTER_LOV:-"master_lov"}
MASTER_LOV_UUID=${MASTER_LOV_UUID:-"master_lov_UUID"}
CACHE_MDS_UUID=${CACHE_MDS_UUID:-"mds1_UUID"}
MASTER_MDC=${MASTER_MDC:-"master_mdc"}
MASTER_MDC_UUID=${MASTER_MDC_UUID:-"master_mdc_UUID"}
MASTER_MDS_UUID=${MASTER_MDS_UUID:-"mds1_UUID"}
CMOBD_OST=${CMOBD:-"cmobd_ost"}
CMOBD_OST_UUID=${CMOBD_UUID:-"cmobd_ost_UUID"}
CMOBD_MDS=${CMOBD:-"cmobd_mds"}
CMOBD_MDS_UUID=${CMOBD_UUID:-"cmobd_mds_UUID"}
MASTER_OST_UP=${MASTER_OST_UP:-1}
MASTER_MDS_UP=${MASTER_MDS_UP:-0}
 
echo "add uuid ${MASTER_UUID} and connect to ${MASTER_IP} ..." 
${LCTL} << EOF
network tcp
add_uuid ${MASTER_UUID} ${MASTER_IP} tcp
send_mem 8388608
recv_mem 8388608
add_autoconn ${MASTER_IP} ${MASTER_HOST} 988
connect ${MASTER_IP} 988
EOF
echo "done!"

echo "insmod cmobd.o"
insmod "../cmobd/cmobd.o" || exit 1
echo "reprovide gdb-friendly module information"
[ -d /r ] && ${LCTL} modules > /r/tmp/ogdb-`hostname`


if [ ${MASTER_OST_UP} == 1 ]; then
	echo "add osc for master lov ..."
${LCTL} << EOF
newdev
attach osc ${MASTER_OSC} ${MASTER_LOV_UUID}
setup ${MASTER_OST_UUID} ${MASTER_UUID}
EOF
	echo "done!"

	echo "add master lov ..."
${LCTL} << EOF
newdev
attach lov ${MASTER_LOV} ${MASTER_LOV_UUID}
lov_setup ${MASTER_LOV_UUID} 1 65536 0 0 ${MASTER_OST_UUID} 
EOF
	echo "done!"

	echo "setup cmobd ost..."
${LCTL} << EOF
newdev
attach cmobd ${CMOBD_OST} ${CMOBD_OST_UUID}
setup ${MASTER_LOV_UUID} ${CACHE_OST_UUID}
EOF
	echo "done!"
fi


if [ ${MASTER_MDS_UP} == 1 ]; then
	echo "add mdc for master mds ..."
${LCTL} << EOF
newdev
attach mdc ${MASTER_MDC} ${MASTER_MDC_UUID}
setup ${MASTER_MDS_UUID} ${MASTER_UUID}
EOF
	echo "done!"

	echo "setup cmobd mdc..."
${LCTL} << EOF
newdev
attach cmobd ${CMOBD_MDS} ${CMOBD_MDS_UUID}
setup ${MASTER_MDC_UUID} ${CACHE_MDS_UUID}
EOF
	echo "done!"
fi
