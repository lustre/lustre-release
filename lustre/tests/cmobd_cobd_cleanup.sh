#!/bin/bash

LCTL=${LCTL:-"../utils/lctl"}
CACHE_OST_UUID=${CACHE_OST_UUID:-"OST_localhost_UUID"}
MASTER_NID_UUID=${MASTER_NID_UUID:-"uml1_UUID"}
MASTER_NID=${MASTER_NID:-"uml1"}
CACHE_NID=${MASTER_NID:-"uml"}
MASTER_OST_UUID=${MASTER_OST_UUID:-"OST_uml1_UUID"}
MASTER_IP=${MASTER_IP:-"192.168.0.5"}
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
MASTER_MDS_UP=${MASTER_MDS_UP:-1}
 
echo "cleanup ${CMOBD_MDS} ..." 
${LCTL} << EOF
ignore_errors
cfg_device ${CMOBD_MDS}
cleanup
detach
EOF
echo "done!"

echo "cleanup ${MASTER_MDC}"
${LCTL} << EOF
ignore_errors
cfg_device ${MASTER_MDC}
cleanup
detach
EOF
echo "done!"

echo "cleanup ${CMOBD_OST}"
${LCTL} << EOF
ignore_errors
cfg_device ${CMOBD_OST}
cleanup
detach
EOF
echo "done!"

echo "cleanup ${MASTER_OSC}"
${LCTL} << EOF
ignore_errors
cfg_device ${MASTER_OSC}
cleanup
detach
EOF
echo "done!"

echo "cleanup ${MASTER_LOV}"
${LCTL} << EOF
ignore_errors
cfg_device ${MASTER_LOV}
cleanup
detach
EOF
echo "done!"

rmmod cmobd
