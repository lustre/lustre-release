#!/bin/bash
# usually run out of qos.sh
# the following variables are set in qos.sh too and
# get exported
SERVER=${SERVER:-`hostname`}
MOUNT=${MOUNT:-/mnt/lustre} 
# override server_nid and network type if not running
# tcp on interface same as hostname
NETWORKTYPE=${NETWORKTYPE:-tcp}
SERVER_NID=${SERVER_NID:-${SERVER}}

# generic settings
SRCDIR=`dirname $0`
PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$PATH
LMC=${LMC:-lmc}
CONFIG=${1:-qos-config.xml}
TMP=${TMP:-/tmp}
FSTYPE=${FSTYPE:-ext3}
MDSDEV=${MDSDEV:-${TMP}/mds1-`hostname`}
MDSSIZE=${MDSSIZE:-50000}
OSTDEVS=${OSTDEVS:-"${TMP}/ost1-`hostname` ${TMP}/ost2-`hostname` ${TMP}/ost3-`hostname`"}
OSTSIZES=${OSTSIZES:-"100000 100000 100000 "}
STRIPE_BYTES=65536
STRIPES_PER_OBJ=0       # 0 means stripe over all OSTs

element() {
    shift $1
    echo $1
}

# create server node
${LMC} -o ${CONFIG} --add node --node ${SERVER} || exit 10
${LMC} -m ${CONFIG} --add net --node ${SERVER} --nid ${SERVER_NID} --nettype ${NETWORKTYPE} || exit 11
                                                                                                                                  
# configure MDS
${LMC} -m ${CONFIG} --add mds --nspath /mnt/mds_ns --node ${SERVER} --mds qos_mds --fstype ${FSTYPE} \
    --dev ${MDSDEV} --size ${MDSSIZE} || exit 20

# configure LOV
${LMC} -m ${CONFIG} --add lov --lov qos_lov --mds qos_mds --stripe_sz ${STRIPE_BYTES} \
    --stripe_cnt ${STRIPES_PER_OBJ} || exit 30

# configure OSTS
i=1
for obd in $OSTDEVS; do
    obd_size=`element $i ${OSTSIZES}`
    ${LMC} -m ${CONFIG} --add ost --node ${SERVER} --nid ${SERVER_NID} \
	--ost obd$i --lov qos_lov --dev ${obd} --fstype ${FSTYPE} --size ${obd_size} || exit $((i+40))
    i=$((i+1))
done

# create local mount point
${LMC} -m ${CONFIG} --add mtpt --node ${SERVER} --path ${MOUNT} --mds qos_mds --lov qos_lov || exit 50

# create generic client node
${LMC} -m ${CONFIG} --add net --node client --nid '*' --nettype $NETWORKTYPE || exit 60
${LMC} -m ${CONFIG} --add mtpt --node client --path ${MOUNT} --mds qos_mds --lov qos_lov || exit 70
