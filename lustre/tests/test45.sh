#!/bin/bash

export PATH="$PATH:`dirname $0`/../utils"

config=${1:-test45.xml}
LMC=${LMC:-lmc}
TMP=${TMP:-/tmp}

COBD_MDS1=${COBD_MDS1:-"cobd_mds1"}
COBD_MDS2=${COBD_MDS2:-"cobd_mds2"}
COBD_LOV1=${COBD_LOV1:-"cobd_lov1"}
COBD_LOV2=${COBD_LOV2:-"cobd_lov2"}
CMOBD_MDS1=${CMOBD_MDS1:-"cmobd-mds1"}
CMOBD_MDS2=${CMOBD_MDS2:-"cmobd-mds2"}
CMOBD_OST1=${CMOBD_OST1:-"cmobd-ost1"}
CMOBD_OST2=${CMOBD_OST2:-"cmobd-ost2"}

MASTER_LMV=${MASTER_LMV:-master-lmv1}
MASTER_MDS1=${MASTER_MDS1:-"master-mds1"}
MASTER_MDS2=${MASTER_MDS2:-"master-mds2"}

CACHE_MDS1=${CACHE_MDS1:-"cache-mds1"}
CACHE_MDS2=${CACHE_MDS2:-"cache-mds2"}

MDS1_MASTER_DEV=$TMP/mds1-master-localhost
MDS2_MASTER_DEV=$TMP/mds2-master-localhost

MDS1_CACHE_DEV=$TMP/mds1-cache-localhost
MDS2_CACHE_DEV=$TMP/mds2-cache-localhost

MDS_MOUNT_OPTS=${MDS_MOUNT_OPTS:-"kml"}
OST_MOUNT_OPTS=${OST_MOUNT_OPTS:-"kml"}

MDSSIZE=${MDSSIZE:-100000}

MASTER_LOV=${MASTER_LOV:-"master-lov"}
MASTER_OST=${MASTER_OST:-"master-ost"}
OST_MASTER_DEV=$TMP/ost1-master-localhost

CACHE_LOV1=${CACHE_LOV1:-"cache-lov1"}
CACHE_LOV2=${CACHE_LOV2:-"cache-lov2"}
CACHE_OST1=${CACHE_OST1:-"cache-ost1"}
CACHE_OST2=${CACHE_OST2:-"cache-ost2"}
OST1_CACHE_DEV=$TMP/ost1-cache-localhost
OST2_CACHE_DEV=$TMP/ost2-cache-localhost

OSTSIZE=${OSTSIZE:-100000}

STRIPECNT=${STRIPECNT:-1}
OSDTYPE=${OSDTYPE:-obdfilter}
OSTFAILOVER=${OSTFAILOVER:-}

FSTYPE=${FSTYPE:-smfs}
BACK_FSTYPE=${BACK_FSTYPE:-ldiskfs}

NETTYPE=${NETTYPE:-tcp}
NIDTYPE=${NIDTYPE:-$NETTYPE}
STRIPE_SIZE=${STRIPE_SIZE:-65536}

NODE1=${NODE1:-"node1"}
NODE2=${NODE2:-"node2"}

FS_NODE1="FS_node1"
FS_NODE2="FS_node2"
FS_MASTER="FS_master"

rm -f $config

h2tcp () {
	case $1 in
	client) echo '\*' ;;
	*) echo $1 ;;
	esac
}

${LMC} -m $config --add filesystem --filesystem $FS_NODE1 || exit 1
${LMC} -m $config --add filesystem --filesystem $FS_NODE2 || exit 1
${LMC} -m $config --add filesystem --filesystem $FS_MASTER || exit 1

# node 1
${LMC} -m $config --add net --node client --nid "*" --nettype $NETTYPE  || exit 1

${LMC} -m $config --add node --node $NODE1 || exit 1
${LMC} -m $config --add net --node $NODE1 --nid `h2$NIDTYPE $NODE1` \
--nettype $NETTYPE || exit 1

${LMC} -m $config --add mds --node $NODE1 --mds $CACHE_MDS1 \
--fstype $FSTYPE --backfstype $BACK_FSTYPE --dev $MDS1_CACHE_DEV \
--mountfsoptions $MDS_MOUNT_OPTS --size $MDSSIZE --format \
--filesystem $FS_NODE1 || exit 10

${LMC} -m $config --add lov --lov $CACHE_LOV1 --mds $CACHE_MDS1 \
--stripe_sz $STRIPE_SIZE --stripe_cnt $STRIPECNT --stripe_pattern 0 || exit 20

${LMC} -m $config --add ost --ost $CACHE_OST1 --node $NODE1 --lov $CACHE_LOV1 \
--fstype $FSTYPE --backfstype $BACK_FSTYPE --dev $OST1_CACHE_DEV --size $OSTSIZE \
--filesystem $FS_NODE1 --mountfsoptions $OST_MOUNT_OPTS || exit 21

${LMC} -m $config --add lmv --lmv $MASTER_LMV || exit 12

${LMC} -m $config --add mds --node $NODE1 --mds $MASTER_MDS1 \
--fstype $BACK_FSTYPE --dev $MDS1_MASTER_DEV --size $MDSSIZE \
--lmv $MASTER_LMV --format --filesystem $FS_MASTER || exit 10

${LMC} -m $config --add mds --node $NODE1 --mds $MASTER_MDS2 \
--fstype $BACK_FSTYPE --dev $MDS2_MASTER_DEV --size $MDSSIZE \
--lmv $MASTER_LMV --format --filesystem $FS_MASTER || exit 10

${LMC} -m $config --add lov --lov $MASTER_LOV --lmv $MASTER_LMV \
--stripe_sz $STRIPE_SIZE --stripe_cnt $STRIPECNT --stripe_pattern 0 || exit 20

${LMC} -m $config --add ost --ost $MASTER_OST --node $NODE1 --lov $MASTER_LOV \
--fstype $BACK_FSTYPE --dev $OST_MASTER_DEV --size $OSTSIZE --filesystem $FS_MASTER || exit 21

${LMC} -m $config --add cmobd --node $NODE1 --cmobd $CMOBD_MDS1 \
--master_obd $MASTER_LMV --cache_obd $CACHE_MDS1 || exit 23

${LMC} -m $config --add cmobd --node $NODE1 --cmobd $CMOBD_OST1 \
--master_obd $MASTER_LOV --cache_obd $CACHE_OST1 || exit 23

# node 2
${LMC} -m $config --add node --node $NODE2 || exit 1
${LMC} -m $config --add net --node $NODE2 --nid `h2$NIDTYPE $NODE2` \
--nettype $NETTYPE || exit 1

${LMC} -m $config --add mds --node $NODE2 --mds $CACHE_MDS2 \
--fstype $FSTYPE --backfstype $BACK_FSTYPE --dev $MDS2_CACHE_DEV \
--mountfsoptions $MDS_MOUNT_OPTS --size $MDSSIZE --format \
--filesystem $FS_NODE2 || exit 10

${LMC} -m $config --add lov --lov $CACHE_LOV2 --mds $CACHE_MDS2 \
--stripe_sz $STRIPE_SIZE --stripe_cnt $STRIPECNT --stripe_pattern 0 || exit 20

${LMC} -m $config --add ost --ost $CACHE_OST2 --node $NODE2 --lov $CACHE_LOV2 \
--fstype $FSTYPE --backfstype $BACK_FSTYPE --dev $OST2_CACHE_DEV --size $OSTSIZE \
--filesystem $FS_NODE2 --mountfsoptions $OST_MOUNT_OPTS || exit 21

${LMC} -m $config --add cmobd --node $NODE2 --cmobd $CMOBD_MDS2 \
--master_obd $MASTER_LMV --cache_obd $CACHE_MDS2 || exit 23

${LMC} -m $config --add cmobd --node $NODE2 --cmobd $CMOBD_OST2 \
--master_obd $MASTER_LOV --cache_obd $CACHE_OST2 || exit 23

# client of node1
${LMC} -m $config --add cobd --node $NODE1 --cobd $COBD_MDS1 \
--master_obd $MASTER_LMV --cache_obd $CACHE_MDS1 || exit 22

${LMC} -m $config --add cobd --node $NODE1 --cobd $COBD_LOV1 \
--master_obd $MASTER_LOV --cache_obd $CACHE_LOV1 || exit 22

${LMC} -m $config --add mtpt --filesystem $FS_NODE1 --node $NODE1 \
--path /mnt/lustre --lmv $COBD_MDS1 --lov $COBD_LOV1 || exit 30

# client of node2
${LMC} -m $config --add cobd --node $NODE2 --cobd $COBD_MDS2 \
--master_obd $MASTER_LMV --cache_obd $CACHE_MDS2 || exit 22

${LMC} -m $config --add cobd --node $NODE2 --cobd $COBD_LOV2 \
--master_obd $MASTER_LOV --cache_obd $CACHE_LOV2 || exit 22

${LMC} -m $config --add mtpt --filesystem $FS_NODE2 --node $NODE2 \
--path /mnt/lustre --lmv $COBD_MDS2 --lov $COBD_LOV2 || exit 30
