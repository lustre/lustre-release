#!/bin/bash

export PATH="$PATH:`dirname $0`/../utils"

config=${1:-cmobd.xml}
LMC=${LMC:-lmc}
TMP=${TMP:-/tmp}

COBD_MDS=${COBD_MDS:-"cobd_mds"}
COBD_OST=${COBD_OST:-"cobd_ost"}
CMOBD_MDS=${CMOBD_MDS:-"cmobd-mds"}

MASTER_LMV=${MASTER_LMV:-master-lmv1}
MASTER_MDS1=${MASTER_MDS1:-"master-mds1"}
MASTER_MDS2=${MASTER_MDS2:-"master-mds2"}
CACHE_MDS=${CACHE_MDS:-"cache-mds"}

MDS1_MASTER_DEV=$TMP/mds1-master-localhost
MDS2_MASTER_DEV=$TMP/mds2-master-localhost
MDS_CACHE_DEV=$TMP/mds-cache-localhost

MDS_MOUNT_OPTS=${MDS_MOUNT_OPTS:-"kml"}
OST_MOUNT_OPTS=${OST_MOUNT_OPTS:-"kml"}

MDSSIZE=${MDSSIZE:-100000}

MASTER_LOV=${MASTER_LOV:-"master-lov1"}
CACHE_LOV=${CACHE_LOV:-"cache-lov1"}
MASTER_OST=${MASTER_OST:-"master-ost1"}
CACHE_OST=${CACHE_OST:-"cache-ost1"}
OST_MASTER_DEV=$TMP/ost1-master-localhost
OST_CACHE_DEV=$TMP/ost1-cache-localhost

OSTSIZE=${OSTSIZE:-100000}

STRIPECNT=${STRIPECNT:-1}
OSDTYPE=${OSDTYPE:-obdfilter}
OSTFAILOVER=${OSTFAILOVER:-}

FSTYPE=${FSTYPE:-smfs}
BACK_FSTYPE=${BACK_FSTYPE:-ldiskfs}

NETTYPE=${NETTYPE:-tcp}
NIDTYPE=${NIDTYPE:-$NETTYPE}
STRIPE_SIZE=${STRIPE_SIZE:-65536}

NODE=${NODE:-"localhost"}

rm -f $config

h2tcp () {
	case $1 in
	client) echo '\*' ;;
	*) echo $1 ;;
	esac
}

${LMC} -m $config --add net --node $NODE --nid `h2$NIDTYPE $NODE` \
--nettype $NETTYPE || exit 1

${LMC} -m $config --add mds --node $NODE --mds $CACHE_MDS \
--fstype $FSTYPE --backfstype $BACK_FSTYPE --dev $MDS_CACHE_DEV \
--mountfsoptions $MDS_MOUNT_OPTS --size $MDSSIZE --format || exit 10

${LMC} -m $config --add lmv --lmv $MASTER_LMV || exit 12

${LMC} -m $config --add mds --node $NODE --mds $MASTER_MDS1 \
--fstype $BACK_FSTYPE --dev $MDS1_MASTER_DEV --size $MDSSIZE \
--lmv $MASTER_LMV --format || exit 10

${LMC} -m $config --add mds --node $NODE --mds $MASTER_MDS2 \
--fstype $BACK_FSTYPE --dev $MDS2_MASTER_DEV --size $MDSSIZE \
--lmv $MASTER_LMV --format || exit 10

${LMC} -m $config --add lov --lov $CACHE_LOV --mds $CACHE_MDS --aware $MASTER_LMV \
--stripe_sz $STRIPE_SIZE --stripe_cnt $STRIPECNT --stripe_pattern 0 || exit 20

${LMC} -m $config --add ost --ost $CACHE_OST --node $NODE --lov $CACHE_LOV \
--fstype $BACK_FSTYPE --dev $OST_CACHE_DEV --size $OSTSIZE  || exit 21

${LMC} -m $config --add cobd --node $NODE --cobd $COBD_MDS \
--master_obd $MASTER_LMV --cache_obd $CACHE_MDS || exit 22

${LMC} -m $config --add mtpt --node $NODE --path /mnt/lustre \
--lmv $COBD_MDS --lov $CACHE_LOV || exit 30

${LMC} -m $config --add cmobd --node $NODE --cmobd $CMOBD_MDS \
--master_obd $MASTER_LMV --cache_obd $CACHE_MDS || exit 23

