#!/bin/bash

export PATH="$PATH:`dirname $0`/../utils"

config=${1:-cmobd.xml}
LMC=${LMC:-lmc}
TMP=${TMP:-/tmp}

CMOBD_MDS1=${CMOBD_MDS1:-"cmobd-mds1"}
CMOBD_MDS2=${CMOBD_MDS2:-"cmobd-mds2"}

MASTER_LMV=${MASTER_LMV1:-master-lmv1}

CACHE_MDS1=${CACHE_MDS1:-"cache-mds1"}
CACHE_MDS2=${CACHE_MDS2:-"cache-mds2"}
MASTER_MDS1=${MASTER_MDS1:-"master-mds1"}
MASTER_MDS2=${MASTER_MDS2:-"master-mds2"}

MDS1_CACHE_DEV=$TMP/mds1-cache-localhost
MDS2_CACHE_DEV=$TMP/mds2-cache-localhost
MDS1_MASTER_DEV=$TMP/mds1-master-localhost
MDS2_MASTER_DEV=$TMP/mds2-master-localhost

MDS_MOUNT_OPTS=${MDS_MOUNT_OPTS:-"kml"}
OST_MOUNT_OPTS=${OST_MOUNT_OPTS:-"kml"}

MDSSIZE=${MDSSIZE:-100000}

MASTER_LOV=${MASTER_LOV:-"master-lov1"}
MASTER_OST=${MASTER_OST:-"master-ost1"}
OST_MASTER_DEV=$TMP/ost1-master-localhost

OSTSIZE=${OSTSIZE:-100000}

STRIPECNT=${STRIPECNT:-1}
OSDTYPE=${OSDTYPE:-obdfilter}
OSTFAILOVER=${OSTFAILOVER:-}

FSTYPE=${FSTYPE:-smfs}
BACKUP_FSTYPE=${BACKUP_FSTYPE:-ext3}

NETTYPE=${NETTYPE:-tcp}
NIDTYPE=${NIDTYPE:-$NETTYPE}

NODE=${NODE:-"localhost"}

CLIENTS=${CLIENTS:-1}
MODE=${MODE:-lmv}

rm -f $config

h2tcp () {
	case $1 in
	client) echo '\*' ;;
	*) echo $1 ;;
	esac
}

${LMC} -m $config --add net --node $NODE --nid `h2$NIDTYPE $NODE` \
--nettype $NETTYPE || exit 1

${LMC} -m $config --add mds --node $NODE --mds $CACHE_MDS1 --fstype $FSTYPE \
--backfstype $BACKUP_FSTYPE --backdev $MDS1_CACHE_DEV --dev $FSTYPE \
--mountfsoptions $MDS_MOUNT_OPTS --size $MDSSIZE --format || exit 10

if test "x$CLIENTS" = "x2"; then
        ${LMC} -m $config --add mds --node $NODE --mds $CACHE_MDS2 \
        --fstype $FSTYPE --backfstype $BACKUP_FSTYPE --backdev $MDS2_CACHE_DEV \
        --dev $FSTYPE --mountfsoptions $MDS_MOUNT_OPTS --size $MDSSIZE --format || exit 10
fi

if test "x$MODE" = "xmds"; then
        ${LMC} -m $config --add mds --node $NODE --mds $MASTER_MDS1 \
        --fstype $BACKUP_FSTYPE --dev $MDS1_MASTER_DEV --size $MDSSIZE --format || exit 10
else
        ${LMC} -m $config --add lmv --lmv $MASTER_LMV || exit 12

        ${LMC} -m $config --add mds --node $NODE --mds $MASTER_MDS1 \
        --fstype $BACKUP_FSTYPE --dev $MDS1_MASTER_DEV --size $MDSSIZE \
        --lmv $MASTER_LMV --format || exit 10

        ${LMC} -m $config --add mds --node $NODE --mds $MASTER_MDS2 \
        --fstype $BACKUP_FSTYPE --dev $MDS2_MASTER_DEV --size $MDSSIZE \
        --lmv $MASTER_LMV --format || exit 10
fi

if test "x$MODE" = "xmds"; then
        ${LMC} -m $config --add lov --lov $MASTER_LOV --mds $MASTER_MDS1 \
        --stripe_sz 65536 --stripe_cnt $STRIPECNT --stripe_pattern 0 || exit 20
else
        ${LMC} -m $config --add lov --lov $MASTER_LOV --lmv $MASTER_LMV \
        --stripe_sz 65536 --stripe_cnt $STRIPECNT --stripe_pattern 0 || exit 20
fi

${LMC} -m $config --add ost --ost $MASTER_OST --node $NODE --lov $MASTER_LOV \
--fstype $BACKUP_FSTYPE --dev $OST_MASTER_DEV --size $OSTSIZE  || exit 21

if test "x$MODE" = "xmds"; then
        ${LMC} -m $config --add cmobd --node $NODE --cmobd $CMOBD_MDS1 \
        --master_obd $MASTER_MDS1 --cache_obd $CACHE_MDS1 || exit 23 
else
        ${LMC} -m $config --add cmobd --node $NODE --cmobd $CMOBD_MDS1 \
        --master_obd $MASTER_LMV --cache_obd $CACHE_MDS1 || exit 23 
fi

if test "x$CLIENTS" = "x2"; then
        if test "x$MODE" = "xmds"; then
                ${LMC} -m $config --add cmobd --node $NODE --cmobd $CMOBD_MDS2 \
                --master_obd $MASTER_MDS1 --cache_obd $CACHE_MDS2 || exit 23 
        else
                ${LMC} -m $config --add cmobd --node $NODE --cmobd $CMOBD_MDS2 \
                --master_obd $MASTER_LMV --cache_obd $CACHE_MDS2 || exit 23 
        fi
fi

${LMC} -m $config --add mtpt --node $NODE --path /mnt/lustre \
--mds $CACHE_MDS1 --lov $MASTER_LOV || exit 30

if test "x$CLIENTS" = "x2"; then
        ${LMC} -m $config --add mtpt --node $NODE --path /mnt/lustre1 \
        --mds $CACHE_MDS2 --lov $MASTER_LOV || exit 30
fi
