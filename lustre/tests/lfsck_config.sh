#!/bin/bash

export PATH=`dirname $0`/../../utils:$PATH

config=${1:-lfsck_config.xml}

LMC="${LMC:-lmc} -m $config"
TMP=${TMP:-/tmp}

MDSDEV=${MDSDEV:-$TMP/mds1-`hostname`}
MDSSIZE=${MDSSIZE:-100000}
FSTYPE=${FSTYPE:-ext3}
MOUNT=${MOUNT:-/mnt/lustre}
#MOUNT2=${MOUNT2:-${MOUNT}2}
NETWORKTYPE=${NETWORKTYPE:-tcp}

OSTSIZE=${OSTSIZE:-200000}

# specific journal size for the ost, in MB
JSIZE=${JSIZE:-0}
[ "$JSIZE" -gt 0 ] && JARG="--journal_size $JSIZE"
MDSISIZE=${MDSISIZE:-128}

STRIPE_BYTES=524288
STRIPES_PER_OBJ=0	# 0 means stripe over all OSTs

rm -f $config

# create nodes
${LMC} --add node --node localhost || exit 10
${LMC} --add net --node  localhost --nid `hostname` --nettype $NETWORKTYPE || exit 11

# configure mds server
${LMC} --add mds --nspath /mnt/mds_ns  --node localhost --mds mds1 --fstype $FSTYPE --dev $MDSDEV --size $MDSSIZE $JARG --mkfsoptions "-I $MDSISIZE" || exit 20

# configure osts
${LMC} -m $config --add lov --lov lov1 --mds mds1 --stripe_sz $STRIPE_BYTES --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0 || exit 20
i=0
while [ $i -lt $NUM_OSTS ]
do
${LMC} --add ost --node localhost --lov lov1 --fstype $FSTYPE --dev $TMP/ost$i-`hostname` --size $OSTSIZE $JARG || exit 30
i=`expr $i + 1`
done

# create client config
${LMC} --add mtpt --node localhost --path $MOUNT --mds mds1 --lov lov1 || exit 40
#${LMC} --add mtpt --node localhost --path $MOUNT2 --mds mds1 --lov lov1 || exit 40
