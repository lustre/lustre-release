#!/bin/bash

config=${1:-lov.xml}

LMC=../utils/lmc
TMP=${TMP:-/tmp}

MDSDEV=$TMP/mds1
MDSSIZE=50000

OSTDEV1=$TMP/ost1
OSTDEV2=$TMP/ost2
OSTDEV3=$TMP/ost3
OSTSIZE=100000

STRIPE_BYTES=65536
STRIPES_PER_OBJ=2	# 0 means stripe over all OSTs

# create nodes
${LMC} -o $config --node localhost --net localhost tcp || exit 1

# configure mds server
${LMC} -m $config --format --node localhost --mds mds1 $MDSDEV $MDSSIZE || exit 10

# configure ost
${LMC} -m $config --lov lov1 mds1 $STRIPE_BYTES $STRIPES_PER_OBJ 0 || exit 20
${LMC} -m $config --node localhost --lov lov1 --ost $OSTDEV1 $OSTSIZE || exit 21
${LMC} -m $config --node localhost --lov lov1 --ost $OSTDEV2 $OSTSIZE || exit 22
${LMC} -m $config --node localhost --lov lov1 --ost $OSTDEV3 $OSTSIZE || exit 23

# create client config
${LMC} -m $config  --node localhost --mtpt /mnt/lustre mds1 lov1 || exit 30
