#!/bin/bash

config=${1:-mount2.xml}

SRCDIR=`dirname $0`
PATH=$SRCDIR:$SRCDIR/../utils:$PATH
LMC="${LMC:-lmc} -m $config"
TMP=${TMP:-/tmp}

MDSDEV=${MDSDEV:-$TMP/mds1-`hostname`}
MDSSIZE=${MDSSIZE:-50000}
FSTYPE=${FSTYPE:-ext3}

OSTDEV1=${OSTDEV1:-$TMP/ost1-`hostname`}
OSTDEV2=${OSTDEV2:-$TMP/ost2-`hostname`}
OSTDEV3=${OSTDEV3:-$TMP/ost3-`hostname`}
OSTSIZE=${OSTSIZE:-100000}

STRIPE_BYTES=65536
STRIPES_PER_OBJ=2	# 0 means stripe over all OSTs

rm -f $config

# create nodes
${LMC} --add net --node  localhost --nid localhost --nettype tcp || exit 1

# configure MDS server
${LMC} --add mds  --node localhost --mds mds1 --fstype $FSTYPE --dev $MDSDEV --size $MDSSIZE || exit 10

# configure OSTs
${LMC} --add lov --lov lov1 --mds mds1 --stripe_sz $STRIPE_BYTES --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0 || exit 20
${LMC} --add ost --node localhost --lov lov1 --fstype $FSTYPE --dev $OSTDEV1 --size $OSTSIZE || exit 21
${LMC} --add ost --node localhost --lov lov1 --fstype $FSTYPE --dev $OSTDEV2 --size $OSTSIZE || exit 22
${LMC} --add ost --node localhost --lov lov1 --fstype $FSTYPE --dev $OSTDEV3 --size $OSTSIZE || exit 23

# create client config
${LMC} --add mtpt --node localhost --path /mnt/lustre1 --mds mds1 --ost lov1 || exit 40
${LMC} --add mtpt --node localhost --path /mnt/lustre2 --mds mds1 --ost lov1 || exit 41
