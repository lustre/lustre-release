#!/bin/bash

export PATH=`dirname $0`/../utils:$PATH

config=${1:-lov.xml}

LMC=${LMC:-lmc}
TMP=${TMP:-/tmp}

MDSDEV=${MDSDEV:-$TMP/mds1-`hostname`}
MDSSIZE=${MDSSIZE:-50000}
FSTYPE=${FSTYPE:-ext3}

OSTDEV1=${OSTDEV1:-$TMP/ost1-`hostname`}
OSTDEV2=${OSTDEV2:-$TMP/ost2-`hostname`}
OSTDEV3=${OSTDEV3:-$TMP/ost3-`hostname`}
OSTSIZE=${OSTSIZE:-100000}
# 1 to config an echo client instead of llite
ECHO_CLIENT=${ECHO_CLIENT:-}

STRIPE_BYTES=65536
STRIPES_PER_OBJ=2	# 0 means stripe over all OSTs

# create nodes
${LMC} -o $config --add net --node localhost --nid localhost --nettype tcp || exit 1

# configure mds server
${LMC} -m $config --format --add mds --node localhost --mds mds1 --fstype $FSTYPE --dev $MDSDEV --size $MDSSIZE || exit 10

# configure ost
${LMC} -m $config --add lov --lov lov1 --mds mds1 --stripe_sz $STRIPE_BYTES --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0 || exit 20
${LMC} -m $config --add ost --node localhost --lov lov1 --fstype $FSTYPE --dev $OSTDEV1 --size $OSTSIZE || exit 21
${LMC} -m $config --add ost --node localhost --lov lov1 --fstype $FSTYPE --dev $OSTDEV2 --size $OSTSIZE || exit 22
${LMC} -m $config --add ost --node localhost --lov lov1 --fstype $FSTYPE --dev $OSTDEV3 --size $OSTSIZE || exit 23

if [ -z "$ECHO_CLIENT" ]; then
	# create client config
	${LMC} -m $config  --add mtpt --node localhost --path /mnt/lustre --mds mds1 --lov lov1 || exit 30
else
	${LMC} -m $config  --add echo_client --node localhost --ost lov1 || exit 31
fi
