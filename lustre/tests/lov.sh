#!/bin/bash

set -e

export PATH=`dirname $0`/../utils:$PATH

config=${1:-lov.xml}

LMC=${LMC:-lmc}
TMP=${TMP:-/tmp}

MDSDEV=${MDSDEV:-$TMP/mds1-`hostname`}
MDSSIZE=${MDSSIZE:-50000}
FSTYPE=${FSTYPE:-ext3}

OSTCOUNT=${OSTCOUNT:-3}
# OSTDEVN will still override the device for OST N

OSTSIZE=${OSTSIZE:-100000}
# 1 to config an echo client instead of llite
ECHO_CLIENT=${ECHO_CLIENT:-}

STRIPE_BYTES=65536
STRIPES_PER_OBJ=${STRIPES_PER_OBJ:-$((OSTCOUNT -1))}

# create nodes
${LMC} -o $config --add net --node localhost --nid localhost --nettype tcp

# configure mds server
${LMC} -m $config --format --add mds --node localhost --mds mds1 --fstype $FSTYPE --dev $MDSDEV --size $MDSSIZE

# configure ost
${LMC} -m $config --add lov --lov lov1 --mds mds1 --stripe_sz $STRIPE_BYTES --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0

for num in `seq $OSTCOUNT`; do
    OST=ost$num
    DEVPTR=OSTDEV$num
    eval $DEVPTR=${!DEVPTR:=$TMP/$OST-`hostname`}
    ${LMC} -m $config --add ost --node localhost --lov lov1 --ost $OST --fstype $FSTYPE --dev ${!DEVPTR} --size $OSTSIZE
done


if [ -z "$ECHO_CLIENT" ]; then
	# create client config
	${LMC} -m $config  --add mtpt --node localhost --path /mnt/lustre --mds mds1 --lov lov1
else
	${LMC} -m $config  --add echo_client --node localhost --ost lov1
fi
