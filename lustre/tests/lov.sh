#!/bin/bash

set -e

export PATH=`dirname $0`/../utils:$PATH

config=${1:-lov.xml}

LMC="${LMC:-lmc} -m $config"
TMP=${TMP:-/tmp}

MDSDEV=${MDSDEV:-$TMP/mds1-`hostname`}
MDSSIZE=${MDSSIZE:-100000}
FSTYPE=${FSTYPE:-ext3}
MOUNT=${MOUNT:-/mnt/lustre}
MOUNT2=${MOUNT2:-${MOUNT}2}
NETWORKTYPE=${NETWORKTYPE:-tcp}

OSTCOUNT=${OSTCOUNT:-5}
# OSTDEVN will still override the device for OST N

OSTSIZE=${OSTSIZE:-150000}
# 1 to config an echo client instead of llite
ECHO_CLIENT=${ECHO_CLIENT:-}

STRIPE_BYTES=65536
STRIPES_PER_OBJ=${STRIPES_PER_OBJ:-$((OSTCOUNT -1))}

# specific journal size for the ost, in MB
JSIZE=${JSIZE:-0}
JARG=""
[ "$JSIZE" -gt 0 ] && JARG="--journal_size $JSIZE"

rm -f $config

# create nodes
${LMC} --add node --node localhost || exit 10
${LMC} --add net --node  localhost --nid `hostname` --nettype $NETWORKTYPE || exit 11
${LMC} --add net --node client --nid '*' --nettype $NETWORKTYPE || exit 12

# configure mds server
${LMC} --format --add mds --node localhost --mds mds1 --fstype $FSTYPE --dev $MDSDEV --size $MDSSIZE || exit 20

# configure ost
${LMC} --add lov --lov lov1 --mds mds1 --stripe_sz $STRIPE_BYTES --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0 || exit 20

for num in `seq $OSTCOUNT`; do
    OST=ost$num
    DEVPTR=OSTDEV$num
    eval $DEVPTR=${!DEVPTR:=$TMP/$OST-`hostname`}
    ${LMC} --add ost --node localhost --lov lov1 --ost $OST --fstype $FSTYPE --dev ${!DEVPTR} --size $OSTSIZE $JARG || exit 30
done


if [ -z "$ECHO_CLIENT" ]; then
	# create client config
	${LMC} --add mtpt --node localhost --path $MOUNT --mds mds1 --lov lov1 || exit 40
	${LMC} --add mtpt --node client --path $MOUNT2 --mds mds1 --lov lov1 || exit 41
else
	${LMC} --add echo_client --node localhost --ost lov1 || exit 42
fi
