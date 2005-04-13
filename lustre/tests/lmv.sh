#!/bin/bash

set -e

export PATH=`dirname $0`/../utils:$PATH

config=${1:-lmv.xml}

LMC=${LMC:-lmc}
TMP=${TMP:-/tmp}

MDSSIZE=${MDSSIZE:-100000}
MDSCOUNT=${MDSCOUNT:-3}
OSTDEV=${OSTDEV:-$TMP/ost1-`hostname`}
OSTSIZE=${OSTSIZE:-200000}
OSTCOUNT=${OSTCOUNT:-1}

DEF_FSTYPE=`test "x$(uname -r | grep -o '2.6')" = "x2.6" && echo "ldiskfs" || echo "ext3"`
FSTYPE=${FSTYPE:-$DEF_FSTYPE}
#used only if FSTYPE == smfs, otherwise ignored by lconf
MDS_BACKFSTYPE=${MDS_BACKFSTYPE:-$DEF_FSTYPE}
OST_BACKFSTYPE=${OST_BACKFSTYPE:-$DEF_FSTYPE}

# 1 to config an echo client instead of llite
ECHO_CLIENT=${ECHO_CLIENT:-}

STRIPE_BYTES=65536
STRIPES_PER_OBJ=0

MOUNT=${MOUNT:-/mnt/lustre}

# specific journal size for the ost, in MB
JSIZE=${JSIZE:-0}
JARG=""
[ "$JSIZE" -gt 0 ] && JARG="--journal_size $JSIZE"

rm -f $config

# create nodes
${LMC} -m $config --add node --node localhost || exit 10
${LMC} -m $config --add net --node localhost --nid `hostname` --nettype tcp || exit 11

# configure mds server
${LMC} -m $config --add lmv --lmv lmv1 || exit 12

for num in `seq $MDSCOUNT`; do
    MDSDEV=$TMP/mds${num}-`hostname`
    ${LMC} -m $config --format --add mds --node localhost --mds mds${num} \
        --lmv lmv1 --fstype $FSTYPE --backfstype $MDS_BACKFSTYPE --dev $MDSDEV \
        --size $MDSSIZE || exit 13
done

${LMC} -m $config --add lov --lov lov1 --lmv lmv1 --stripe_sz $STRIPE_BYTES --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0 || exit 20

# configure ost
for num in `seq $OSTCOUNT`; do
    OST=ost$num
    DEVPTR=OSTDEV$num
    eval $DEVPTR=${!DEVPTR:=$TMP/$OST-`hostname`}
    ${LMC} -m $config --add ost --node localhost --lov lov1 --ost $OST --fstype $FSTYPE --backfstype $OST_BACKFSTYPE --dev ${!DEVPTR} --size $OSTSIZE $JARG || exit 30
done

${LMC} -m $config --add mtpt --node localhost --path $MOUNT --lmv lmv1 --lov lov1 || exit 40
