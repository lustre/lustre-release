#!/bin/bash

export PATH=`dirname $0`/../utils:$PATH

config=${1:-local.xml}

LMC="${LMC:-lmc} -m $config"
TMP=${TMP:-/tmp}

MDSDEV=${MDSDEV:-$TMP/mds1}
MDSSIZE=${MDSSIZE:-50000}

OSTDEV=${OSTDEV:-$TMP/ost1}
OSTSIZE=${OSTSIZE:-200000}
FSTYPE=${FSTYPE:-ext3}

rm -f $config

# create nodes
${LMC} --add node --node localhost || exit 10
${LMC} --add net --node  localhost --nid localhost --nettype tcp || exit 11

# configure mds server
${LMC} --add mds --nspath /mnt/mds_ns  --node localhost --mds mds1  --fstype $FSTYPE --dev $MDSDEV --size $MDSSIZE || exit 20

# configure ost
${LMC} --add ost --nspath /mnt/ost_ns --node localhost --ost ost1  --fstype $FSTYPE --dev $OSTDEV --size  $OSTSIZE || exit 30

# create client config
${LMC} --add mtpt --node localhost --path /mnt/lustre --mds mds1 --ost ost1 || exit 40
