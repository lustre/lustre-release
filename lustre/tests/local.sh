#!/bin/bash

config=${1:-local.xml}

LMC=${LMC:-../utils/lmc}
TMP=${TMP:-/tmp}

MDSDEV=$TMP/mds1
MDSSIZE=50000

OSTDEV=$TMP/ost1
OSTSIZE=100000

# create nodes
${LMC} -o $config --add node --node localhost || exit 10
${LMC} -o $config --add net --node  localhost --nid localhost --nettype tcp || exit 11

# configure mds server
${LMC} -m $config --add mds  --node localhost --mds mds1 --dev $MDSDEV --size $MDSSIZE || exit 20

# configure ost
${LMC} -m $config --add ost --node localhost --obd obd1 --dev $OSTDEV --size  $OSTSIZE || exit 30

# create client config
${LMC} -m $config --add mtpt --node localhost --path /mnt/lustre --mds mds1 --obd obd1 || exit 40
