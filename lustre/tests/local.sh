#!/bin/bash

config=${1:-local.xml}

LMC=${LMC:-../utils/lmc}
TMP=${TMP:-/tmp}

MDSDEV=$TMP/mds1
MDSSIZE=50000

OSTDEV=$TMP/ost1
OSTSIZE=100000

# create nodes
${LMC} -o $config --node localhost --net localhost tcp || exit 1

# configure mds server
${LMC} -m $config --format  --node localhost --mds mds1 $MDSDEV $MDSSIZE || exit 2

# configure ost
${LMC} -m $config --format --node localhost --ost $OSTDEV $OSTSIZE || exit 3

# create client config
${LMC} -m $config --node localhost --mtpt /mnt/lustre mds1 OBD_localhost || exit 4
