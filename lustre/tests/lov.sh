#!/bin/bash

config=${1:-lov.xml}

LMC=../utils/lmc
TMP=${TMP:-/tmp}

# create nodes
${LMC} -o $config --node localhost --net localhost tcp 

# configure mds server
${LMC} -m $config --format --node localhost --mds mds1 $TMP/mds1 50000

# configure ost
${LMC} -m $config --lov lov1 mds1 65536 0 0
${LMC} -m $config --node localhost --lov lov1 --ost $TMP/ost1 100000
${LMC} -m $config --node localhost --lov lov1 --ost $TMP/ost2 100000

# create client config
${LMC} -m $config  --node localhost --mtpt /mnt/lustre mds1 lov1
