#!/bin/bash

config=lov.xml
LMC=../utils/lmc

echo "FIXME: autoformat is no by default, edit $config to change"

# create nodes
${LMC} -o $config --node localhost --net localhost tcp 

# configure mds server
${LMC} -m $config --format --node localhost --mds mds1 /tmp/mds1 50000

# configure ost
${LMC} -m $config --lov lov1 mds1 4096 0 0
${LMC} -m $config --format --node localhost --lov lov1 --ost /tmp/ost1 100000
${LMC} -m $config --format --node localhost --lov lov1 --ost /tmp/ost2 100000

# create client config
${LMC} -m $config  --node localhost --mtpt /mnt/lustre mds1 lov1
