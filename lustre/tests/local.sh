#!/bin/bash

config=local.xml
LMC=../utils/lmc

# create nodes
${LMC} -o $config --node localhost --net localhost tcp 

# configure mds server
${LMC} -m $config --format  --node localhost --mds mds1 /tmp/mds1 50000

# configure ost
${LMC} -m $config --format --node localhost --ost /tmp/ost1 100000

# create client config
${LMC} -m $config --node localhost --mtpt /mnt/lustre mds1 OSC_localhost
