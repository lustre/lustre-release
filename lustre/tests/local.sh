#!/bin/bash

config=${1:-local.xml}

LMC=${LMC-../utils/lmc}

# create nodes
${LMC} -o $config --node localhost --net localhost tcp || exit 1

# configure mds server
${LMC} -m $config --format  --node localhost --mds mds1 /tmp/mds1 50000 || exit 2

# configure ost
${LMC} -m $config --format --node localhost --ost /tmp/ost1 100000 || exit 3

# create client config
${LMC} -m $config --node localhost --mtpt /mnt/lustre mds1 OSC_localhost || exit 4
