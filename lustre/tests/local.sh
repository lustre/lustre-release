#!/bin/bash

config=uml.xml
LMC=../utils/lmc

echo "FIXME: autoformat is no by default, edit $config to change"

# create nodes
${LMC} -o $config --node localhost --net localhost tcp 

# configure mds server
${LMC} -m $config  --node localhost --mds mds1 /tmp/mds1 50000

# configure ost
${LMC} -m $config  --node localhost --ost /tmp/ost1 100000
# is this needed?
# ${LMC} -m $config  --node localhost --mdc MDC_mds1

# create client config
${LMC} -m $config  --node localhost --mtpt /mnt/lustre mds1 ost1

