#!/bin/bash

config=${1-uml.xml}
LMC=${LMC-../utils/lmc}
TMP=${TMP:-/tmp}

MDSDEV=$TMP/mds1
MDSSIZE=50000

OSTDEV1=$TMP/ost1
OSTDEV2=$TMP/ost2
OSTSIZE=100000

MDSNODE=uml1
OSTNODE=uml2
CLIENT=uml3

# create nodes
${LMC} -o $config --node $MDSNODE --net $MDSNODE tcp || exit 1
${LMC} -m $config --node $OSTNODE --net $OSTNODE tcp || exit 2
${LMC} -m $config --node $CLIENT --net $CLIENT tcp || exit 3

# configure mds server
${LMC} -m $config --format --node $MDSNODE --mds mds1 $MDSDEV $MDSSIZE ||exit 10

# configure ost
${LMC} -m $config  --lov lov1 mds1 65536 0 0 || exit 20
${LMC} -m $config --node $OSTNODE --lov lov1 --ost $OSTDEV1 $OSTSIZE || exit 21
${LMC} -m $config --node $OSTNODE --lov lov1 --ost $OSTDEV2 $OSTSIZE || exit 22

# create client config
${LMC} -m $config  --node $CLIENT --mtpt /mnt/lustre mds1 lov1 || exit 30

