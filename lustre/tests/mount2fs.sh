#!/bin/bash
#
# Test case for 2 different filesystems mounted on the same client.
# Uses 3 umls

config=${1-mds-bug.xml}
LMC=${LMC-../utils/lmc}
TMP=${TMP:-/tmp}

MDSDEV=$TMP/mds1
MDSDEV2=$TMP/mds2
MDSSIZE=50000

OSTDEV1=$TMP/ost1
OSTDEV2=$TMP/ost2
OSTSIZE=100000

MDSNODE=uml1
OSTNODE=uml2
CLIENT=uml3

# create nodes
${LMC} -o $config --add net --node $MDSNODE --nid $MDSNODE --nettype tcp || exit 1
${LMC} -m $config --add net --node $OSTNODE --nid $OSTNODE --nettype tcp || exit 2
${LMC} -m $config --add net --node $CLIENT --nid $CLIENT --nettype tcp || exit 3

# configure mds server
${LMC} -m $config --format --add mds --node $MDSNODE --mds mds1 --dev $MDSDEV --size $MDSSIZE ||exit 10
${LMC} -m $config --format --add mds --node $MDSNODE --mds mds2 --dev $MDSDEV2 --size $MDSSIZE ||exit 10

# configure ost
${LMC} -m $config --add lov --lov lov1 --mds mds1 --stripe_sz 65536 --stripe_cnt 0 --stripe_pattern 0 || exit 20
${LMC} -m $config --add lov --lov lov2 --mds mds2 --stripe_sz 65536 --stripe_cnt 0 --stripe_pattern 0 || exit 20
${LMC} -m $config --add ost --node $OSTNODE --lov lov1 --dev $OSTDEV1 --size $OSTSIZE || exit 21
${LMC} -m $config --add ost --node $OSTNODE --lov lov2 --dev $OSTDEV2 --size $OSTSIZE || exit 22

# create client config
${LMC} -m $config --add mtpt --node $CLIENT --path /mnt/lustre --mds mds1 --lov lov1 || exit 30
${LMC} -m $config --add mtpt --node $CLIENT --path /mnt/lustre2 --mds mds2 --lov lov2 || exit 30




