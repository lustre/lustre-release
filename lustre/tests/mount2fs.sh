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
${LMC} -o $config --node $MDSNODE --net $MDSNODE tcp || exit 1
${LMC} -m $config --node $OSTNODE --net $OSTNODE tcp || exit 2
${LMC} -m $config --node $CLIENT --net $CLIENT tcp || exit 3

# configure mds server
${LMC} -m $config --format --node $MDSNODE --mds mds1 $MDSDEV $MDSSIZE ||exit 10
${LMC} -m $config --format --node $MDSNODE --mds mds2 $MDSDEV2 $MDSSIZE ||exit 10

# configure ost
${LMC} -m $config  --lov lov1 mds1 65536 0 0 || exit 20
${LMC} -m $config  --lov lov2 mds2 65536 0 0 || exit 20
${LMC} -m $config --node $OSTNODE --lov lov1 --ost $OSTDEV1 $OSTSIZE || exit 21
${LMC} -m $config --node $OSTNODE --lov lov2 --ost $OSTDEV2 $OSTSIZE || exit 22

# create client config
${LMC} -m $config  --node $CLIENT --mtpt /mnt/lustre mds1 lov1 || exit 30
${LMC} -m $config  --node $CLIENT --mtpt /mnt/lustre2 mds2 lov2 || exit 30




