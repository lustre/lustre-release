#!/bin/bash
#
# Test case for 2 different filesystems mounted on the same client.
# Uses 3 umls

config=${config:-`basename $0 .sh`.xml}
LMC=${LMC-../utils/lmc}
TMP=${TMP:-/tmp}

MDSDEV=${MDSDEV:-$TMP/mds1-`hostname`}
MDSDEV2=${MDSDEV2:-$TMP/mds2-`hostname`}
MOUNT=${MOUNT:-/mnt/lustre}
MOUNT1=${MOUNT1:-$MOUNT}
MOUNT2=${MOUNT2:-${MOUNT}2}
MDSSIZE=50000
FSTYPE=${FSTYPE:-ext3}

STRIPE_BYTES=${STRIPE_BYTES:-1048576}
OSTDEV1=${OSTDEV1:-$TMP/ost1-`hostname`}
OSTDEV2=${OSTDEV2:-$TMP/ost2-`hostname`}
OSTSIZE=100000

MDSNODE=${MDSNODE:-uml1}
OSTNODE=${OSTNODE:-uml2}
CLIENT=${CLIENT:-client1}
CLIENT2=${CLIENT2:-client2}

# create nodes
${LMC} -o $config --add net --node $MDSNODE --nid $MDSNODE --nettype tcp || exit 1
${LMC} -m $config --add net --node $OSTNODE --nid $OSTNODE --nettype tcp || exit 2
${LMC} -m $config --add net --node $CLIENT --nid '*' --nettype tcp || exit 3
if [ "$CLIENT" != "$CLIENT2" ]; then
	${LMC} -m $config --add net --node $CLIENT2 --nid '*' --nettype tcp || exit 3
fi

# configure mds server
${LMC} -m $config --add mds --node $MDSNODE --mds mds1 --group fs1 --fstype $FSTYPE --dev $MDSDEV --size $MDSSIZE ||exit 10
${LMC} -m $config --add mds --node $MDSNODE --mds mds2 --group fs2 --fstype $FSTYPE --dev $MDSDEV2 --size $MDSSIZE ||exit 10

# configure ost
${LMC} -m $config --add lov --lov lov1 --mds mds1 --stripe_sz $STRIPE_BYTES --stripe_cnt 0 --stripe_pattern 0 || exit 20
${LMC} -m $config --add lov --lov lov2 --mds mds2 --stripe_sz $STRIPE_BYTES --stripe_cnt 0 --stripe_pattern 0 || exit 20
${LMC} -m $config --add ost --node $OSTNODE --group fs1 --lov lov1 --fstype $FSTYPE --dev $OSTDEV1 --size $OSTSIZE || exit 21
${LMC} -m $config --add ost --node $OSTNODE --group fs2 --lov lov2 --fstype $FSTYPE --dev $OSTDEV2 --size $OSTSIZE || exit 22

# create client config
${LMC} -m $config --add mtpt --node $CLIENT --path ${MOUNT1} --mds mds1 --lov lov1 || exit 30
${LMC} -m $config --add mtpt --node $CLIENT2 --path ${MOUNT2} --mds mds2 --lov lov2 || exit 30
