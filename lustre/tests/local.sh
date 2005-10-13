#!/bin/bash

export PATH=`dirname $0`/../utils:$PATH

config=${1:-`basename $0 .sh`.xml}

LMC="${LMC:-lmc} -m $config"
TMP=${TMP:-/tmp}

MDSDEV=${MDSDEV:-$TMP/mds1-`hostname`}
MDSSIZE=${MDSSIZE:-400000}
FSTYPE=${FSTYPE:-ext3}
MOUNT=${MOUNT:-/mnt/lustre}
MOUNT2=${MOUNT2:-${MOUNT}2}
NETTYPE=${NETTYPE:-tcp}

OSTDEV=${OSTDEV:-$TMP/ost1-`hostname`}
OSTSIZE=${OSTSIZE:-400000}

CLIENTOPT="user_xattr,${CLIENTOPT:-""}"

# specific journal size for the ost, in MB
JSIZE=${JSIZE:-0}
[ "$JSIZE" -gt 0 ] && JARG="--journal_size $JSIZE"
MDSISIZE=${MDSISIZE:-0}
[ "$MDSISIZE" -gt 0 ] && IARG="--inode_size $MDSISIZE"

STRIPE_BYTES=${STRIPE_BYTES:-1048576}
STRIPES_PER_OBJ=0	# 0 means stripe over all OSTs

rm -f $config

# create nodes
${LMC} --add node --node localhost || exit 10
${LMC} --add net --node  localhost --nid `hostname` --nettype $NETTYPE || exit 11
${LMC} --add net --node client --nid '*' --nettype $NETTYPE || exit 12

[ "x$MDS_MOUNT_OPTS" != "x" ] &&
    MDS_MOUNT_OPTS="--mountfsoptions $MDS_MOUNT_OPTS"

# configure mds server
${LMC} --add mds --node localhost --mds mds1 --fstype $FSTYPE \
	--dev $MDSDEV \
	$MDS_MOUNT_OPTS --size $MDSSIZE $JARG $IARG $MDSOPT || exit 20

[ "x$OST_MOUNT_OPTS" != "x" ] &&
    OST_MOUNT_OPTS="--mountfsoptions $OST_MOUNT_OPTS"

# configure ost
${LMC} -m $config --add lov --lov lov1 --mds mds1 --stripe_sz $STRIPE_BYTES \
	--stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0 $LOVOPT || exit 20

${LMC} --add ost --node localhost --lov lov1 --fstype $FSTYPE \
	--dev $OSTDEV \
	$OST_MOUNT_OPTS --size $OSTSIZE $JARG $OSTOPT || exit 30

# create client config
[ "x$CLIENTOPT" != "x" ] && CLIENTOPT="--clientoptions $CLIENTOPT"

${LMC} --add mtpt --node localhost --path $MOUNT \
	--mds mds1 --lov lov1 $CLIENTOPT || exit 40
${LMC} --add mtpt --node client --path $MOUNT2 \
	--mds mds1 --lov lov1 $CLIENTOPT || exit 41
