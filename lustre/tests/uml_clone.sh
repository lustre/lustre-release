#!/bin/bash
#
# Test case for 2 different filesystems mounted on the same client.
# Uses 3 umls

set -vx
LMC=${LMC-../utils/lmc}
LCONF=${LCONF-../utils/lconf}
TMP=${TMP:-/tmp}
LLMOUNT=${LLMOUNT:-../utils/llmount}
config=${config:-local_clone.xml}

MDSDEV=${MDSDEV:-$TMP/mds1-`hostname`}
MDS_BACKDEV=${MDS_BACKDEV:-$TMP/mds1-`hostname`}
MDSSIZE=50000
OSTDEV=${OSTDEV:-$TMP/ost1-`hostname`}
OST_BACKDEV=${OST_BACKDEV:-$TMP/ost1-`hostname`}
OSTSIZE=100000
MOUNT=${MOUNT:-/mnt/lustre}
MOUNT_CLONE=${MOUNT_CLONE:-/mnt/clone}

FSTYPE=${FSTYPE:-smfs}
BACKFSTYPE=${BACKFSTYPE:-ext3}

MDS_MOUNT_OPTS=${MDS_MOUNT_OPTS:-"kml,snap"}
OST_MOUNT_OPTS=${OST_MOUNT_OPTS:-"kml,snap"}

CLIENT_MOUNT_OPTS=${CLIENT_MOUNT_OPTS:-"clone=1"}

STRIPE_BYTES=${STRIPE_BYTES:-"65536"}
STRIPE_CNT=${STRIPE_CNT:-"1"}

NETWORKTYPE=${NETWORKTYPE:-tcp}

mkdir -p $MOUNT
mkdir -p $MOUNT_CLONE

rm -rf $config

gen_config() {
	# create nodes
	${LMC} -m $config --add node --node localhost || exit 10
	${LMC} -m $config --add node --node client || exit 10
	${LMC} -m $config --add net --node localhost --nid `hostname` --nettype $NETWORKTYPE || exit 11
	${LMC} -m $config --add net --node client --nid '*' --nettype $NETWORKTYPE || exit 12

	[ "x$MDS_MOUNT_OPTS" != "x" ] &&
	    MDS_MOUNT_OPTS="--mountfsoptions $MDS_MOUNT_OPTS"

	[ "x$OST_MOUNT_OPTS" != "x" ] &&
	    OST_MOUNT_OPTS="--mountfsoptions $OST_MOUNT_OPTS"

	# configure mds server
	${LMC} -m $config --add mds --node localhost --mds mds --fstype $FSTYPE \
	--backfstype $BACKFSTYPE --dev $MDSDEV  --backdev $MDS_BACKDEV \
	$MDS_MOUNT_OPTS --size $MDSSIZE || exit 20

	# configure ost
	${LMC} -m $config --add lov --lov lov --mds mds --stripe_sz $STRIPE_BYTES \
	--stripe_cnt $STRIPE_CNT --stripe_pattern 0 || exit 20

	${LMC} -m $config --add ost  --node localhost --lov lov \
	--fstype $FSTYPE --backfstype $BACKFSTYPE --dev $OSTDEV \
	--backdev $OST_BACKDEV $OST_MOUNT_OPTS --size $OSTSIZE  || exit 30

        ${LMC} -m $config --add mtpt --node client --mds mds --lov lov --path $MOUNT
}
#create snap config
gen_config

$LCONF --reformat -v $config
#setup lustre
$LCONF --nosetup --node client $config

$LLMOUNT `hostname`:/mds/client $MOUNT -o nettype=$NETWORKTYPE

$LLMOUNT `hostname`:/mds/client $MOUNT_CLONE -o nettype=$NETWORKTYPE,clone=1



