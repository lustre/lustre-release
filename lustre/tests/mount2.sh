#!/bin/bash

config=${1:-mount2.xml}

SRCDIR=`dirname $0`
PATH=$SRCDIR:$SRCDIR/../utils:$PATH
LMC="${LMC:-lmc} -m $config"
TMP=${TMP:-/tmp}

MDSDEV=${MDSDEV:-$TMP/mds1-`hostname`}
MDSSIZE=${MDSSIZE:-50000}
FSTYPE=${FSTYPE:-ext3}

OSTDEV=${OSTDEV:-$TMP/ost1-`hostname`}
OSTSIZE=${OSTSIZE:-200000}

rm -f $config

# create nodes
${LMC} --add node --node localhost || exit 10
${LMC} --add net --node  localhost --nid localhost --nettype tcp || exit 11

# configure mds server
${LMC} --add mds  --node localhost --mds mds1 --fstype $FSTYPE --dev $MDSDEV --size $MDSSIZE || exit 20

# configure ost
${LMC} --add ost --node localhost --ost ost1 --fstype $FSTYPE --dev $OSTDEV --size  $OSTSIZE || exit 30

# create client config
${LMC} --add mtpt --node localhost --path /mnt/lustre1 --mds mds1 --ost ost1 || exit 40
${LMC} --add mtpt --node localhost --path /mnt/lustre2 --mds mds1 --ost ost1 || exit 40
