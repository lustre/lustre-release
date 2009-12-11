#!/bin/bash


config=${1:-$(basename $0 .sh)}.xml

LMC=${LMC:-../utils/lmc -m $config}
TMP=${TMP:-/tmp}

HOSTNAME=`hostname`

MDSDEV=${MDSDEV:-$TMP/mds1-`hostname`}
MDSSIZE=50000
FSTYPE=${FSTYPE:-ext3}

OSTDEV=${OSTDEV:-$TMP/ost1-`hostname`}
OSTSIZE=200000

rm -f $config
# create nodes
${LMC} --add node --node $HOSTNAME || exit 10
${LMC} --add net --node  $HOSTNAME --nid $HOSTNAME --nettype tcp || exit 11

# configure mds server
${LMC}  --add mds  --node $HOSTNAME --mds mds1 --fstype $FSTYPE --dev $MDSDEV --size $MDSSIZE || exit 20

# configure ost
${LMC} --add ost --node $HOSTNAME --obd obd1 --fstype $FSTYPE --obdtype obdecho || exit 30
# configure ost
${LMC} --add ost --node $HOSTNAME --obd obd2 --fstype $FSTYPE --obdtype obdecho || exit 30

${LMC} --add cobd --node $HOSTNAME --real_obd obd1 --cache_obd obd2

# create client config
# ${LMC} -m $config --add mtpt --node $HOSTNAME --path /mnt/lustre --mds mds1 --obd obd1 || exit 40
