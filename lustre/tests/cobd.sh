#!/bin/bash


config=${1:-$(basename $0 .sh)}.xml

LMC=${LMC:-../utils/lmc -m $config}
TMP=${TMP:-/tmp}

MDSDEV=$TMP/mds1
MDSSIZE=50000

OSTDEV=$TMP/ost1
OSTSIZE=200000

kver=`uname -r | cut -d "." -f 1,2`

case $kver in
  2.4) FSTYPE="--fstype=extN"  ;;
  2.5) FSTYPE="--fstype=ext3"  ;;
  *) echo "Kernel version $kver not supported"
     exit 1
     ;;
esac

rm -f $config
# create nodes
${LMC} --add node --node localhost || exit 10
${LMC} --add net --node  localhost --nid localhost --nettype tcp || exit 11

# configure mds server
${LMC}  --add mds  --node localhost --mds mds1 --dev $MDSDEV --size $MDSSIZE || exit 20

# configure ost
${LMC} --add ost --node localhost --obd obd1 --obdtype obdecho || exit 30
# configure ost
${LMC} --add ost --node localhost --obd obd2 --obdtype obdecho || exit 30

${LMC} --add cobd --node localhost --real_obd obd1 --cache_obd obd2

# create client config
# ${LMC} -m $config --add mtpt --node localhost --path /mnt/lustre --mds mds1 --obd obd1 || exit 40
