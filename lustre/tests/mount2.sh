#!/bin/bash

config=${1:-mount2.xml}

LMC=${LMC:-../utils/lmc}
TMP=${TMP:-/tmp}

MDSDEV=$TMP/mds1
MDSSIZE=50000

OSTDEV=$TMP/ost1
OSTSIZE=100000

kver=`uname -r | cut -d "." -f 1,2`

case $kver in
  2.4) FSTYPE="--fstype=extN"  ;;
  2.5) FSTYPE="--fstype=ext3"  ;;
  *) echo "Kernel version $kver not supported"
     exit 1
     ;;
esac

# create nodes
${LMC} -o $config --add net --node localhost --nid localhost --nettype tcp || exit 1

# configure mds server
${LMC} -m $config --add mds --format --node localhost $FSTYPE --mds mds1 --dev $MDSDEV --size $MDSSIZE || exit 2

# configure ost
${LMC} -m $config --add ost --format --obd obd1 --node localhost $FSTYPE --dev $OSTDEV --size $OSTSIZE || exit 3

# create client config
${LMC} -m $config --add mtpt --node localhost --path /mnt/lustre1 --mds mds1 --obd obd1 || exit 4
${LMC} -m $config --add mtpt --node localhost --path /mnt/lustre2 --mds mds1 --obd obd1 || exit 4
