#!/bin/bash

config=${1:-local.xml}

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
${LMC} -o $config --node localhost --net localhost tcp || exit 1

# configure mds server
${LMC} -m $config --format --node localhost $FSTYPE --mds mds1 $MDSDEV $MDSSIZE || exit 2

# configure ost
${LMC} -m $config --format --node localhost $FSTYPE --ost $OSTDEV $OSTSIZE || exit 3

# create client config
${LMC} -m $config --node localhost --mtpt /mnt/lustre mds1 OSC_localhost || exit 4
