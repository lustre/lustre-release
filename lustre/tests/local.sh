
#!/bin/bash

config=${1:-local.xml}

LMC="${LMC:-../utils/lmc} -m $config"
TMP=${TMP:-/tmp}

MDSDEV=${MDSDEV:-$TMP/mds1}
MDSSIZE=${MDSSIZE:-50000}

OSTDEV=${OSTDEV:-$TMP/ost1}
OSTSIZE=${OSTSIZE:-200000}

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
${LMC} --add mds  --node localhost --mds mds1 $FSTYPE --dev $MDSDEV --size $MDSSIZE || exit 20

# configure ost
${LMC} --add ost --node localhost --ost obd1 $FSTYPE --dev $OSTDEV --size  $OSTSIZE || exit 30

# create client config
${LMC} --add mtpt --node localhost --path /mnt/lustre --mds mds1 --ost obd1 || exit 40
