#!/bin/bash -x

config=${1:-mdev_linost_lov.xml}

CONFIGDESC=-linost-lov
LMC=${LMC:-../utils/lmc}
TMP=/tmp
#ROUTERS=
OSTS=mdev[6,8]
MDS=mdev9
CLIENTS=mdev[10-15]

OST1=mdev6
OST2=mdev8
h2elan () {
    echo $1 | sed 's/[^0-9]*//g'
}

# configure the mds
${LMC} -o $config --node $MDS --net `h2elan $MDS` elan
${LMC} -m $config --node $MDS --mds mds1 $TMP/mds1 500000
${LMC} -m $config --lov lov1 mds1 4096 0 0

# configure the osts
${LMC} -m $config --node $OST1 --net `h2elan $OST1` elan
${LMC} -m $config --node $OST1 --lov lov1 --ost $TMP/ost1 1000000
${LMC} -m $config --node $OST2 --net `h2elan $OST2` elan
${LMC} -m $config --node $OST2 --lov lov1 --ost $TMP/ost1 1000000

# configure the clients
${LMC} -m $config --node localhost --net '*' elan
${LMC} -m $config --node localhost --mtpt /p/gm1 mds1 lov1
