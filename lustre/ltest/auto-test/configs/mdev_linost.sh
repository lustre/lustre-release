#!/bin/bash -x

config=${1:-mdev_linost.xml}

CONFIGDESC=-linux-ost
LMC=${LMC:-../utils/lmc}
TMP=/tmp
#ROUTERS=
OSTS=mdev6
MDS=mdev8
CLIENTS=mdev[10-15]

h2elan () {
    echo $1 | sed 's/[^0-9]*//g'
}

# configure the mds
${LMC} -o $config --node $MDS --net `h2elan $MDS` elan
${LMC} -m $config --node $MDS --mds mds1 $TMP/mds1 500000

# configure the ost
${LMC} -m $config --node $OSTS --net `h2elan $OSTS` elan
${LMC} -m $config --node $OSTS --ost $TMP/ost1 1000000

# configure the clients
${LMC} -m $config --node localhost --net '*' elan
${LMC} -m $config --node localhost --mtpt /p/gm1 mds1 OSC_$OSTS
