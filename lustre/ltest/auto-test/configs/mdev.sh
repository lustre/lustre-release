#!/bin/bash -x

config=${1:-mdev.xml}

CONFIGDESC=-ba-lov
LMC=${LMC:-../utils/lmc}
TMP=/tmp
ROUTERS=mdev2
#OSTS=
MDS=mdev6
CLIENTS=mdev[10-15]
CLIENT_LO=mdev10
CLIENT_HI=mdev15

# Strip all but the number from a hostname
h2elan () {
    echo $1 | sed 's/[^0-9]*//g'
}

h2ip () {
    echo "${1}"
}


# configure the mds
${LMC} -o $config --node $MDS --net `h2elan $MDS` elan
${LMC} -m $config --node $MDS --mds mds1 $TMP/mds1 500000

# configure the bluearc osts
${LMC} -m $config --node ba-ost-1 --tcpbuf 1048576 --net ba-ost-1 tcp 988
${LMC} -m $config --node ba-ost-2 --tcpbuf 1048576 --net ba-ost-2 tcp 988

# configure the lov
${LMC} -m $config --lov lov1 mds1 4096 0 0
${LMC} -m $config --node ba-ost-1 --lov lov1 --obduuid d1a77a10-6a5a-11c2-2488-00301700036e --ost bluearc
${LMC} -m $config --node ba-ost-2 --lov lov1 --obduuid 2918e220-6a5b-11c2-26db-00301700043c --ost bluearc

# configure the clients
${LMC} -m $config --node localhost --net '*' elan
${LMC} -m $config --node localhost --mtpt /p/gm1 mds1 lov1

# configure the router
${LMC} -m $config --node $ROUTERS --router
${LMC} -m $config --node $ROUTERS --tcpbuf 1048576 --net `h2ip $ROUTERS` tcp 988
${LMC} -m $config --node $ROUTERS --net `h2elan $ROUTERS` elan
${LMC} -m $config --node $ROUTERS --route elan `h2elan $ROUTERS` `h2elan $CLIENT_LO` `h2elan $CLIENT_HI`
${LMC} -m $config --node $ROUTERS --route tcp $ROUTERS ba-ost-1
${LMC} -m $config --node $ROUTERS --route tcp $ROUTERS ba-ost-2
