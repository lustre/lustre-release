#!/bin/bash

# There are configurations for three machines in this config file: the OST,
# the MDS/client, other clients
#
# To start your cluster using the ba-mount.xml file that this produces, first
# run:
# > lconf ba-mount.xml
# on the MDS/client, and then run:
# > lconf --node client ba-mount.xml
# on any other clients.

config=${1:-ba-mount.xml}

LMC_REAL="${LMC:-../utils/lmc} -m $config"
LMC="save_cmd"

TCPBUF=1048576
OST=${OST:-ba-ost-1}
MDS=`hostname`
 
UUIDLIST=${UUIDLIST:-/usr/local/admin/ba-ost/UUID.txt}

h2ip () {
    echo "${1}"
}
BATCH=/tmp/lmc-batch.$$
save_cmd() {
    echo "$@" >> $BATCH
}

[ -f $config ] && rm $config

# MDS/client node
${LMC} --node $MDS --tcpbuf $TCPBUF --net $MDS tcp
${LMC} --node $MDS --mds mds1 /tmp/mds1 50000

OBD_UUID=`awk "/$OST / { print \\$3 }" $UUIDLIST`
[ "$OBD_UUID" ] && OBD_UUID="--obduuid=$OBD_UUID" || echo "$OST: no UUID"

# server node
${LMC} --node $OST --tcpbuf $TCPBUF --net $OST tcp
${LMC} --node $OST $OBD_UUID --ost bluearc

# mount point on the MDS/client
${LMC} --node $MDS --mtpt /mnt/lustre mds1 OSC_$OST

# other clients
${LMC} --node client --tcpbuf $TCPBUF --net '*' tcp
${LMC} --node client --mtpt /mnt/lustre mds1 OSC_$OST

$LMC_REAL --batch $BATCH
rm -f $BATCH
