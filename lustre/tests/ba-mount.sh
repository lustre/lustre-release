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
${LMC} --add net --node $MDS --tcpbuf $TCPBUF --nid $MDS --nettype tcp
${LMC} --add mds --node $MDS --mds mds1 --dev /tmp/mds1 --size 50000

OBD_UUID=`awk "/$OST / { print \\$3 }" $UUIDLIST`
[ "$OBD_UUID" ] && OBD_UUID="--obduuid=$OBD_UUID" || echo "$OST: no UUID"

# server node
${LMC} --add net --node $OST --tcpbuf $TCPBUF --nid $OST --nettype tcp
${LMC} --add ost --node $OST -obd obd1 --obduuid $OBD_UUID --dev bluearc

# mount point on the MDS/client
${LMC} --add mtpt --node $MDS --path /mnt/lustre --mds mds1 --lov obd1

# other clients
${LMC} --add net --node client --tcpbuf $TCPBUF --nid '*' --nettype tcp
${LMC} --add mtpt --node client --path /mnt/lustre --mds mds1 --lov obd1

$LMC_REAL --batch $BATCH
rm -f $BATCH
