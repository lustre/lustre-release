#!/bin/bash

config=${1:-ba-echo.xml}

LMC="save_cmd"
LMC_REAL="../../lustre/utils/lmc -m $config"

PORT=988
TCPBUF=1048576
OST=ba-ost-1
CLIENT=client
 
UUIDLIST=${UUIDLIST:-/usr/local/admin/ba-ost/UUID.txt}

h2ip () {
    echo "${1}"
}
BATCH=/tmp/lmc-batch.$$
save_cmd() {
    echo "$@" >> $BATCH
}

[ -f $config ] && rm $config

# Client node
${LMC} --node $CLIENT --tcpbuf $TCPBUF --net '*' tcp $PORT

OBD_UUID=`awk "/$OST / { print \\$3 }" $UUIDLIST`
[ "$OBD_UUID" ] && OBD_UUID="--obduuid=$OBD_UUID" || echo "$OST: no UUID"

# server node
${LMC} --node $OST --tcpbuf $TCPBUF --net $OST tcp $PORT
${LMC} --node $OST --obdtype=obdecho $OBD_UUID --ost

# osc on client
${LMC} --node $CLIENT --osc OSC_$OST

$LMC_REAL --batch $BATCH
rm -f $BATCH
