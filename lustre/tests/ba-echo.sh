#!/bin/bash

config=${1:-ba-echo.xml}

LMC="save_cmd"
LMC_REAL="../../lustre/utils/lmc -m $config"

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
${LMC} --add net --node $CLIENT --tcpbuf $TCPBUF --nid '*' --nettype tcp

OBD_UUID=`awk "/$OST / { print \\$3 }" $UUIDLIST`
[ "$OBD_UUID" ] && OBD_UUID="--obduuid=$OBD_UUID" || echo "$OST: no UUID"

# server node
${LMC} --add net --node $OST --tcpbuf $TCPBUF --nid $OST --nettype tcp
${LMC} --add ost --node $OST --obd obd1 --obdtype=obdecho -obduuid $OBD_UUID 

# osc on client
${LMC} --add oscref --node $CLIENT --echo_client obd1

$LMC_REAL --batch $BATCH
rm -f $BATCH
