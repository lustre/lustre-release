#!/bin/bash

config=${1:-ba-echo.xml}

LMC_REAL="${LMC:-../utils/lmc} -m $config"
LMC="save_cmd"

TCPBUF=1048576
OST=${OST:-ba-ost-1}
CLIENT=`hostname`

UUIDLIST=${UUIDLIST:-/usr/local/admin/ba-ost/UUID.txt}

h2tcp () {
    echo "${1}"
}
BATCH=/tmp/lmc-batch.$$
save_cmd() {
    echo "$@" >> $BATCH
}

[ -f $config ] && rm $config

# Client node
${LMC} --add net --node $CLIENT --tcpbuf $TCPBUF --nid '*' --nettype tcp

OST_UUID=`awk "/$OST / { print \\$3 }" $UUIDLIST`
[ "$OST_UUID" ] && OST_UUID="--ostuuid=$OST_UUID" || echo "$OST: no UUID"

# server node
${LMC} --add net --node $OST --tcpbuf $TCPBUF --nid $OST --nettype tcp
${LMC} --add ost --node $OST --ost ost1 --osdtype=obdecho $OST_UUID 

# osc on client
${LMC} --add echo_client --node $CLIENT --ost ost1

$LMC_REAL --batch $BATCH
rm -f $BATCH
