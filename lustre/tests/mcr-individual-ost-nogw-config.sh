#!/bin/bash

config=${1:-echo-no-gw.xml}

LMC="save_cmd"
LMC_REAL="../../lustre/utils/lmc -m $config"

# TCP/IP servers
SERVER_START=0
SERVER_CNT=62

PORT=2432
TCPBUF=1048576
 
h2ip () {
    echo "${1}"
}
BATCH=/tmp/lmc-batch.$$
save_cmd() {
    echo "$@" >> $BATCH
}

[ -f $config ] && rm $config

# Client node
${LMC} --node client --tcpbuf $TCPBUF --net '*' tcp $PORT || exit 1

# this is crude, but effective
let server_per_gw=($SERVER_CNT / $GW_CNT )
let tot_server=$server_per_gw*$GW_CNT

let server=$SERVER_START
while (( $server < $SERVER_CNT + SERVER_START ));
do 
      echo "server: $server"
      ba=ba$server
      # server node
      ${LMC} --node $ba --tcpbuf $TCPBUF --net $ba tcp $PORT || exit 1
      # the device on the server
      ${LMC} --node $ba --obdtype=obdecho --ost || exit 3
      # osc on client
      ${LMC} --node client --osc OSC_$ba
      let server=$server+1 
done

$LMC_REAL --batch $BATCH
rm -f $BATCH
