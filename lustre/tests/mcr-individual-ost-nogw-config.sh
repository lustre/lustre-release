#!/bin/bash

config=${1:-echo-no-gw.xml}

LMC="save_cmd"
LMC_REAL="../../lustre/utils/lmc -m $config"

# TCP/IP servers
SERVER_START=0
SERVER_CNT=62

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
${LMC} --add net --node client --tcpbuf $TCPBUF --nid '*' --nettype tcp || exit 1

# this is crude, but effective
let server_per_gw=($SERVER_CNT / $GW_CNT )
let tot_server=$server_per_gw*$GW_CNT

let server=$SERVER_START
while (( $server < $SERVER_CNT + SERVER_START ));
do 
      echo "server: $server"
      OST=ba$server
      # server node
      ${LMC} --add net --node $OST --tcpbuf $TCPBUF --nid $OST --nettype tcp || exit 1
      # the device on the server
      ${LMC} --add ost --node $OST --obd obd_$OST --obdtype=obdecho || exit 3
      # osc on client
      ${LMC} --add oscref --node client --osc OSC_obd_$OST
      let server=$server+1 
done

$LMC_REAL --batch $BATCH
rm -f $BATCH
