#!/bin/bash

config=${1:-mcr.xml}

LMC="../utils/lmc -m $config"

# TCP/IP servers
SERVERS="ba-ost-1  ba-ost-2"
ROUTER=dev5

# Elan clients
CLIENT_LO=dev2
CLIENT_HI=dev25

PORT=988
TCPBUF=1048576
 

h2elan () {
    echo $1 | sed 's/[^0-9]*//g'
}

h2ip () {
    echo "${1}"
}

[ -f $config ] && rm $config

# Client node
${LMC} --node client --net '*' elan || exit 1
# Router node
${LMC} --router --node $ROUTER --tcpbuf $TCPBUF --net `h2ip $ROUTER`  tcp $PORT || exit 1
${LMC} --node $ROUTER --net `h2elan $ROUTER` elan|| exit 1
${LMC} --node $ROUTER --route elan `h2elan $ROUTER` `h2elan $CLIENT_LO` `h2elan $CLIENT_HI` || exit 2

for s in $SERVERS
 do
   # server node
   ${LMC} --node $s --tcpbuf $TCPBUF --net $s tcp $PORT || exit 1
   # route to server
   ${LMC} --node $ROUTER --route tcp `h2ip $ROUTER` $s || exit 2
   # the device on the server
   ${LMC} --node $s --obdtype=obdecho --ost || exit 3
   # attach to the device on the client (this would normally be a moun)
   ${LMC} --node client --osc  OSC_$s || exit 4
done
