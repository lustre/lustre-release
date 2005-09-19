#!/bin/bash

config=${1:-mcr.xml}

LMC="../utils/lmc -m $config"

# TCP/IP servers
SERVERS="ba-ost-1  ba-ost-2"
ROUTER=dev5

# Elan clients
CLIENT_LO=dev2
CLIENT_HI=dev25

TCPBUF=1048576
 

h2elan () {
    echo $1 | sed 's/[^0-9]*//g'
}

h2tcp () {
    echo "${1}"
}

[ -f $config ] && rm $config

# Client node
${LMC} --add net --node client --nid '*' --nettype elan || exit 1
# Router node
${LMC} --add net --router --node $ROUTER --tcpbuf $TCPBUF --nid `h2tcp $ROUTER` --nettype tcp || exit 1
${LMC} --add net --node $ROUTER --nid `h2elan $ROUTER` --nettype elan|| exit 1
${LMC} -m $config --add route --node $ROUTER --nettype elan --gw `h2elan $ROUTER` --lo `h2elan $CLIENT_LO` --hi `h2elan $CLIENT_HI` || exit 2

for s in $SERVERS
 do
   # server node
   ${LMC} --add net --node $s --tcpbuf $TCPBUF --nid $s --nettype tcp || exit 1
   # route to server
   ${LMC} --add route --node $ROUTER --nettype tcp --gw `h2tcp $ROUTER` --lo $s || exit 2
   # the device on the server
   ${LMC} --add ost --node $s --obd obd_$s --obdtype=obdecho || exit 3
   # attach to the device on the client (this would normally be a mount)
   ${LMC} --add oscref --node client --osc  OSC_obd_$s || exit 4
done
