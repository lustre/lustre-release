#!/bin/bash

config=${1:-mcrlov.xml}

LMC="../utils/lmc -m $config"

# TCP/IP servers
SERVERS="ba-ost-1  ba-ost-2"
ROUTER=dev5
MDS=dev7

# Elan clients
CLIENT_LO=dev2
CLIENT_HI=dev25

PORT=2432
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

${LMC} --node $MDS --net `h2elan $MDS` elan || exit 1
${LMC} --node $MDS --mds mds1 /tmp/mds1 100000 || exit 1
${LMC} --lov lov1 mds1 65536 0 0

${LMC} --node client --mtpt /mnt/lustre mds1 lov1

for s in $SERVERS
 do
   # server node
   ${LMC} --node $s --tcpbuf $TCPBUF --net $s tcp $PORT || exit 1
   # route to server
   ${LMC} --node $ROUTER --route tcp `h2ip $ROUTER` $s || exit 2
   # the device on the server
   ${LMC} --format --lov lov1 --node $s --ost bluearc || exit 3
done
