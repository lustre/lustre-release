#!/bin/bash

BASE=`hostname | sed "s/[i0-9]*$//"`
[ $BASE = "mcr" ] && OSTBASE=${OSTBASE:-ba} || OSTBASE=${OSTBASE:-ba-ost-}

config=${1:-$BASE.xml}

BATCH=/tmp/lmc-batch.$$
save_cmd() {
    echo "$@" >> $BATCH
}

LMC="save_cmd"
LMC_REAL="../../lustre/utils/lmc -m $config"

# TCP/IP servers
SERVER_START=0
SERVER_CNT=64
GW_START=0
GW_CNT=32
MDS=${BASE}23
UUIDLIST=${UUIDLIST:-/usr/local/admin/ba-ost/UUID.txt}

echo "MDS: $MDS"

# This is needed for to create route for elan network
CLIENT_LO=36
CLIENT_HI=155

TCPBUF=1048576
 
h2elan () {
    echo $1 | sed 's/[^0-9]*//g'
}

h2ip () {
    echo "${1}"
}

# map gateway NN to host NN (assumes mcr[22-25] are not gateways)
gw2node() {
	[ $1 -gt 21 ] && echo $(($1 + 4)) || echo $1
}

[ -f $config ] && rm $config

${LMC} --node $MDS --net `h2elan $MDS` elan || exit 1
${LMC} --node $MDS --mds mds1 /tmp/mds1 100000 || exit 1
${LMC} --lov lov1 mds1 65536 1 0

# Client node
#${LMC} --node client --tcpbuf $TCPBUF --net '*' tcp || exit 1
${LMC} --node client --net '*' elan || exit 1
${LMC} --node client --mtpt /mnt/lustre mds1 lov1

# this is crude, but effective
let server_per_gw=($SERVER_CNT / $GW_CNT )
let tot_server=$server_per_gw*$GW_CNT
echo "Allocating $server_per_gw OSTs per gateway."
echo "For a total of $tot_server Blue Arc OSTs"

let gw=$GW_START
let server=$SERVER_START
while (( $gw < $GW_CNT + GW_START ));
do 
   gwnode=$BASE`gw2node $gw`
   echo "Router: $gwnode"
   ${LMC} --router --node $gwnode --tcpbuf $TCPBUF --net `h2ip $gwnode`  tcp || exit 1
   ${LMC} --node $gwnode --net `h2elan $gwnode` elan|| exit 1
   ${LMC} --node $gwnode --route elan `h2elan $gwnode` `h2elan $CLIENT_LO` `h2elan $CLIENT_HI` || exit 2

   let  i=0
   while (( $i < $server_per_gw ));
   do
      OST=${OSTBASE}$server
      echo "server: $OST"
      OBD_UUID=`awk "/$OST / { print \\$3 }" $UUIDLIST`
      [ "$OBD_UUID" ] && OBD_UUID="--obduuid=$OBD_UUID" || echo "$OST: no UUID"
      # server node
      ${LMC} --node $OST --tcpbuf $TCPBUF --net $OST tcp || exit 1
      # the device on the server
      ${LMC} --lov lov1 --node $OST $OBD_UUID --ost bluearc || exit 3
      # route to server
      ${LMC} --node $gwnode --route tcp `h2ip $gwnode` $OST || exit 2
      let server=$server+1 
      let i=$i+1
   done

   let gw=$gw+1
done

$LMC_REAL --batch $BATCH
rm -f $BATCH
