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
SERVER_CNT=4
GW_START=0
GW_CNT=2
MDS=${BASE}23
UUIDLIST=${UUIDLIST:-/usr/local/admin/ba-ost/UUID.txt}

echo "MDS: $MDS"

# This is needed for to create route for elan network
CLIENT_LO=38
CLIENT_HI=191

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

${LMC} --add net --node $MDS --nid `h2elan $MDS` --nettype elan || exit 1
${LMC} --add mds --node $MDS --mds mds1 --dev /tmp/mds1 --size 100000 || exit 1
${LMC} --add lov --lov lov1 --mds mds1 --stripe_sz 65536 --stripe_cnt 1 --stripe_pattern 0

# Client node
#${LMC} --add net --node client --tcpbuf $TCPBUF --nid '*' --nettype tcp || exit 1
${LMC} --add net --node client --nid '*' --nettype elan || exit 1
${LMC} --add mtpt --node client --path /mnt/lustre --mds mds1 --lov lov1

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
   ${LMC} --add net --router --node $gwnode --tcpbuf $TCPBUF --nid `h2ip $gwnode`  --nettype tcp || exit 1
   ${LMC} --add net --node $gwnode --nid `h2elan $gwnode` --nettype elan || exit 1
   ${LMC} --add route --node $gwnode --nettype elan --gw `h2elan $gwnode` --lo `h2elan $CLIENT_LO` --hi `h2elan $CLIENT_HI` || exit 2

   let  i=0
   while (( $i < $server_per_gw ));
   do
      OST=${OSTBASE}$server
      echo "server: $OST"
#      OBD_UUID=`awk "/$OST / { print \\$3 }" $UUIDLIST`
#      [ "$OBD_UUID" ] && OBD_UUID="--obduuid $OBD_UUID" || echo "$OST: no UUID"
      # server node
      ${LMC} --add net --node $OST --tcpbuf $TCPBUF --nid $OST --nettype tcp || exit 1
      # the device on the server
      ${LMC} --add ost --lov lov1 --node $OST $OBD_UUID --dev bluearc || exit 3
      # route to server
      ${LMC} --add route --node $gwnode --nettype tcp --gw `h2ip $gwnode` --lo $OST || exit 2
      let server=$server+1 
      let i=$i+1
   done

   let gw=$gw+1
done

$LMC_REAL --batch $BATCH
rm -f $BATCH
