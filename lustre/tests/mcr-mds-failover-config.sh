#!/bin/sh

LMC=/usr/local/cfs/lustre/utils/lmc
# LMC="echo lmc"
CONFIG=mcr-mds-failover.xml
LUSTRE_QUERY=/usr/local/cfs/lustre-failover/lustre-query
GW_NODE=mcr21
CLIENT_ELAN=`hostname | sed s/[^0-9]*//;`
OST_BA=ba50
OST_UUID=10400010-5dec-11c2-0b5f-00301700041a
MDS_DEVICE=/dev/sda3
MDS_SIZE=500000
TCPBUF=1048576

MDSNODES=`$LUSTRE_QUERY -h emcri -s id=mds -f`
ACTIVEMDS=`$LUSTRE_QUERY -h emcri -s id=mds -a`

echo "MDS nodes: $MDSNODES, active: $ACTIVEMDS"

h2elan () {
    echo $1 | sed 's/[^0-9]*//g'
}

h2ip () {
    echo "${1}"
}


# create client node
$LMC -o $CONFIG --add net --node client --nid '*' --nettype elan
$LMC -m $CONFIG --add net --router --node mcr21 --tcpbuf $TCPBUF --nid `h2ip $GW_NODE` --nettype tcp
$LMC -m $CONFIG --add net --router --node mcr21 --nid `h2elan $GW_NODE` --nettype elan
$LMC -m $CONFIG --add route --node $GW_NODE --nettype elan --gw `h2elan $GW_NODE` --lo $CLIENT_ELAN 

# create MDS node entries
for mds in $MDSNODES; do
  elanaddr=`$LUSTRE_QUERY -h emcri -s id=$mds -e`
  $LMC -m $CONFIG --add net --node $mds --nid $elanaddr --nettype elan
  $LMC -m $CONFIG --add mds --node $mds --mds mds_$mds --dev $MDS_DEVICE --size $MDS_SIZE
done

# create OST node entry
$LMC -m $CONFIG --add net --node $OST_BA --tcpbuf $TCPBUF --nid $OST_BA --nettype tcp
$LMC -m $CONFIG --add ost --node $OST_BA --obd obd_$OST_BA --obduuid $OST_UUID --dev bluearc
$LMC -m $CONFIG --add route --node $GW_NODE --nettype tcp --gw `h2ip $GW_NODE` --lo $OST_BA

# mount
$LMC -m $CONFIG --add mtpt --node client --path /mnt/lustre --mds mds_$ACTIVEMDS --lov obd_$OST_BA
