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
TCPPORT=988

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
$LMC -o $CONFIG --node client --net '*' elan
$LMC -m $CONFIG --router --node mcr21 --tcpbuf $TCPBUF --net `h2ip $GW_NODE` tcp
$LMC -m $CONFIG --router --node mcr21 --net `h2elan $GW_NODE` elan
$LMC -m $CONFIG --node $GW_NODE --route elan `h2elan $GW_NODE` $CLIENT_ELAN 

# create MDS node entries
for mds in $MDSNODES; do
  elanaddr=`$LUSTRE_QUERY -h emcri -s id=$mds -e`
  $LMC -m $CONFIG --node $mds --net $elanaddr elan
  $LMC -m $CONFIG --node $mds --mds mds_$mds $MDS_DEVICE $MDS_SIZE
done

# create OST node entry
$LMC -m $CONFIG --node $OST_BA --tcpbuf $TCPBUF --net $OST_BA tcp $TCPPORT
$LMC -m $CONFIG --node $OST_BA --obduuid $OST_UUID --ost bluearc
$LMC -m $CONFIG --node $GW_NODE --route tcp `h2ip $GW_NODE` $OST_BA

# mount
$LMC -m $CONFIG --node client --mtpt /mnt/lustre mds_$ACTIVEMDS OSC_$OST_BA
