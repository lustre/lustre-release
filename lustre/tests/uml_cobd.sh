#!/bin/bash

export PATH=`dirname $0`/../utils:$PATH

config=${1:-uml_cobd.xml}
LMC=${LMC:-lmc}
TMP=${TMP:-/tmp}

COBD_MDS=${COBD_MDS:-"cobd1"}
COBD_OST=${COBD_OST:-"cobd2"}

CMOBD_MDS=${CMOBD_MDS:-"cmobd1"}
CMOBD_OST=${CMOBD_OST:-"cmobd2"}


CACHE_MDS=${CACHE_MDS:-"mds1"}
REAL_MDS=${REAL_MDS:-"mds2"}
MDS_CACHE_DEV=$TMP/mds1-`hostname`
MDS_REAL_DEV=$TMP/mds2-`hostname`
MDS_DEV=$TMP/mds
MDSSIZE=${MDSSIZE:-100000}

CACHE_LOV=${CACHE_LOV:-"lov1"}
REAL_LOV=${REAL_LOV:-"lov2"}

CACHE_OST=${CACHE_OST:-"ost1"}
REAL_OST=${REAL_OST:-"ost2"}
OST_CACHE_DEV=$TMP/ost1-`hostname`
OST_REAL_DEV=$TMP/ost2-`hostname`
OST_DEV=$TMP/ost
OSTSIZE=${OSTSIZE:-100000}


STRIPECNT=${STRIPECNT:-1}
OSDTYPE=${OSDTYPE:-obdfilter}
OSTFAILOVER=${OSTFAILOVER:-}

FSTYPE=${FSTYPE:-smfs}
BACKUP_FSTYPE=${BACKUP_FSTYPE:-ext3}

NETTYPE=${NETTYPE:-tcp}
NIDTYPE=${NIDTYPE:-$NETTYPE}

MDSNODE=${MDSNODE:-uml}
OSTNODE=${OSTNODE:-uml}
CLIENT=${CLIENT:-"uml"}
NODE=${NODE:-"uml"}

MDS_MOUNT_OPTS=${MDS_MOUNT_OPTS:-"kml"}
OST_MOUNT_OPTS=${OST_MOUNT_OPTS:-"kml"}


rm -f $config

h2tcp () {
	case $1 in
	client) echo '\*' ;;
	*) echo $1 ;;
	esac
}

                                                                                                                                                                                      
# create nodes
${LMC} -m $config --add net --node $NODE --nid `h2$NIDTYPE $NODE` --nettype $NETTYPE || exit 1

# configure mds server
echo "adding cache MDS on: $MDSNODE"
${LMC} -m $config --add mds --format --node $MDSNODE --mds $CACHE_MDS --fstype $FSTYPE \
--backfstype $BACKUP_FSTYPE --dev $MDS_DEV --backdev $MDS_CACHE_DEV \
--mountfsoptions $MDS_MOUNT_OPTS --size $MDSSIZE ||exit 10

echo "adding real MDS on: $MDSNODE"
${LMC} -m $config --add mds --format --node $MDSNODE --mds $REAL_MDS --fstype $BACKUP_FSTYPE \
--dev $MDS_REAL_DEV --size $MDSSIZE ||exit 10

echo "add cache lov on: $MDSNODE"
${LMC} -m $config --add lov --lov $CACHE_LOV --mds $CACHE_MDS \
--stripe_sz 65536 --stripe_cnt $STRIPECNT --stripe_pattern 0 || exit 20
echo "add real lov on: $MDSNODE"
${LMC} -m $config --add lov --lov $REAL_LOV --mds $REAL_MDS \
--stripe_sz 65536 --stripe_cnt $STRIPECNT --stripe_pattern 0 || exit 20

echo "add cache ost on $OSTNODE"
${LMC} -m $config --add ost --node $NODE --lov $CACHE_LOV \
--fstype $FSTYPE --backfstype $BACKUP_FSTYPE --dev $OST_DEV \
--backdev $OST_CACHE_DEV --mountfsoptions $OST_MOUNT_OPTS --size $OSTSIZE  || exit 21

echo "add real ost on $OSTNODE"
${LMC} -m $config --add ost --node $NODE --lov $REAL_LOV \
--fstype $BACKUP_FSTYPE --dev $OST_REAL_DEV --size $OSTSIZE  || exit 21

echo "add mds lov: $COBD_MDS $COBD_OST"
${LMC} -m $config --add cobd --node $NODE --cobd $COBD_OST --real_obd $REAL_LOV --cache_obd $CACHE_LOV || exit 22 
${LMC} -m $config --add cobd --node $NODE --cobd $COBD_MDS --real_obd $REAL_MDS --cache_obd $CACHE_MDS || exit 22
# create client config(s)

echo "add cmobd: $CMOBD_MDS $CMOBD_OST"
${LMC} -m $config --add cmobd --node $NODE --cmobd $CMOBD_MDS --master_dev $MDS_REAL_DEV --cache_dev $MDS_DEV || exit 23 
${LMC} -m $config --add cmobd --node $NODE --cmobd $CMOBD_OST --master_dev $OST_REAL_DEV --cache_dev $OST_DEV || exit 23

${LMC} -m $config --add mtpt --node $NODE --path /mnt/lustre --mds $COBD_MDS --lov $COBD_OST || exit 30
