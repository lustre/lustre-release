#!/bin/bash

LOV=${LOV:-0}
while [ "$1" ]; do
        case $1 in
        --lov) LOV="1" ;;
	*) [ -z $config ] && config=$1 || OPTS="$OPTS $1" ;;
        esac
        shift
done

config=${config:-$(basename $0 .sh).xml}
LMC=${LMC:-../utils/lmc -m $config}
TMP=${TMP:-/tmp}

SERVER=${SERVER:-localhost}
CLIENT=${CLIENT:-localhost}
NET=${NET:-tcp}

# FIXME: make LMC not require MDS for obdecho LOV
MDSDEV=${MDSDEV:-$TMP/mds1}
MDSSIZE=10000

STRIPE_BYTES=65536
STRIPES_PER_OBJ=2	# 0 means stripe over all OSTs

rm -f $config
# create nodes
$LMC --add node --node $SERVER  || exit 1
$LMC --add net --node $SERVER --nid $SERVER --nettype tcp || exit 2

if (($LOV)); then
    $LMC --add mds --node $SERVER --mds mds1 --dev $MDSDEV --size $MDSSIZE || exit 10
    $LMC --add lov --lov lov1 --mds mds1 --stripe_sz $STRIPE_BYTES --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0 || exit 11
    $LMC --add ost --node $SERVER --lov lov1 --obdtype=obdecho || exit 12
    $LMC --add ost --node $SERVER --lov lov1 --obdtype=obdecho || exit 13
    OBD_NAME=lov1
else
    $LMC --add ost --obd obd1 --node $SERVER --obdtype=obdecho || exit 12
    OBD_NAME=obd1
fi

if [ "$SERVER" != "$CLIENT" ]; then
   $LMC --add node --node $CLIENT  || exit 1
   $LMC --add net --node $CLIENT --nid $CLIENT --nettype tcp || exit 2
fi

$LMC --add echo_client --node $CLIENT --obd ${OBD_NAME} || exit 3

