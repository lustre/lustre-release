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

HOSTNAME=`hostname`
SERVER=${SERVER:-$HOSTNAME}
CLIENT=${CLIENT:-$HOSTNAME}
NET=${NET:-tcp}
[ "$ACCEPTOR_PORT" ] && PORT_OPT="--port $ACCEPTOR_PORT"

h2tcp () {
	case $1 in
	client) echo '\*' ;;
	*) echo $1 ;;
	esac
}

h2mx () {
	case $1 in
	client) echo '\*' ;;
	*) echo $1 ;;
	esac
}

h2gm () {
	echo `gmnalnid -n $1`
}

h2elan () {
	echo $1 | sed 's/[^0-9]*//g'
}

h2iib () {
        case $1 in
        client) echo '\*' ;;
        *) echo $1 | sed "s/[^0-9]*//" ;;
        esac
}

#
# PJK: I believe this is correct
# PTL NID's are of the form
# num@ptl
#
h2ptl () { 
        echo $1 | sed 's/[^0-9]*//g' 
}
        
# FIXME: make LMC not require MDS for obdecho LOV
MDSDEV=${MDSDEV:-$TMP/mds1-`hostname`}
MDSSIZE=10000
FSTYPE=${FSTYPE:-ext3}

STRIPE_BYTES=1048576
STRIPES_PER_OBJ=2	# 0 means stripe over all OSTs

rm -f $config
# create nodes
$LMC --add node --node $SERVER  || exit 1
$LMC --add net --node $SERVER --nid `h2$NET $SERVER` --nettype $NET $PORT_OPT|| exit 2

if (($LOV)); then
    $LMC --add mds --node $SERVER --mds mds1 --fstype $FSTYPE --dev $MDSDEV --size $MDSSIZE || exit 10
    $LMC --add lov --lov lov1 --mds mds1 --stripe_sz $STRIPE_BYTES --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0 || exit 11
    $LMC --add ost --node $SERVER --lov lov1 --osdtype=obdecho || exit 12
    $LMC --add ost --node $SERVER --lov lov1 --osdtype=obdecho || exit 13
    OBD_NAME=lov1
else
    $LMC --add ost --ost obd1 --node $SERVER --osdtype=obdecho || exit 12
    OBD_NAME=obd1
fi

if [ "$SERVER" != "$CLIENT" ]; then
   $LMC --add node --node $CLIENT  || exit 1
   $LMC --add net --node $CLIENT --nid `h2$NET $CLIENT` --nettype $NET $PORT_OPT || exit 2
fi

$LMC --add echo_client --node $CLIENT --ost ${OBD_NAME} || exit 3

