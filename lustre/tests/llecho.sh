#!/bin/sh

config=echo.xml
LCONF=${LCONF:-../utils/lconf}
LMC=${LMC:-../utils/lmc}

SERVER=localhost
CLIENT=localhost

# FIXME: make LMC not require MDS for obdecho LOV
MDSDEV=$TMP/mds1
MDSSIZE=10000

STRIPE_BYTES=65536
STRIPES_PER_OBJ=2	# 0 means stripe over all OSTs

LOV=0
while [ "$1" ]; do
        case $1 in
        --lov) LOV="1" ;;
	*) OPTS="$OPTS $1" ;;
        esac
        shift
done

rm -f $config
# create nodes
$LMC -o $config --add node --node $SERVER  || exit 1
$LMC -m $config --add net --node $SERVER --nid $SERVER --nettype tcp || exit 2

if (($LOV)); then
    $LMC -m $config --add mds --node $SERVER --mds mds1 --dev $MDSDEV --size $MDSSIZE || exit 10
    $LMC -m $config --add lov --lov lov1 --mds mds1 --stripe_sz $STRIPE_BYTES --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0 || exit 11
    $LMC -m $config --add ost --node $SERVER --lov lov1 --obdtype=obdecho || exit 12
    $LMC -m $config --add ost --node $SERVER --lov lov1 --obdtype=obdecho || exit 13
    OBD_NAME=lov1
else
    $LMC -m $config --add ost --obd obd1 --node $SERVER --obdtype=obdecho || exit 2
    OBD_NAME=obd1
fi

if [ "$SERVER" != "$CLIENT" ]; then
   $LMC -m $config --add node --node $CLIENT  || exit 1
   $LMC -m $config --add node --node $CLIENT --nid $CLIENT --nettype tcp || exit 2
fi

$LMC -m $config --add echo_client --node $CLIENT --obd ${OBD_NAME} || exit 3

$LCONF --reformat --gdb $OPTS $config || exit 4

cat <<EOF

run getattr tests as:
../utils/lctl --device '\$ECHO_$SERVER' test_getattr 1000000
EOF
