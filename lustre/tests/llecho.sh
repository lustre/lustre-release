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

# create nodes
$LMC -o $config --node $SERVER --net $SERVER tcp || exit 1

if (($LOV)); then
    $LMC -m $config --node $SERVER --mds mds1 $MDSDEV $MDSSIZE || exit 10
    $LMC -m $config --lov lov1 mds1 $STRIPE_BYTES $STRIPES_PER_OBJ 0 || exit 11
    $LMC -m $config --node $SERVER --lov lov1 --obdtype=obdecho --ost || exit 12
    $LMC -m $config --node $SERVER --lov lov1 --obdtype=obdecho --ost || exit 13

    $LMC -m $config --node $CLIENT --echo_client lov1 || exit 3
else
    $LMC -m $config --node $SERVER --obdtype=obdecho --ost || exit 2
    # force the osc to be configured (this is normally done when it is mounted)
    $LMC -m $config --node $CLIENT --osc OSC_$SERVER || exit 3
    $LMC -m $config --node $CLIENT --echo_client OSC_${SERVER} || exit 3
fi

$LCONF --gdb $OPTS $config || exit 4

cat <<EOF

run getattr tests as:
../utils/lctl --device '\$ECHO_$SERVER' test_getattr 1000000
EOF
