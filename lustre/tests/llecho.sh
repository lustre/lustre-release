#!/bin/sh

config=echo.xml
LCONF=${LCONF:-../utils/lconf}
LMC=${LMC:-../utils/lmc}

SERVER=localhost
CLIENT=localhost

# create nodes
$LMC -o $config --node $SERVER --net $SERVER tcp || exit 1
$LMC -m $config --node $SERVER --obdtype=obdecho --ost || exit 2

# force the osc to be configured (this is normally done when it is mounted)
$LMC -m $config --node $CLIENT --osc OSC_$SERVER || exit 3

$LCONF --gdb $config || exit 4

cat <<EOF

run getattr tests as:
../utils/lctl --device \'\$OSC_$SERVER\' test_getattr 1000000
EOF

