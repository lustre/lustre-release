#!/bin/sh

config=echo.xml
lmc=../utils/lmc
lconf=../utils/lconf

SERVER=localhost
CLIENT=localhost

# create nodes
$lmc -o $config --node $SERVER --net $SERVER tcp || exit 1
$lmc -m $config --node $SERVER --obdtype=obdecho --ost || exit 2

# force the osc to be configured (this is normally done when it is mounted)
$lmc -m $config --node $CLIENT --osc OSC_$SERVER || exit 3

$lconf --gdb $config || exit 4

cat <<EOF

run getattr tests as:
../utils/lctl --device \'\$OSC_$SERVER\' test_getattr 1000000
EOF

