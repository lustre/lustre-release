#!/bin/sh

config=echo.xml
lmc=../utils/lmc
lconf=../utils/lconf

# create nodes
$lmc -o $config --node localhost --net localhost tcp 
$lmc -m $config --node localhost --obdtype=obdecho --ost
# force the osc to be configured (this is normally done when it is mounted)
$lmc -m $config --node localhost --osc OSC_localhost

$lconf --gdb $config

cat <<EOF

run getattr tests as:
../utils/lctl --device '\$OSC_localhost' test_getattr 1000000
EOF

