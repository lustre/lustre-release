#!/bin/sh

config=echo.xml
lmc=../utils/lmc
lconf=../utils/lconf

# create nodes
$lmc -o $config --node localhost --net localhost tcp || exit 1
$lmc -m $config --node localhost --obdtype=obdecho --ost|| exit 2
# force the osc to be configured (this is normally done when it is mounted)
$lmc -m $config --node localhost --osc OSC_localhost|| exit 3

$lconf --gdb $config || exit 4

cat <<EOF

run getattr tests as:
../utils/lctl --device '\$OSC_localhost' test_getattr 1000000
EOF

