#!/bin/sh
# suggested boilerplate for test script

LCONF=${LCONF:-../utils/lconf}
NAME=${NAME:-local2-hack}

config=$NAME.xml

${LCONF}  --reformat --gdb $config || exit 2

../utils/lctl <<EOF
newdev
attach osc OSC2_localhost OSC2_localhost_UUID
setup OBD_localhost_UUID NET_localhost_tcp_UUID
newdev
attach mdc MDC2_mds1 MDC2_uuid
setup mds1_UUID NET_localhost_tcp_UUID
quit
EOF

mount -t lustre_lite -o osc=OSC2_localhost_UUID,mdc=MDC2_uuid none /mnt/lustre2
