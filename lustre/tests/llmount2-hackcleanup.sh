#!/bin/sh
# suggested boilerplate for test script

LCONF=${LCONF:-../utils/lconf}
NAME=${NAME:-local2-hack}

config=$NAME.xml

umount /mnt/lustre1
umount /mnt/lustre2
../utils/lctl <<EOF
name2dev OSC2_localhost
cleanup
detach
name2dev MDC2_mds1
cleanup
detach
quit
EOF

${LCONF} --cleanup $config
