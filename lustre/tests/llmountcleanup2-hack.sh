#!/bin/sh

umount /mnt/lustre2
umount /mnt/lustre1
../utils/lctl <<EOF
name2dev OSC2_localhost
cleanup
detach
name2dev MDC2_mds1
cleanup
detach
quit
EOF

LCONF=${LCONF:-../utils/lconf}
NAME=${NAME:-local}

config=$NAME.xml
mkconfig=./$NAME.sh

if [ ! -f $config -o $mkconfig -nt $config ]; then
   sh $mkconfig $config || exit 1
fi

${LCONF} --cleanup --dump /tmp/debug $config
