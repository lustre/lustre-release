#!/bin/sh

LCONF=${LCONF:-../utils/lconf}
NAME=${NAME:-echo}

config=$NAME.xml
mkconfig=./$NAME.sh

if [ ! -f $config -o $mkconfig -nt $config ]; then
   sh $mkconfig $config || exit 1
fi

$LCONF --reformat --gdb $OPTS $config || exit 4

cat <<EOF

run getattr tests as:
../utils/lctl --device '\$ECHO_$SERVER' test_getattr 1000000
EOF
