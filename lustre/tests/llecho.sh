#!/bin/sh

PATH=`dirname $0`/../utils:$PATH

LCONF=${LCONF:-lconf}
NAME=${NAME:-echo}

config=$NAME.xml
mkconfig=$NAME.sh

if [ "$LUSTRE" ]; then
  lustre_opt="--lustre=$LUSTRE"
fi

[ -f $config ] || sh -x $mkconfig $config || exit 1

$LCONF $lustre_opt --reformat $@ $OPTS $config || exit 4

cat <<EOF

run getattr tests as:
`dirname $0`../utils/lctl --device '\$ECHO_$SERVER' test_getattr 1000000
EOF
