#!/bin/sh
# suggested boilerplate for test script

export PATH=`dirname $0`/../utils:$PATH

LCONF=${LCONF:-lconf}
NAME=${NAME:-local}

config=$NAME.xml
mkconfig=$NAME.sh

if [ "$PORTALS" ]; then
  portals_opt="--portals=$PORTALS"
fi

if [ "$LUSTRE" ]; then
  lustre_opt="--lustre=$LUSTRE"
fi

if [ "$LDAPURL" ]; then
    conf_opt="--ldapurl $LDAPURL --config $NAME"
else
    sh $mkconfig $config || exit 1
    conf_opt="$config"
fi    

[ "$NODE" ] && node_opt="--node $NODE"

if [ "$1" = "-v" ]; then
  verbose="-v"
fi

${LCONF} $portals_opt $lustre_opt $node_opt ${REFORMAT:---reformat} \
    ${GDB:---gdb} $verbose $conf_opt  || exit 2
