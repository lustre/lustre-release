#!/bin/sh

LCONF=${LCONF:-../utils/lconf}
NAME=${NAME:-local}

config=$NAME.xml
mkconfig=$NAME.sh

if [ "$PORTALS" ]; then
  portals_opt="--portals=$PORTALS"
fi

if [ ! -f $config -o $mkconfig -nt $config ]; then
   sh $mkconfig $config || exit 1
fi

${LCONF} $portals_opt --gdb $config || exit 2
