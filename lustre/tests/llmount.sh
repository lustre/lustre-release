#!/bin/sh
# suggested boilerplate for test script

LCONF=${LCONF:-../utils/lconf}
NAME=${NAME:-local}

config=$NAME.xml
mkconfig=$NAME.sh

if [ "$PORTALS" ]; then
  portals_opt="--portals=$PORTALS"
fi

[ -x $LCONF ] || chmod a+rx $LCONF

sh $mkconfig $config || exit 1

${LCONF} $portals_opt --reformat --gdb $config || exit 2
