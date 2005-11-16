#!/bin/sh

LCONF=../utils/lconf
NAME=${NAME:-echo}
TMP=${TMP:-/tmp}

config=$NAME.xml
mkconfig=$NAME.sh

if [ ! -f $config ]; then
   sh $mkconfig $config || exit 1
fi

${LCONF} --cleanup $NAME.xml

