#!/bin/sh

LCONF=${LCONF:-../utils/lconf}

if [ ! -f local.xml ]; then
   ./local.sh
fi

${LCONF} --cleanup --dump /tmp/debug local.xml

