#!/bin/sh

LCONF=../utils/lconf

if [ ! -f local.xml ]; then
   ./local.sh
fi

${LCONF} --cleanup local.xml

