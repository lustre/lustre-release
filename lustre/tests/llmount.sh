#!/bin/sh

LCONF=../utils/lconf

if [ ! -f local.xml ]; then
   ./local.sh
fi

${LCONF} --gdb local.xml

