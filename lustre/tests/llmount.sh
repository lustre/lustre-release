#!/bin/sh

LCONF=../utils/lconf

if [ ! -f local.xml ]; then
   ./local.sh || exit 1
fi

${LCONF} --reformat --gdb local.xml || exit 2

