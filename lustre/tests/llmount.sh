#!/bin/sh
# suggested boilerplate for test script

LCONF=${LCONF:-../utils/lconf}
NAME=${NAME:-local}

config=$NAME.xml
mkconfig=./$NAME.sh

sh $mkconfig $config || exit 1

${LCONF} --reformat --gdb $config || exit 2
