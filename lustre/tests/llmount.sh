#!/bin/sh
# suggested boilerplate for test script

LCONF=../utils/lconf
NAME=local

config=$NAME.xml
mkconfig=./$NAME.sh

if [ $mkconfig -nt $local.xml ]; then
   $mkconfig $config || exit 1
fi

${LCONF} --reformat --gdb $config || exit 2

