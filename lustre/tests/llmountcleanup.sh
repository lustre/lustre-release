#!/bin/sh

LCONF=${LCONF:-../utils/lconf}
NAME=${NAME:-local}
TMP=${TMP:-/tmp}

config=$NAME.xml
mkconfig=./$NAME.sh

if [ ! -f $config ]; then
   sh $mkconfig $config || exit 1
fi

sync; sleep 2; sync
${LCONF} --cleanup --dump $TMP/debug $config
LEAK=`dmesg | grep -v " 0 bytes" | grep leaked`
if [ "$LEAK" ]; then
	echo "$LEAK" 1>&2
	mv $TMP/debug $TMP/debug.`date +%s`
	#exit -1
fi
BUSY=`dmesg | grep -i destruct`
if [ "$BUSY" ]; then
	echo "$BUSY" 1>&2
	#exit -2
fi
