#!/bin/sh

LCONF=${LCONF:-../utils/lconf}
NAME=${NAME:-local}
TMP=${TMP:-/tmp}

config=$NAME.xml
mkconfig=$NAME.sh

if [ "$PORTALS" ]; then
  portals_opt="--portals=$PORTALS"
fi

if [ ! -f $config ]; then
   sh $mkconfig $config || exit 1
fi

sync; sleep 2; sync
${LCONF} $portals_opt --cleanup --dump $TMP/debug $config
rc=$?
BUSY=`dmesg | grep -i destruct`
if [ "$BUSY" ]; then
	echo "$BUSY" 1>&2
	mv $TMP/debug $TMP/debug-busy.`date +%s`
	exit 255
fi
LEAK_LUSTRE=`dmesg | tail -20 | grep -v "leaked: 0" | grep leaked`
LEAK_PORTALS=`dmesg | tail -20 | grep "Portals memory leaked"`
if [ "$LEAK_LUSTRE" -o "$LEAK_PORTALS" ]; then
	echo "$LEAK_LUSTRE" 1>&2
	echo "$LEAK_PORTALS" 1>&2
	mv $TMP/debug $TMP/debug-leak.`date +%s`
	exit 254
fi

exit $rc
