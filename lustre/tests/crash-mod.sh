#!/bin/sh
TMP=${TMP:-/tmp}
BASEDIR=${1:-`dirname $0`/..}
LCMD=$TMP/crash-mod-`hostname`
echo "Storing crash module info in $LCMD"
cat /tmp/ogdb-`hostname` | while read JUNK M JUNK; do
	MOD="$BASEDIR/$M"
	MODNAME=`basename $MOD .o`

	echo mod -s $MODNAME $MOD  | tee -a $LCMD
done
