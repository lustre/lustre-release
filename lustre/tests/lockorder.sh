#!/bin/sh
set -e

export PATH=`dirname $0`:`dirname $0`/../utils:$PATH
CREATEMANY=${CREATEMANY:-createmany}
STATMANY=${STATMANY:-statmany}
UNLINKMANY=${UNLINKMANY:-unlinkmany}
LCTL=${LCTL:-lctl}

MOUNT=${MOUNT:-/mnt/lustre}
MOUNT2=${MOUNT2:-/mnt/lustre2}
DIR=${DIR:-$MOUNT}
DIR2=${DIR2:-$MOUNT2}
COUNT=${COUNT:-100}

cleanup() {
	[ $CR_PID ] && kill -9 $CR_PID
	[ $ST_PID ] && kill -9 $ST_PID
}

trap cleanup EXIT

LOCKDIR=$DIR/lockdir
LOCKFILE=$LOCKDIR/lockfile
rm -rf $LOCKDIR

NUM=0

MINDIR=$DIR
MAXDIR=$DIR
MINRES=4294967295
MAXRES=0
mkdir -p $MINDIR
while [ $MINRES -gt $MAXRES ]; do
	FILETMP=$MINDIR/f$$${NUM}
	DIRTMP=$DIR/d$$/d${NUM}
	touch $FILETMP
	mkdir -p $DIRTMP
	FILERES=`ls -id $FILETMP | awk '{ print $1 }'`
	DIRRES=`ls -id $DIRTMP | awk '{ print $1 }'`
	if [ $DIRRES -gt $MAXRES ]; then
		MAXDIR=$DIRTMP
		MAXRES=$DIRRES
	fi
	if [ $FILERES -lt $MINRES -o -z "$MINFILE" ]; then
		[ -f "$MINFILE" ] && rm $MINFILE
		MINFILE=$FILETMP
		MINRES=$FILERES
	else
		rm $FILETMP
	fi
	NUM=$(($NUM + 1))
done

mv $MAXDIR $LOCKDIR
mv $MINFILE $LOCKFILE
rm -rf $DIR/d$$

$LCTL mark "start dir: $LOCKDIR=$MAXRES file: $LOCKFILE=$MINRES"
# link will lock $LOCKFILE and $DIR as it creates ${LOCKFILE}{0,1,...}
$CREATEMANY -l$LOCKFILE $LOCKFILE -$COUNT &
CR_PID=$!

while ! test -f ${LOCKFILE}1 ; do
	sleep 1
done

# this will lock $DIR and ${LOCKFILE}0
$STATMANY -s $DIR2/lockdir/lockfile 1 -$COUNT &
ST_PID=$!

sleep $(($COUNT / 2))

$UNLINKMANY $DIR2/lockdir/lockfile 1 $(($COUNT * 1000)) || true

trap 0
kill $CR_PID || true
kill $ST_PID || true

rm -rf $LOCKDIR
