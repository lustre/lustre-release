#!/bin/bash

set -e

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
. ${CONFIG:=$LUSTRE/tests/cfg/${NAME}.sh}

export PATH=$LUSTRE/utils:$PATH
LFS=${LFS:-lfs}
LCTL=${LCTL:-lctl}
MOUNT=${MOUNT:-$1}
MOUNT=${MOUNT:-/mnt/lustre}
MOUNT2=${MOUNT2:-$2}
MOUNT2=${MOUNT2:-${MOUNT}2}
OOS=$MOUNT/oosfile
OOS2=$MOUNT2/oosfile2
TMP=${TMP:-/tmp}
LOG=$TMP/$(basename $0 .sh).log
LOG2=${LOG}2

SUCCESS=1

rm -f $OOS $OOS2 $LOG $LOG2

sync; sleep 1; sync	# to ensure we get up-to-date statfs info

STRIPECOUNT=`$LCTL get_param -n lov.*.activeobd | head -n 1`
ORIGFREE=`$LCTL get_param -n llite.*.kbytesavail | head -n 1`
MAXFREE=${MAXFREE:-$((400000 * $STRIPECOUNT))}
echo STRIPECOUNT=$STRIPECOUNT ORIGFREE=$ORIGFREE MAXFREE=$MAXFREE
if [ $ORIGFREE -gt $MAXFREE ]; then
	skip "$0: ${ORIGFREE}kB free gt MAXFREE ${MAXFREE}kB, increase $MAXFREE (or reduce test fs size) to proceed"
	exit 0
fi

export LANG=C LC_LANG=C # for "No space left on device" message

# make sure we stripe over all OSTs to avoid OOS on only a subset of OSTs
$LFS setstripe $OOS -c $STRIPECOUNT
$LFS setstripe $OOS2 -c $STRIPECOUNT
dd if=/dev/zero of=$OOS count=$((3 * $ORIGFREE / 4 + 100)) bs=1k 2>> $LOG &
DDPID=$!
if dd if=/dev/zero of=$OOS2 count=$((3*$ORIGFREE/4 + 100)) bs=1k 2>> $LOG2; then
	echo "ERROR: dd2 did not fail"
	SUCCESS=0
fi
if wait $DDPID; then
	echo "ERROR: dd did not fail"
	SUCCESS=0
fi

[ ! -s "$LOG" ] && error "LOG file is empty!"
[ ! -s "$LOG2" ] && error "LOG2 file is empty!"

if [ "`cat $LOG $LOG2 | grep -c 'No space left on device'`" -ne 2 ]; then
	echo "ERROR: dd not return ENOSPC"
	SUCCESS=0
fi

# flush cache to OST(s) so avail numbers are correct
sync; sleep 1 ; sync

if ! oos_full; then
	echo "no OSTs are close to full"
	SUCCESS=0
fi

RECORDSOUT=$((`grep "records out" $LOG | cut -d+ -f 1` + \
              `grep "records out" $LOG2 | cut -d+ -f 1`))

FILESIZE=$((`ls -l $OOS | awk '{print $5}'` + `ls -l $OOS2 | awk '{print $5}'`))
if [ "$RECORDSOUT" -ne $(($FILESIZE / 1024)) ]; then
        echo "ERROR: blocks written by dd not equal to the size of file"
        SUCCESS=0
fi

echo LOG LOG2 file
cat $LOG $LOG2

rm -f $OOS $OOS2
sync; sleep 1; sync

if [ $SUCCESS -eq 1 ]; then
	echo "Success!"
	rm -f $LOG $LOG2
else
	exit 1
fi
