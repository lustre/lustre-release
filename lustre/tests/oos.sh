#!/bin/bash

set -e
#set -vx

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
. ${CONFIG:=$LUSTRE/tests/cfg/${NAME}.sh}

export PATH=`dirname $0`/../utils:$PATH
LFS=${LFS:-lfs}
LCTL=${LCTL:-lctl}
MOUNT=${MOUNT:-$1}
MOUNT=${MOUNT:-/mnt/lustre}
OOS=$MOUNT/oosfile
TMP=${TMP:-/tmp}
LOG=$TMP/$(basename $0 .sh).log

SUCCESS=1

rm -f $OOS $LOG

sync; sleep 1; sync	# to ensure we get up-to-date statfs info

#$LCTL set_param -n debug=-1
#$LCTL set_param -n subsystem_debug=0x40a8

#$LCTL clear
#$LCTL debug_daemon start /r/tmp/debug 1024

STRIPECOUNT=`$LCTL get_param -n lov.*.activeobd | head -n 1`
ORIGFREE=`$LCTL get_param -n llite.*.kbytesavail | head -n 1`
MAXFREE=${MAXFREE:-$((400000 * $STRIPECOUNT))}
echo STRIPECOUNT=$STRIPECOUNT ORIGFREE=$ORIGFREE MAXFREE=$MAXFREE
if [ $ORIGFREE -gt $MAXFREE ]; then
	skip "$0: ${ORIGFREE}kB free gt MAXFREE ${MAXFREE}kB, increase $MAXFREE (or reduce test fs size) to proceed"
	exit 0
fi

export LANG=C LC_LANG=C # for "No space left on device" message

[ -f $LOG ] && error "log file wasn't removed?"

echo BEFORE dd started
oos_full || true

# make sure we stripe over all OSTs to avoid OOS on only a subset of OSTs
$LFS setstripe $OOS -c $STRIPECOUNT
# add 20% of margin since the metadata overhead estimated in bavail might be
# too aggressive and we might be able to write more than reported initially
# by statfs.
echo dd size $((ORIGFREE * 120 / 100))kB
if dd if=/dev/zero of=$OOS count=$((ORIGFREE * 120 / 100)) bs=1k 2> $LOG; then
	echo "ERROR: dd did not fail"
	SUCCESS=0
fi

[ ! -s "$LOG" ] && error "LOG file is empty!"

if [ "`grep -c 'No space left on device' $LOG`" -ne 1 ]; then
	echo "ERROR: dd not return ENOSPC"
	sed "s/^/LOG: /" $LOG
	SUCCESS=0
fi

# flush cache to OST(s) so avail numbers are correct
sync; sleep 1 ; sync

echo AFTER dd
if ! oos_full; then
	echo "no OSTs are close to full"
	SUCCESS=0
fi

RECORDSOUT=`grep "records out" $LOG | cut -d + -f1`
FILESIZE=`ls -l $OOS | awk '{ print $5 }'`
if [ -z "$RECORDSOUT" ]; then
	echo "ERROR: no blocks written by dd?"
	sed "s/^/LOG: /" $LOG
	SUCCESS=0
elif [ "$RECORDSOUT" -ne $((FILESIZE / 1024)) ]; then
	echo "ERROR: blocks written by dd not equal to the size of file"
	SUCCESS=0
fi

#$LCTL debug_daemon stop

[ $SUCCESS != 0 ] && echo LOG file && sed "s/^/LOG: /" $LOG
rm -f $OOS

sync; sleep 3; sync

wait_delete_completed 300

if [ $SUCCESS -eq 1 ]; then
	echo "Success!"
	rm -f $LOG
else
	exit 1
fi
