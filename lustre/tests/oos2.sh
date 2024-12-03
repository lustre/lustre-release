#!/bin/bash

set -e

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env "$@"

MOUNT=${MOUNT:-$1}
MOUNT=${MOUNT:-/mnt/lustre}
MOUNT2=${MOUNT2:-$2}
MOUNT2=${MOUNT2:-${MOUNT}2}
OOS=$MOUNT/oosfile
OOS2=$MOUNT2/oosfile2
OOSFALLOCATE=$MOUNT/oosfile_fallocate
LOG=$TMP/$(basename $0 .sh).log
LOG2=${LOG}2

SUCCESS=1

rm -f $OOS $OOS2 $LOG $LOG2 $OOSFALLOCATE

sync; sleep 1; sync	# to ensure we get up-to-date statfs info

STRIPECOUNT=$($LCTL get_param -n lov.*.activeobd | head -n 1)
ORIGFREE=$($LCTL get_param -n llite.*.kbytesavail | head -n 1)
NUMBER_OF_FREE_BLOCKS=4096  # for dd command keep only 4MB space
FALLOCATE_SIZE=$(( $ORIGFREE - $NUMBER_OF_FREE_BLOCKS )) # space to fill FS
MAXFREE=${MAXFREE:-$((1048576000 * $STRIPECOUNT))}
echo STRIPECOUNT=$STRIPECOUNT ORIGFREE=$ORIGFREE MAXFREE=$MAXFREE


if (( $ORIGFREE > $MAXFREE )); then
	skip "$0: ${ORIGFREE}kB free gt MAXFREE ${MAXFREE}kB, increase $MAXFREE (or reduce test fs size) to proceed"
	exit 0
fi

export LANG=C LC_LANG=C # for "No space left on device" message

# make sure we stripe over all OSTs to avoid OOS on only a subset of OSTs
$LFS setstripe $OOS -c $STRIPECOUNT
$LFS setstripe $OOS2 -c $STRIPECOUNT
$LFS setstripe $OOSFALLOCATE -c $STRIPECOUNT

# skip ZFS due to https://github.com/openzfs/zfs/issues/326
# TODO: check support for zfs set reservation=10G to reduce free space
if [[ $(facet_fstype $facet) != zfs ]]; then
	if ! fallocate -l $FALLOCATE_SIZE $OOSFALLOCATE 2>> $LOG; then
		echo "ERROR: fallocate -l $FALLOCATE_SIZE $OOSFALLOCATE failed"
		SUCCESS=0
	fi
fi

NUMBER_OF_IO_BLOCKS=$((3 * $ORIGFREE / 4 + 100)) # use 75% or 3/4 of free space
dd if=/dev/zero of=$OOS count=$NUMBER_OF_IO_BLOCKS bs=1k 2>> $LOG &
DDPID=$!
if dd if=/dev/zero of=$OOS2 count=$NUMBER_OF_IO_BLOCKS bs=1k 2>> $LOG2; then
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

RECORDSOUT=$((`grep "records out" $LOG | cut -d+ -f 1` +
              `grep "records out" $LOG2 | cut -d+ -f 1`))

FILESIZE=$((`ls -l $OOS | awk '{print $5}'` + `ls -l $OOS2 | awk '{print $5}'`))
if [ "$RECORDSOUT" -ne $(($FILESIZE / 1024)) ]; then
	echo "ERROR: blocks written by dd not equal to the size of file"
	SUCCESS=0
fi

echo LOG LOG2 file
cat $LOG $LOG2

rm -f $OOS $OOS2 $OOSFALLOCATE
sync; sleep 1; sync

if [ $SUCCESS -eq 1 ]; then
	echo "Success!"
	rm -f $LOG $LOG2
else
	exit 1
fi
