#!/bin/bash

TMP=${TMP:-/tmp}

TESTLOG_PREFIX=${TESTLOG_PREFIX:-$TMP/recovery-mds-scale}
TESTNAME=${TESTNAME:-""}
[ -n "$TESTNAME" ] && TESTLOG_PREFIX=$TESTLOG_PREFIX.$TESTNAME

LOG=$TESTLOG_PREFIX.$(basename $0 .sh)_stdout.$(hostname -s).log
DEBUGLOG=$(echo $LOG | sed 's/\(.*\)stdout/\1debug/')

mkdir -p ${LOG%/*}

rm -f $LOG $DEBUGLOG
exec 2>$DEBUGLOG
set -x

. $(dirname $0)/functions.sh

assert_env MOUNT END_RUN_FILE LOAD_PID_FILE LFS CLIENT_COUNT

trap signaled TERM

# recovery-*-scale scripts use this to signal the client loads to die
echo $$ >$LOAD_PID_FILE

TESTDIR=$MOUNT/d0.dd-$(hostname)

CONTINUE=true
while [ ! -e "$END_RUN_FILE" ] && $CONTINUE; do
	echoerr "$(date +'%F %H:%M:%S'): dd run starting"
	mkdir -p $TESTDIR
	$LFS setstripe -c -1 $TESTDIR
	cd $TESTDIR
	sync

	# suppress dd xfer stat to workaround buggy coreutils/gettext
	# combination in RHEL5 and OEL5, see BZ 21264
	FREE_SPACE=$(df -P $TESTDIR | awk '/:/ { print $4 }')
	BLKS=$((FREE_SPACE * 9 / 40 / CLIENT_COUNT))
	echoerr "Total free disk space is $FREE_SPACE, 4k blocks to dd is $BLKS"

	df $TESTDIR || true
	dd bs=4k count=$BLKS status=noxfer if=/dev/zero of=$TESTDIR/dd-file \
								1>$LOG
	if [ $? -eq 0 ]; then
		echoerr "$(date +'%F %H:%M:%S'): dd succeeded"
		cd $TMP
		rm -rf $TESTDIR
		echoerr "$(date +'%F %H:%M:%S'): dd run finished"
	else
		echoerr "$(date +'%F %H:%M:%S'): dd failed"
		if [ -z "$ERRORS_OK" ]; then
			echo $(hostname) >> $END_RUN_FILE
		fi
		if [ $BREAK_ON_ERROR ]; then
			# break
			CONTINUE=false
		fi
	fi
done

echoerr "$(date +'%F %H:%M:%S'): dd run exiting"
