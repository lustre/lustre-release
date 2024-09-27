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

while [ ! -e "$END_RUN_FILE" ]; do
	echoerr "$(date +'%F %H:%M:%S'): dd run starting"
	rm -rf $TESTDIR
	client_load_mkdir $TESTDIR
	if [ $? -ne 0 ]; then
		echoerr "$(date +'%F %H:%M:%S'): failed to create $TESTDIR"
		echo $(hostname) >> $END_RUN_FILE
		break
	fi
	cd $TESTDIR
	sync

	# suppress dd xfer stat to workaround buggy coreutils/gettext
	# combination in RHEL5 and OEL5, see BZ 21264
	FREE_SPACE=$(df -P $TESTDIR | awk '/:/ { print $4 }')
	BLKS=$((FREE_SPACE / 4 / CLIENT_COUNT))
	echoerr "Total free disk space is $FREE_SPACE, 4k blocks to dd is $BLKS"

	df $TESTDIR || true
	dd bs=4k count=$BLKS status=noxfer if=/dev/zero of=$TESTDIR/dd-file \
								1>$LOG & wait $!
	if [ $? -eq 0 ]; then
		echoerr "$(date +'%F %H:%M:%S'): dd succeeded"
		cd $TMP
	else
		enospc_detected $DEBUGLOG &&
			echoerr "$(date +'%F %H:%M:%S'): dd ENOSPC, ignored" &&
			continue
		echoerr "$(date +'%F %H:%M:%S'): dd failed"
		if [ -z "$ERRORS_OK" ]; then
			echo $(hostname) >> $END_RUN_FILE
		fi
	fi
done

echoerr "$(date +'%F %H:%M:%S'): dd run exiting"
