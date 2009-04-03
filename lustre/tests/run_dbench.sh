#!/bin/bash
set -x

TMP=${TMP:-/tmp}

TESTSUITELOG=${TESTSUITELOG:-$TMP/recovery-mds-scale}
LOG=${TESTSUITELOG}_$(basename $0)-$(hostname)
DEBUGLOG=${LOG}.debug

mkdir -p ${LOG%/*}

rm -f $LOG $DEBUGLOG
exec 2>$DEBUGLOG

. $(dirname $0)/functions.sh

assert_env MOUNT END_RUN_FILE LOAD_PID_FILE

trap signaled TERM

# recovery-*-scale scripts use this to signal the client loads to die
echo $$ >$LOAD_PID_FILE

TESTDIR=$MOUNT/d0.dbench-$(hostname)

CONTINUE=true

while [ ! -e "$END_RUN_FILE" ] && $CONTINUE; do
    echoerr "$(date +'%F %H:%M:%S'): dbench run starting"

    mkdir -p $TESTDIR
    rundbench -D $TESTDIR 2 1>$LOG &
    load_pid=$!

    wait $load_pid
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
	echoerr "$(date +'%F %H:%M:%S'): dbench succeeded"
	cd $TMP
	rm -rf $TESTDIR
	echoerr "$(date +'%F %H:%M:%S'): dbench run finished"
    else
	echoerr "$(date +'%F %H:%M:%S'): dbench failed"
	if [ -z "$ERRORS_OK" ]; then
	    echo $(hostname) >> $END_RUN_FILE
	fi
	if [ $BREAK_ON_ERROR ]; then
	    # break
            CONTINUE=false
	fi
    fi
done

echoerr "$(date +'%F %H:%M:%S'): dbench run exiting"
