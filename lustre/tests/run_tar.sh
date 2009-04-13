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

TESTDIR=$MOUNT/d0.tar-$(hostname)

CONTINUE=true
while [ ! -e "$END_RUN_FILE" ] && $CONTINUE; do
    echoerr "$(date +'%F %H:%M:%S'): tar run starting"
    mkdir -p $TESTDIR
    cd $TESTDIR
    tar cf - /etc | tar xf - 2>&1 | tee $LOG &
    load_pid=$!
ps -e f -o "pid ppid pgrp comm" >$TMP/client-load.ps-list
    wait $load_pid
    RC=${PIPESTATUS[0]}
    PREV_ERRORS=$(grep "exit delayed from previous errors" $LOG) || true
    if [ $RC -ne 0 -a "$ERRORS_OK" -a "$PREV_ERRORS" ]; then
        echoerr "$(date +'%F %H:%M:%S'): tar errors earlier, ignoring"
        RC=0
    fi
    if [ $RC -eq 0 ]; then
	echoerr "$(date +'%F %H:%M:%S'): tar succeeded"
	cd $TMP
	rm -rf $TESTDIR
	echoerr "$(date +'%F %H:%M:%S'): tar run finished"
    else
	echoerr "$(date +'%F %H:%M:%S'): tar failed"
	if [ -z "$ERRORS_OK" ]; then
	    echo $(hostname) >> $END_RUN_FILE
	fi
	if [ $BREAK_ON_ERROR ]; then
	    # break
            CONTINUE=false
	fi
    fi
done

echoerr "$(date +'%F %H:%M:%S'): tar run exiting"
