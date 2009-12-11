#!/bin/bash
set -x

TMP=${TMP:-/tmp}

TESTSUITELOG=${TESTSUITELOG:-$TMP/recovery-mds-scale}
LOG=${TESTSUITELOG}_$(basename $0)-$(hostname)
DEBUGLOG=${LOG}.debug

mkdir -p ${LOG%/*}

rm -f $LOG $DEBUGLOG
exec 2>$DEBUGLOG

if [ -z "$MOUNT" -o -z "$END_RUN_FILE" -o -z "$LOAD_PID_FILE" ]; then
    echo "The following must be set: MOUNT END_RUN_FILE LOAD_PID_FILE"
    exit 1
fi

echoerr () { echo "$@" 1>&2 ; }

signaled() {
    echoerr "$(date +'%F %H:%M:%S'): client load was signaled to terminate"
    kill -TERM -$PPID
    sleep 5
    kill -KILL -$PPID
}

trap signaled TERM

# recovery-mds-scale uses this to signal the client loads to die
echo $$ >$LOAD_PID_FILE

TESTDIR=$MOUNT/d0.iozone-$(hostname)

# needed to debug oom problem
#echo 1 > /proc/sys/vm/vm_gfp_debug
#killpids=""
#vmstat 1 1000000 >$TMP/iozone.vmstat.out &
#killpids="$killpids $!"
#$LUSTRE_TESTS/runvmstat > $TMP/iozone.runvmstat.out &
#killpids="$killpids $!"

CONTINUE=true
while [ ! -e "$END_RUN_FILE" ] && $CONTINUE; do
    echoerr "$(date +'%F %H:%M:%S'): iozone run starting"
    mkdir -p $TESTDIR
    cd $TESTDIR
    iozone -a -M -R -V 0xab -g 100M -q 512k -i0 -i1 -f $TESTDIR/iozone-file 1>$LOG &
    load_pid=$!
    wait $load_pid
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
	echoerr "$(date +'%F %H:%M:%S'): iozone succeeded"
	cd $TMP
	rm -rf $TESTDIR
        if [ -d $TESTDIR ]; then
	    echoerr "$(date +'%F %H:%M:%S'): failed to remove $TESTDIR"
	    echo $(hostname) >> $END_RUN_FILE
            CONTINUE=false
        fi
	echoerr "$(date +'%F %H:%M:%S'): iozone run finished"
    else
	echoerr "$(date +'%F %H:%M:%S'): iozone failed"
	if [ -z "$ERRORS_OK" ]; then
	    echo $(hostname) >> $END_RUN_FILE
	fi
	if [ $BREAK_ON_ERROR ]; then
	    # break
            CONTINUE=false
	fi
    fi
done

echoerr "$(date +'%F %H:%M:%S'): iozone run exiting"
#kill $killpids
#sleep 5
#kill -9 $killpids
