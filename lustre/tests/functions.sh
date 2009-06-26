#!/bin/bash

# Simple function used by run_*.sh scripts

assert_env() {
    local failed=""
    for name in $@; do
        if [ -z "${!name}" ]; then
            echo "$0: $name must be set"
            failed=1
        fi
    done
    [ $failed ] && exit 1 || true
}

echoerr () { echo "$@" 1>&2 ; }

signaled() {
    echoerr "$(date +'%F %H:%M:%S'): client load was signaled to terminate"

    local PGID=$(ps -eo "%c %p %r" | awk "/ $PPID / {print \$3}")
    kill -TERM -$PGID
    sleep 5
    kill -KILL -$PGID
}

mpi_run () {
    local mpirun="$MPIRUN $MPIRUN_OPTIONS"
    local command="$mpirun $@"
    local mpilog=$TMP/mpi.log
    local rc

    if [ "$MPI_USER" != root -a $mpirun ]; then
        echo "+ chmod 0777 $MOUNT"
        chmod 0777 $MOUNT
        command="su $MPI_USER sh -c \"$command \""
    fi

    ls -ald $MOUNT
    echo "+ $command"
    eval $command 2>&1 > $mpilog || true

    rc=${PIPESTATUS[0]}
    if [ $rc -eq 0 ] && grep -q "p4_error: : [^0]" $mpilog ; then
       rc=1
    fi
    cat $mpilog
    return $rc
}

