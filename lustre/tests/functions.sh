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

