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

nids_list () {
   local list
   for i in ${1//,/ }; do
       list="$list $i@$NETTYPE"
   done
   echo $list
}

# FIXME: all setup/cleanup can be done without rpc.sh
lst_end_session () {
    local verbose=false
    [ x$1 = x--verbose ] && verbose=true

    export LST_SESSION=`$LST show_session 2>/dev/null | awk -F " " '{print $5}'`
    [ "$LST_SESSION" == "" ] && return

    if $verbose; then 
        $LST show_error c s
    fi
    $LST stop b
    $LST end_session
}

lst_session_cleanup_all () {
    local list=$(comma_list $(nodes_list))
    do_rpc_nodes $list lst_end_session
}

lst_cleanup () {
    lsmod | grep -q lnet_selftest && rmmod lnet_selftest > /dev/null 2>&1 || true
}

lst_cleanup_all () {
   local list=$(comma_list $(nodes_list))

   # lst end_session needs to be executed only locally
   # i.e. on node where lst new_session was called
   lst_end_session --verbose 
   do_rpc_nodes $list lst_cleanup
}

lst_setup () {
    load_module lnet_selftest
}

lst_setup_all () {
    local list=$(comma_list $(nodes_list))
    do_rpc_nodes $list lst_setup 
}

