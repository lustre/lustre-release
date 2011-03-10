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

# lrepl - Lustre test Read-Eval-Print Loop.
#
# This function implements a REPL for the Lustre test framework.  It
# doesn't exec an actual shell because the user may want to inspect
# variables and use functions from the test framework.
lrepl() {
    local line
    local rawline
    local prompt

    cat <<EOF
        This is an interactive read-eval-print loop interactive shell
        simulation that you can use to debug failing tests.  You can
        enter most bash command lines (see notes below).

        Use this REPL to inspect variables, set them, call test
        framework shell functions, etcetera.

        'exit' or EOF to exit this shell.

        set \$retcode to 0 to cause the assertion failure that
        triggered this REPL to be ignored.

        Examples:
            do_facet ost1 lctl get_param ost.*.ost.threads_*
            do_rpc_nodes \$OSTNODES unload_modules

        NOTES:
            All but the last line of multi-line statements or blocks
            must end in a backslash.

            "Here documents" are not supported.

            History is not supported, but command-line editing is.

EOF

    # Prompt escapes don't work in read -p, sadly.
    prompt=":test_${testnum:-UNKNOWN}:$(uname -n):$(basename $PWD)% "

    # We use read -r to get close to a shell experience
    while read -e -r -p "$prompt" rawline; do
        line=
        case "$rawline" in
        # Don't want to exit-exit, just exit the REPL
        exit) break;;
        # We need to handle continuations, and read -r doesn't do
        # that for us.  Yet we need read -r.
        #
        # We also use case/esac to compare lines read to "*\\"
        # because [ "$line" = *\\ ] and variants of that don't work.
        *\\) line="$rawline"
            while read -e -r -p '> ' rawline
            do
                line="$line"$'\n'"$rawline"
                case "$rawline" in
                # We could check for here documents by matching
                # against *<<*, but who cares.
                *\\) continue;;
                *) break;;
                esac
            done
            ;;
        *) line=$rawline
        esac

        case "$line" in
        *\\) break;;
        esac

        # Finally!  Time to eval.
        eval "$line"
    done

    echo $'\n\tExiting interactive shell...\n'
    return 0
}

# lassert - Lustre test framework assert
#
# Arguments: failure code, failure message, expression/statement
#
# lassert evaluates the expression given, and, if false, calls
# error() to trigger test failure.  If REPL_ON_LASSERT is true then
# lassert will call lrepl() to give the user an interactive shell.
# If the REPL sets retcode=0 then the assertion failure will be
# ignored.
lassert() {
    local retcode=$1
    local msg=$2
    shift 2

    echo "checking $* ($(eval echo \""$*"\"))..."
    eval "$@" && return 0;

    if ${REPL_ON_LASSERT:-false}; then
        echo "Assertion $retcode failed: $* (expanded: $(eval echo \""$*"\"))
$msg"
        lrepl
    fi

    error "Assertion $retcode failed: $* (expanded: $(eval echo \""$*"\"))
$msg"
    return $retcode
}

# setmodopts- set module options for subsequent calls to load_modules
#
# Usage: setmodopts module_name new_value [var_in_which_to_save_old_value]
#        setmodopts -a module_name new_value [var_in_which_to_save_old_value]
#
# In the second usage the new value is appended to the old.
setmodopts() {
        local _append=false

        if [ "$1" = -a ]; then
            _append=true
            shift
        fi

        local _var=MODOPTS_$1
        local _newvalue=$2
        local _savevar=$3
        local _oldvalue

        # Dynamic naming of variables is a pain in bash.  In ksh93 we could
        # write "nameref opts_var=${modname}_MODOPTS" then assign directly
        # to opts_var.  Associative arrays would also help, alternatively.
        # Alas, we're stuck with eval until all distros move to a more recent
        # version of bash.  Fortunately we don't need to eval unset and export.

        if [ -z "$_newvalue" ]; then
            unset $_var
            return 0
        fi

        _oldvalue=${!var}
        $_append && _newvalue="$_oldvalue $_newvalue"
        export $_var="$_newvalue"
        echo setmodopts: ${_var}=${_newvalue}

        [ -n "$_savevar" ] && eval $_savevar=\""$_oldvalue"\"
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

    if [ -n "$MPI_USER" -a "$MPI_USER" != root -a -n "$mpirun" ]; then
        echo "+ chmod 0777 $MOUNT"
        chmod 0777 $MOUNT
        command="su $MPI_USER sh -c \"$command \""
    fi

    ls -ald $MOUNT
    echo "+ $command"
    eval $command 2>&1 | tee $mpilog || true

    rc=${PIPESTATUS[0]}
    if [ $rc -eq 0 ] && grep -q "p4_error:" $mpilog ; then
       rc=1
    fi
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

###
# short_hostname
#
# Passed a single argument, strips everything off following and includes the first period.
# client-20.lab.whamcloud.com becomes client-20
short_hostname() {
  echo $(sed 's/\..*//' <<< $1)
}

