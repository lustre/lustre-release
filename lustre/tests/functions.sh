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
    prompt=":${TESTNAME:-UNKNOWN}:$(uname -n):$(basename $PWD)% "

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

	_oldvalue=${!_var}
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
    local mpirun="$MPIRUN $MPIRUN_OPTIONS --oversubscribe"
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
	local escape="$2"
	for i in ${1//,/ }; do
		if [ "$list" = "" ]; then
			list="$i@$NETTYPE"
		else
			list="$list$escape $i@$NETTYPE"
		fi
	done
	echo $list
}

# FIXME: all setup/cleanup can be done without rpc.sh
lst_end_session () {
    local verbose=false
    [ x$1 = x--verbose ] && verbose=true

    export LST_SESSION=`$LST show_session 2>/dev/null | awk -F " " '{print $5}'`
    [ "$LST_SESSION" == "" ] && return

	$LST stop b
    if $verbose; then
        $LST show_error c s
    fi
    $LST end_session
}

lst_session_cleanup_all () {
    local list=$(comma_list $(nodes_list))
    do_rpc_nodes $list lst_end_session
}

lst_cleanup () {
    lsmod | grep -q lnet_selftest && \
        rmmod lnet_selftest > /dev/null 2>&1 || true
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
# Passed a single argument, strips everything off following
# and includes the first period.
# client-20.lab.whamcloud.com becomes client-20
short_hostname() {
  echo $(sed 's/\..*//' <<< $1)
}

###
# short_nodename
#
# Find remote nodename, stripped of any domain, etc.
# 'hostname -s' is easy, but not implemented on all systems
short_nodename() {
	local rname=$(do_node $1 "uname -n" || echo -1)
	if [[ "$rname" = "-1" ]]; then
		rname=$1
	fi
	echo $(short_hostname $rname)
}

print_opts () {
    local var

    echo OPTIONS:

    for i in $@; do
        var=$i
        echo "${var}=${!var}"
    done
    [ -e $MACHINEFILE ] && cat $MACHINEFILE
}

is_lustre () {
	[ "$(stat -f -c %T $1)" = "lustre" ]
}

setstripe_getstripe () {
	local file=$1
	shift
	local params=$@

	is_lustre $file || return 0

	if [ -n "$params" ]; then
		$LFS setstripe $params $file ||
			error "setstripe $params failed"
	fi
	$LFS getstripe $file ||
		error "getstripe $file failed"
}

run_compilebench() {
	local dir=${1:-$DIR}
	local cbench_DIR=${cbench_DIR:-""}
	local cbench_IDIRS=${cbench_IDIRS:-2}
	local cbench_RUNS=${cbench_RUNS:-2}

	print_opts cbench_DIR cbench_IDIRS cbench_RUNS

	[ x$cbench_DIR = x ] &&
		skip_env "compilebench not found"

	[ -e $cbench_DIR/compilebench ] ||
		skip_env "No compilebench build"

	# Space estimation:
	# compile dir kernel-0	~1GB
	# required space	~1GB * cbench_IDIRS
	local space=$(df -P $dir | tail -n 1 | awk '{ print $4 }')
	if [[ $space -le $((1024 * 1024 * cbench_IDIRS)) ]]; then
		cbench_IDIRS=$((space / 1024 / 1024))
		[[ $cbench_IDIRS -eq 0 ]] &&
			skip_env "Need free space at least 1GB, have $space"

		echo "reducing initial dirs to $cbench_IDIRS"
	fi
	echo "free space = $space KB"

	# FIXME:
	# t-f _base needs to be modifyed to set properly tdir
	# for new "test_foo" functions names
	# local testdir=$DIR/$tdir
	local testdir=$dir/d0.compilebench.$$
	test_mkdir -p $testdir
	setstripe_getstripe $testdir $cbench_STRIPEPARAMS

    local savePWD=$PWD
    cd $cbench_DIR
    local cmd="./compilebench -D $testdir -i $cbench_IDIRS \
        -r $cbench_RUNS --makej"

    log "$cmd"

    local rc=0
    eval $cmd
    rc=$?

    cd $savePWD
    [ $rc = 0 ] || error "compilebench failed: $rc"
    rm -rf $testdir
}

run_metabench() {
	local dir=${1:-$DIR}
	local mntpt=${2:-$MOUNT}
	METABENCH=${METABENCH:-$(which metabench 2> /dev/null || true)}
	mbench_NFILES=${mbench_NFILES:-30400}
	# threads per client
	mbench_THREADS=${mbench_THREADS:-4}
	mbench_OPTIONS=${mbench_OPTIONS:-}
	mbench_CLEANUP=${mbench_CLEANUP:-true}

	[ x$METABENCH = x ] && skip_env "metabench not found"

	print_opts METABENCH clients mbench_NFILES mbench_THREADS

	local testdir=$dir/d0.metabench
	test_mkdir -p $testdir
	setstripe_getstripe $testdir $mbench_STRIPEPARAMS

	# mpi_run uses mpiuser
	chmod 0777 $testdir

	# -C             Run the file creation tests. Creates zero byte files.
	# -S             Run the file stat tests.
	# -c nfile       Number of files to be used in each test.
	# -k             Cleanup files when finished.
	local cmd="$METABENCH -w $testdir -c $mbench_NFILES -C -S $mbench_OPTIONS"
	echo "+ $cmd"

	# find out if we need to use srun by checking $SRUN_PARTITION
	if [ "$SRUN_PARTITION" ]; then
		$SRUN $SRUN_OPTIONS -D $testdir -w $clients -N $num_clients \
			-n $((num_clients * mbench_THREADS)) \
			-p $SRUN_PARTITION -- $cmd
	else
		mpi_run ${MACHINEFILE_OPTION} ${MACHINEFILE} \
			-np $((num_clients * $mbench_THREADS)) $cmd
	fi

	local rc=$?
	if [ $rc != 0 ] ; then
		error "metabench failed! $rc"
	fi

	if $mbench_CLEANUP; then
		rm -rf $testdir
	else
		mv $dir/d0.metabench $mntpt/_xxx.$(date +%s).d0.metabench
	fi
}

run_simul() {
	SIMUL=${SIMUL:=$(which simul 2> /dev/null || true)}
	[ x$SIMUL = x ] && skip_env "simul not found"
	[ "$NFSCLIENT" ] && skip "skipped for NFSCLIENT mode"

	# threads per client
	simul_THREADS=${simul_THREADS:-2}
	simul_REP=${simul_REP:-20}

	# FIXME
	# Need space estimation here.

	print_opts SIMUL clients simul_REP simul_THREADS

	local testdir=$DIR/d0.simul
	test_mkdir $testdir
	setstripe_getstripe $testdir $simul_STRIPEPARAMS

	# mpi_run uses mpiuser
	chmod 0777 $testdir

	# -n # : repeat each test # times
	# -N # : repeat the entire set of tests # times

	local cmd="$SIMUL -d $testdir -n $simul_REP -N $simul_REP"

	echo "+ $cmd"
	# find out if we need to use srun by checking $SRUN_PARTITION
	if [ "$SRUN_PARTITION" ]; then
		$SRUN $SRUN_OPTIONS -D $testdir -w $clients -N $num_clients \
			-n $((num_clients * simul_THREADS)) -p $SRUN_PARTITION \
			-- $cmd
	else
		mpi_run ${MACHINEFILE_OPTION} ${MACHINEFILE} \
			-np $((num_clients * simul_THREADS)) $cmd
	fi

    local rc=$?
    if [ $rc != 0 ] ; then
        error "simul failed! $rc"
    fi
    rm -rf $testdir
}

run_mdtest() {
	MDTEST=${MDTEST:=$(which mdtest 2> /dev/null || true)}
	[ x$MDTEST = x ] && skip_env "mdtest not found"
	[ "$NFSCLIENT" ] && skip "skipped for NFSCLIENT mode"

	# threads per client
	mdtest_THREADS=${mdtest_THREADS:-2}
	mdtest_nFiles=${mdtest_nFiles:-"100000"}
	# We devide the files by number of core
	mdtest_nFiles=$((mdtest_nFiles/mdtest_THREADS/num_clients))
	mdtest_iteration=${mdtest_iteration:-1}
	local mdtest_custom_params=${mdtest_custom_params:-""}
	local type=${1:-"ssf"}

	local mdtest_Nmntp=${mdtest_Nmntp:-1}

	if [ $type = "ssf" ] && [ $mdtest_Nmntp -ne 1 ]; then
		skip "shared directory mode is not compatible" \
			"with multiple directory paths"
	fi

	# FIXME
	# Need space estimation here.

	print_opts MDTEST mdtest_iteration mdtest_THREADS mdtest_nFiles

	local testdir=$DIR/d0.mdtest
	test_mkdir $testdir
	setstripe_getstripe $testdir $mdtest_STRIPEPARAMS
	chmod 0777 $testdir

	for ((i=1; i<mdtest_Nmntp; i++)); do
		zconf_mount_clients $clients $MOUNT$i "$mntopts" ||
			error_exit "Failed $clients on $MOUNT$i"
		local dir=$DIR$i/d0.mdtest$i
		test_mkdir $dir
		setstripe_getstripe $dir $mdtest_SETSTRIPEPARAMS
		chmod 0777 $dir
		testdir="$testdir@$dir"
	done
	# mpi_run uses mpiuser

	# -i # : repeat each test # times
	# -d   : test dir
	# -n # : number of file/dir to create/stat/remove
	# -u   : each process create/stat/remove individually

	local cmd="$MDTEST -d $testdir -i $mdtest_iteration \
		-n $mdtest_nFiles $mdtest_custom_params"

	[ $type = "fpp" ] && cmd="$cmd -u"

	echo "+ $cmd"
	# find out if we need to use srun by checking $SRUN_PARTITION
	if [ "$SRUN_PARTITION" ]; then
		$SRUN $SRUN_OPTIONS -D $testdir -w $clients -N $num_clients \
			-n $((num_clients * mdtest_THREADS)) \
			-p $SRUN_PARTITION -- $cmd
	else
		mpi_run ${MACHINEFILE_OPTION} ${MACHINEFILE} \
			-np $((num_clients * mdtest_THREADS)) $cmd
	fi

    local rc=$?
    if [ $rc != 0 ] ; then
        error "mdtest failed! $rc"
    fi
	rm -rf $testdir
	for ((i=1; i<mdtest_Nmntp; i++)); do
		local dir=$DIR$i/d0.mdtest$i
		rm -rf $dir
		zconf_umount_clients $clients $MOUNT$i ||
			error_exit "Failed umount $MOUNT$i on $clients"
	done
}

run_connectathon() {
	local dir=${1:-$DIR}
	cnt_DIR=${cnt_DIR:-""}
	cnt_NRUN=${cnt_NRUN:-10}

	print_opts cnt_DIR cnt_NRUN

	[ x$cnt_DIR = x ] && skip_env "connectathon dir not found"
	[ -e $cnt_DIR/runtests ] || skip_env "No connectathon runtests found"

	# Space estimation:
	# "special" tests create a 30 MB file + misc. small files
	# required space ~40 MB
	local space=$(df -P $dir | tail -n 1 | awk '{ print $4 }')
	if [[ $space -le $((1024 * 40)) ]]; then
		skip_env "Need free space at least 40MB, have $space KB"
	fi
	echo "free space = $space KB"

	local testdir=$dir/d0.connectathon
	test_mkdir -p $testdir
	setstripe_getstripe $testdir $cnt_STRIPEPARAMS

	local savePWD=$PWD
	cd $cnt_DIR

	#
	# To run connectathon:
	# runtests [-a|-b|-g|-s|-l] [-f|-n|-t] [-N numpasses] [test-directory]
	#
	# One of the following test types
	#    -b  basic
	#    -g  general
	#    -s  special
	#    -l  lock
	#    -a  all of the above
	#
	# -f  a quick functional test
	# -n  suppress directory operations (mkdir and rmdir)
	# -t  run with time statistics (default for basic tests)
	#
	# -N numpasses - specifies the number of times to run
	#                the tests. Optional.

	tests="-b -g -s"
	# Include lock tests unless we're running on nfsv4
	local fstype=$(df -TP $testdir | awk 'NR==2  {print $2}')
	echo "$testdir: $fstype"
	if [[ $fstype != "nfs4" ]]; then
		tests="$tests -l"
	fi
	echo "tests: $tests"
	for test in $tests; do
		local cmd="sh ./runtests -N $cnt_NRUN $test -f $testdir"
		local rc=0

		log "$cmd"
		eval $cmd
		rc=$?
		[ $rc = 0 ] || error "connectathon failed: $rc"
	done

	cd $savePWD
	rm -rf $testdir
}

run_ior() {
	local type=${1:="ssf"}
	local dir=${2:-$DIR}
	local testdir=$dir/d0.ior.$type
	local nfs_srvmntpt=$3

	if [ "$NFSCLIENT" ]; then
		[[ -n $nfs_srvmntpt ]] ||
			{ error "NFSCLIENT mode, but nfs exported dir"\
				"is not set!" && return 1; }
	fi

	IOR=${IOR:-$(which IOR 2> /dev/null || true)}
	[ x$IOR = x ] && skip_env "IOR not found"

	# threads per client
	ior_THREADS=${ior_THREADS:-2}
	ior_iteration=${ior_iteration:-1}
	ior_blockSize=${ior_blockSize:-6}
	ior_blockUnit=${ior_blockUnit:-M}   # K, M, G
	ior_xferSize=${ior_xferSize:-1M}
	ior_type=${ior_type:-POSIX}
	ior_DURATION=${ior_DURATION:-30}        # minutes
	ior_CLEANUP=${ior_CLEANUP:-true}
	local multiplier=1
	case ${ior_blockUnit} in
		[G])
			multiplier=$((1024 * 1024 * 1024))
			;;
		[M])
			multiplier=$((1024 * 1024))
			;;
		[K])
			multiplier=1024
			;;
		*)      error "Incorrect block unit should be one of [KMG]"
			;;
	esac

	# calculate the space in bytes
	local space=$(df -B 1 -P $dir | tail -n 1 | awk '{ print $4 }')
	local total_threads=$((num_clients * ior_THREADS))
	echo "+ $ior_blockSize * $multiplier * $total_threads "
	if [ $((space / 2)) -le \
	     $((ior_blockSize * multiplier * total_threads)) ]; then
		ior_blockSize=$((space / 2 / multiplier / total_threads))
		[ $ior_blockSize -eq 0 ] &&
		skip_env "Need free space more than $((2 * total_threads)) \
			 ${ior_blockUnit}: have $((space / multiplier))"

		echo "(reduced blockSize to $ior_blockSize \
		     ${ior_blockUnit} bytes)"
	fi

	print_opts IOR ior_THREADS ior_DURATION MACHINEFILE

	test_mkdir -p $testdir

	# mpi_run uses mpiuser
	chmod 0777 $testdir
	[[ "$ior_stripe_params" && -z "$ior_STRIPEPARAMS" ]] &&
		ior_STRIPEPARAMS="$ior_stripe_params" &&
		echo "got deprecated ior_stripe_params,"\
			"use ior_STRIPEPARAMS instead"
	setstripe_getstripe $testdir $ior_STRIPEPARAMS

	#
	# -b N  blockSize --
	#       contiguous bytes to write per task (e.g.: 8, 4K, 2M, 1G)"
	# -o S  testFileName
	# -t N  transferSize -- size of transfer in bytes (e.g.: 8, 4K, 2M, 1G)"
	# -w    writeFile -- write file"
	# -r    readFile -- read existing file"
	# -W    checkWrite -- check read after write"
	# -C    reorderTasks -- changes task ordering to n+1 ordering for readback
	# -T    maxTimeDuration -- max time in minutes to run tests"
	# -k    keepFile -- keep testFile(s) on program exit

	local cmd
	if [ -n "$ior_custom_params" ]; then
		cmd="$IOR -o $testdir/iorData $ior_custom_params"
	else
		cmd="$IOR -a $ior_type -b ${ior_blockSize}${ior_blockUnit} \
		-o $testdir/iorData -t $ior_xferSize -v -C -w -r -W \
		-i $ior_iteration -T $ior_DURATION -k"
	fi

	[ $type = "fpp" ] && cmd="$cmd -F"

	echo "+ $cmd"
	# find out if we need to use srun by checking $SRUN_PARTITION
	if [ "$SRUN_PARTITION" ]; then
		$SRUN $SRUN_OPTIONS -D $testdir -w $clients -N $num_clients \
			-n $((num_clients * ior_THREADS)) -p $SRUN_PARTITION \
			-- $cmd
	else
		mpi_ior_custom_threads=${mpi_ior_custom_threads:-"$((num_clients * ior_THREADS))"}
		mpi_run ${MACHINEFILE_OPTION} ${MACHINEFILE} \
			-np $mpi_ior_custom_threads $cmd
	fi

    local rc=$?
    if [ $rc != 0 ] ; then
        error "ior failed! $rc"
    fi
    $ior_CLEANUP && rm -rf $testdir || true
}

run_mib() {
	MIB=${MIB:=$(which mib 2> /dev/null || true)}
	[ "$NFSCLIENT" ] && skip "skipped for NFSCLIENT mode"
	[ x$MIB = x ] && skip_env "MIB not found"

	# threads per client
	mib_THREADS=${mib_THREADS:-2}
	mib_xferSize=${mib_xferSize:-1m}
	mib_xferLimit=${mib_xferLimit:-5000}
	mib_timeLimit=${mib_timeLimit:-300}
	mib_STRIPEPARAMS=${mib_STRIPEPARAMS:-"-c -1"}

	print_opts MIB mib_THREADS mib_xferSize mib_xferLimit mib_timeLimit \
		MACHINEFILE

	local testdir=$DIR/d0.mib
	test_mkdir $testdir
	setstripe_getstripe $testdir $mib_STRIPEPARAMS

	# mpi_run uses mpiuser
	chmod 0777 $testdir

	#
	# -I    Show intermediate values in output
	# -H    Show headers in output
	# -L    Do not issue new system calls after this many seconds
	# -s    Use system calls of this size
	# -t    test dir
	# -l    Issue no more than this many system calls
	local cmd="$MIB -t $testdir -s $mib_xferSize -l $mib_xferLimit \
		-L $mib_timeLimit -HI -p mib.$(date +%Y%m%d%H%M%S)"

	echo "+ $cmd"
	# find out if we need to use srun by checking $SRUN_PARTITION
	if [ "$SRUN_PARTITION" ]; then
		$SRUN $SRUN_OPTIONS -D $testdir -w $clients -N $num_clients \
			-n $((num_clients * mib_THREADS)) -p $SRUN_PARTITION \
			-- $cmd
	else
		mpi_run ${MACHINEFILE_OPTION} ${MACHINEFILE} \
			-np $((num_clients * mib_THREADS)) $cmd
	fi

    local rc=$?
    if [ $rc != 0 ] ; then
        error "mib failed! $rc"
    fi
    rm -rf $testdir
}

run_cascading_rw() {
	CASC_RW=${CASC_RW:-$(which cascading_rw 2> /dev/null || true)}
	[ x$CASC_RW = x ] && skip_env "cascading_rw not found"
	[ "$NFSCLIENT" ] && skip "skipped for NFSCLIENT mode"

	# threads per client
	casc_THREADS=${casc_THREADS:-2}
	casc_REP=${casc_REP:-300}

	# FIXME
	# Need space estimation here.

	print_opts CASC_RW clients casc_THREADS casc_REP MACHINEFILE

	local testdir=$DIR/d0.cascading_rw
	test_mkdir $testdir
	setstripe_getstripe $testdir $casc_STRIPEPARAMS

	# mpi_run uses mpiuser
	chmod 0777 $testdir

	# -g: debug mode
	# -n: repeat test # times

	local cmd="$CASC_RW -g -d $testdir -n $casc_REP"

	echo "+ $cmd"
	mpi_run ${MACHINEFILE_OPTION} ${MACHINEFILE} \
		-np $((num_clients * $casc_THREADS)) $cmd

    local rc=$?
    if [ $rc != 0 ] ; then
        error "cascading_rw failed! $rc"
    fi
    rm -rf $testdir
}

run_write_append_truncate() {
	[ "$NFSCLIENT" ] && skip "skipped for NFSCLIENT mode"
	# location is lustre/tests dir
	if ! which write_append_truncate > /dev/null 2>&1 ; then
		skip_env "write_append_truncate not found"
	fi

	# threads per client
	write_THREADS=${write_THREADS:-8}
	write_REP=${write_REP:-10000}

	# FIXME
	# Need space estimation here.

	local testdir=$DIR/d0.write_append_truncate
	local file=$testdir/f0.wat

	print_opts clients write_REP write_THREADS MACHINEFILE

	test_mkdir $testdir
	# mpi_run uses mpiuser
	setstripe_getstripe $testdir $write_STRIPEPARAMS

	chmod 0777 $testdir

	local cmd="write_append_truncate -n $write_REP $file"

	echo "+ $cmd"
	mpi_run ${MACHINEFILE_OPTION} ${MACHINEFILE} \
		-np $((num_clients * $write_THREADS)) $cmd

    local rc=$?
    if [ $rc != 0 ] ; then
        error "write_append_truncate failed! $rc"
        return $rc
    fi
    rm -rf $testdir
}

run_write_disjoint() {
	WRITE_DISJOINT=${WRITE_DISJOINT:-$(which write_disjoint 2> /dev/null ||
					   true)}
	[ x$WRITE_DISJOINT = x ] && skip_env "write_disjoint not found"
	[ "$NFSCLIENT" ] && skip "skipped for NFSCLIENT mode"

	# threads per client
	wdisjoint_THREADS=${wdisjoint_THREADS:-4}
	wdisjoint_REP=${wdisjoint_REP:-10000}
	chunk_size_limit=$1

	# FIXME
	# Need space estimation here.

	print_opts WRITE_DISJOINT clients wdisjoint_THREADS wdisjoint_REP \
		MACHINEFILE
	local testdir=$DIR/d0.write_disjoint
	test_mkdir $testdir
	setstripe_getstripe $testdir $wdisjoint_STRIPEPARAMS

	# mpi_run uses mpiuser
	chmod 0777 $testdir

	local cmd="$WRITE_DISJOINT -f $testdir/file -n $wdisjoint_REP -m \
			$chunk_size_limit"

	echo "+ $cmd"
	mpi_run ${MACHINEFILE_OPTION} ${MACHINEFILE} \
		-np $((num_clients * $wdisjoint_THREADS)) $cmd

    local rc=$?
    if [ $rc != 0 ] ; then
        error "write_disjoint failed! $rc"
    fi
    rm -rf $testdir
}

run_parallel_grouplock() {
	PARALLEL_GROUPLOCK=${PARALLEL_GROUPLOCK:-$(which parallel_grouplock \
	    2> /dev/null || true)}

	[ x$PARALLEL_GROUPLOCK = x ] && skip "PARALLEL_GROUPLOCK not found"
	[ "$NFSCLIENT" ] && skip "skipped for NFSCLIENT mode"

	parallel_grouplock_MINTASKS=${parallel_grouplock_MINTASKS:-5}

	print_opts clients parallel_grouplock_MINTASKS MACHINEFILE

	local testdir=$DIR/d0.parallel_grouplock
	test_mkdir $testdir
	setstripe_getstripe $testdir $parallel_grouplock_STRIPEPARAMS

	# mpi_run uses mpiuser
	chmod 0777 $testdir

	local cmd
	local status=0
	local subtest
	for i in $(seq 12); do
		subtest="-t $i"
		local cmd="$PARALLEL_GROUPLOCK -g -v -d $testdir $subtest"
		echo "+ $cmd"

		mpi_run ${MACHINEFILE_OPTION} ${MACHINEFILE} \
			-np $parallel_grouplock_MINTASKS $cmd
		local rc=$?
		if [ $rc != 0 ] ; then
			error_noexit "parallel_grouplock subtests $subtest " \
				     "failed! $rc"
		else
			echo "parallel_grouplock subtests $subtest PASS"
		fi
		let status=$((status + rc))
		# clear debug to collect one log per one test
		do_nodes $(comma_list $(nodes_list)) lctl clear
	done
	[ $status -eq 0 ] || error "parallel_grouplock status: $status"
	rm -rf $testdir
}

cleanup_statahead () {
    trap 0

    local clients=$1
    local mntpt_root=$2
    local num_mntpts=$3

    for i in $(seq 0 $num_mntpts);do
        zconf_umount_clients $clients ${mntpt_root}$i ||
            error_exit "Failed to umount lustre on ${mntpt_root}$i"
    done
}

run_statahead () {
	if [[ -n $NFSCLIENT ]]; then
		skip "Statahead testing is not supported on NFS clients."
	fi
	[ x$MDSRATE = x ] && skip_env "mdsrate not found"

	statahead_NUMMNTPTS=${statahead_NUMMNTPTS:-5}
	statahead_NUMFILES=${statahead_NUMFILES:-500000}

	print_opts MDSRATE clients statahead_NUMMNTPTS statahead_NUMFILES

	# create large dir

	# do not use default "d[0-9]*" dir name
	# to avoid of rm $statahead_NUMFILES (500k) files in t-f cleanup
	local dir=dstatahead
	local testdir=$DIR/$dir

	# cleanup only if dir exists
	# cleanup only $statahead_NUMFILES number of files
	# ignore the other files created by someone else
	[ -d $testdir ] &&
	mdsrate_cleanup $((num_clients * 32)) $MACHINEFILE \
		$statahead_NUMFILES $testdir 'f%%d' --ignore

	test_mkdir $testdir
	setstripe_getstripe $testdir $statahead_STRIPEPARAMS

    # mpi_run uses mpiuser
    chmod 0777 $testdir

    local num_files=$statahead_NUMFILES

    local IFree=$(inodes_available)
    if [ $IFree -lt $num_files ]; then
      num_files=$IFree
    fi

    cancel_lru_locks mdc

    local cmd1="${MDSRATE} ${MDSRATE_DEBUG} --mknod --dir $testdir"
    local cmd2="--nfiles $num_files --filefmt 'f%%d'"
    local cmd="$cmd1 $cmd2"
    echo "+ $cmd"

	mpi_run ${MACHINEFILE_OPTION} ${MACHINEFILE} \
		-np $((num_clients * 32)) $cmd

    local rc=$?
    if [ $rc != 0 ] ; then
        error "mdsrate failed to create $rc"
        return $rc
    fi

    local num_mntpts=$statahead_NUMMNTPTS
    local mntpt_root=$TMP/mntpt/lustre
    local mntopts=$MNTOPTSTATAHEAD

    echo "Mounting $num_mntpts lustre clients starts on $clients"
    trap "cleanup_statahead $clients $mntpt_root $num_mntpts" EXIT ERR
    for i in $(seq 0 $num_mntpts); do
        zconf_mount_clients $clients ${mntpt_root}$i "$mntopts" ||
            error_exit "Failed to mount lustre on ${mntpt_root}$i on $clients"
    done

    do_rpc_nodes $clients cancel_lru_locks mdc

    do_rpc_nodes $clients do_ls $mntpt_root $num_mntpts $dir

    mdsrate_cleanup $((num_clients * 32)) $MACHINEFILE \
        $num_files $testdir 'f%%d' --ignore

    # use rm instead of rmdir because of
    # testdir could contain the files created by someone else,
    # or by previous run where is num_files prev > num_files current
    rm -rf $testdir
    cleanup_statahead $clients $mntpt_root $num_mntpts
}

cleanup_rr_alloc () {
	trap 0
	local clients="$1"
	local mntpt_root="$2"
	local rr_alloc_MNTPTS="$3"
	local mntpt_dir=$(dirname ${mntpt_root})

	for i in $(seq 0 $((rr_alloc_MNTPTS - 1))); do
		zconf_umount_clients $clients ${mntpt_root}$i ||
		error_exit "Failed to umount lustre on ${mntpt_root}$i"
	done
	do_nodes $clients "rm -rf $mntpt_dir"
}

run_rr_alloc() {
	remote_mds_nodsh && skip "remote MDS with nodsh"
	echo "===Test gives more reproduction percentage if number of "\
		"client and ost are more. Test with 44 or more clients "\
		"and 73 or more OSTs gives 100% reproduction rate=="

	RR_ALLOC=${RR_ALLOC:-$(which rr_alloc 2> /dev/null || true)}
	[ x$RR_ALLOC = x ] && skip_env "rr_alloc not found"
	declare -a diff_max_min_arr
	# foeo = file on each ost. calc = calculated.
	local ost_idx
	local foeo_calc
	local qos_prec_objs="${TMP}/qos_and_precreated_objects"
	local rr_alloc_NFILES=${rr_alloc_NFILES:-555}
	local rr_alloc_MNTPTS=${rr_alloc_MNTPTS:-11}
	local total_MNTPTS=$((rr_alloc_MNTPTS * num_clients))
	local mntpt_root="${TMP}/rr_alloc_mntpt/lustre"
	test_mkdir $DIR/$tdir
	setstripe_getstripe $DIR/$tdir $rr_alloc_STRIPEPARAMS

	chmod 0777 $DIR/$tdir

	trap "cleanup_rr_alloc $clients $mntpt_root $rr_alloc_MNTPTS" EXIT ERR
	for i in $(seq 0 $((rr_alloc_MNTPTS - 1))); do
		zconf_mount_clients $clients ${mntpt_root}$i $MOUNT_OPTS ||
		error_exit "Failed to mount lustre on ${mntpt_root}$i $clients"
	done

	local cmd="$RR_ALLOC $mntpt_root/$tdir/ash $rr_alloc_NFILES \
		$num_clients"

	# Save mdt values, set threshold to 100% i.e always Round Robin,
	# restore the saved values again after creating files...
	save_lustre_params mds1 \
		"lod.$FSNAME-MDT0000*.qos_threshold_rr" > $qos_prec_objs
	save_lustre_params mds1 \
		"osp.$FSNAME-OST*-osc-MDT0000.create_count" >> $qos_prec_objs

	local old_create_count=$(grep -e "create_count" $qos_prec_objs |
		cut -d'=' -f 2 | sort -nr | head -n1)

	# Make sure that every osp has enough precreated objects for the file
	# creation app

	# create_count is always set to the power of 2 only, so if the files
	# per OST are not multiple of that then it will be set to nearest
	# lower power of 2. So set 'create_count' to the upper power of 2.

	foeo_calc=$((rr_alloc_NFILES * total_MNTPTS / OSTCOUNT))
	local create_count=$((2 * foeo_calc))

	# create_count accepted values:
	#   [OST_MIN_PRECREATE=32, OST_MAX_PRECREATE=20000]
	# values outside this range are ignored and -ERANGE is returned.
	# NOTE: actual maximum value is 16384 (2^14)
	[[ $create_count -lt 32 ]] && create_count=32
	[[ $create_count -gt 20000 ]] && create_count=20000
	local i
	for i in $(seq $MDSCOUNT); do
		do_facet mds$i "$LCTL set_param -n \
			lod.$FSNAME-MDT*.qos_threshold_rr=100 \
			osp.$FSNAME-OST*-osc-MDT*.create_count=$create_count" ||
			error "failed while setting qos_threshold_rr & creat_count"
	done

	# Create few temporary files in order to increase the precreated objects
	# to a desired value, before starting 'rr_alloc' app. Due to default
	# value 32 of precreation count (OST_MIN_PRECREATE=32), precreated
	# objects available are 32 initially, these gets exhausted very soon,
	# which causes skip of some osps when very large number of files
	# is created per OSTs.
	createmany -o $DIR/$tdir/foo- $(((old_create_count + 1) * OSTCOUNT)) \
		> /dev/null
	rm -f /$DIR/$tdir/foo*

	# Check for enough precreated objects... We should not
	# fail here because code(osp_precreate.c) also takes care of it.
	# So we have good chances of passing test even if this check fails.
	local mdt_idx=0
	for ost_idx in $(seq 0 $((OSTCOUNT - 1))); do
		[[ $(precreated_ost_obj_count $mdt_idx $ost_idx) -ge \
			$foeo_calc ]] || echo "Warning: test may fail because" \
			"of lack of precreated objects on OST${ost_idx}"
	done

	if [[ $total_MNTPTS -ne 0 ]]; then
		# Now start the actual file creation app.
		mpi_run "-np $total_MNTPTS" $cmd || return
	else
		error "No mount point"
	fi

	restore_lustre_params < $qos_prec_objs
	rm -f $qos_prec_objs

	diff_max_min_arr=($($LFS getstripe -r $DIR/$tdir/ |
		grep "lmm_stripe_offset:" | awk '{print $2}' | sort -n |
		uniq -c | awk 'NR==1 {min=max=$1} \
		{ $1<min ? min=$1 : min; $1>max ? max=$1 : max} \
		END {print max-min, max, min}'))

	rm -rf $DIR/$tdir

	# In-case of fairly large number of file creation using RR (round-robin)
	# there can be two cases in which deviation will occur than the regular
	# RR algo behaviour-
	# 1- When rr_alloc does not start right with 'lqr_start_count' reseeded,
	# 2- When rr_alloc does not finish with 'lqr_start_count == 0'.
	# So the difference of files b/w any 2 OST should not be more than 2.
	[[ ${diff_max_min_arr[0]} -le 2 ]] ||
		error "Uneven distribution detected: difference between" \
		"maximum files per OST (${diff_max_min_arr[1]}) and" \
		"minimum files per OST (${diff_max_min_arr[2]}) must not be" \
		"greater than 2"
}

run_fs_test() {
	# fs_test.x is the default name for exe
	FS_TEST=${FS_TEST:=$(which fs_test.x 2> /dev/null || true)}

	local clients=${CLIENTS:-$(hostname)}
	local testdir=$DIR/d0.fs_test
	local file=${testdir}/fs_test
	fs_test_threads=${fs_test_threads:-2}
	fs_test_type=${fs_test_type:-1}
	fs_test_nobj=${fs_test_nobj:-10}
	fs_test_check=${fs_test_check:-3}
	fs_test_strided=${fs_test_strided:-1}
	fs_test_touch=${fs_test_touch:-3}
	fs_test_supersize=${fs_test_supersize:-1}
	fs_test_op=${fs_test_op:-write}
	fs_test_barriers=${fs_test_barriers:-bopen,bwrite,bclose}
	fs_test_io=${fs_test_io:-mpi}
	fs_test_objsize=${fs_test_objsize:-100}
	fs_test_objunit=${fs_test_objunit:-1048576} # 1 mb
	fs_test_ndirs=${fs_test_ndirs:-80000}

	[ x$FS_TEST = x ] && skip "FS_TEST not found"

	# Space estimation  in bytes
	local space=$(df -B 1 -P $dir | tail -n 1 | awk '{ print $4 }')
	local total_threads=$((num_clients * fs_test_threads))
	echo "+ $fs_test_objsize * $fs_test_objunit * $total_threads "
	if [ $((space / 2)) -le \
		$((fs_test_objsize * fs_test_objunit * total_threads)) ]; then
			fs_test_objsize=$((space / 2 / fs_test_objunit / \
				total_threads))
			[ $fs_test_objsize -eq 0 ] &&
			skip_env "Need free space more than \
				$((2 * total_threads * fs_test_objunit)) \
				: have $((space / fs_test_objunit))"

			echo "(reduced objsize to \
				$((fs_test_objsize * fs_test_objunit)) bytes)"
	fi

	print_opts FS_TEST clients fs_test_threads fs_test_objsize MACHINEFILE

	test_mkdir $testdir
	setstripe_getstripe $testdir $fs_test_STRIPEPARAMS

	# mpi_run uses mpiuser
	chmod 0777 $testdir

	# --nodb          Turn off the database code at runtime
	# -g --target     The path to the data file
	# -t --type       Whether to do N-N (1) or N-1 (2)
	# -n --nobj       The number of objects written/read by each proc
	# -z --size       The size of each object
	# -d ---num_nn_dirs Number of subdirectories for files
	# -C --check      Check every byte using argument 3.
	# --collective    Whether to use collective I/O (for N-1, mpi-io only)
	# -s --strided    Whether to use a strided pattern (for N-1 only)
	# -T --touch      Touch every byte using argument 3
	# -o --op         Whether to read only (read) or write only (write)
	# -b --barriers   When to barrier.
	# -i --io         Use POSIX, MPI, or PLFS IO routines (mpi|posix|plfs)
	# -S --supersize  Specify how many objects per superblock

	local cmd="$FS_TEST -nodb -g $file -t $fs_test_type -n $fs_test_nobj \
		-z $((fs_test_objsize * fs_test_objunit)) -d $fs_test_ndirs \
		-C $fs_test_check -collective -s $fs_test_strided \
		-T $fs_test_touch -o $fs_test_op -b $fs_test_barriers \
		-i $fs_test_io -S $fs_test_supersize"

	echo "+ $cmd"
	mpi_run "-np $((num_clients * fs_test_threads))" $cmd

	local rc=$?
	if [ $rc != 0 ] ; then
		error "fs_test failed! $rc"
	fi

	rm -rf $testdir
}

ior_mdtest_parallel() {
	local rc1=0
	local rc2=0
	local type=$1

	run_ior $type &
	local pids=$!

	run_mdtest $type || rc2=$?
	[[ $rc2 -ne 0 ]] && echo "mdtest failed with error $rc2"

	wait $pids || rc1=$?
	[[ $rc1 -ne 0 ]] && echo "ior failed with error $rc1"

	[[ $rc1 -ne 0 || $rc2 -ne 0 ]] && return 1
	return 0
}

run_fio() {
	FIO=${FIO:=$(which fio 2> /dev/null || true)}

	local clients=${CLIENTS:-$(hostname)}
	local fio_jobNum=${fio_jobNum:-4}
	local fio_jobFile=${fio_jobFile:-$TMP/fiojobfile.$(date +%s)}
	local fio_bs=${fio_bs:-1}
	local testdir=$DIR/d0.fio
	local file=${testdir}/fio
	local runtime=60
	local propagate=false

	[ "$SLOW" = "no" ] || runtime=600

	[ x$FIO = x ] && skip_env "FIO not found"

	test_mkdir $testdir
	setstripe_getstripe $testdir $fio_STRIPEPARAMS

	# use fio job file if exists,
	# create a simple one if missing
	if ! [ -f $fio_jobFile ]; then
		cat >> $fio_jobFile <<EOF
[global]
rw=randwrite
size=128m
time_based=1
runtime=$runtime
filename=${file}_\$(hostname)
EOF
		# bs size increased by $i for each job
		for ((i=1; i<=fio_jobNum; i++)); do
			cat >> $fio_jobFile <<EOF

[job$i]
bs=$(( fio_bs * i ))m
EOF
		done
		# job file is created, should be propagated to all clients
		propagate=true
	fi


	# propagate the job file if not all clients have it yet or
	# if the job file was created during the test run
	if ! do_nodesv $clients " [ -f $fio_jobFile ] " ||
	   $propagate; then
		local cfg=$(cat $fio_jobFile)
		do_nodes $clients "echo \\\"$cfg\\\" > ${fio_jobFile}" ||
			error "job file $fio_jobFile is not propagated"
		do_nodesv $clients "cat ${fio_jobFile}"
	fi

	cmd="$FIO $fio_jobFile"
	echo "+ $cmd"

	log "clients: $clients $cmd"

	local rc=0
	do_nodesv $clients "$cmd "
	rc=$?

	[ $rc = 0 ] || error "fio failed: $rc"
	rm -rf $testdir
}

run_xdd() {
	XDD=${XDD:=$(which xdd 2> /dev/null || true)}

	local clients=${CLIENTS:-$(hostname)}
	local testdir=$DIR/d0.xdd
	xdd_queuedepth=${xdd_queuedepth:-4}
	xdd_blocksize=${xdd_blocksize:-512}
	xdd_reqsize=${xdd_reqsize:-128}
	xdd_mbytes=${xdd_mbytes:-100}
	xdd_passes=${xdd_passes:-40}
	xdd_rwratio=${xdd_rwratio:-0}
	xdd_ntargets=${xdd_ntargets:-6}
	local xdd_custom_params=${xdd_custom_params:-"-dio -stoponerror \
		-maxpri -minall -noproclock -nomemlock"}

	[ x$XDD = x ] && skip "XDD not found"

	print_opts XDD clients xdd_queuedepth xdd_blocksize xdd_reqsize \
		xdd_mbytes xdd_passes xdd_rwratio

	test_mkdir $testdir
	setstripe_getstripe $testdir $xdd_STRIPEPARAMS

	local files=""
	# Target files creates based on the given number of targets
	for (( i=0; i < $xdd_ntargets; i++ ))
	do
		files+="${testdir}/xdd"$i" "
	done

	# -targets      specifies the devices or files to perform operation
	# -reqsize      number of 'blocks' per operation
	# -mbytes       number of 1024*1024-byte blocks to transfer
	# -blocksize    size of a single 'block'
	# -passes       number of times to read mbytes
	# -queuedepth   number of commands to queue on the target
	# -rwratio      percentage of read to write operations
	# -verbose      will print out statistics on each pass

	local cmd="$XDD -targets $xdd_ntargets $files -reqsize $xdd_reqsize \
		-mbytes $xdd_mbytes -blocksize $xdd_blocksize \
		-passes $xdd_passes -queuedepth $xdd_queuedepth \
		-rwratio $xdd_rwratio -verbose $xdd_custom_params"
	echo "+ $cmd"

	local rc=0
	do_nodesv $clients "$cmd "
	rc=$?

	[ $rc = 0 ] || error "xdd failed: $rc"

	rm -rf $testdir
}
