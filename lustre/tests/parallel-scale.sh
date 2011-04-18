#!/bin/bash
#
#set -vx

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

#              bug 20670 
ALWAYS_EXCEPT="parallel_grouplock $PARALLEL_SCALE_EXCEPT"

#
# compilbench
#
cbench_DIR=${cbench_DIR:-""}
cbench_IDIRS=${cbench_IDIRS:-4}
cbench_RUNS=${cbench_RUNS:-4}	# FIXME: wiki page requirements is 30, do we really need 30 ?

if [ "$SLOW" = "no" ]; then
    cbench_IDIRS=2
    cbench_RUNS=2
fi

#
# metabench
#
METABENCH=${METABENCH:-$(which metabench 2> /dev/null || true)}
mbench_NFILES=${mbench_NFILES:-30400}
[ "$SLOW" = "no" ] && mbench_NFILES=10000
MACHINEFILE=${MACHINEFILE:-$TMP/$(basename $0 .sh).machines}
# threads per client
mbench_THREADS=${mbench_THREADS:-4}

#
# simul
#
SIMUL=${SIMUL:=$(which simul 2> /dev/null || true)}
# threads per client
simul_THREADS=${simul_THREADS:-2}
simul_REP=${simul_REP:-20}
[ "$SLOW" = "no" ] && simul_REP=2

#
# connectathon
#
cnt_DIR=${cnt_DIR:-""}
cnt_NRUN=${cnt_NRUN:-10}
[ "$SLOW" = "no" ] && cnt_NRUN=2

#
# cascading rw
#
CASC_RW=${CASC_RW:-$(which cascading_rw 2> /dev/null || true)}
# threads per client
casc_THREADS=${casc_THREADS:-2}
casc_REP=${casc_REP:-300}
[ "$SLOW" = "no" ] && casc_REP=10

#
# IOR
#
IOR=${IOR:-$(which IOR 2> /dev/null || true)}
# threads per client
ior_THREADS=${ior_THREADS:-2}
ior_blockSize=${ior_blockSize:-6}	# Gb
ior_DURATION=${ior_DURATION:-30}	# minutes
[ "$SLOW" = "no" ] && ior_DURATION=5

#
# write_append_truncate
#
# threads per client
write_THREADS=${write_THREADS:-8}
write_REP=${write_REP:-10000}
[ "$SLOW" = "no" ] && write_REP=100

#
# write_disjoint
#
WRITE_DISJOINT=${WRITE_DISJOINT:-$(which write_disjoint 2> /dev/null || true)}
# threads per client
wdisjoint_THREADS=${wdisjoint_THREADS:-4}
wdisjoint_REP=${wdisjoint_REP:-10000}
[ "$SLOW" = "no" ] && wdisjoint_REP=100

#
# parallel_grouplock
#
#
PARALLEL_GROUPLOCK=${PARALLEL_GROUPLOCK:-$(which parallel_grouplock 2> /dev/null || true)}
parallel_grouplock_MINTASKS=${parallel_grouplock_MINTASKS:-5}

build_test_filter
check_and_setup_lustre

get_mpiuser_id $MPI_USER
MPI_RUNAS=${MPI_RUNAS:-"runas -u $MPI_USER_UID -g $MPI_USER_GID"}
$GSS_KRB5 && refresh_krb5_tgt $MPI_USER_UID $MPI_USER_GID $MPI_RUNAS

print_opts () {
    local var

    echo OPTIONS:

    for i in $@; do
        var=$i
        echo "${var}=${!var}"
    done
    [ -e $MACHINEFILE ] && cat $MACHINEFILE
}

# Takes:
# 5 min * cbench_RUNS
#        SLOW=no     10 mins
#        SLOW=yes    50 mins
# Space estimation:
#        compile dir kernel-1 680MB
#        required space       680MB * cbench_IDIRS = ~7 Gb

test_compilebench() {
    print_opts cbench_DIR cbench_IDIRS cbench_RUNS

    [ x$cbench_DIR = x ] &&
        { skip_env "compilebench not found" && return; }

    [ -e $cbench_DIR/compilebench ] || \
        { skip_env "No compilebench build" && return; }

    local space=$(df -P $DIR | tail -n 1 | awk '{ print $4 }')
    if [ $space -le $((680 * 1024 * cbench_IDIRS)) ]; then
        cbench_IDIRS=$(( space / 680 / 1024))
        [ $cbench_IDIRS = 0 ] && \
            skip_env "Need free space atleast 680 Mb, have $space" && return

        log free space=$space, reducing initial dirs to $cbench_IDIRS
    fi
    # FIXME:
    # t-f _base needs to be modifyed to set properly tdir
    # for new "test_foo" functions names
    # local testdir=$DIR/$tdir
    local testdir=$DIR/d0.compilebench
    mkdir -p $testdir

    local savePWD=$PWD
    cd $cbench_DIR 
    local cmd="./compilebench -D $testdir -i $cbench_IDIRS -r $cbench_RUNS --makej"

    log "$cmd"

    local rc=0
    eval $cmd
    rc=$?
        
    cd $savePWD
    [ $rc = 0 ] || error "compilebench failed: $rc"
    rm -rf $testdir
}
run_test compilebench "compilebench"

test_metabench() {
    [ x$METABENCH = x ] &&
        { skip_env "metabench not found" && return; }

    local clients=$CLIENTS
    [ -z $clients ] && clients=$(hostname)

    num_clients=$(get_node_count ${clients//,/ })

    # FIXME
    # Need space estimation here.

    generate_machine_file $clients $MACHINEFILE || return $?

    print_opts METABENCH clients mbench_NFILES mbench_THREADS

    local testdir=$DIR/d0.metabench
    mkdir -p $testdir
    # mpi_run uses mpiuser
    chmod 0777 $testdir

    # -C             Run the file creation tests.
    # -S             Run the file stat tests.
    # -c nfile       Number of files to be used in each test.
    # -k             Cleanup.  Remove the test directories.
    local cmd="$METABENCH -w $testdir -c $mbench_NFILES -C -S -k"
    echo "+ $cmd"
    mpi_run -np $((num_clients * $mbench_THREADS)) -machinefile ${MACHINEFILE} $cmd
    local rc=$?
    if [ $rc != 0 ] ; then
        error "metabench failed! $rc"
    fi
    rm -rf $testdir
}
run_test metabench "metabench"

test_simul() {
    if [ "$NFSCLIENT" ]; then
        skip "skipped for NFSCLIENT mode"
        return
    fi

    [ x$SIMUL = x ] &&
        { skip_env "simul not found" && return; }

    local clients=$CLIENTS
    [ -z $clients ] && clients=$(hostname)

    local num_clients=$(get_node_count ${clients//,/ })

    # FIXME
    # Need space estimation here.

    generate_machine_file $clients $MACHINEFILE || return $?

    print_opts SIMUL clients simul_REP simul_THREADS

    local testdir=$DIR/d0.simul
    mkdir -p $testdir
    # mpi_run uses mpiuser
    chmod 0777 $testdir

    # -n # : repeat each test # times
    # -N # : repeat the entire set of tests # times

    local cmd="$SIMUL -d $testdir -n $simul_REP -N $simul_REP"

    echo "+ $cmd"
    mpi_run -np $((num_clients * $simul_THREADS)) -machinefile ${MACHINEFILE} $cmd

    local rc=$?
    if [ $rc != 0 ] ; then
        error "simul failed! $rc"
    fi
    rm -rf $testdir
}
run_test simul "simul"

test_connectathon() {
    print_opts cnt_DIR cnt_NRUN

    [ x$cnt_DIR = x ] &&
        { skip_env "connectathon dir not found" && return; }

    [ -e $cnt_DIR/runtests ] || \
        { skip_env "No connectathon runtests found" && return; }

    local testdir=$DIR/d0.connectathon
    mkdir -p $testdir

    local savePWD=$PWD
    cd $cnt_DIR

    #
    # cthon options (must be in this order)
    #
    # -N numpasses - will be passed to the runtests script.  This argument
    #         is optional.  It specifies the number of times to run
    #         through the tests.
    #
    # One of these test types
    #    -b  basic
    #    -g  general
    #    -s  special
    #    -l  lock
    #    -a  all of the above
    #   
    # -f      a quick functionality test
    # 

    tests="-b -g -s"
    # Include lock tests unless we're running on nfsv4
    local fstype=$(df -TP $testdir | awk 'NR==2  {print $2}')
    echo "$testdir: $fstype"
    if [[ $fstype != "nfs4" ]]; then
	tests="$tests -l"
    fi
    echo "tests: $tests"
    for test in $tests; do
	local cmd="./runtests -N $cnt_NRUN $test -f $testdir"
	local rc=0

	log "$cmd"
	eval $cmd
	rc=$?
	[ $rc = 0 ] || error "connectathon failed: $rc"
    done

    cd $savePWD
    rm -rf $testdir
}
run_test connectathon "connectathon"

test_ior() {
    [ x$IOR = x ] &&
        { skip_env "IOR not found" && return; }

    local clients=$CLIENTS
    [ -z $clients ] && clients=$(hostname)

    local num_clients=$(get_node_count ${clients//,/ })

    local space=$(df -P $DIR | tail -n 1 | awk '{ print $4 }')
    echo "+ $ior_blockSize * 1024 * 1024 * $num_clients * $ior_THREADS "
    if [ $((space / 2)) -le $(( ior_blockSize * 1024 * 1024 * num_clients * ior_THREADS)) ]; then
        echo "+ $space * 9/10 / 1024 / 1024 / $num_clients / $ior_THREADS"
        ior_blockSize=$(( space /2 /1024 /1024 / num_clients / ior_THREADS ))
        [ $ior_blockSize = 0 ] && \
            skip_env "Need free space more than ($num_clients * $ior_THREADS )Gb: $((num_clients*ior_THREADS *1024 *1024*2)), have $space" && return

        echo "free space=$space, Need: $num_clients x $ior_THREADS x $ior_blockSize Gb (blockSize reduced to $ior_blockSize Gb)"
    fi
 
    generate_machine_file $clients $MACHINEFILE || return $?

    print_opts IOR ior_THREADS ior_DURATION MACHINEFILE

    local testdir=$DIR/d0.ior
    mkdir -p $testdir
    # mpi_run uses mpiuser
    chmod 0777 $testdir
    if [ "$NFSCLIENT" ]; then
        setstripe_nfsserver $testdir -c -1 || 
            { error "setstripe on nfsserver failed" && return 1; } 
    else
        $LFS setstripe $testdir -c -1 ||
            { error "setstripe failed" && return 2; }
    fi
    # 
    # -b N  blockSize -- contiguous bytes to write per task  (e.g.: 8, 4k, 2m, 1g)"
    # -o S  testFileName
    # -t N  transferSize -- size of transfer in bytes (e.g.: 8, 4k, 2m, 1g)"
    # -w    writeFile -- write file"
    # -r    readFile -- read existing file"
    # -T    maxTimeDuration -- max time in minutes to run tests"
    # -k    keepFile -- keep testFile(s) on program exit
    local cmd="$IOR -a POSIX -b ${ior_blockSize}g -o $testdir/iorData -t 2m -v -w -r -T $ior_DURATION -k"

    echo "+ $cmd"
    mpi_run -np $((num_clients * $ior_THREADS)) -machinefile ${MACHINEFILE} $cmd

    local rc=$?
    if [ $rc != 0 ] ; then
        error "ior failed! $rc"
    fi
    rm -rf $testdir
}
run_test ior "ior"
 
test_cascading_rw() {
    if [ "$NFSCLIENT" ]; then
        skip "skipped for NFSCLIENT mode"
        return
    fi

    [ x$CASC_RW = x ] &&
        { skip_env "cascading_rw not found" && return; }

    local clients=$CLIENTS
    [ -z $clients ] && clients=$(hostname)

    num_clients=$(get_node_count ${clients//,/ })

    # FIXME
    # Need space estimation here.

    generate_machine_file $clients $MACHINEFILE || return $?

    print_opts CASC_RW clients casc_THREADS casc_REP MACHINEFILE

    local testdir=$DIR/d0.cascading_rw
    mkdir -p $testdir
    # mpi_run uses mpiuser
    chmod 0777 $testdir

    # -g: debug mode 
    # -n: repeat test # times

    local cmd="$CASC_RW -g -d $testdir -n $casc_REP"

    echo "+ $cmd"
    mpi_run -np $((num_clients * $casc_THREADS)) -machinefile ${MACHINEFILE} $cmd

    local rc=$?
    if [ $rc != 0 ] ; then
        error "cascading_rw failed! $rc"
    fi
    rm -rf $testdir
}
run_test cascading_rw "cascading_rw"

test_write_append_truncate() {
    if [ "$NFSCLIENT" ]; then
        skip "skipped for NFSCLIENT mode"
        return
    fi

    # location is lustre/tests dir 
    if ! which write_append_truncate > /dev/null 2>&1 ; then
        skip_env "write_append_truncate not found"
        return
    fi

    local clients=$CLIENTS
    [ -z $clients ] && clients=$(hostname)

    local num_clients=$(get_node_count ${clients//,/ })

    # FIXME
    # Need space estimation here.

    generate_machine_file $clients $MACHINEFILE || return $?

    local testdir=$DIR/d0.write_append_truncate
    local file=$testdir/f0.wat

    print_opts clients write_REP write_THREADS MACHINEFILE

    mkdir -p $testdir
    # mpi_run uses mpiuser
    chmod 0777 $testdir

    local cmd="write_append_truncate -n $write_REP $file"

    echo "+ $cmd"
    mpi_run -np $((num_clients * $write_THREADS)) -machinefile ${MACHINEFILE} $cmd

    local rc=$?
    if [ $rc != 0 ] ; then
        error "write_append_truncate failed! $rc"
        return $rc
    fi
    rm -rf $testdir
}
run_test write_append_truncate "write_append_truncate"

test_write_disjoint() {
    if [ "$NFSCLIENT" ]; then
        skip "skipped for NFSCLIENT mode"
        return
    fi

    [ x$WRITE_DISJOINT = x ] &&
        { skip_env "write_disjoint not found" && return; }

    local clients=$CLIENTS
    [ -z $clients ] && clients=$(hostname)

    local num_clients=$(get_node_count ${clients//,/ })

    # FIXME
    # Need space estimation here.

    generate_machine_file $clients $MACHINEFILE || return $?

    print_opts WRITE_DISJOINT clients wdisjoint_THREADS wdisjoint_REP MACHINEFILE
    local testdir=$DIR/d0.write_disjoint
    mkdir -p $testdir
    # mpi_run uses mpiuser
    chmod 0777 $testdir

    local cmd="$WRITE_DISJOINT -f $testdir/file -n $wdisjoint_REP"

    echo "+ $cmd"
    mpi_run -np $((num_clients * $wdisjoint_THREADS)) -machinefile ${MACHINEFILE} $cmd

    local rc=$?
    if [ $rc != 0 ] ; then
        error "write_disjoint failed! $rc"
    fi
    rm -rf $testdir
}
run_test write_disjoint "write_disjoint"

test_parallel_grouplock() {
    if [ "$NFSCLIENT" ]; then
        skip "skipped for NFSCLIENT mode"
        return
    fi

    [ x$PARALLEL_GROUPLOCK = x ] &&
        { skip "PARALLEL_GROUPLOCK not found" && return; }

    local clients=$CLIENTS
    [ -z $clients ] && clients=$(hostname)

    local num_clients=$(get_node_count ${clients//,/ })

    generate_machine_file $clients $MACHINEFILE || return $?

    print_opts clients parallel_grouplock_MINTASKS MACHINEFILE

    local testdir=$DIR/d0.parallel_grouplock
    mkdir -p $testdir
    # mpi_run uses mpiuser
    chmod 0777 $testdir

    do_nodes $clients "lctl set_param llite.*.max_rw_chunk=0" ||
        error "set_param max_rw_chunk=0 failed "

    local cmd
    local status=0
    local subtest
    for i in $(seq 12); do
        subtest="-t $i"
        local cmd="$PARALLEL_GROUPLOCK -g -v -d $testdir $subtest"
        echo "+ $cmd"

        mpi_run -np $parallel_grouplock_MINTASKS -machinefile ${MACHINEFILE} $cmd
        local rc=$?
        if [ $rc != 0 ] ; then
            error_noexit "parallel_grouplock subtests $subtest failed! $rc"
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
run_test parallel_grouplock "parallel_grouplock"

statahead_NUMMNTPTS=${statahead_NUMMNTPTS:-5}
statahead_NUMFILES=${statahead_NUMFILES:-500000}

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

test_statahead () {
    if [[ -n $NFSCLIENT ]]; then
        skip "Statahead testing is not supported on NFS clients."
        return 0
    fi

    [ x$MDSRATE = x ] &&
        { skip_env "mdsrate not found" && return; }

    local clients=$CLIENTS
    [ -z $clients ] && clients=$(hostname)

    local num_clients=$(get_node_count ${clients//,/ })

    generate_machine_file $clients $MACHINEFILE || return $?

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
        mdsrate_cleanup $((num_clients * 32)) $MACHINEFILE $statahead_NUMFILES $testdir 'f%%d' --ignore

    mkdir -p $testdir
    # mpi_run uses mpiuser
    chmod 0777 $testdir

    local num_files=$statahead_NUMFILES

    local IFree=$(inodes_available)
    if [ $IFree -lt $num_files ]; then
      num_files=$IFree
    fi

    cancel_lru_locks mdc

    local cmd="${MDSRATE} ${MDSRATE_DEBUG} --mknod --dir $testdir --nfiles $num_files --filefmt 'f%%d'"    
    echo "+ $cmd"
    
    mpi_run -np $((num_clients * 32)) -machinefile ${MACHINEFILE} $cmd

    local rc=$?
    if [ $rc != 0 ] ; then
        error "mdsrate failed to create $rc"
        return $rc
    fi

    local num_mntpts=$statahead_NUMMNTPTS
    local mntpt_root=$TMP/mntpt/lustre
    local mntopts=${MNTOPTSTATAHEAD:-$MOUNTOPT}

    echo "Mounting $num_mntpts lustre clients starts on $clients"
    trap "cleanup_statahead $clients $mntpt_root $num_mntpts" EXIT ERR
    for i in $(seq 0 $num_mntpts); do
        zconf_mount_clients $clients ${mntpt_root}$i "$mntopts" ||
            error_exit "Failed to mount lustre on ${mntpt_root}$i on $clients"
    done

    do_rpc_nodes $clients cancel_lru_locks mdc

    do_rpc_nodes $clients do_ls $mntpt_root $num_mntpts $dir

    mdsrate_cleanup $((num_clients * 32)) $MACHINEFILE $num_files $testdir 'f%%d' --ignore

    # use rm instead of rmdir because of
    # testdir could contain the files created by someone else,
    # or by previous run where is num_files prev > num_files current
    rm -rf $testdir
    cleanup_statahead $clients $mntpt_root $num_mntpts
}

run_test statahead "statahead test, multiple clients"

complete $(basename $0) $SECONDS
check_and_cleanup_lustre
exit_status
