#!/bin/bash
#
#set -vx

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

#
# compilbench
#
cbench_DIR=${cbench_DIR:-""}
cbench_IDIRS=${cbench_IDIRS:-10}
cbench_RUNS=${cbench_RUNS:-10}	# FIXME: wiki page requirements is 30, do we really need 30 ?

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

build_test_filter
check_and_setup_lustre

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
        { skip "compilebench not found" && return; }

    [ -e $cbench_DIR/compilebench ] || \
        { skip "No compilebench build" && return; }

    local space=$(df -P $DIR | tail -n 1 | awk '{ print $4 }')
    if [ $space -le $((680 * 1024 * cbench_IDIRS)) ]; then
        cbench_IDIRS=$(( space / 680 / 1024))
        [ $cbench_IDIRS = 0 ] && \
            skip "Need free space atleast 680 Mb, have $space" && return

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
        { skip "metabench not found" && return; }

    local clients=$CLIENTS
    [ -z $clients ] && clients=$(hostname)

    num_clients=$(get_node_count ${clients//,/ })

    # FIXME
    # Need space estimation here.

    generate_machine_file $clients $MACHINEFILE || \
        error "can not generate machinefile $MACHINEFILE"

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
    [ x$SIMUL = x ] &&
        { skip "simul not found" && return; }

    local clients=$CLIENTS
    [ -z $clients ] && clients=$(hostname)

    local num_clients=$(get_node_count ${clients//,/ })

    # FIXME
    # Need space estimation here.

    generate_machine_file $clients $MACHINEFILE || \
        error "can not generate machinefile $MACHINEFILE"

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
        { skip "connectathon dir not found" && return; }

    [ -e $cnt_DIR/runtests ] || \
        { skip "No connectathon runtests found" && return; }

    local testdir=$DIR/d0.connectathon
    mkdir -p $testdir

    local savePWD=$PWD
    cd $cnt_DIR

    # -f      a quick functionality test
    # -a      run basic, general, special, and lock tests
    # -N numpasses - will be passed to the runtests script.  This argument
    #         is optional.  It specifies the number of times to run
    #         through the tests.

    local cmd="./runtests -N $cnt_NRUN -a -f $testdir"

    log "$cmd"

    local rc=0
    eval $cmd
    rc=$?

    cd $savePWD
    [ $rc = 0 ] || error "connectathon failed: $rc"
    rm -rf $testdir
}
run_test connectathon "connectathon"

test_ior() {
    [ x$IOR = x ] &&
        { skip "IOR not found" && return; }

    local clients=$CLIENTS
    [ -z $clients ] && clients=$(hostname)

    local num_clients=$(get_node_count ${clients//,/ })

    local space=$(df -P $DIR | tail -n 1 | awk '{ print $4 }')
    echo "+ $ior_blockSize * 1024 * 1024 * $num_clients * $ior_THREADS "
    if [ $((space / 2)) -le $(( ior_blockSize * 1024 * 1024 * num_clients * ior_THREADS)) ]; then
        echo "+ $space * 9/10 / 1024 / 1024 / $num_clients / $ior_THREADS"
        ior_blockSize=$(( space /2 /1024 /1024 / num_clients / ior_THREADS ))
        [ $ior_blockSize = 0 ] && \
            skip "Need free space more than ($num_clients * $ior_THREADS )Gb: $((num_clients*ior_THREADS *1024 *1024*2)), have $space" && return

        echo "free space=$space, Need: $num_clients x $ior_THREADS x $ior_blockSize Gb (blockSize reduced to $ior_blockSize Gb)"
    fi
 
    generate_machine_file $clients $MACHINEFILE || \
        error "can not generate machinefile $MACHINEFILE"

    print_opts IOR ior_THREADS ior_DURATION MACHINEFILE

    local testdir=$DIR/d0.ior
    mkdir -p $testdir
    # mpi_run uses mpiuser
    chmod 0777 $testdir

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
    [ x$CASC_RW = x ] &&
        { skip "cascading_rw not found" && return; }

    local clients=$CLIENTS
    [ -z $clients ] && clients=$(hostname)

    num_clients=$(get_node_count ${clients//,/ })

    # FIXME
    # Need space estimation here.

    generate_machine_file $clients $MACHINEFILE || \
        error "can not generate machinefile $MACHINEFILE"

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
    # location is lustre/tests dir 
    if ! which write_append_truncate > /dev/null 2>&1 ; then
        skip "write_append_truncate not found"
        return
    fi

    local clients=$CLIENTS
    [ -z $clients ] && clients=$(hostname)

    local num_clients=$(get_node_count ${clients//,/ })

    # FIXME
    # Need space estimation here.

    generate_machine_file $clients $MACHINEFILE || \
        error "can not generate machinefile $MACHINEFILE"

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
    [ x$WRITE_DISJOINT = x ] &&
        { skip "write_disjoint not found" && return; }

    local clients=$CLIENTS
    [ -z $clients ] && clients=$(hostname)

    local num_clients=$(get_node_count ${clients//,/ })

    # FIXME
    # Need space estimation here.

    generate_machine_file $clients $MACHINEFILE || \
        error "can not generate machinefile $MACHINEFILE"

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

equals_msg `basename $0`: test complete, cleaning up
check_and_cleanup_lustre
[ -f "$TESTSUITELOG" ] && cat $TESTSUITELOG || true
