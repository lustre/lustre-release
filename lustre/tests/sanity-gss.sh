#!/bin/bash
# vim:expandtab:shiftwidth=4:softtabstop=4:tabstop=4:
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# e.g. ONLY="22 23" or ONLY="`seq 32 39`" or EXCEPT="31"
set -e

ONLY=${ONLY:-"$*"}
# bug number for skipped test:
ALWAYS_EXCEPT=${ALWAYS_EXCEPT:-"$SANITY_GSS_EXCEPT"}
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

# Tests that fail on uml
CPU=`awk '/model/ {print $4}' /proc/cpuinfo`
[ "$CPU" = "UML" ] && EXCEPT="$EXCEPT"

case `uname -r` in
2.6*) FSTYPE=${FSTYPE:-ldiskfs}; ALWAYS_EXCEPT="$ALWAYS_EXCEPT " ;;
*) error "unsupported kernel (gss only works with 2.6.x)" ;;
esac

SRCDIR=`dirname $0`
export PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$SRCDIR/../utils/gss:$PATH:/sbin
export NAME=${NAME:-local}
SAVE_PWD=$PWD

CLEANUP=${CLEANUP:-""}
SETUP=${SETUP:-""}

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

remote_mds_nodsh && skip "remote MDS with nodsh" && exit 0

[ "$SLOW" = "no" ] && EXCEPT_SLOW="100 101"

# $RUNAS_ID may get set incorrectly somewhere else
[ $UID -eq 0 -a $RUNAS_ID -eq 0 ] && error "\$RUNAS_ID set to 0, but \$UID is also 0!"

# remove $SEC, we'd like to control everything by ourselves
unset SEC

#
# global variables of this sanity
#
KRB5_CCACHE_DIR=/tmp
KRB5_CRED=$KRB5_CCACHE_DIR/krb5cc_$RUNAS_ID
KRB5_CRED_SAVE=$KRB5_CCACHE_DIR/krb5cc.sanity.save
CLICOUNT=2
cnt_mdt2ost=0
cnt_mdt2mdt=0
cnt_cli2ost=0
cnt_cli2mdt=0
cnt_all2ost=0
cnt_all2mdt=0
cnt_all2all=0
DBENCH_PID=0
PROC_CLI="srpc_info"

# set manually
GSS=true
GSS_KRB5=true

prepare_krb5_creds() {
    echo prepare krb5 cred
    rm -f $KRB5_CRED_SAVE
    echo RUNAS=$RUNAS
    $RUNAS krb5_login.sh || exit 1
    [ -f $KRB5_CRED ] || exit 2
    echo CRED=$KRB5_CRED
    cp $KRB5_CRED $KRB5_CRED_SAVE
}

prepare_krb5_creds

# we want double mount
MOUNT_2=${MOUNT_2:-"yes"}
check_and_setup_lustre

rm -rf $DIR/[df][0-9]*

check_runas_id $RUNAS_ID $RUNAS

build_test_filter

combination()
{
    local M=$1
    local N=$2
    local R=1

    if [ $M -lt $N ]; then
        R=0
    else
        N=$((N + 1))
        while [ $N -le $M ]; do
            R=$((R * N))
            N=$((N + 1))
        done
    fi

    echo $R
    return 0
}

calc_connection_cnt() {
    # MDT->MDT = 2 * C(M, 2)
    # MDT->OST = M * O
    # CLI->OST = C * O
    # CLI->MDT = C * M
    comb_m2=$(combination $MDSCOUNT 2)

    cnt_mdt2mdt=$((comb_m2 * 2))
    cnt_mdt2ost=$((MDSCOUNT * OSTCOUNT))
    cnt_cli2ost=$((CLICOUNT * OSTCOUNT))
    cnt_cli2mdt=$((CLICOUNT * MDSCOUNT))
    cnt_all2ost=$((cnt_mdt2ost + cnt_cli2ost))
    cnt_all2mdt=$((cnt_mdt2mdt + cnt_cli2mdt))
    cnt_all2all=$((cnt_mdt2ost + cnt_mdt2mdt + cnt_cli2ost + cnt_cli2mdt))
}

set_rule()
{
    local tgt=$1
    local net=$2
    local dir=$3
    local flavor=$4
    local cmd="$tgt.srpc.flavor"

    if [ $net == "any" ]; then
        net="default"
    fi
    cmd="$cmd.$net"

    if [ $dir != "any" ]; then
        cmd="$cmd.$dir"
    fi

    cmd="$cmd=$flavor"
    log "Setting sptlrpc rule: $cmd"
    do_facet mgs "$LCTL conf_param $cmd"
}

count_flvr()
{
    local output=$1
    local flavor=$2
    local count=0

    rpc_flvr=`echo $flavor | awk -F - '{ print $1 }'`
    bulkspec=`echo $flavor | awk -F - '{ print $2 }'`

    count=`echo "$output" | grep "rpc flavor" | grep $rpc_flvr | wc -l`

    if [ "x$bulkspec" != "x" ]; then
        algs=`echo $bulkspec | awk -F : '{ print $2 }'`

        if [ "x$algs" != "x" ]; then
            bulk_count=`echo "$output" | grep "bulk flavor" | grep $algs | wc -l`
        else
            bulk=`echo $bulkspec | awk -F : '{ print $1 }'`
            if [ $bulk == "bulkn" ]; then
                bulk_count=`echo "$output" | grep "bulk flavor" \
                            | grep "null/null" | wc -l`
            elif [ $bulk == "bulki" ]; then
                bulk_count=`echo "$output" | grep "bulk flavor" \
                            | grep "/null" | grep -v "null/" | wc -l`
            else
                bulk_count=`echo "$output" | grep "bulk flavor" \
                            | grep -v "/null" | grep -v "null/" | wc -l`
            fi
        fi

        [ $bulk_count -lt $count ] && count=$bulk_count
    fi

    echo $count
}

flvr_cnt_cli2mdt()
{
    local flavor=$1

    output=`do_facet client lctl get_param -n mdc.*-MDT*-mdc-*.$PROC_CLI 2>/dev/null`
    count_flvr "$output" $flavor
}

flvr_cnt_cli2ost()
{
    local flavor=$1

    output=`do_facet client lctl get_param -n osc.*OST*-osc-[^M][^D][^T]*.$PROC_CLI 2>/dev/null`
    count_flvr "$output" $flavor
}

flvr_cnt_mdt2mdt()
{
    local flavor=$1
    local cnt=0

    if [ $MDSCOUNT -le 1 ]; then
        echo 0
        return
    fi

    for num in `seq $MDSCOUNT`; do
        output=`do_facet mds$num lctl get_param -n mdc.*-MDT*-mdc[0-9]*.$PROC_CLI 2>/dev/null`
        tmpcnt=`count_flvr "$output" $flavor`
        cnt=$((cnt + tmpcnt))
    done
    echo $cnt;
}

flvr_cnt_mdt2ost()
{
    local flavor=$1
    local cnt=0

    for num in `seq $MDSCOUNT`; do
        output=`do_facet mds$num lctl get_param -n osc.*OST*-osc-MDT*.$PROC_CLI 2>/dev/null`
        tmpcnt=`count_flvr "$output" $flavor`
        cnt=$((cnt + tmpcnt))
    done
    echo $cnt;
}

flvr_cnt_mgc2mgs()
{
    local flavor=$1

    output=`do_facet client lctl get_param -n mgc.*.$PROC_CLI 2>/dev/null`
    count_flvr "$output" $flavor
}

do_check_flavor()
{
    local dir=$1        # from to
    local flavor=$2     # flavor expected
    local res=0

    if [ $dir == "cli2mdt" ]; then
        res=`flvr_cnt_cli2mdt $flavor`
    elif [ $dir == "cli2ost" ]; then
        res=`flvr_cnt_cli2ost $flavor`
    elif [ $dir == "mdt2mdt" ]; then
        res=`flvr_cnt_mdt2mdt $flavor`
    elif [ $dir == "mdt2ost" ]; then
        res=`flvr_cnt_mdt2ost $flavor`
    elif [ $dir == "all2ost" ]; then
        res1=`flvr_cnt_mdt2ost $flavor`
        res2=`flvr_cnt_cli2ost $flavor`
        res=$((res1 + res2))
    elif [ $dir == "all2mdt" ]; then
        res1=`flvr_cnt_mdt2mdt $flavor`
        res2=`flvr_cnt_cli2mdt $flavor`
        res=$((res1 + res2))
    elif [ $dir == "all2all" ]; then
        res1=`flvr_cnt_mdt2ost $flavor`
        res2=`flvr_cnt_cli2ost $flavor`
        res3=`flvr_cnt_mdt2mdt $flavor`
        res4=`flvr_cnt_cli2mdt $flavor`
        res=$((res1 + res2 + res3 + res4))
    fi

    echo $res
}

wait_flavor()
{
    local dir=$1        # from to
    local flavor=$2     # flavor expected
    local expect=$3     # number expected
    local res=0

    for ((i=0;i<20;i++)); do
        echo -n "checking..."
        res=$(do_check_flavor $dir $flavor)
        if [ $res -eq $expect ]; then
            echo "found $res $flavor connections of $dir, OK"
            return 0
        else
            echo "found $res $flavor connections of $dir, not ready ($expect)"
            sleep 4
        fi
    done

    echo "Error checking $flavor of $dir: expect $expect, actual $res"
    return 1
}

restore_to_default_flavor()
{
    local proc="mgs.MGS.live.$FSNAME"

    echo "restoring to default flavor..."

    nrule=`do_facet mgs lctl get_param -n $proc 2>/dev/null | grep ".srpc.flavor." | wc -l`

    # remove all existing rules if any
    if [ $nrule -ne 0 ]; then
        echo "$nrule existing rules"
        for rule in `do_facet mgs lctl get_param -n $proc 2>/dev/null | grep ".srpc.flavor."`; do
            echo "remove rule: $rule"
            spec=`echo $rule | awk -F = '{print $1}'`
            do_facet mgs "$LCTL conf_param $spec="
        done
    fi

    # verify no rules left
    nrule=`do_facet mgs lctl get_param -n $proc 2>/dev/null | grep ".srpc.flavor." | wc -l`
    [ $nrule -ne 0 ] && error "still $nrule rules left"

    # wait for default flavor to be applied
    # currently default flavor for all connections are 'null'
    wait_flavor all2all null $cnt_all2all
    echo "now at default flavor settings"
}

set_flavor_all()
{
    local flavor=$1

    echo "setting all flavor to $flavor"

    res=$(do_check_flavor all2all $flavor)
    if [ $res -eq $cnt_all2all ]; then
        echo "already have total $res $flavor connections"
        return
    fi

    echo "found $res $flavor out of total $cnt_all2all connections"
    restore_to_default_flavor

    set_rule $FSNAME any any $flavor
    wait_flavor all2all $flavor $cnt_all2all
}

start_dbench()
{
    NPROC=`cat /proc/cpuinfo 2>/dev/null | grep ^processor | wc -l`
    [ $NPROC -gt 2 ] && NPROC=2
    sh rundbench $NPROC 1>/dev/null &
    DBENCH_PID=$!
    sleep 2

    num=`ps --no-headers -p $DBENCH_PID 2>/dev/null | wc -l`
    if [ $num -ne 1 ]; then
        error "failed to start dbench $NPROC"
    else
        echo "started dbench with $NPROC processes at background"
    fi

    return 0
}

check_dbench()
{
    num=`ps --no-headers -p $DBENCH_PID 2>/dev/null | wc -l`
    if [ $num -eq 0 ]; then
        echo "dbench $DBENCH_PID already finished"
        wait $DBENCH_PID || error "dbench $PID exit with error"
        start_dbench
    elif [ $num -ne 1 ]; then
        killall -9 dbench
        error "found $num instance of pid $DBENCH_PID ???"
    fi

    return 0
}

stop_dbench()
{
    for ((;;)); do
        killall dbench 2>/dev/null
        num=`ps --no-headers -p $DBENCH_PID | wc -l`
        if [ $num -eq 0 ]; then
            echo "dbench finished"
            break
        fi
        echo "dbench $DBENCH_PID is still running, waiting 2s..."
        sleep 2
    done

    wait $DBENCH_PID || true
    sync || true
}

restore_krb5_cred() {
    cp $KRB5_CRED_SAVE $KRB5_CRED
    chown $RUNAS_ID:$RUNAS_ID $KRB5_CRED
    chmod 0600 $KRB5_CRED
}

check_multiple_gss_daemons() {
    local facet=$1
    local gssd=$2
    local gssd_name=`basename $gssd`

    for ((i=0;i<10;i++)); do
        do_facet $facet "$gssd -v &"
    done

    # wait daemons entering "stable" status
    sleep 5

    num=`do_facet $facet ps -o cmd -C $gssd_name | grep $gssd_name | wc -l`
    echo "$num instance(s) of $gssd_name are running"

    if [ $num -ne 1 ]; then
        error "$gssd_name not unique"
    fi
}

calc_connection_cnt
umask 077

test_0() {
    local my_facet=mds

    echo "bring up gss daemons..."
    start_gss_daemons

    echo "check with someone already running..."
    check_multiple_gss_daemons $my_facet $LSVCGSSD
    if $GSS_PIPEFS; then
        check_multiple_gss_daemons $my_facet $LGSSD
    fi

    echo "check with someone run & finished..."
    do_facet $my_facet killall -q -2 lgssd lsvcgssd || true
    sleep 5 # wait fully exit
    check_multiple_gss_daemons $my_facet $LSVCGSSD
    if $GSS_PIPEFS; then
        check_multiple_gss_daemons $my_facet $LGSSD
    fi

    echo "check refresh..."
    do_facet $my_facet killall -q -2 lgssd lsvcgssd || true
    sleep 5 # wait fully exit
    do_facet $my_facet ipcrm -S 0x3b92d473
    check_multiple_gss_daemons $my_facet $LSVCGSSD
    if $GSS_PIPEFS; then
        do_facet $my_facet ipcrm -S 0x3a92d473
        check_multiple_gss_daemons $my_facet $LGSSD
    fi
}
run_test 0 "start multiple gss daemons"

set_flavor_all krb5p

test_1() {
    local file=$DIR/$tfile

    chmod 0777 $DIR || error "chmod $DIR failed"
    # access w/o cred
    $RUNAS kdestroy
    $RUNAS $LFS flushctx || error "can't flush ctx"
    $RUNAS touch $file && error "unexpected success"

    # access w/ cred
    restore_krb5_cred
    $RUNAS touch $file || error "should not fail"
    [ -f $file ] || error "$file not found"
}
run_test 1 "access with or without krb5 credential"

test_2() {
    local file1=$DIR/$tfile-1
    local file2=$DIR/$tfile-2

    chmod 0777 $DIR || error "chmod $DIR failed"
    # current access should be ok
    $RUNAS touch $file1 || error "can't touch $file1"
    [ -f $file1 ] || error "$file1 not found"

    # cleanup all cred/ctx and touch
    $RUNAS kdestroy
    $RUNAS $LFS flushctx || error "can't flush ctx"
    $RUNAS touch $file2 && error "unexpected success"

    # restore and touch
    restore_krb5_cred
    $RUNAS touch $file2 || error "should not fail"
    [ -f $file2 ] || error "$file2 not found"
}
run_test 2 "lfs flushctx"

test_3() {
    local file=$DIR/$tfile

    # create file
    echo "aaaaaaaaaaaaaaaaa" > $file
    chmod 0666 $file
    $CHECKSTAT -p 0666 $file || error "$UID checkstat error"
    $RUNAS $CHECKSTAT -p 0666 $file || error "$RUNAS_ID checkstat error"
    $RUNAS cat $file > /dev/null || error "$RUNAS_ID cat error"

    # start multiop
    $RUNAS multiop $file o_r &
    OPPID=$!
    # wait multiop finish its open()
    sleep 1

    # cleanup all cred/ctx and check
    # metadata check should fail, but file data check should success
    # because we always use root credential to OSTs
    $RUNAS kdestroy
    $RUNAS $LFS flushctx
    echo "destroied credentials/contexs for $RUNAS_ID"
    $RUNAS $CHECKSTAT -p 0666 $file && error "checkstat succeed"
    kill -s 10 $OPPID
    wait $OPPID || error "read file data failed"
    echo "read file data OK"

    # restore and check again
    restore_krb5_cred
    echo "restored credentials for $RUNAS_ID"
    $RUNAS $CHECKSTAT -p 0666 $file || error "$RUNAS_ID checkstat (2) error"
    echo "$RUNAS_ID checkstat OK"
    $CHECKSTAT -p 0666 $file || error "$UID checkstat (2) error"
    echo "$UID checkstat OK"
    $RUNAS cat $file > /dev/null || error "$RUNAS_ID cat (2) error"
    echo "$RUNAS_ID read file data OK"
}
run_test 3 "local cache under DLM lock"

test_4() {
    local file1=$DIR/$tfile-1
    local file2=$DIR/$tfile-2

    ! $GSS_PIPEFS && skip "pipefs not used" && return

    chmod 0777 $DIR || error "chmod $DIR failed"
    # current access should be ok
    $RUNAS touch $file1 || error "can't touch $file1"
    [ -f $file1 ] || error "$file1 not found"

    # stop lgssd
    send_sigint client lgssd
    sleep 5
    check_gss_daemon_facet client lgssd && error "lgssd still running"

    # flush context, and touch
    $RUNAS $LFS flushctx
    $RUNAS touch $file2 &
    TOUCHPID=$!
    echo "waiting touch pid $TOUCHPID"
    wait $TOUCHPID && error "touch should fail"

    # restart lgssd
    do_facet client "$LGSSD -v"
    sleep 5
    check_gss_daemon_facet client lgssd

    # touch new should succeed
    $RUNAS touch $file2 || error "can't touch $file2"
    [ -f $file2 ] || error "$file2 not found"
}
run_test 4 "lgssd dead, operations should wait timeout and fail"

test_5() {
    local file1=$DIR/$tfile-1
    local file2=$DIR/$tfile-2
    local wait_time=$((TIMEOUT + TIMEOUT / 2))

    chmod 0777 $DIR || error "chmod $DIR failed"
    # current access should be ok
    $RUNAS touch $file1 || error "can't touch $file1"
    [ -f $file1 ] || error "$file1 not found"

    # stop lsvcgssd
    send_sigint mds lsvcgssd
    sleep 5
    check_gss_daemon_facet mds lsvcgssd && error "lsvcgssd still running"

    # flush context, and touch
    $RUNAS $LFS flushctx
    $RUNAS touch $file2 &
    TOUCHPID=$!

    # wait certain time
    echo "waiting $wait_time seconds for touch pid $TOUCHPID"
    sleep $wait_time
    num=`ps --no-headers -p $TOUCHPID | wc -l`
    [ $num -eq 1 ] || error "touch already ended ($num)"
    echo "process $TOUCHPID still hanging there... OK"

    # restart lsvcgssd, expect touch suceed
    echo "restart lsvcgssd and recovering"
    do_facet mds "$LSVCGSSD -v"
    sleep 5
    check_gss_daemon_facet mds lsvcgssd
    wait $TOUCHPID || error "touch fail"
    [ -f $file2 ] || error "$file2 not found"
}
run_test 5 "lsvcgssd dead, operations lead to recovery"

test_6() {
    local nfile=10

    mkdir $DIR/d6 || error "mkdir $DIR/d6 failed"
    for ((i=0; i<$nfile; i++)); do
        dd if=/dev/zero of=$DIR/d6/file$i bs=8k count=1 || error "dd file$i failed"
    done
    ls -l $DIR/d6/* > /dev/null || error "ls failed"
    rm -rf $DIR2/d6/* || error "rm failed"
    rmdir $DIR2/d6/ || error "rmdir failed"
}
run_test 6 "test basic DLM callback works"

test_7() {
    local tdir=$DIR/d7
    local num_osts

    #
    # for open(), client only reserve space for default stripe count lovea,
    # and server may return larger lovea in reply (because of larger stripe
    # count), client need call enlarge_reqbuf() and save the replied lovea
    # in request for future possible replay.
    #
    # Note: current script does NOT guarantee enlarge_reqbuf() will be in
    # the path, however it does work in local test which has 2 OSTs and
    # default stripe count is 1.
    #
    num_osts=`$LFS getstripe $MOUNT | egrep "^[0-9]*:.*ACTIVE" | wc -l`
    echo "found $num_osts active OSTs"
    [ $num_osts -lt 2 ] && echo "skipping $TESTNAME (must have >= 2 OSTs)" && return

    mkdir $tdir || error
    $LFS setstripe -c $num_osts $tdir || error

    echo "creating..."
    for ((i=0;i<20;i++)); do
        dd if=/dev/zero of=$tdir/f$i bs=4k count=16 2>/dev/null
    done
    echo "reading..."
    for ((i=0;i<20;i++)); do
        dd if=$tdir/f$i of=/dev/null bs=4k count=16 2>/dev/null
    done
    rm -rf $tdir
}
run_test 7 "exercise enlarge_reqbuf()"

test_8()
{
    sleep $TIMEOUT
    $LCTL dk > /dev/null
    debugsave
    sysctl -w lnet.debug="+other"

    # sleep sometime in ctx handle
    do_facet mds lctl set_param fail_val=30
#define OBD_FAIL_SEC_CTX_HDL_PAUSE       0x1204
    do_facet mds lctl set_param fail_loc=0x1204

    $RUNAS $LFS flushctx || error "can't flush ctx"

    $RUNAS df $DIR &
    DFPID=$!
    echo "waiting df (pid $TOUCHPID) to finish..."
    sleep 2 # give df a chance to really trigger context init rpc
    do_facet mds sysctl -w lustre.fail_loc=0
    wait $DFPID || error "df should have succeeded"

    $LCTL dk | grep "Early reply #" || error "No early reply"
    debugrestore
}
run_test 8 "Early reply sent for slow gss context negotiation"

#
# following tests will manipulate flavors and may end with any flavor set,
# so each test should not assume any start flavor.
#

test_50() {
    local sample=$TMP/sanity-gss-8
    local tdir=$MOUNT/dir8
    local iosize="256K"
    local hash_algs="adler32 crc32 md5 sha1 sha256 sha384 sha512 wp256 wp384 wp512"

    # create sample file with aligned size for direct i/o
    dd if=/dev/zero of=$sample bs=$iosize count=1 || error
    dd conv=notrunc if=/etc/termcap of=$sample bs=$iosize count=1 || error

    rm -rf $tdir
    mkdir $tdir || error "create dir $tdir"

    restore_to_default_flavor

    for alg in $hash_algs; do
        echo "Testing $alg..."
        flavor=krb5i-bulki:$alg/null
        set_rule $FSNAME any cli2ost $flavor
        wait_flavor cli2ost $flavor $cnt_cli2ost

        dd if=$sample of=$tdir/$alg oflag=direct,dsync bs=$iosize || error "$alg write"
        diff $sample $tdir/$alg || error "$alg read"
    done

    rm -rf $tdir
    rm -f $sample
}
run_test 50 "verify bulk hash algorithms works"

test_51() {
    local s1=$TMP/sanity-gss-9.1
    local s2=$TMP/sanity-gss-9.2
    local s3=$TMP/sanity-gss-9.3
    local s4=$TMP/sanity-gss-9.4
    local tdir=$MOUNT/dir9
    local s1_size=4194304   # n * pagesize (4M)
    local s2_size=512       # n * blksize
    local s3_size=111       # n * blksize + m
    local s4_size=5         # m
    local cipher_algs="arc4 aes128 aes192 aes256 cast128 cast256 twofish128 twofish256"

    # create sample files for each situation
    rm -f $s1 $s2 $s2 $s4
    dd if=/dev/urandom of=$s1 bs=1M count=4 || error
    dd if=/dev/urandom of=$s2 bs=$s2_size count=1 || error
    dd if=/dev/urandom of=$s3 bs=$s3_size count=1 || error
    dd if=/dev/urandom of=$s4 bs=$s4_size count=1 || error

    rm -rf $tdir
    mkdir $tdir || error "create dir $tdir"

    restore_to_default_flavor

    #
    # different bulk data alignment will lead to different behavior of
    # the implementation: (n > 0; 0 < m < encryption_block_size)
    #  - full page i/o
    #  - partial page, size = n * encryption_block_size
    #  - partial page, size = n * encryption_block_size + m
    #  - partial page, size = m
    #
    for alg in $cipher_algs; do
        echo "Testing $alg..."
        flavor=krb5p-bulkp:sha1/$alg
        set_rule $FSNAME any cli2ost $flavor
        wait_flavor cli2ost $flavor $cnt_cli2ost

        # sync write
        dd if=$s1 of=$tdir/$alg.1 oflag=dsync bs=1M || error "write $alg.1"
        dd if=$s2 of=$tdir/$alg.2 oflag=dsync || error "write $alg.2"
        dd if=$s3 of=$tdir/$alg.3 oflag=dsync || error "write $alg.3"
        dd if=$s4 of=$tdir/$alg.4 oflag=dsync || error "write $alg.4"

        # remount client
        umount_client $MOUNT
        umount_client $MOUNT2
        mount_client $MOUNT
        mount_client $MOUNT2

        # read & compare
        diff $tdir/$alg.1 $s1 || error "read $alg.1"
        diff $tdir/$alg.2 $s2 || error "read $alg.2"
        diff $tdir/$alg.3 $s3 || error "read $alg.3"
        diff $tdir/$alg.4 $s4 || error "read $alg.4"
    done

    rm -rf $tdir
    rm -f $sample
}
run_test 51 "bulk data alignment test under encryption mode"

test_90() {
    if [ "$SLOW" = "no" ]; then
        total=10
    else
        total=60
    fi

    restore_to_default_flavor
    set_rule $FSNAME any any krb5p
    wait_flavor all2all krb5p $cnt_all2all

    start_dbench

    for ((n=0;n<$total;n++)); do
        sleep 2
        check_dbench
        echo "flush ctx ($n/$total) ..."
        $LFS flushctx
    done
    check_dbench
    #sleep to let ctxs be re-established
    sleep 10
    stop_dbench
}
run_test 90 "recoverable from losing contexts under load"

test_99() {
    local nrule_old=0
    local nrule_new=0
    local max=64

    #
    # general rules
    #
    nrule_old=`do_facet mgs lctl get_param -n mgs.MGS.live.$FSNAME 2>/dev/null \
               | grep "$FSNAME.srpc.flavor." | wc -l`
    echo "original general rules: $nrule_old"

    for ((i = $nrule_old; i < $max; i++)); do
        set_rule $FSNAME elan$i any krb5n || error "set rule $i"
    done
    for ((i = $nrule_old; i < $max; i++)); do
        set_rule $FSNAME elan$i any || error "remove rule $i"
    done

    nrule_new=`do_facet mgs lctl get_param -n mgs.MGS.live.$FSNAME 2>/dev/null \
               | grep "$FSNAME.srpc.flavor." | wc -l`
    if [ $nrule_new != $nrule_old ]; then
        error "general rule: $nrule_new != $nrule_old"
    fi

    #
    # target-specific rules
    #
    nrule_old=`do_facet mgs lctl get_param -n mgs.MGS.live.$FSNAME 2>/dev/null \
               | grep "$FSNAME-MDT0000.srpc.flavor." | wc -l`
    echo "original target rules: $nrule_old"

    for ((i = $nrule_old; i < $max; i++)); do
        set_rule $FSNAME-MDT0000 elan$i any krb5i || error "set rule $i"
    done
    for ((i = $nrule_old; i < $max; i++)); do
        set_rule $FSNAME-MDT0000 elan$i any || error "remove rule $i"
    done

    nrule_new=`do_facet mgs lctl get_param -n mgs.MGS.live.$FSNAME 2>/dev/null \
               | grep "$FSNAME-MDT0000.srpc.flavor." | wc -l`
    if [ $nrule_new != $nrule_old ]; then
        error "general rule: $nrule_new != $nrule_old"
    fi
}
run_test 99 "set large number of sptlrpc rules"

error_dbench()
{
    local err_str=$1

    killall -9 dbench
    sleep 1

    error $err_str
}

test_100() {
    # started from default flavors
    restore_to_default_flavor

    # running dbench background
    start_dbench

    #
    # all: null -> krb5n -> krb5a -> krb5i -> krb5p -> plain
    #
    set_rule $FSNAME any any krb5n
    wait_flavor all2all krb5n $cnt_all2all || error_dbench "1"
    check_dbench

    set_rule $FSNAME any any krb5a
    wait_flavor all2all krb5a $cnt_all2all || error_dbench "2"
    check_dbench

    set_rule $FSNAME any any krb5i
    wait_flavor all2all krb5i $cnt_all2all || error_dbench "3"
    check_dbench

    set_rule $FSNAME any any krb5p
    wait_flavor all2all krb5p $cnt_all2all || error_dbench "4"
    check_dbench

    set_rule $FSNAME any any plain
    wait_flavor all2all plain $cnt_all2all || error_dbench "5"
    check_dbench

    #
    # M - M: krb5a
    # C - M: krb5i
    # M - O: krb5p
    # C - O: krb5n
    #
    set_rule $FSNAME any mdt2mdt krb5a
    wait_flavor mdt2mdt krb5a $cnt_mdt2mdt || error_dbench "6"
    check_dbench

    set_rule $FSNAME any cli2mdt krb5i
    wait_flavor cli2mdt krb5i $cnt_cli2mdt || error_dbench "7"
    check_dbench

    set_rule $FSNAME any mdt2ost krb5p
    wait_flavor mdt2ost krb5p $cnt_mdt2ost || error_dbench "8"
    check_dbench

    set_rule $FSNAME any cli2ost krb5n
    wait_flavor cli2ost krb5n $cnt_cli2ost || error_dbench "9"
    check_dbench

    #
    # * - MDT0: krb5p
    # * - OST0: krb5i
    #
    # nothing should be changed because they are override by above dir rules
    #
    set_rule $FSNAME-MDT0000 any any krb5p
    set_rule $FSNAME-OST0000 any any krb5i
    wait_flavor mdt2mdt krb5a $cnt_mdt2mdt || error_dbench "10"
    wait_flavor cli2mdt krb5i $cnt_cli2mdt || error_dbench "11"
    check_dbench
    wait_flavor mdt2ost krb5p $cnt_mdt2ost || error_dbench "12"
    wait_flavor cli2ost krb5n $cnt_cli2ost || error_dbench "13"

    #
    # delete all dir-specific rules
    #
    set_rule $FSNAME any mdt2mdt
    set_rule $FSNAME any cli2mdt
    set_rule $FSNAME any mdt2ost
    set_rule $FSNAME any cli2ost
    wait_flavor mdt2mdt krb5p $((MDSCOUNT - 1)) || error_dbench "14"
    wait_flavor cli2mdt krb5p $CLICOUNT || error_dbench "15"
    check_dbench
    wait_flavor mdt2ost krb5i $MDSCOUNT || error_dbench "16"
    wait_flavor cli2ost krb5i $CLICOUNT || error_dbench "17"
    check_dbench

    #
    # remove:
    #  * - MDT0: krb5p
    #  * - OST0: krb5i
    #
    set_rule $FSNAME-MDT0000 any any
    set_rule $FSNAME-OST0000 any any || error_dbench "18"
    wait_flavor all2all plain $cnt_all2all || error_dbench "19"
    check_dbench

    stop_dbench
}
run_test 100 "change security flavor on the fly under load"

switch_sec_test()
{
    local count=$1
    local flavor0=$2
    local flavor1=$3
    local flavor2=$4
    local df_pid=0
    local wait_time=$((TIMEOUT + TIMEOUT / 4))
    local num

    #
    # stop gss daemon, then switch to flavor1 (which should be a gss flavor),
    # and run a 'df' which should hanging, wait the request timeout and
    # resend, then switch the flavor to another one. To exercise the code of
    # switching ctx/sec for a resend request.
    #
    echo ">>>>>>>>>>>>>>> Testing $flavor0 -> $flavor1 -> $flavor2..."

    echo "(0) set base flavor $flavor0"
    set_rule $FSNAME any cli2mdt $flavor0
    wait_flavor cli2mdt $flavor0 $count
    df $MOUNT
    if [ $? -ne 0 ]; then
        error "initial df failed"
    fi

    stop_gss_daemons
    sleep 1

    echo "(1) $flavor0 -> $flavor1"
    set_rule $FSNAME any cli2mdt $flavor1
    wait_flavor cli2mdt $flavor1 $count
    df $MOUNT &
    df_pid=$!
    sleep 1

    echo "waiting $wait_time seconds for df ($df_pid)"
    sleep $wait_time
    num=`ps --no-headers -p $df_pid 2>/dev/null | wc -l`
    [ $num -eq 1 ] || error "df already ended ($num)"
    echo "process $df_pid is still hanging there... OK"

    echo "(2) set end flavor $flavor2"
    set_rule $FSNAME any cli2mdt $flavor2
    wait_flavor cli2mdt $flavor2 $count
    start_gss_daemons
    wait $df_pid || error "df returned error"
}

test_101()
{
    # started from default flavors
    restore_to_default_flavor

    switch_sec_test $cnt_cli2mdt null krb5n null
    switch_sec_test $cnt_cli2mdt null krb5a null
    switch_sec_test $cnt_cli2mdt null krb5i null
    switch_sec_test $cnt_cli2mdt null krb5p null
    switch_sec_test $cnt_cli2mdt null krb5i plain
    switch_sec_test $cnt_cli2mdt plain krb5p plain
    switch_sec_test $cnt_cli2mdt plain krb5n krb5a
    switch_sec_test $cnt_cli2mdt krb5a krb5i krb5p
    switch_sec_test $cnt_cli2mdt krb5p krb5a krb5n
    switch_sec_test $cnt_cli2mdt krb5n krb5p krb5i
}
run_test 101 "switch ctx as well as sec for resending request"

error_102()
{
    local err_str=$1

    killall -9 dbench
    sleep 1

    error $err_str
}

test_102() {
    # started from default flavors
    restore_to_default_flavor

    # run dbench background
    start_dbench

    echo "Testing null->krb5n->krb5a->krb5i->krb5p->plain->null"
    set_rule $FSNAME any any krb5n
    set_rule $FSNAME any any krb5a
    set_rule $FSNAME any any krb5i
    set_rule $FSNAME any any krb5p
    set_rule $FSNAME any any plain
    set_rule $FSNAME any any null

    check_dbench
    wait_flavor all2all null $cnt_all2all || error_dbench "1"
    check_dbench

    echo "waiting for 15s and check again"
    sleep 15
    check_dbench

    echo "Testing null->krb5i->null->krb5i->null..."
    for ((i=0; i<10; i++)); do
        set_rule $FSNAME any any krb5i
        set_rule $FSNAME any any null
    done
    set_rule $FSNAME any any krb5i

    check_dbench
    wait_flavor all2all krb5i $cnt_all2all || error_dbench "2"
    check_dbench

    echo "waiting for 15s and check again"
    sleep 15
    check_dbench

    stop_dbench
}
run_test 102 "survive from insanely fast flavor switch"

test_150() {
    local save_opts

    # started from default flavors
    restore_to_default_flavor

    # at this time no rules has been set on mgs; mgc use null
    # flavor connect to mgs.
    count=`flvr_cnt_mgc2mgs null`
    [ $count -eq 1 ] || error "$count mgc connection use null flavor"

    # umount both clients
    zconf_umount $HOSTNAME $MOUNT || return 1
    zconf_umount $HOSTNAME $MOUNT2 || return 2

    # mount client with default flavor - should succeed
    zconf_mount $HOSTNAME $MOUNT || error "mount with default flavor should have succeeded"
    zconf_umount $HOSTNAME $MOUNT || return 5

    # mount client with conflict flavor - should fail
    save_opts=$MOUNTOPT
    MOUNTOPT="$MOUNTOPT,mgssec=krb5p"
    zconf_mount $HOSTNAME $MOUNT && error "mount with conflict flavor should have failed"
    MOUNTOPT=$save_opts

    # mount client with same flavor - should succeed
    save_opts=$MOUNTOPT
    MOUNTOPT="$MOUNTOPT,mgssec=null"
    zconf_mount $HOSTNAME $MOUNT || error "mount with same flavor should have succeeded"
    zconf_umount $HOSTNAME $MOUNT || return 6
    MOUNTOPT=$save_opts
}
run_test 150 "secure mgs connection: client flavor setting"

test_151() {
    local save_opts

    # set mgs only accept krb5p
    set_rule _mgs any any krb5p

    # umount everything, modules still loaded
    stopall

    # mount mgs with default flavor, in current framework it means mgs+mdt1.
    # the connection of mgc of mdt1 to mgs is expected fail.
    DEVNAME=$(mdsdevname 1)
    start mds1 $DEVNAME $MDS_MOUNT_OPTS && error "mount with default flavor should have failed"

    # mount with unauthorized flavor should fail
    save_opts=$MDS_MOUNT_OPTS
    MDS_MOUNT_OPTS="$MDS_MOUNT_OPTS,mgssec=null"
    start mds1 $DEVNAME $MDS_MOUNT_OPTS && error "mount with unauthorized flavor should have failed"
    MDS_MOUNT_OPTS=$save_opts

    # mount with designated flavor should succeed
    save_opts=$MDS_MOUNT_OPTS
    MDS_MOUNT_OPTS="$MDS_MOUNT_OPTS,mgssec=krb5p"
    start mds1 $DEVNAME $MDS_MOUNT_OPTS || error "mount with designated flavor should have succeeded"
    MDS_MOUNT_OPTS=$save_opts

    stop mds1 -f
}
run_test 151 "secure mgs connection: server flavor control"

equals_msg `basename $0`: test complete, cleaning up
check_and_cleanup_lustre
[ -f "$TESTSUITELOG" ] && cat $TESTSUITELOG && grep -q FAIL $TESTSUITELOG && exit 1 || true
