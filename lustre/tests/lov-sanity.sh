#!/bin/sh
export OSTCOUNT=6
export OSTSIZE=81919
export NAME=lov
export MOUNTPT=${MOUNTPT:-"/mnt/lustre"}
export LCONF=${LCONF:-"../utils/lconf"}
export CONFIG=${CONFIG:-"$NAME.xml"}
export MCREATE=${MCREATE:-"mcreate"}
export LFS=${LFS:-"/usr/sbin/lfs"}
export SETSTRIPE_SIZE=${SETSTRIPE_SIZE:-"131072"}
export OPENFILE=${OPENFILE:-"./openfile"}
fail()
{
    echo "ERROR $@"
    exit 1
}
lustre_mount()
{
    . ./llmount.sh || fail "Mount lustre failed"
}
test_0()
{
    echo "test 0 IO after open file"
    mkdir $MOUNTPT/d0 
    $OPENFILE -f O_RDWR:O_CREAT -m 0755  $MOUNTPT/d0/f       || fail "open file failed."
    ls -lR >> $MOUNTPT/d0/f                                  || fail "IO after open failed."
    rm -fr  $MOUNTPT/d0                                      || fail "Unable to ereas dir."
    echo "test 0 success."
}
test_1()
{
    echo "test 1 IO after mcreate "
    mkdir $MOUNTPT/d1
    $MCREATE $MOUNTPT/d1/f    || fail "mcreate file failed."
    ls -lR >> $MOUNTPT/d1/f   || fail "IO after mcreate failed."
    rm -fr  $MOUNTPT/d1       || fail "Unable to ereas the file."
    echo "test 1 success."
}
test_2()
{
    echo "test 2 IO after mcreate with strip 1 "
    mkdir $MOUNTPT/d2
    $MCREATE $MOUNTPT/d2/f                             || fail "mcreate file failed."
    $LFS setstripe $MOUNTPT/d2/f $SETSTRIPE_SIZE 0 1   || fail "setstipe to stripe 1 failed"
    ls -lR >> $MOUNTPT/d2/f                            || fail "IO after mcreate failed."
    rm -fr  $MOUNTPT/d2                                || fail "Unable to ereas the file."
    echo "test 2 success."
}

test_3()
{
    echo "test 2 IO after mcreate with strip 4 "
    mkdir $MOUNTPT/d3
    $MCREATE $MOUNTPT/d3/f                             || fail "mcreate file failed."
    $LFS setstripe $MOUNTPT/d3/f $SETSTRIPE_SIZE 0 4   || fail "setstipe to stripe 4 failed"
    ls -lR >> $MOUNTPT/d3/f                            || fail "IO after mcreate failed."
    rm -fr  $MOUNTPT/d3                                || fail "Unable to ereas the file."
    echo "test 3 success."
}
test_4()
{
    echo "test 4 IO after mcreate with strip 6 "
    mkdir $MOUNTPT/d3
    $MCREATE $MOUNTPT/d3/f                             || fail "mcreate file failed."
    $LFS setstripe $MOUNTPT/d3/f $SETSTRIPE_SIZE 0 6   || fail "setstipe to stripe 6 failed"
    ls -lR >> $MOUNTPT/d3/f                            || fail "IO after mcreate failed."
    rm -fr  $MOUNTPT/d3                                || fail "Unable to ereas the file."
    echo "test 4 success."
}

lustre_clean()
{
    echo "clean up lustre"
    cd $CURRENT
    $LCONF --cleanup  $CONFIG  || fail "Unable to clean up lustre."
    echo "clean up lustre success"
}
run_all()
{
    lustre_mount 
    test_0	 
    test_1
    test_2
    test_3
    test_4
    lustre_clean 
}
run_all 

