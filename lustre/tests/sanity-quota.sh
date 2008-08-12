#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# Run test by setting NOSETUP=true when ltest has setup env for us
set -e

#kernel 2.4.x doesn't support quota
K_VER=`uname --kernel-release | cut -b 1-3`
if [ $K_VER = "2.4" ]; then
    echo "Kernel 2.4 doesn't support quota"
    exit 0
fi

SRCDIR=`dirname $0`
export PATH=$PWD/$SRCDIR:$SRCDIR:$PWD/$SRCDIR/../utils:$PATH:/sbin

ONLY=${ONLY:-"$*"}
ALWAYS_EXCEPT="$SANITY_QUOTA_EXCEPT"
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

case `uname -r` in
2.6*) FSTYPE=${FSTYPE:-ldiskfs};;
*) error "unsupported kernel" ;;
esac

[ "$ALWAYS_EXCEPT$EXCEPT" ] && \
	echo "Skipping tests: `echo $ALWAYS_EXCEPT $EXCEPT`"

TMP=${TMP:-/tmp}

ORIG_PWD=${PWD}
TSTID=${TSTID:-60000}
TSTID2=${TSTID2:-60001}
TSTUSR=${TSTUSR:-"quota_usr"}
TSTUSR2=${TSTUSR2:-"quota_2usr"}
BLK_SZ=1024
BUNIT_SZ=${BUNIT_SZ:-1000}	# default 1000 quota blocks
BTUNE_SZ=${BTUNE_SZ:-500}	# default 50% of BUNIT_SZ
IUNIT_SZ=${IUNIT_SZ:-10}	# default 10 files
ITUNE_SZ=${ITUNE_SZ:-5}		# default 50% of IUNIT_SZ
MAX_DQ_TIME=604800
MAX_IQ_TIME=604800

TRACE=${TRACE:-""}
LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

[ "$SLOW" = "no" ] && EXCEPT_SLOW="9 10 11"

QUOTALOG=${TESTSUITELOG:-$TMP/$(basename $0 .sh).log}

[ "$QUOTALOG" ] && rm -f $QUOTALOG || true

DIR=${DIR:-$MOUNT}
DIR2=${DIR2:-$MOUNT2}

cleanup_and_setup_lustre

LOVNAME=`cat $LPROC/llite/*/lov/common_name | tail -n 1`
OSTCOUNT=`cat $LPROC/lov/$LOVNAME/numobd`

SHOW_QUOTA_USER="$LFS quota -u $TSTUSR $DIR"
SHOW_QUOTA_GROUP="$LFS quota -g $TSTUSR $DIR"
SHOW_QUOTA_INFO="$LFS quota -t $DIR"

# control the time of tests
cycle=30
[ "$SLOW" = "no" ] && cycle=10

build_test_filter

eval ONLY_0=true
eval ONLY_99=true

# set_blk_tunables(btune_sz)
set_blk_tunesz() {
	# set btune size on all obdfilters
	do_facet ost1 "set -x; for i in /proc/fs/lustre/obdfilter/*/quota_btune_sz; do
		echo $(($1 * BLK_SZ)) >> \\\$i;
	done"
	# set btune size on mds
	do_facet $SINGLEMDS "for i in /proc/fs/lustre/mds/${FSNAME}-MDT*/quota_btune_sz; do
		echo $(($1 * BLK_SZ)) >> \\\$i;
	done"
}

# set_blk_unitsz(bunit_sz)
set_blk_unitsz() {
	do_facet ost1 "for i in /proc/fs/lustre/obdfilter/*/quota_bunit_sz; do
		echo $(($1 * BLK_SZ)) >> \\\$i;
	done"
	do_facet $SINGLEMDS "for i in /proc/fs/lustre/mds/${FSNAME}-MDT*/quota_bunit_sz; do
		echo $(($1 * BLK_SZ)) >> \\\$i;
	done"
}

# set_file_tunesz(itune_sz)
set_file_tunesz() {
	# set iunit and itune size on all obdfilters
	do_facet ost1 "for i in /proc/fs/lustre/obdfilter/*/quota_itune_sz; do
		echo $1 >> \\\$i;
	done"
	# set iunit and itune size on mds
	do_facet $SINGLEMDS "for i in /proc/fs/lustre/mds/${FSNAME}-MDT*/quota_itune_sz; do
		echo $1 >> \\\$i;
	done"
}

# set_file_unitsz(iunit_sz)
set_file_unitsz() {
	do_facet ost1 "for i in /proc/fs/lustre/obdfilter/*/quota_iunit_sz; do
		echo $1 >> \\\$i;
	done"
	do_facet $SINGLEMDS "for i in /proc/fs/lustre/mds/${FSNAME}-MDT*/quota_iunit_sz; do
		echo $1 >> \\\$i;
	done"
}

# These are for test on local machine,if run sanity-quota.sh on 
# real cluster, ltest should have setup the test environment: 
#
# - create test user/group on all servers with same id.
# - set unit size/tune on all servers size to reasonable value.
pre_test() {
	if [ -z "$NOSETUP" ]; then
		# set block tunables
		set_blk_tunesz $BTUNE_SZ
		set_blk_unitsz $BUNIT_SZ
		# set file tunables
		set_file_tunesz $ITUNE_SZ
		set_file_unitsz $IUNIT_SZ
	fi
}
pre_test

post_test() {
	if [ -z "$NOSETUP" ]; then
		# restore block tunables to default size
		set_blk_unitsz $((1024 * 100))
		set_blk_tunesz $((1024 * 50))
		# restore file tunables to default size
		set_file_unitsz 5000
		set_file_tunesz 2500
	fi
}

RUNAS="runas -u $TSTID"
RUNAS2="runas -u $TSTID2"
FAIL_ON_ERROR=true check_runas_id $TSTID $RUNAS
FAIL_ON_ERROR=true check_runas_id $TSTID2 $RUNAS2

FAIL_ON_ERROR=false

# set quota
test_0() {
	$LFS quotaoff -ug $DIR
	$LFS quotacheck -ug $DIR

	$LFS setquota -u $TSTUSR 0 0 0 0 $DIR
	$LFS setquota -g $TSTUSR 0 0 0 0 $DIR
}
run_test 0 "Set quota ============================="

# block hard limit (normal use and out of quota)
test_1() {
	mkdir -p $DIR/$tdir
	chmod 0777 $DIR/$tdir

	LIMIT=$(( $BUNIT_SZ * $(($OSTCOUNT + 1)) * 5)) # 5 bunits each sever
	TESTFILE=$DIR/$tdir/$tfile-0	
	
	echo "  User quota (limit: $LIMIT kbytes)"
	$LFS setquota -u $TSTUSR 0 $LIMIT 0 0 $DIR
	$SHOW_QUOTA_USER
	
	$LFS setstripe $TESTFILE -c 1
	chown $TSTUSR.$TSTUSR $TESTFILE

	echo "    Write ..."
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$(($LIMIT/2)) || error "(usr) write failure, but expect success"
	echo "    Done"
	echo "    Write out of block quota ..."
	# this time maybe cache write,  ignore it's failure
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$(($LIMIT/2)) seek=$(($LIMIT/2)) || true
	# flush cache, ensure noquota flag is setted on client
	sync; sleep 1; sync;
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$BUNIT_SZ seek=$LIMIT && error "(usr) write success, but expect EDQUOT"

	rm -f $TESTFILE
	
	echo "  Group quota (limit: $LIMIT kbytes)"
	$LFS setquota -u $TSTUSR 0 0 0 0 $DIR		# clear user limit
	$LFS setquota -g $TSTUSR 0 $LIMIT 0 0 $DIR
	$SHOW_QUOTA_GROUP
	TESTFILE=$DIR/$tdir/$tfile-1	

	$LFS setstripe $TESTFILE -c 1
	chown $TSTUSR.$TSTUSR $TESTFILE

	echo "    Write ..."
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$(($LIMIT/2)) || error "(grp) write failure, but expect success"
	echo "    Done"
	echo "    Write out of block quota ..."
	# this time maybe cache write, ignore it's failure
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$(($LIMIT/2)) seek=$(($LIMIT/2)) || true
	sync; sleep 1; sync;
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$BUNIT_SZ seek=$LIMIT && error "(grp) write success, but expect EDQUOT"

	# cleanup
	rm -f $TESTFILE
	$LFS setquota -g $TSTUSR 0 0 0 0 $DIR
}
run_test 1 "Block hard limit (normal use and out of quota) ==="

# file hard limit (normal use and out of quota)
test_2() {
	mkdir -p $DIR/$tdir
	chmod 0777 $DIR/$tdir

	LIMIT=$(($IUNIT_SZ * 10)) # 10 iunits on mds
	TESTFILE=$DIR/$tdir/$tfile-0	

	echo "  User quota (limit: $LIMIT files)"
	$LFS setquota -u $TSTUSR 0 0 0 $LIMIT $DIR
	$SHOW_QUOTA_USER

	echo "    Create $LIMIT files ..."
	$RUNAS createmany -m ${TESTFILE} $LIMIT || \
	    error "(usr) create failure, but expect success"
	echo "    Done"
	echo "    Create out of file quota ..."
	$RUNAS touch ${TESTFILE}_xxx && \
	        error "(usr) touch success, but expect EDQUOT"

	unlinkmany ${TESTFILE} $LIMIT
	rm ${TESTFILE}_xxx

	echo "  Group quota (limit: $LIMIT files)"
	$LFS setquota -u $TSTUSR 0 0 0 0 $DIR		# clear user limit
	$LFS setquota -g $TSTUSR 0 0 0 $LIMIT $DIR
	$SHOW_QUOTA_GROUP
	TESTFILE=$DIR/$tdir/$tfile-1

	echo "    Create $LIMIT files ..."
	$RUNAS createmany -m ${TESTFILE} $LIMIT || \
	        error "(grp) create failure, but expect success"

	echo "    Done"
	echo "    Create out of file quota ..."
        $RUNAS touch ${TESTFILE}_xxx && \
                error "(grp) touch success, but expect EDQUOT"

	$RUNAS touch ${TESTFILE}_xxx > /dev/null 2>&1 && error "(grp) touch success, but expect EDQUOT"

	# cleanup
	unlinkmany ${TESTFILE} $LIMIT
	rm ${TESTFILE}_xxx

	$LFS setquota -g $TSTUSR 0 0 0 0 $DIR
}
run_test 2 "File hard limit (normal use and out of quota) ==="

test_block_soft() {
	TESTFILE=$1
	TIMER=$(($2 * 3 / 2))
	OFFSET=0

	echo "    Write to exceed soft limit"
	RUNDD="$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ"
	$RUNDD count=$((BUNIT_SZ+1)) || \
	        error "write failure, but expect success"
	OFFSET=$((OFFSET + BUNIT_SZ + 1))
	sync; sleep 1; sync;

	$SHOW_QUOTA_USER
	$SHOW_QUOTA_GROUP
	$SHOW_QUOTA_INFO

	echo "    Write before timer goes off"
	$RUNDD count=$BUNIT_SZ seek=$OFFSET || \
	        error "write failure, but expect success"
	OFFSET=$((OFFSET + BUNIT_SZ))
	sync; sleep 1; sync;
	echo "    Done"
	
        echo "    Sleep $TIMER seconds ..."
        sleep $TIMER

        $SHOW_QUOTA_USER
        $SHOW_QUOTA_GROUP
        $SHOW_QUOTA_INFO

	echo "    Write after timer goes off"
	# maybe cache write, ignore.
	sync; sleep 1; sync;
	$RUNDD count=$BUNIT_SZ seek=$OFFSET || true
	OFFSET=$((OFFSET + BUNIT_SZ))
	sync; sleep 1; sync;
	$RUNDD count=$BUNIT_SZ seek=$OFFSET && \
	        error "write success, but expect EDQUOT"

        $SHOW_QUOTA_USER
        $SHOW_QUOTA_GROUP
        $SHOW_QUOTA_INFO

	echo "    Unlink file to stop timer"
	rm -f $TESTFILE
	echo "    Done"

        $SHOW_QUOTA_USER
        $SHOW_QUOTA_GROUP
        $SHOW_QUOTA_INFO

	echo "    Write ..."
	$RUNDD count=$BUNIT_SZ || error "write failure, but expect success"
	echo "    Done"

	# cleanup
	rm -f $TESTFILE
}

# block soft limit (start timer, timer goes off, stop timer)
test_3() {
	mkdir -p $DIR/$tdir
	chmod 0777 $DIR/$tdir

	LIMIT=$(( $BUNIT_SZ * 2 )) # 1 bunit on mds and 1 bunit on the ost
	GRACE=10

	echo "  User quota (soft limit: $LIMIT kbytes  grace: $GRACE seconds)"
	TESTFILE=$DIR/$tdir/$tfile-0

	$LFS setstripe $TESTFILE -c 1
	chown $TSTUSR.$TSTUSR $TESTFILE

	$LFS setquota -t -u $GRACE $MAX_IQ_TIME $DIR
	$LFS setquota -u $TSTUSR $LIMIT 0 0 0 $DIR

	test_block_soft $TESTFILE $GRACE
	$LFS setquota -u $TSTUSR 0 0 0 0 $DIR

	echo "  Group quota (soft limit: $LIMIT kbytes  grace: $GRACE seconds)"
	TESTFILE=$DIR/$tdir/$tfile-1

	$LFS setstripe $TESTFILE -c 1
	chown $TSTUSR.$TSTUSR $TESTFILE

	$LFS setquota -t -g $GRACE $MAX_IQ_TIME $DIR
	$LFS setquota -g $TSTUSR $LIMIT 0 0 0 $DIR

	test_block_soft $TESTFILE $GRACE
	$LFS setquota -g $TSTUSR 0 0 0 0 $DIR
}
run_test 3 "Block soft limit (start timer, timer goes off, stop timer) ==="

test_file_soft() {
	TESTFILE=$1
	LIMIT=$2
	TIMER=$(($3 * 3 / 2))

	echo "    Create files to exceed soft limit"
	$RUNAS createmany -m ${TESTFILE}_ $((LIMIT + 1)) || \
		error "create failure, but expect success"
	sync; sleep 1; sync
	echo "    Done"

	echo "    Create file before timer goes off"
	$RUNAS touch ${TESTFILE}_before || \
		error "failed create before timer expired, but expect success"
	sync; sleep 1; sync
	echo "    Done"

	echo "    Sleep $TIMER seconds ..."
	sleep $TIMER
	
	$SHOW_QUOTA_USER
	$SHOW_QUOTA_GROUP
	$SHOW_QUOTA_INFO
	
	echo "    Create file after timer goes off"
	$RUNAS createmany -m ${TESTFILE}_after_ $((IUNIT_SZ - 2)) || \
		error "create ${TESTFILE}_after failure, but expect success"
	sync; sleep 1; sync
	$RUNAS touch ${TESTFILE}_after && \
		error "create after timer expired, but expect EDQUOT"
	sync; sleep 1; sync

	$SHOW_QUOTA_USER
	$SHOW_QUOTA_GROUP
	$SHOW_QUOTA_INFO
	
	echo "    Unlink files to stop timer"
	find `dirname $TESTFILE` -name "`basename ${TESTFILE}`*" | xargs rm -f
	echo "    Done"

	echo "    Create file"
	$RUNAS touch ${TESTFILE}_xxx || \
		error "touch after timer stop failure, but expect success"
	sync; sleep 1; sync
	echo "    Done"

	# cleanup
	rm -f ${TESTFILE}_xxx
}

# file soft limit (start timer, timer goes off, stop timer)
test_4a() {	# was test_4
	mkdir -p $DIR/$tdir
	chmod 0777 $DIR/$tdir
	LIMIT=$(($IUNIT_SZ * 10))	# 10 iunits on mds
	TESTFILE=$DIR/$tdir/$tfile-0

	GRACE=5

	echo "  User quota (soft limit: $LIMIT files  grace: $GRACE seconds)"
	$LFS setquota -t -u $MAX_DQ_TIME $GRACE $DIR
	$LFS setquota -u $TSTUSR 0 0 $LIMIT 0 $DIR
	$SHOW_QUOTA_USER

	test_file_soft $TESTFILE $LIMIT $GRACE
	$LFS setquota -u $TSTUSR 0 0 0 0 $DIR

	echo "  Group quota (soft limit: $LIMIT files  grace: $GRACE seconds)"
	$LFS setquota -t -g $MAX_DQ_TIME $GRACE $DIR
	$LFS setquota -g $TSTUSR 0 0 $LIMIT 0 $DIR
	$SHOW_QUOTA_GROUP
	TESTFILE=$DIR/$tdir/$tfile-1

	test_file_soft $TESTFILE $LIMIT $GRACE
	$LFS setquota -g $TSTUSR 0 0 0 0 $DIR

	# cleanup
	$LFS setquota -t -u $MAX_DQ_TIME $MAX_IQ_TIME $DIR
	$LFS setquota -t -g $MAX_DQ_TIME $MAX_IQ_TIME $DIR
}
run_test 4a "File soft limit (start timer, timer goes off, stop timer) ==="

test_4b() {	# was test_4a
        GR_STR1="1w3d"
        GR_STR2="1000s"
        GR_STR3="5s"
        GR_STR4="1w2d3h4m5s"
        GR_STR5="5c"
        GR_STR6="1111111111111111"

        # test of valid grace strings handling
        echo "  Valid grace strings test"
        $LFS setquota -t -u $GR_STR1 $GR_STR2 $DIR
        $LFS quota -u -t $DIR | grep "Block grace time: $GR_STR1"
        $LFS setquota -t -g $GR_STR3 $GR_STR4 $DIR
        $LFS quota -g -t $DIR | grep "Inode grace time: $GR_STR4"

        # test of invalid grace strings handling
        echo "  Invalid grace strings test"
        ! $LFS setquota -t -u $GR_STR4 $GR_STR5 $DIR
        ! $LFS setquota -t -g $GR_STR4 $GR_STR6 $DIR

        # cleanup
        $LFS setquota -t -u $MAX_DQ_TIME $MAX_IQ_TIME $DIR
        $LFS setquota -t -g $MAX_DQ_TIME $MAX_IQ_TIME $DIR
}
run_test 4b "Grace time strings handling ==="

# chown & chgrp (chown & chgrp successfully even out of block/file quota)
test_5() {
	mkdir -p $DIR/$tdir
	BLIMIT=$(( $BUNIT_SZ * $((OSTCOUNT + 1)) * 10)) # 10 bunits on each server
	ILIMIT=$(( $IUNIT_SZ * 10 )) # 10 iunits on mds
	
	echo "  Set quota limit (0 $BLIMIT 0 $ILIMIT) for $TSTUSR.$TSTUSR"
	$LFS setquota -u $TSTUSR 0 $BLIMIT 0 $ILIMIT $DIR
	$LFS setquota -g $TSTUSR 0 $BLIMIT 0 $ILIMIT $DIR
	$SHOW_QUOTA_USER
	$SHOW_QUOTA_GROUP
	
	echo "  Create more than $ILIMIT files and more than $BLIMIT kbytes ..."
	createmany -m $DIR/$tdir/$tfile-0_ $((ILIMIT + 1)) || \
		error "touch failure, expect success"
	dd if=/dev/zero of=$DIR/$tdir/$tfile-0_1 bs=$BLK_SZ count=$((BLIMIT+1)) || error "write failure, expect success"

	echo "  Chown files to $TSTUSR.$TSTUSR ..."
	for i in `seq 0 $ILIMIT`; do
	chown $TSTUSR.$TSTUSR $DIR/$tdir/$tfile-0_$i || \
			error "chown failure, but expect success"
	done

	# cleanup
	unlinkmany $DIR/$tdir/$tfile-0_ $((ILIMIT + 1))

	$LFS setquota -u $TSTUSR 0 0 0 0 $DIR
	$LFS setquota -g $TSTUSR 0 0 0 0 $DIR
}
run_test 5 "Chown & chgrp successfully even out of block/file quota ==="

# block quota acquire & release
test_6() {
	if [ $OSTCOUNT -lt 2 ]; then
		skip "$OSTCOUNT < 2, too few osts"
		return 0;
	fi

	mkdir -p $DIR/$tdir
	chmod 0777 $DIR/$tdir

	LIMIT=$((BUNIT_SZ * (OSTCOUNT + 1) * 5)) # 5 bunits per server
	FILEA="$DIR/$tdir/$tfile-0_a"
	FILEB="$DIR/$tdir/$tfile-0_b"
	
	echo "  Set block limit $LIMIT kbytes to $TSTUSR.$TSTUSR"
	$LFS setquota -u $TSTUSR 0 $LIMIT 0 0 $DIR
	$LFS setquota -g $TSTUSR 0 $LIMIT 0 0 $DIR
	$SHOW_QUOTA_USER
	$SHOW_QUOTA_GROUP

	echo "  Create filea on OST0 and fileb on OST1"
	$LFS setstripe $FILEA -i 0 -c 1
	$LFS setstripe $FILEB -i 1 -c 1
	chown $TSTUSR.$TSTUSR $FILEA
	chown $TSTUSR.$TSTUSR $FILEB

	echo "  Exceed quota limit ..."
        RUNDD="$RUNAS dd if=/dev/zero of=$FILEB bs=$BLK_SZ"
        $RUNDD count=$((LIMIT - BUNIT_SZ * OSTCOUNT)) || \
                error "write fileb failure, but expect success"

	sync; sleep 1; sync;
        $SHOW_QUOTA_USER
        $SHOW_QUOTA_GROUP
        $RUNDD seek=$LIMIT count=$((BUNIT_SZ * OSTCOUNT)) && \
                error "write fileb success, but expect EDQUOT"
	sync; sleep 1; sync;
	echo "  Write to OST0 return EDQUOT"
	# this write maybe cache write, ignore it's failure
        RUNDD="$RUNAS dd if=/dev/zero of=$FILEA bs=$BLK_SZ"
        $RUNDD count=$(($BUNIT_SZ * 2)) || true
	sync; sleep 1; sync;
        $SHOW_QUOTA_USER
        $SHOW_QUOTA_GROUP
        $RUNDD count=$((BUNIT_SZ * 2)) seek=$((BUNIT_SZ *2)) && \
                error "write filea success, but expect EDQUOT"

	echo "  Remove fileb to let OST1 release quota"
	rm -f $FILEB
        sync; sleep 10; sync; # need to allow journal commit for small fs

	echo "  Write to OST0"
	$RUNDD count=$((LIMIT - BUNIT_SZ * OSTCOUNT)) || \
	        error "write filea failure, expect success"
	echo "  Done"

	# cleanup
	rm -f $FILEA
	$LFS setquota -u $TSTUSR 0 0 0 0 $DIR
	$LFS setquota -g $TSTUSR 0 0 0 0 $DIR
	return 0
}
run_test 6 "Block quota acquire & release ========="

# quota recovery (block quota only by now)
test_7()
{
	mkdir -p $DIR/$tdir
	chmod 0777 $DIR/$tdir

	LIMIT=$(( $BUNIT_SZ * $(($OSTCOUNT + 1)) * 10)) # 10 bunits each sever
	TESTFILE="$DIR/$tdir/$tfile-0"
	
	$LFS setquota -u $TSTUSR 0 $LIMIT 0 0 $DIR
	
	$LFS setstripe $TESTFILE -c 1
	chown $TSTUSR.$TSTUSR $TESTFILE

	echo "  Write to OST0..."
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$BUNIT_SZ || \
		error "write failure, but expect success"
	
	#define OBD_FAIL_OBD_DQACQ               0x604
	echo 0x604 > /proc/sys/lustre/fail_loc
	echo "  Remove files on OST0"
	rm -f $TESTFILE
	echo 0 > /proc/sys/lustre/fail_loc

	echo "  Trigger recovery..."
	OSC0_UUID="`$LCTL dl | awk '$3 ~ /osc/ { print $1 }'`"
	for i in $OSC0_UUID; do
		$LCTL --device $i activate || error "activate osc failed!"
	done

	# sleep a while to wait for recovery done
	sleep 20

	# check limits
	PATTERN="`echo $DIR | sed 's/\//\\\\\//g'`"
	TOTAL_LIMIT="`$LFS quota -u $TSTUSR $DIR | awk '/^.*'$PATTERN'.*[[:digit:]+][[:space:]+]/ { print $4 }'`"
	[ $TOTAL_LIMIT -eq $LIMIT ] || error "total limits not recovery!"
	echo "  total limits = $TOTAL_LIMIT"
	
        OST0_UUID=`do_facet ost1 "$LCTL dl | grep -m1 obdfilter" | awk '{print $((NF-1))}'`
        [ -z "$OST0_UUID" ] && OST0_UUID=`do_facet ost1 "$LCTL dl | grep -m1 obdfilter" | awk '{print $((NF-1))}'`
	OST0_LIMIT="`$LFS quota -o $OST0_UUID -u $TSTUSR $DIR | awk '/^.*[[:digit:]+][[:space:]+]/ { print $3 }'`"
	[ $OST0_LIMIT -eq $BUNIT_SZ ] || error "high limits not released!"
	echo "  limits on $OST0_UUID = $OST0_LIMIT"

	# cleanup
	$LFS setquota -u $TSTUSR 0 0 0 0 $DIR
}
run_test 7 "Quota recovery (only block limit) ======"

# run dbench with quota enabled
test_8() {
	mkdir -p $DIR/$tdir
	BLK_LIMIT=$((100 * 1024 * 1024)) # 100G
	FILE_LIMIT=1000000
	DBENCH_LIB=${DBENCH_LIB:-/usr/lib/dbench}
	
	[ ! -d $DBENCH_LIB ] && skip "dbench not installed" && return 0

	wait_delete_completed
	
	echo "  Set enough high limit for user: $TSTUSR"
	$LFS setquota -u $TSTUSR 0 $BLK_LIMIT 0 $FILE_LIMIT $DIR
	echo "  Set enough high limit for group: $TSTUSR"
	$LFS setquota -g $USER 0 $BLK_LIMIT 0 $FILE_LIMIT $DIR

	TGT=$DIR/$tdir/client.txt
	SRC=${SRC:-$DBENCH_LIB/client.txt}
	[ ! -e $TGT -a -e $SRC ] && echo "copying $SRC to $TGT" && cp $SRC $TGT
	SRC=$DBENCH_LIB/client_plain.txt
	[ ! -e $TGT -a -e $SRC ] && echo "copying $SRC to $TGT" && cp $SRC $TGT

	mkdir -p $DIR/$tdir
	chmod 0777 $DIR/$tdir
	SAVE_PWD=$PWD
	cd $DIR/$tdir
	local duration=""
	[ "$SLOW" = "no" ] && duration=" -t 120"
	$RUNAS dbench -c client.txt 3 $duration
	RC=$?
	[ $RC -ne 0 ] && killall -9 dbench
	
	rm -f client.txt
	sync; sleep 3; sync;

	cd $SAVE_PWD
	return $RC
}
run_test 8 "Run dbench with quota enabled ==========="

# run for fixing bug10707, it needs a big room. test for 64bit
KB=1024
GB=$((KB * 1024 * 1024))
FSIZE=$((OSTCOUNT * 9 / 2))
# Use this as dd bs to decrease time
# inode->i_blkbits = min(PTLRPC_MAX_BRW_BITS+1, LL_MAX_BLKSIZE_BITS);
blksize=$((1 << 21)) # 2Mb

test_9() {
	chmod 0777 $DIR/$tdir
        lustrefs_size=`(echo 0; df -t lustre -P | awk '{print $4}') | tail -n 1`
        size_file=$((FSIZE * GB))
        echo "lustrefs_size:$lustrefs_size  size_file:$((size_file / KB))"
        if [ $((lustrefs_size * KB)) -lt $size_file ]; then
		skip "less than $size_file bytes free"
	    	return 0;
        fi

        set_blk_unitsz $((1024 * 100))
        set_blk_tunesz $((1024 * 50))

        # set the D_QUOTA flag
	debugsave
	sysctl -w lnet.debug="+quota"

        TESTFILE="$DIR/$tdir/$tfile-0"

        BLK_LIMIT=$((100 * KB * KB)) # 100G
        FILE_LIMIT=1000000

        echo "  Set enough high limit(block:$BLK_LIMIT; file: $FILE_LIMIT) for user: $TSTUSR"
        $LFS setquota -u $TSTUSR 0 $BLK_LIMIT 0 $FILE_LIMIT $DIR
        echo "  Set enough high limit(block:$BLK_LIMIT; file: $FILE_LIMIT) for group: $TSTUSR"
        $LFS setquota -g $TSTUSR 0 $BLK_LIMIT 0 $FILE_LIMIT $DIR

        echo "  Set stripe"
        [ $OSTCOUNT -ge 2 ] && $LFS setstripe $TESTFILE -c $OSTCOUNT
        touch $TESTFILE
        chown $TSTUSR.$TSTUSR $TESTFILE

        $SHOW_QUOTA_USER
        $SHOW_QUOTA_GROUP

        echo "    Write the big file of $FSIZE G ..."
        $RUNAS dd if=/dev/zero of=$TESTFILE  bs=$blksize count=$((size_file / blksize)) || \
               error "(usr) write $FSIZE G file failure, but expect success"

        $SHOW_QUOTA_USER
        $SHOW_QUOTA_GROUP

        echo "    delete the big file of $FSIZE G..." 
        $RUNAS rm -f $TESTFILE

        $SHOW_QUOTA_USER
        $SHOW_QUOTA_GROUP

        echo "    write the big file of 2 G..."
        $RUNAS dd if=/dev/zero of=$TESTFILE  bs=$blksize count=$((2 * GB / blksize)) || \
               error "(usr) write 2 G file failure, but expect seccess"

        echo "    delete the big file of 2 G..."
        $RUNAS rm -f $TESTFILE 
        RC=$?

        set_blk_tunesz $BTUNE_SZ
        set_blk_unitsz $BUNIT_SZ

	debugrestore
	wait_delete_completed

        return $RC
}
run_test 9 "run for fixing bug10707(64bit) ==========="

# run for fixing bug10707, it need a big room. test for 32bit
test_10() {
	mkdir -p $DIR/$tdir
	chmod 0777 $DIR/$tdir
	lustrefs_size=`(echo 0; df -t lustre -P | awk '{print $4}') | tail -n 1`
	size_file=$((FSIZE * GB))
	echo "lustrefs_size:$lustrefs_size  size_file:$((size_file / KB))"
	if [ $((lustrefs_size * KB)) -lt $size_file ]; then
		skip "less than $size_file bytes free"
		return 0;
	fi

	sync; sleep 10; sync;

	set_blk_unitsz $((1024 * 100))
	set_blk_tunesz $((1024 * 50))

	# set the D_QUOTA flag
	debugsave
	sysctl -w lnet.debug="+quota"
	
	# make qd_count 32 bit
	sysctl -w lustre.fail_loc=0xA00

	TESTFILE="$DIR/$tdir/$tfile-0"

	BLK_LIMIT=$((100 * KB * KB)) # 100G
	FILE_LIMIT=1000000

	echo "  Set enough high limit(block:$BLK_LIMIT; file: $FILE_LIMIT) for user: $TSTUSR"
	$LFS setquota -u $TSTUSR 0 $BLK_LIMIT 0 $FILE_LIMIT $DIR
	echo "  Set enough high limit(block:$BLK_LIMIT; file: $FILE_LIMIT) for group: $TSTUSR"
	$LFS setquota -g $TSTUSR 0 $BLK_LIMIT 0 $FILE_LIMIT $DIR
       
	echo "  Set stripe"
	[ $OSTCOUNT -ge 2 ] && $LFS setstripe $TESTFILE -c $OSTCOUNT
	touch $TESTFILE
	chown $TSTUSR.$TSTUSR $TESTFILE

        $SHOW_QUOTA_USER
        $SHOW_QUOTA_GROUP

        echo "    Write the big file of $FSIZE G ..."
        $RUNAS dd if=/dev/zero of=$TESTFILE  bs=$blksize count=$((size_file / blksize)) || \
		error "(usr) write $FSIZE G file failure, but expect success"
 
        $SHOW_QUOTA_USER
        $SHOW_QUOTA_GROUP

        echo "    delete the big file of $FSIZE G..."
        $RUNAS rm -f $TESTFILE 

        $SHOW_QUOTA_USER
        $SHOW_QUOTA_GROUP

	echo "    write the big file of 2 G..."
	$RUNAS dd if=/dev/zero of=$TESTFILE  bs=$blksize count=$((2 * GB / blkzise)) || \
		error "(usr) write 2 G file failure, but expect success" 

	echo "    delete the big file of 2 G..."
	$RUNAS rm -f $TESTFILE 

	RC=$?

	# clear the flage
	debugrestore

	# make qd_count 64 bit
	sysctl -w lustre.fail_loc=0

	set_blk_tunesz $BTUNE_SZ
	set_blk_unitsz $BUNIT_SZ

	wait_delete_completed

	return $RC
}
run_test 10 "run for fixing bug10707(32bit) ==========="

test_11() {
       wait_delete_completed

       #prepare the test
       block_limit=`(echo 0; df -t lustre -P | awk '{print $(NF - 4)}') | tail -n 1`
       echo $block_limit
       orig_dbr=`cat /proc/sys/vm/dirty_background_ratio`
       orig_dec=`cat /proc/sys/vm/dirty_expire_centisecs`
       orig_dr=`cat /proc/sys/vm/dirty_ratio`
       orig_dwc=`cat /proc/sys/vm/dirty_writeback_centisecs`
       echo 1  > /proc/sys/vm/dirty_background_ratio
       echo 30 > /proc/sys/vm/dirty_expire_centisecs
       echo 1  > /proc/sys/vm/dirty_ratio
       echo 50 > /proc/sys/vm/dirty_writeback_centisecs
       TESTDIR="$DIR/$tdir"
       local RV=0

       #do the test
       local SECS=0
       local REPS=3
       [ "$SLOW" = no ] && REPS=1
       local sleep=20
       local i=1
       while [ $i -le $REPS ]; do
	   echo "test: cycle($i of $REPS) start at $(date)"
	   mkdir -p $TESTDIR && chmod 777 $TESTDIR
	   echo -n "    create a file for uid "
	   for j in `seq 1 30`; do
	       echo -n "$j "
               # 30MB per dd for a total of 900MB (if space even permits)
	       runas -u $j dd if=/dev/zero of=$TESTDIR/$tfile  bs=$blksize count=15 > /dev/null 2>&1 &
	   done
	   echo ""
	   PROCS=$(ps -ef | grep -v grep | grep "dd if /dev/zero of $TESTDIR" | wc -l)
	   LAST_USED=0
	   while [ $PROCS -gt 0 ]; do 
	     sleep 20
	     SECS=$((SECS + sleep))
	     PROCS=$(ps -ef | grep -v grep | grep "dd if /dev/zero of $TESTDIR" | wc -l)
	     USED=$(du -s $TESTDIR | awk '{print $1}')
	     PCT=$(($USED * 100 / $block_limit))
	     echo "${i}/${REPS} ${PCT}% p${PROCS} t${SECS}  "
	     if [ $USED -le $LAST_USED ]; then
		 kill -9 $(ps -ef | grep "dd if /dev/zero of $TESTDIR" | grep -v grep | awk '{ print $2 }')
		 i=$REPS
		 RV=2
		 break
	     fi
             LAST_USED=$USED
	   done
	   echo "    removing the test files..."
	   rm -f $TESTDIR/$tfile
	   echo "cycle $i done at $(date)"
	   i=$[$i+1]
       done
       echo "Test took $SECS sec"

       #clean
       echo $orig_dbr > /proc/sys/vm/dirty_background_ratio
       echo $orig_dec > /proc/sys/vm/dirty_expire_centisecs
       echo $orig_dr  > /proc/sys/vm/dirty_ratio
       echo $orig_dwc > /proc/sys/vm/dirty_writeback_centisecs
       if [ $RV -ne 0 ]; then
           error "Nothing was written for $SECS sec ... aborting"
       fi
       return $RV
}
run_test 11 "run for fixing bug10912 ==========="


# test a deadlock between quota and journal b=11693
test_12() {
	mkdir -p $DIR/$tdir
	chmod 0777 $DIR/$tdir

	[ "$(grep $DIR2 /proc/mounts)" ] || mount_client $DIR2 || \
		{ skip "Need lustre mounted on $MOUNT2 " && retutn 0; }

	LIMIT=$(( $BUNIT_SZ * $(($OSTCOUNT + 1)) * 10)) # 10 bunits each sever
	TESTFILE="$DIR/$tdir/$tfile-0"
	TESTFILE2="$DIR2/$tdir/$tfile-1"
	
	echo "   User quota (limit: $LIMIT kbytes)"
	$LFS setquota -u $TSTUSR 0 $LIMIT 0 0 $DIR

	$LFS setstripe $TESTFILE -i 0 -c 1 
	chown $TSTUSR.$TSTUSR $TESTFILE
	$LFS setstripe $TESTFILE2 -i 0 -c 1
        chown $TSTUSR2.$TSTUSR2 $TESTFILE2

	#define OBD_FAIL_OST_HOLD_WRITE_RPC      0x21f
	sysctl -w lustre.fail_loc=0x0000021f        

	echo "   step1: write out of block quota ..."
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$(($LIMIT*2)) & 
	DDPID=$!
	sleep 5
	$RUNAS2 dd if=/dev/zero of=$TESTFILE2 bs=$BLK_SZ count=102400 & 
	DDPID1=$!

	echo  "   step2: testing ......"
	count=0
	while [ true ]; do
	    if [ -z `ps -ef | awk '$2 == '${DDPID1}' { print $8 }'` ]; then break; fi
	    count=$[count+1]
	    if [ $count -gt 64 ]; then
		sysctl -w lustre.fail_loc=0
		error "dd should be finished!"
	    fi
	    sleep 1
	done	
	echo "(dd_pid=$DDPID1, time=$count)successful"

	#Recover fail_loc and dd will finish soon
	sysctl -w lustre.fail_loc=0

	echo  "   step3: testing ......"
	count=0
	while [ true ]; do
	    if [ -z `ps -ef | awk '$2 == '${DDPID}' { print $8 }'` ]; then break; fi
	    count=$[count+1]
	    if [ $count -gt 100 ]; then
		error "dd should be finished!"
	    fi
	    sleep 1
	done	
	echo "(dd_pid=$DDPID, time=$count)successful"

	rm -f $TESTFILE $TESTFILE2
	
	$LFS setquota -u $TSTUSR 0 0 0 0 $DIR		# clear user limit
}
run_test 12 "test a deadlock between quota and journal ==="

# test multiple clients write block quota b=11693
test_13() {
	# one OST * 10 + (mds + other OSTs)
	LIMIT=$((BUNIT_SZ * 10 + (BUNIT_SZ * OSTCOUNT)))
	TESTFILE="$DIR/$tdir/$tfile"
	mkdir -p $DIR/$tdir

	echo "   User quota (limit: $LIMIT kbytes)"
	$LFS setquota -u $TSTUSR 0 $LIMIT 0 0 $DIR
	$SHOW_QUOTA_USER
	
	$LFS setstripe $TESTFILE -i 0 -c 1
	chown $TSTUSR.$TSTUSR $TESTFILE
	$LFS setstripe $TESTFILE.2 -i 0 -c 1
        chown $TSTUSR.$TSTUSR $TESTFILE.2

	echo "   step1: write out of block quota ..."
	# one bunit will give mds
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$[($LIMIT - $BUNIT_SZ) / 2] & 
	DDPID=$!
	$RUNAS dd if=/dev/zero of=$TESTFILE.2 bs=$BLK_SZ count=$[($LIMIT - $BUNIT_SZ) / 2] & 
	DDPID1=$!

	echo  "   step2: testing ......"
	count=0
	while [ true ]; do
	    if [ -z `ps -ef | awk '$2 == '${DDPID}' { print $8 }'` ]; then break; fi
	    count=$[count+1]
	    if [ $count -gt 64 ]; then
		error "dd should be finished!"
	    fi
	    sleep 1
	done	
	echo "(dd_pid=$DDPID, time=$count)successful"

	count=0
	while [ true ]; do
	    if [ -z `ps -ef | awk '$2 == '${DDPID1}' { print $8 }'` ]; then break; fi
	    count=$[count+1]
	    if [ $count -gt 64 ]; then
		error "dd should be finished!"
	    fi
	    sleep 1
	done	
	echo "(dd_pid=$DDPID1, time=$count)successful"

	sync; sleep 5; sync;

	echo  "   step3: checking ......"
	fz=`stat -c %s $TESTFILE`
	fz2=`stat -c %s $TESTFILE.2`
	$SHOW_QUOTA_USER
	[ $((fz + fz2)) -lt $((BUNIT_SZ * BLK_SZ * 10)) ] && \
		error "files too small $fz + $fz2 < $((BUNIT_SZ * BLK_SZ * 10))"

	rm -f $TESTFILE $TESTFILE.2
	
	$LFS setquota -u $TSTUSR 0 0 0 0 $DIR		# clear user limit
}
run_test 13 "test multiple clients write block quota ==="

check_if_quota_zero(){
        line=`$LFS quota -$1 $2 $DIR | wc -l`
	for i in `seq 3 $line`; do
	    if [ $i -eq 3 ]; then
		field="3 4 6 7"
	    else
		field="3 5"
	    fi
	    for j in $field; do
		tmp=`$LFS quota -$1 $2 $DIR | sed -n ${i}p | 
                     awk  '{print $'"$j"'}'`
		[ -n "$tmp" ] && [ $tmp -ne 0 ] && $LFS quota -$1 $2 $DIR && \
		    error "quota on $2 isn't clean"
	    done
	done
	echo "pass check_if_quota_zero"
}

pre_test_14 () {
        # reboot the lustre
        cd $T_PWD; sh llmountcleanup.sh || error "llmountcleanup failed"
        sh llmount.sh
        pre_test
        run_test 0 "reboot lustre"
}

pre_test_14 

test_14a() {	# was test_14 b=12223 -- setting quota on root
	TESTFILE="$DIR/$tdir/$tfile"
	mkdir -p $DIR/$tdir

	# out of root's file and block quota
        $LFS setquota -u root 10 10 10 10 $DIR
	createmany -m ${TESTFILE} 20 || \
	    error "unexpected: user(root) create files failly!"
	dd if=/dev/zero of=$TESTFILE bs=4k count=4096 || \
	    error "unexpected: user(root) write files failly!"
	chmod 666 $TESTFILE
	$RUNAS dd if=/dev/zero of=${TESTFILE} seek=4096 bs=4k count=4096 && \
	    error "unexpected: user(quota_usr) write a file successfully!"	

	# trigger the llog
	chmod 777 $DIR
	for i in `seq 1 10`; do $RUNAS touch ${TESTFILE}a_$i; done 
	for i in `seq 1 10`; do $RUNAS rm -f ${TESTFILE}a_$i; done 

	# do the check
	dmesg | tail | grep "\-122" |grep llog_obd_origin_add && error "err -122 not found in dmesg" 
	$LFS setquota -u root 0 0 0 0 $DIR
	#check_if_quota_zero u root

	# clean 
	unlinkmany ${TESTFILE} 15
	rm -f $TESTFILE
}
run_test 14a "test setting quota on root ==="

# turn off quota
test_99()
{
	$LFS quotaoff $DIR
	return 0
}
run_test 99 "Quota off ==============================="


log "cleanup: ======================================================"
cd $ORIG_PWD
post_test
check_and_cleanup_lustre
echo '=========================== finished ==============================='
[ -f "$QUOTALOG" ] && cat $QUOTALOG && grep -q FAIL $QUOTALOG && exit 1 || true
echo "$0: completed"
