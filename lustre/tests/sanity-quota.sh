#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# Run test by setting NOSETUP=true when ltest has setup env for us
set -e

SRCDIR=`dirname $0`
export PATH=$PWD/$SRCDIR:$SRCDIR:$PWD/$SRCDIR/../utils:$PATH:/sbin

ONLY=${ONLY:-"$*"}
ALWAYS_EXCEPT=${ALWAYS_EXCEPT:-""}
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

case `uname -r` in
2.6*) FSTYPE=${FSTYPE:-ldiskfs};;
*) error "unsupported kernel" ;;
esac

[ "$ALWAYS_EXCEPT$EXCEPT" ] && \
	echo "Skipping tests: `echo $ALWAYS_EXCEPT $EXCEPT`"

TMP=${TMP:-/tmp}

LFS=${LFS:-lfs}
LCTL=${LCTL:-lctl}
SETSTRIPE=${SETSTRIPE:-"$LFS setstripe"}
TSTID=${TSTID:-60000}
RUNAS=${RUNAS:-"runas -u $TSTID"}
TSTUSR=${TSTUSR:-"quota_usr"}
BLK_SZ=1024
BUNIT_SZ=${BUNIT_SZ:-1000}	# default 1000 quota blocks
BTUNE_SZ=${BTUNE_SZ:-500}	# default 50% of BUNIT_SZ
IUNIT_SZ=${IUNIT_SZ:-10}	# default 10 files
ITUNE_SZ=${ITUNE_SZ:-5}		# default 50% of IUNIT_SZ
MAX_DQ_TIME=604800
MAX_IQ_TIME=604800

log() {
	echo "$*"
	$LCTL mark "$*" 2> /dev/null || true
}

trace() {
	log "STARTING: $*"
	strace -o $TMP/$1.strace -ttt $*
	RC=$?
	log "FINISHED: $*: rc $RC"
	return 1
}
TRACE=${TRACE:-""}

run_one() {
	BEFORE=`date +%s`
	log "== test $1: $2= `date +%H:%M:%S` ($BEFORE)"
	export TESTNAME=test_$1
	test_$1 || error "exit with rc=$?"
	unset TESTNAME
	pass "($((`date +%s` - $BEFORE))s)"
	cd $SAVE_PWD
}

build_test_filter() {
        for O in $ONLY; do
            eval ONLY_${O}=true
        done
        for E in $EXCEPT $ALWAYS_EXCEPT; do
            eval EXCEPT_${E}=true
        done
	# turn on/off quota tests must be included
	eval ONLY_0=true
	eval ONLY_99=true
}

_basetest() {
	echo $*
}

basetest() {
	IFS=abcdefghijklmnopqrstuvwxyz _basetest $1
}

run_test() {
         base=`basetest $1`
         if [ "$ONLY" ]; then
                 testname=ONLY_$1
                 if [ ${!testname}x != x ]; then
 			run_one $1 "$2"
 			return $?
                 fi
                 testname=ONLY_$base
                 if [ ${!testname}x != x ]; then
                         run_one $1 "$2"
                         return $?
                 fi
                 echo -n "."
                 return 0
 	fi
        testname=EXCEPT_$1
        if [ ${!testname}x != x ]; then
                 echo "skipping excluded test $1"
                 return 0
        fi
        testname=EXCEPT_$base
        if [ ${!testname}x != x ]; then
                 echo "skipping excluded test $1 (base $base)"
                 return 0
        fi
        run_one $1 "$2"
 	return $?
}

[ "$SANITYLOG" ] && rm -f $SANITYLOG || true

error() { 
	sysctl -w lustre.fail_loc=0
	log "FAIL: $TESTNAME $@"
	if [ "$SANITYLOG" ]; then
		echo "FAIL: $TESTNAME $@" >> $SANITYLOG
	else
		exit 1
	fi
}

pass() { 
	echo PASS $@
}

mounted_lustre_filesystems() {
	awk '($3 ~ "lustre" && $1 ~ ":") { print $2 }' /proc/mounts
}
MOUNT="`mounted_lustre_filesystems`"
if [ -z "$MOUNT" ]; then
	export QUOTA_OPTS="quotaon=ug"
	sh llmount.sh
	MOUNT="`mounted_lustre_filesystems`"
	[ -z "$MOUNT" ] && error "NAME=$NAME not mounted"
	I_MOUNTED=yes
fi

[ `echo $MOUNT | wc -w` -gt 1 ] && error "NAME=$NAME mounted more than once"

DIR=${DIR:-$MOUNT}
[ -z "`echo $DIR | grep $MOUNT`" ] && echo "$DIR not in $MOUNT" && exit 99

LPROC=/proc/fs/lustre
LOVNAME=`cat $LPROC/llite/*/lov/common_name | tail -n 1`
OSTCOUNT=`cat $LPROC/lov/$LOVNAME/numobd`
STRIPECOUNT=`cat $LPROC/lov/$LOVNAME/stripecount`
STRIPESIZE=`cat $LPROC/lov/$LOVNAME/stripesize`
ORIGFREE=`cat $LPROC/lov/$LOVNAME/kbytesavail`
MAXFREE=${MAXFREE:-$((200000 * $OSTCOUNT))}
MDS=$(\ls $LPROC/mds 2> /dev/null | grep -v num_refs | tail -n 1)
TSTDIR="$MOUNT/quota_dir"

build_test_filter


# set_blk_tunables(btune_sz)
set_blk_tunesz() {
	# set btune size on all obdfilters
	for i in `ls /proc/fs/lustre/obdfilter/*/quota_btune_sz`; do
		echo $(($1 * $BLK_SZ)) > $i
	done
	# set btune size on mds
	for i in `ls /proc/fs/lustre/mds/lustre-MDT*/quota_btune_sz`; do
		echo $(($1 * $BLK_SZ)) > $i
	done
}
# se_blk_unitsz(bunit_sz)
set_blk_unitsz() {
	for i in `ls /proc/fs/lustre/obdfilter/*/quota_bunit_sz`; do
		echo $(($1 * $BLK_SZ)) > $i
	done
	for i in `ls /proc/fs/lustre/mds/lustre-MDT*/quota_bunit_sz`; do
		echo $(($1 * $BLK_SZ)) > $i
	done
}
# set_file_tunesz(itune_sz)
set_file_tunesz() {
	# set iunit and itune size on all obdfilters
	for i in `ls /proc/fs/lustre/obdfilter/*/quota_itune_sz`; do
		echo $1 > $i
	done
	# set iunit and itune size on mds
	for i in `ls /proc/fs/lustre/mds/lustre-MDT*/quota_itune_sz`; do
		echo $1 > $i
	done


}
# set_file_unitsz(iunit_sz)
set_file_unitsz() {
	for i in `ls /proc/fs/lustre/obdfilter/*/quota_iunit_sz`; do
		echo $1 > $i
	done;
	for i in `ls /proc/fs/lustre/mds/lustre-MDT*/quota_iunit_sz`; do
		echo $1 > $i
	done
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

setup() {
	# create local test group
	GRP="`cat /etc/group | grep "$TSTUSR" | awk -F: '{print $1}'`"
	if [ -z "$GRP" ]; then
		groupadd -g $TSTID "$TSTUSR"
	fi
	TSTID="`cat /etc/group | grep "$TSTUSR" | awk -F: '{print $3}'`"

	# create test user
	USR="`cat /etc/passwd | grep "$TSTUSR" | awk -F: '{print $1}'`"
	if [ -z "$USR" ]; then
		useradd -u $TSTID -g $TSTID -d /tmp "$TSTUSR"
	fi
	
	RUNAS="runas -u $TSTID"
	
	# create test directory
	[ -d $TSTDIR ] || mkdir $TSTDIR 
	chmod 777 $TSTDIR
}
setup

# set quota
test_0() {
	$LFS quotaoff -ug $MOUNT
	$LFS quotacheck -ug $MOUNT

	$LFS setquota -u $TSTUSR 0 0 0 0 $MOUNT
	$LFS setquota -g $TSTUSR 0 0 0 0 $MOUNT
}
run_test 0 "Set quota ============================="

# block hard limit (normal use and out of quota)
test_1() {
	LIMIT=$(( $BUNIT_SZ * $(($OSTCOUNT + 1)) * 10)) # 10 bunits each sever
	TESTFILE="$TSTDIR/quota_tst10"
	
	echo "  User quota (limit: $LIMIT bytes)"
	$LFS setquota -u $TSTUSR 0 $LIMIT 0 0 $MOUNT
	
	$LFS setstripe $TESTFILE 65536 0 1
	chown $TSTUSR.$TSTUSR $TESTFILE

	echo "    Write ..."
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$(($LIMIT/2)) > /dev/null 2>&1 || error "(usr) write failure, but expect success"
	echo "    Done"
	echo "    Write out of block quota ..."
	# this time maybe cache write,  ignore it's failure
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$(($LIMIT/2)) seek=$(($LIMIT/2)) > /dev/null 2>&1 || echo " " > /dev/null
	# flush cache, ensure noquota flag is setted on client
	sync; sleep 1; sync;
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$BUNIT_SZ seek=$LIMIT > /dev/null 2>&1 && error "(usr) write success, but expect EDQUOT"
	echo "    EDQUOT"

	rm -f $TESTFILE
	
	echo "  Group quota (limit: $LIMIT bytes)"
	$LFS setquota -u $TSTUSR 0 0 0 0 $MOUNT		# clear user limit
	$LFS setquota -g $TSTUSR 0 $LIMIT 0 0 $MOUNT
	TESTFILE="$TSTDIR/quota_tst11"

	$LFS setstripe $TESTFILE 65536 0 1
	chown $TSTUSR.$TSTUSR $TESTFILE

	echo "    Write ..."
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$(($LIMIT/2)) > /dev/null 2>&1 || error "(grp) write failure, but expect success"
	echo "    Done"
	echo "    Write out of block quota ..."
	# this time maybe cache write, ignore it's failure
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$(($LIMIT/2)) seek=$(($LIMIT/2)) > /dev/null 2>&1 || echo " " > /dev/null
	sync; sleep 1; sync;
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$BUNIT_SZ seek=$LIMIT > /dev/null 2>&1 && error "(grp) write success, but expect EDQUOT"
	echo "    EDQUOT"

	# cleanup
	rm -f $TESTFILE
	$LFS setquota -g $TSTUSR 0 0 0 0 $MOUNT
}
run_test 1 "Block hard limit (normal use and out of quota) ==="

# file hard limit (normal use and out of quota)
test_2() {
	LIMIT=$(($IUNIT_SZ * 10)) # 10 iunits on mds
	TESTFILE="$TSTDIR/quota_tstr20"

	echo "  User quota (limit: $LIMIT files)"
	$LFS setquota -u $TSTUSR 0 0 0 $LIMIT $MOUNT

	echo "    Create $LIMIT files ..."
	for i in `seq ${LIMIT}`; do
		$RUNAS touch ${TESTFILE}_$i > /dev/null 2>&1 || error "(usr) touch failure, but except success"
	done
	echo "    Done"
	echo "    Create out of file quota ..."
	$RUNAS touch ${TESTFILE}_xxx > /dev/null 2>&1 && error "(usr) touch success, but expect EDQUOT"
	echo "    EDQUOT"

	for i in `seq ${LIMIT}`; do
		rm -f ${TESTFILE}_$i
	done

	echo "  Group quota (limit: $LIMIT files)"
	$LFS setquota -u $TSTUSR 0 0 0 0 $MOUNT		# clear user limit
	$LFS setquota -g $TSTUSR 0 0 0 $LIMIT $MOUNT
	TESTFILE="$TSTDIR/quota_tst21"

	echo "    Create $LIMIT files ..."
	for i in `seq ${LIMIT}`; do
		$RUNAS touch ${TESTFILE}_$i > /dev/null 2>&1 || error "(grp) touch failure, but expect success"
	done
	echo "    Done"
	echo "    Create out of file quota ..."
	$RUNAS touch ${TESTFILE}_xxx > /dev/null 2>&1 && error "(grp) touch success, but expect EDQUOT"
	echo "    EDQUOT"

	# cleanup
	for i in `seq ${LIMIT}`; do
		rm -f ${TESTFILE}_$i
	done
	$LFS setquota -g $TSTUSR 0 0 0 0 $MOUNT
}
run_test 2 "File hard limit (normal use and out of quota) ==="

test_block_soft() {
	TESTFILE=$1
	GRACE=$2

	echo "    Write to exceed soft limit"
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$BUNIT_SZ >/dev/null 2>&1 || error "write failure, but expect success"
	sync; sleep 1; sync;

	echo "    Write before timer goes off"
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$BUNIT_SZ seek=$BUNIT_SZ >/dev/null 2>&1 || error "write failure, but expect success"
	echo "    Done"
	
	echo "    Sleep $GRACE seconds ..."
	sleep $GRACE

	echo "    Write after timer goes off"
	# maybe cache write, ignore.
	sync; sleep 1; sync;
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$BUNIT_SZ seek=$(($BUNIT_SZ * 2)) >/dev/null 2>&1 || echo " " > /dev/null
	sync; sleep 1; sync;
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=1 seek=$(($BUNIT_SZ * 3)) >/dev/null 2>&1 && error "write success, but expect EDQUOT"
	echo "    EDQUOT"

	echo "    Unlink file to stop timer"
	rm -f $TESTFILE
	echo "    Done"

	echo "    Write ..."
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$BUNIT_SZ >/dev/null 2>&1 || error "write failure, but expect success"
	echo "    Done"

	# cleanup
	rm -f $TESTFILE
}

# block soft limit (start timer, timer goes off, stop timer)
test_3() {
	LIMIT=$(( $BUNIT_SZ * 2 )) # 1 bunit on mds and 1 bunit on the ost
	GRACE=10

	echo "  User quota (soft limit: $LIMIT bytes  grace: $GRACE seconds)"
	TESTFILE="$TSTDIR/quota_tst30"
	$LFS setstripe $TESTFILE 65536 0 1
	chown $TSTUSR.$TSTUSR $TESTFILE

	$LFS setquota -t -u $GRACE $MAX_IQ_TIME $MOUNT
	$LFS setquota -u $TSTUSR $LIMIT 0 0 0 $MOUNT

	test_block_soft $TESTFILE $GRACE
	$LFS setquota -u $TSTUSR 0 0 0 0 $MOUNT

	echo "  Group quota (soft limit: $LIMIT bytes  grace: $GRACE seconds)"
	TESTFILE="$TSTDIR/quota_tst31"
	$LFS setstripe $TESTFILE 65536 0 1
	chown $TSTUSR.$TSTUSR $TESTFILE

	$LFS setquota -t -g $GRACE $MAX_IQ_TIME $MOUNT
	$LFS setquota -g $TSTUSR $LIMIT 0 0 0 $MOUNT
	TESTFILE="$TSTDIR/quota_tst31"

	test_block_soft $TESTFILE $GRACE
	$LFS setquota -g $TSTUSR 0 0 0 0 $MOUNT
}
run_test 3 "Block soft limit (start timer, timer goes off, stop timer) ==="

test_file_soft() {
	TESTFILE=$1
	LIMIT=$2
	GRACE=$3

	echo "    Create files to exceed soft limit"
	for i in `seq $LIMIT`; do
		$RUNAS touch ${TESTFILE}_$i >/dev/null 2>&1 || error "touch failure, but expect success"
	done
	echo "    Done"

	echo "    Create file before timer goes off"
	$RUNAS touch ${TESTFILE}_before >/dev/null 2>&1 || error "touch before timer goes off failure, but expect success"
	echo "    Done"

	echo "    Sleep $GRACE seconds ..."
	sleep $GRACE
	
	echo "    Create file after timer goes off"
	for i in `seq $(($IUNIT_SZ - 1))`; do
		$RUNAS touch ${TESTFILE}_after_$i >/dev/null 2>&1 || error "touch ${TESTFILE}_after_$i failure, but expect success"
	done
	$RUNAS touch ${TESTFILE}_after >/dev/null 2>&1 && error "touch after timer goes off success, but expect EDQUOT"
	echo "    EDQUOT"

	echo "    Unlink files to stop timer"
	for i in `seq $LIMIT`; do
		rm -f ${TESTFILE}_$i >/dev/null 2>&1 || error "rm ${TESTFILE}_$i failure"
	done
	rm -f ${TESTFILE}_before
	for i in `seq $(($IUNIT_SZ - 1))`; do
		rm -f ${TESTFILE}_after_$i >/dev/null 2>&1 || error "rm ${TESTFILE}_after_$i failure"
	done
	echo "    Done"

	echo "    Create file"
	$RUNAS touch ${TESTFILE}_xxx >/dev/null 2>&1 || error "touch after timer stop failure, but expect success"
	echo "    Done"

	# cleanup
	rm -f ${TESTFILE}_xxx
}

# file soft limit (start timer, timer goes off, stop timer)
test_4() {
	LIMIT=$(($IUNIT_SZ * 10))	# 10 iunits on mds
	TESTFILE="$TSTDIR/quota_tst40"
	GRACE=5

	echo "  User quota (soft limit: $LIMIT files  grace: $GRACE seconds)"
	$LFS setquota -t -u $MAX_DQ_TIME $GRACE $MOUNT
	$LFS setquota -u $TSTUSR 0 0 $LIMIT 0 $MOUNT

	test_file_soft $TESTFILE $LIMIT $GRACE
	$LFS setquota -u $TSTUSR 0 0 0 0 $MOUNT

	echo "  Group quota (soft limit: $LIMIT files  grace: $GRACE seconds)"
	$LFS setquota -t -g $MAX_DQ_TIME $GRACE $MOUNT
	$LFS setquota -g $TSTUSR 0 0 $LIMIT 0 $MOUNT
	TESTFILE="$TSTDIR/quota_tst41"

	test_file_soft $TESTFILE $LIMIT $GRACE
	$LFS setquota -g $TSTUSR 0 0 0 0 $MOUNT
	
	# cleanup
	$LFS setquota -t -u $MAX_DQ_TIME $MAX_IQ_TIME $MOUNT
	$LFS setquota -t -g $MAX_DQ_TIME $MAX_IQ_TIME $MOUNT
}
run_test 4 "File soft limit (start timer, timer goes off, stop timer) ==="

# chown & chgrp (chown & chgrp successfully even out of block/file quota)
test_5() {
	BLIMIT=$(( $BUNIT_SZ * $((OSTCOUNT + 1)) * 10)) # 10 bunits on each server
	ILIMIT=$(( $IUNIT_SZ * 10 )) # 10 iunits on mds
	
	echo "  Set quota limit (0 $BLIMIT 0 $ILIMIT) for $TSTUSR.$TSTUSR"
	$LFS setquota -u $TSTUSR 0 $BLIMIT 0 $ILIMIT $MOUNT
	$LFS setquota -g $TSTUSR 0 $BLIMIT 0 $ILIMIT $MOUNT
	
	echo "  Create more than $ILIMIT files and alloc more than $BLIMIT blocks ..."
	for i in `seq $(($ILIMIT + 1))`; do
		touch $TSTDIR/quota_tst50_$i > /dev/null 2>&1 || error "touch failure, expect success"
	done
	dd if=/dev/zero of=$TSTDIR/quota_tst50_1 bs=$BLK_SZ count=$(($BLIMIT+1)) > /dev/null 2>&1 || error "write failure, expect success"

	echo "  Chown files to $TSTUSR.$TSTUSR ..."
	for i in `seq $(($ILIMIT + 1))`; do
		chown $TSTUSR.$TSTUSR $TSTDIR/quota_tst50_$i > /dev/null 2>&1 || error "chown failure, but expect success"
	done

	# cleanup
	for i in `seq $(($ILIMIT + 1))`; do
		rm -f $TSTDIR/quota_tst50_$i
	done
	$LFS setquota -u $TSTUSR 0 0 0 0 $MOUNT
	$LFS setquota -g $TSTUSR 0 0 0 0 $MOUNT
}
run_test 5 "Chown & chgrp (chown & chgrp successfully even out of block/file quota) ==="

# block quota acquire & release
test_6() {
	if [ $OSTCOUNT -lt 2 ]; then
		echo "WARN: too few osts, skip this test."
		return 0;
	fi

	LIMIT=$(($BUNIT_SZ * $(($OSTCOUNT + 1)) * 10)) # 10 bunits per server
	FILEA="$TSTDIR/quota_tst60_a"
	FILEB="$TSTDIR/quota_tst60_b"
	
	echo "  Set block limit $LIMIT bytes to $TSTUSR.$TSTUSR"
	$LFS setquota -u $TSTUSR 0 $LIMIT 0 0 $MOUNT
	$LFS setquota -g $TSTUSR 0 $LIMIT 0 0 $MOUNT

	echo "  Create filea on OST0 and fileb on OST1"
	$LFS setstripe $FILEA 65536 0 1
	$LFS setstripe $FILEB 65536 1 1
	chown $TSTUSR.$TSTUSR $FILEA
	chown $TSTUSR.$TSTUSR $FILEB

	echo "  Exceed quota limit ..."
	$RUNAS dd if=/dev/zero of=$FILEB bs=$BLK_SZ count=$(($LIMIT - $BUNIT_SZ * $OSTCOUNT)) >/dev/null 2>&1 || error "write fileb failure, but expect success"
	#sync; sleep 1; sync;
	$RUNAS dd if=/dev/zero of=$FILEB bs=$BLK_SZ seek=$LIMIT count=$BUNIT_SZ >/dev/null 2>&1 && error "write fileb success, but expect EDQUOT"
	#sync; sleep 1; sync;
	echo "  Write to OST0 return EDQUOT"
	# this write maybe cache write, ignore it's failure
	$RUNAS dd if=/dev/zero of=$FILEA bs=$BLK_SZ count=$(($BUNIT_SZ * 2)) >/dev/null 2>&1 || echo " " > /dev/null
	sync; sleep 1; sync;
	$RUNAS dd if=/dev/zero of=$FILEA bs=$BLK_SZ count=$(($BUNIT_SZ * 2)) seek=$(($BUNIT_SZ *2)) >/dev/null 2>&1 && error "write filea success, but expect EDQUOT"
	echo "  EDQUOT"

	echo "  Remove fileb to let OST1 release quota"
	rm -f $FILEB

	echo "  Write to OST0"
	$RUNAS dd if=/dev/zero of=$FILEA bs=$BLK_SZ count=$(($LIMIT - $BUNIT_SZ * $OSTCOUNT)) >/dev/null 2>&1 || error "write filea failure, expect success"
	echo "  Done"

	# cleanup
	rm -f $FILEA
	$LFS setquota -u $TSTUSR 0 0 0 0 $MOUNT
	$LFS setquota -g $TSTUSR 0 0 0 0 $MOUNT
	return 0
}
run_test 6 "Block quota acquire & release ========="

# quota recovery (block quota only by now)
test_7()
{
	if [ -z "`lsmod|grep mds`" ]; then 
		echo "WARN: no local mds, skip this test"
		return 0
	fi

	LIMIT=$(( $BUNIT_SZ * $(($OSTCOUNT + 1)) * 10)) # 10 bunits each sever
	TESTFILE="$TSTDIR/quota_tst70"
	
	$LFS setquota -u $TSTUSR 0 $LIMIT 0 0 $MOUNT
	
	$LFS setstripe $TESTFILE 65536 0 1
	chown $TSTUSR.$TSTUSR $TESTFILE

	echo "  Write to OST0..."
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$BUNIT_SZ >/dev/null 2>&1 || error "write failure, but expect success"
	
	#define OBD_FAIL_OBD_DQACQ               0x604
	echo 0x604 > /proc/sys/lustre/fail_loc
	echo "  Remove files on OST0"
	rm -f $TESTFILE
	echo 0 > /proc/sys/lustre/fail_loc

	echo "  Trigger recovery..."
	OSC0_UUID="`$LCTL dl | awk '$3 ~ /osc/ { print $1 }'`"
	for i in $OSC0_UUID; do
		$LCTL --device $i activate > /dev/null 2>&1 || error "activate osc failed!"
	done

	# sleep a while to wait for recovery done
	sleep 20

	# check limits
	PATTERN="`echo $MOUNT | sed 's/\//\\\\\//g'`"
	TOTAL_LIMIT="`$LFS quota -u $TSTUSR $MOUNT | awk '/^.*'$PATTERN'.*[[:digit:]+][[:space:]+]/ { print $4 }'`"
	[ $TOTAL_LIMIT -eq $LIMIT ] || error "total limits not recovery!"
	echo "  total limits = $TOTAL_LIMIT"
	
	OST0_UUID=`$LCTL dl | awk '$3 ~ /obdfilter/ { print $5 }'| head -n1`
	[ -z "$OST0_UUID" ] && OST0_UUID=`$LCTL dl | awk '$3 ~ /obdfilter/ { print $5 }'|head -n1`
	OST0_LIMIT="`$LFS quota -o $OST0_UUID -u $TSTUSR $MOUNT | awk '/^.*[[:digit:]+][[:space:]+]/ { print $3 }'`"
	[ $OST0_LIMIT -eq $BUNIT_SZ ] || error "high limits not released!"
	echo "  limits on $OST0_UUID = $OST0_LIMIT"

	# cleanup
	$LFS setquota -u $TSTUSR 0 0 0 0 $MOUNT
}
run_test 7 "Quota recovery (only block limit) ======"

# run dbench with quota enabled
test_8() {
	BLK_LIMIT=$((100 * 1024 * 1024)) # 100G
	FILE_LIMIT=1000000
	DBENCH_LIB=${DBENCH_LIB:-/usr/lib/dbench}
	
	[ ! -d $DBENCH_LIB ] && echo "dbench not installed, skip this test" && return 0
	
	echo "  Set enough high limit for user: $TSTUSR"
	$LFS setquota -u $TSTUSR 0 $BLK_LIMIT 0 $FILE_LIMIT $MOUNT
	echo "  Set enough high limit for group: $TSTUSR"
	$LFS setquota -g $USER 0 $BLK_LIMIT 0 $FILE_LIMIT $MOUNT
	

	TGT=$TSTDIR/client.txt
	SRC=${SRC:-$DBENCH_LIB/client.txt}
	[ ! -e $TGT -a -e $SRC ] && echo "copying $SRC to $TGT" && cp $SRC $TGT
	SRC=$DBENCH_LIB/client_plain.txt
	[ ! -e $TGT -a -e $SRC ] && echo "copying $SRC to $TGT" && cp $SRC $TGT

	SAVE_PWD=$PWD
	cd $TSTDIR
	$RUNAS dbench -c client.txt 3
	RC=$?
	
	cd $SAVE_PWD
	return $RC
}
run_test 8 "Run dbench with quota enabled ==========="

# run for fixing bug10707, it needs a big room. test for 64bit
test_9() {
        lustrefs_size=`df | grep $MOUNT | awk '{print $(NF - 2)}'`
        size_file=$((1024 * 1024 * 9 / 2 * $OSTCOUNT))
        echo "lustrefs_size:$lustrefs_size  size_file:$size_file"
        if [ $lustrefs_size -lt $size_file ]; then
            echo "WARN: too few capacity, skip this test."
            return 0;
        fi

        # set the D_QUOTA flag
        debug_flag=`cat /proc/sys/lnet/debug`
        D_QUOTA_FLAG=67108864
        set_flag=0
        if [ $((debug_flag & D_QUOTA_FLAG)) -ne $D_QUOTA_FLAG ]; then
            echo  $((debug_flag | D_QUOTA_FLAG)) > /proc/sys/lnet/debug
            set_flag=1
        fi

        TESTFILE="$TSTDIR/quota_tst90"

        echo "  Set block limit $LIMIT bytes to $TSTUSR.$TSTUSR"
        BLK_LIMIT=$((100 * 1024 * 1024)) # 100G
        FILE_LIMIT=1000000

        echo "  Set enough high limit for user: $TSTUSR"
        $LFS setquota -u $TSTUSR 0 $BLK_LIMIT 0 $FILE_LIMIT $MOUNT
        echo "  Set enough high limit for group: $TSTUSR"
        $LFS setquota -g $TSTUSR 0 $BLK_LIMIT 0 $FILE_LIMIT $MOUNT

        echo "  Set stripe"
        [ $OSTCOUNT -ge 2 ] && $LFS setstripe $TESTFILE 65536 0 $OSTCOUNT
        touch $TESTFILE
        chown $TSTUSR.$TSTUSR $TESTFILE

        echo "    Write the big file of $(($OSTCOUNT * 9 / 2 ))G ..."
        $RUNAS dd if=/dev/zero of=$TESTFILE  bs=$BLK_SZ count=$size_file >/dev/null 2>&1 || error "(usr) write $((9 / 2 * $OSTCOUNT))G file failure, but expect success"
	
	echo "    delete the big file of $(($OSTCOUNT * 9 / 2))G..." 
        $RUNAS rm -f $TESTFILE >/dev/null 2>&1

        echo "    write the big file of 2G..."
        $RUNAS dd if=/dev/zero of=$TESTFILE  bs=$BLK_SZ count=$((1024 * 1024 * 2)) >/dev/null 2>&1 || error "(usr) write $((9 / 2 * $OSTCOUNT))G file failure, but expect seccess"

        echo "    delete the big file of 2G..."
        $RUNAS rm -f $TESTFILE >/dev/null 2>&1

        RC=$?

        # clear the flage
        if [ $set_flag -eq 1 ]; then
            echo  $debug_flag > /proc/sys/lnet/debug
        fi

        return $RC
}
run_test 9 "run for fixing bug10707(64bit) ==========="

# run for fixing bug10707, it need a big room. test for 32bit
test_10() {
       lustrefs_size=`df | grep $MOUNT | awk '{print $(NF - 2)}'`
       size_file=$((1024 * 1024 * 9 / 2 * $OSTCOUNT))
       echo "lustrefs_size:$lustrefs_size  size_file:$size_file"
       if [ $lustrefs_size -lt $size_file ]; then
               echo "WARN: too few capacity, skip this test."
               return 0;
       fi

       if [ ! -d /proc/fs/lustre/ost/ -o ! -d /proc/fs/lustre/mds ]; then
           echo "WARN: mds or ost isn't on the local machine, skip this test."
           return 0;
       fi

       sync; sleep 10; sync;

       # set the D_QUOTA flag
       debug_flag=`cat /proc/sys/lnet/debug`
       D_QUOTA_FLAG=67108864
       set_flag=0
       if [ $((debug_flag & D_QUOTA_FLAG)) -ne $D_QUOTA_FLAG ]; then
           echo  $((debug_flag | D_QUOTA_FLAG)) > /proc/sys/lnet/debug
           set_flag=1
       fi

       # make qd_count 32 bit
       sysctl -w lustre.fail_loc=2560

       TESTFILE="$TSTDIR/quota_tst100"

       echo "  Set block limit $LIMIT bytes to $TSTUSR.$TSTUSR"
       BLK_LIMIT=$((100 * 1024 * 1024)) # 100G
       FILE_LIMIT=1000000

       echo "  Set enough high limit for user: $TSTUSR"
       $LFS setquota -u $TSTUSR 0 $BLK_LIMIT 0 $FILE_LIMIT $MOUNT
       echo "  Set enough high limit for group: $TSTUSR"
       $LFS setquota -g $TSTUSR 0 $BLK_LIMIT 0 $FILE_LIMIT $MOUNT

       echo "  Set stripe"
       [ $OSTCOUNT -ge 2 ] && $LFS setstripe $TESTFILE 65536 0 $OSTCOUNT
       touch $TESTFILE
       chown $TSTUSR.$TSTUSR $TESTFILE

       echo "    Write the big file of $(($OSTCOUNT * 9 / 2 ))G ..."
       $RUNAS dd if=/dev/zero of=$TESTFILE  bs=$BLK_SZ count=$size_file >/dev/null 2>&1 || error "(usr) write $((9 / 2 * $OSTCOUNT))G file failure, but expect success"

       echo "    delete the big file of $(($OSTCOUNT * 9 / 2))G..." 
       $RUNAS rm -f $TESTFILE >/dev/null 2>&1

       echo "    write the big file of 2G..."
       $RUNAS dd if=/dev/zero of=$TESTFILE  bs=$BLK_SZ count=$((1024 * 1024 * 2)) >/dev/null 2>&1 || error "(usr) write $((9 / 2 * $OSTCOUNT))G file failure, but expect success"

       echo "    delete the big file of 2G..."
       $RUNAS rm -f $TESTFILE >/dev/null 2>&1

       RC=$?

       # clear the flage
       if [ $set_flag -eq 1 ]; then
              echo  $debug_flag > /proc/sys/lnet/debug
       fi

       # make qd_count 64 bit
       sysctl -w lustre.fail_loc=0

       return $RC
}
run_test 10 "run for fixing bug10707(32bit) ==========="


# turn off quota
test_99()
{
	$LFS quotaoff $MOUNT
	return 0
}
run_test 99 "Quota off ==============================="


log "cleanup: ======================================================"
if [ "`mount | grep ^$NAME`" ]; then
	rm -fr $TSTDIR
	post_test
	# delete test user and group
	userdel "$TSTUSR"
	if [ "$I_MOUNTED" = "yes" ]; then
		sh llmountcleanup.sh || error "llmountcleanup failed"
	fi
fi

echo '=========================== finished ==============================='
[ -f "$SANITYLOG" ] && cat $SANITYLOG && exit 1 || true

