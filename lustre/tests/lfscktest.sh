#!/bin/bash
#set -vx
set -e

TESTNAME="lfscktest"
TMP=${TMP:-/tmp}
MDSDB=${MDSDB:-$TMP/mdsdb}
OSTDB=${OSTDB:-$TMP/ostdb}
LOG=${LOG:-"$TMP/lfscktest.log"}
L2FSCK_PATH=${L2FSCK_PATH:-""}
NUMFILES=${NUMFILES:-10}
NUMDIRS=${NUMDIRS:-4}
LFIND=${LFIND:-"lfs find"}
GETFATTR=${GETFATTR:-getfattr}
SETFATTR=${SETFATTR:-setfattr}
MAX_ERR=1

export PATH=$LFSCK_PATH:`dirname $0`:`dirname $0`/../utils:$PATH

[ -z "`which $GETFATTR`" ] && echo "$0: $GETFATTR not found" && exit 5
[ -z "`which $SETFATTR`" ] && echo "$0: $SETFATTR not found" && exit 6

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

remote_mds && skip "remote MDS" && exit 0
remote_ost && skip "remote OST" && exit 0

# if nothing mounted, don't nuke MOUNT variable needed in llmount.sh
WAS_MOUNTED=$(mounted_lustre_filesystems | head -1)
if [ -z "$WAS_MOUNTED" ]; then
       # This code doesn't handle multiple mounts well, so nuke MOUNT2 variable
        MOUNT2="" sh llmount.sh
        MOUNT=$(mounted_lustre_filesystems)
        [ -z "$MOUNT" ] && echo "NAME=$NAME not mounted" && exit 2
else
        MOUNT=${WAS_MOUNTED}
fi

DIR=${DIR:-$MOUNT/$TESTNAME}
[ -z "`echo $DIR | grep $MOUNT`" ] && echo "$DIR not in $MOUNT" && exit 3

if [ "$WAS_MOUNTED" ]; then
	LFSCK_SETUP=no
	MAX_ERR=4		# max expected error from e2fsck
fi

get_mnt_devs() {
	DEVS=`lctl get_param -n $1.*.mntdev`
	for DEV in $DEVS; do
		case $DEV in
		*loop*) losetup $DEV | sed -e "s/.*(//" -e "s/).*//" ;;
		*) echo $DEV ;;
		esac
	done
}

if [ "$LFSCK_SETUP" != "no" ]; then
	#Create test directory 
	# -- can't remove the mountpoint...
	[ -z "$DIR" ] && rm -rf $DIR/*
	mkdir -p $DIR
	OSTCOUNT=`$LFIND $MOUNT | grep -c "^[0-9]*: "`

	# Create some files on the filesystem
	for d in `seq -f d%g $NUMDIRS`; do
		echo "creating files in $DIR/$d"
		for e in `seq -f d%g $NUMDIRS`; do
			mkdir -p  $DIR/$d/$e
			for f in `seq -f test%g $NUMDIRS`; do
				cp /etc/fstab $DIR/$d/$e/$f ||exit 5
			done
		done
	done

	# Create Files to be modified
	for f in `seq -f $DIR/testfile.%g $((NUMFILES * 3))`; do
		echo "creating $f"
		cp /etc/termcap $f || exit 10
	done

	#Create some more files
	for d in `seq -f d%g $((NUMDIRS * 2 + 1)) $((NUMDIRS * 2 + 3))`; do
		echo "creating files in $DIR/$d"
		for e in `seq -f d%g $NUMDIRS`; do
			mkdir -p  $DIR/$d/$e
			for f in `seq -f test%g $NUMDIRS`; do
				cp /etc/hosts $DIR/$d/$e/$f ||exit 15
			done
		done
	done

	# these should NOT be taken as duplicates
	for f in `seq -f $DIR/$d/linkfile.%g $NUMFILES`; do
		echo "linking files in $DIR/$d"
		cp /etc/hosts $f
		ln $f $f.link
	done

	# Get objids for a file on the OST
	OST_FILES=`seq -f $DIR/testfile.%g $NUMFILES`
	OST_REMOVE=`$LFIND $OST_FILES | awk '$1 == 0 { print $2 }' | head -n $NUMFILES`

	export MDS_DUPE=""
	for f in `seq -f testfile.%g $((NUMFILES + 1)) $((NUMFILES * 2))`; do
		TEST_FILE=$DIR/$f
		echo "DUPLICATING MDS file $TEST_FILE"
		$LFIND -v $TEST_FILE >> $LOG || exit 20
		MDS_DUPE="$MDS_DUPE $TEST_FILE"
	done
	MDS_DUPE=`echo $MDS_DUPE | sed "s#$MOUNT/##g"`

	export MDS_REMOVE=""
	for f in `seq -f testfile.%g $((NUMFILES * 2 + 1)) $((NUMFILES * 3))`; do
		TEST_FILE=$DIR/$f
		echo "REMOVING MDS file $TEST_FILE which has info:"
		$LFIND -v $TEST_FILE >> $LOG || exit 30
		MDS_REMOVE="$MDS_REMOVE $TEST_FILE"
	done
	MDS_REMOVE=`echo $MDS_REMOVE | sed "s#$MOUNT/##g"`

	# when the OST is also using an OSD this needs to be fixed
	MDTDEVS=`get_mnt_devs osd`
	OSTDEVS=`get_mnt_devs obdfilter`
	OSTCOUNT=`echo $OSTDEVS | wc -w`
	sh llmountcleanup.sh || exit 40

	# Remove objects associated with files
	echo "removing objects: `echo $OST_REMOVE`"
	DEBUGTMP=`mktemp $TMP/debugfs.XXXXXXXXXX`
	for i in $OST_REMOVE; do
		echo "rm O/0/d$((i % 32))/$i" >> $DEBUGTMP
	done
	debugfs -w -f $DEBUGTMP `echo $OSTDEVS | cut -d' ' -f 1`
	RET=$?
	rm $DEBUGTMP
	[ $RET -ne 0 ] && exit 50

	SAVE_PWD=$PWD
	mount -t $FSTYPE -o loop $MDSDEV $MOUNT || exit 60
	do_umount() {
		trap 0
		cd $SAVE_PWD
		umount -f $MOUNT
	}
	trap do_umount EXIT

	#Remove files from mds
	for f in $MDS_REMOVE; do
		rm $MOUNT/ROOT/$f || exit 70
	done

	#Create EAs on files so objects are referenced from different files
	ATTRTMP=`mktemp $TMP/setfattr.XXXXXXXXXX`
	cd $MOUNT/ROOT || exit 78
	for f in $MDS_DUPE; do
		touch $f.bad || exit 74
		getfattr -n trusted.lov $f | sed "s#$f#&.bad#" > $ATTRTMP
		setfattr --restore $ATTRTMP || exit 80
	done
	cd $SAVE_PWD
	rm $ATTRTMP

	do_umount
else
	# when the OST is also using an OSD this needs to be fixed
	MDTDEVS=`get_mnt_devs osd`
	OSTDEVS=`get_mnt_devs obdfilter`
	OSTCOUNT=`echo $OSTDEVS | wc -w`
fi # LFSCK_SETUP

# Run e2fsck to get mds and ost info
# a return status of 1 indicates e2fsck successfuly fixed problems found
set +e

echo "e2fsck -d -v -fn --mdsdb $MDSDB $MDSDEV"
df > /dev/null	# update statfs data on disk
e2fsck -d -v -fn --mdsdb $MDSDB $MDSDEV
RET=$?
[ $RET -gt $MAX_ERR ] && echo "e2fsck returned $RET" && exit 90 || true

export OSTDB_LIST=""
i=0
for OSTDEV in $OSTDEVS; do
	df > /dev/null	# update statfs data on disk
	e2fsck -d -v -fn --mdsdb $MDSDB --ostdb $OSTDB-$i $OSTDEV
	RET=$?
	[ $RET -gt $MAX_ERR ] && echo "e2fsck returned $RET" && exit 100
	OSTDB_LIST="$OSTDB_LIST $OSTDB-$i"
	i=$((i + 1))
done

#Remount filesystem
[ "`mount | grep $MOUNT`" ] || $SETUP

# need to turn off shell error detection to get proper error return
# lfsck will return 1 if the filesystem had errors fixed
echo "LFSCK TEST 1"
echo "lfsck -c -l --mdsdb $MDSDB --ostdb $OSTDB_LIST $MOUNT"
echo y | lfsck -c -l --mdsdb $MDSDB --ostdb $OSTDB_LIST $MOUNT
RET=$?
[ $RET -eq 0 ] && echo "clean after first check" && exit 0
echo "LFSCK TEST 1 - finished with rc=$RET"
[ $RET -gt $MAX_ERR ] && exit 110 || true

# make sure everything gets to the backing store
sync; sleep 2; sync

echo "LFSCK TEST 2"
echo "e2fsck -d -v -fn --mdsdb $MDSDB $MDSDEV"
df > /dev/null	# update statfs data on disk
e2fsck -d -v -fn --mdsdb $MDSDB $MDSDEV
RET=$?
[ $RET -gt $MAX_ERR ] && echo "e2fsck returned $RET" && exit 123 || true

i=0
export OSTDB_LIST=""
for OSTDEV in $OSTDEVS; do
	df > /dev/null	# update statfs data on disk
	e2fsck -d -v -fn --mdsdb $MDSDB --ostdb $OSTDB-$i $OSTDEV
	RET=$?
	[ $RET -gt $MAX_ERR ] && echo "e2fsck returned $RET" && exit 124
	OSTDB_LIST="$OSTDB_LIST $OSTDB-$i"
	i=$((i + 1))
done

echo "LFSCK TEST 2"
echo "lfsck -c -l --mdsdb $MDSDB --ostdb $OSTDB_LIST $MOUNT"
lfsck -c -l --mdsdb $MDSDB --ostdb $OSTDB_LIST $MOUNT
RET=$?
echo "LFSCK TEST 2 - finished with rc=$RET"
[ $RET -ne 0 ] && exit 125 || true
if [ -z "$WAS_MOUNTED" ]; then
	sh llmountcleanup.sh || exit 120
fi

#Cleanup 
rm -f $MDSDB $OSTDB-* || true

echo "$0: completed"
