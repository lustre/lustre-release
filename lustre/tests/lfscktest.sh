#!/bin/bash
set -vx
#set -e

. ./lfscktest_config.sh

sh llmount.sh || exit 1

#Create mount points on target OST and MDS
#Create test directory 
mkdir -p $OST_MOUNTPT
mkdir -p $MDS_MOUNTPT
mkdir -p $TEST_DIR

export PATH=$LFSCK_PATH:`dirname $0`:`dirname $0`/../utils:$PATH

# Create some files on the filesystem
for i in `seq 0 3`; do
	mkdir -p ${MOUNT}/d$i
	for j in `seq 0 5`; do
		mkdir -p  ${MOUNT}/d$i/d$j
		for k in `seq 1 5`; do
			FILE="${MOUNT}/d$i/d$j/test$k"
			echo "creating $FILE"
			dd if=/dev/zero bs=4k count=1 of=$FILE
		done
	done
done

# Create Files to be modified
file_name=${TESTNAME}
for FILE in `seq -f ${TEST_DIR}/${file_name}.%g 0 40`; do
	dd if=/dev/zero count=1 bs=64K of=$FILE || exit 1
done

#Create some more files
for i in `seq 21 23`; do
	mkdir -p ${MOUNT}/d$i
	for j in `seq 0 5`; do
		mkdir -p  ${MOUNT}/d$i/d$j
		for k in `seq 0 5`; do
			FILE="${MOUNT}/d$i/d$j/test$k"
			echo "creating $FILE"
			dd if=/dev/zero bs=4k count=1 of=$FILE
		done
	done
done

# Get objids for a file on the OST
OST_TEST_FILE_OBJIDS=""
for i in `seq 0 19`; do
	OST_TEST_FILE=${TEST_DIR}/${file_name}.$i
	##Get the file OBJID
	OST_TEST_FILE_OBJID=`$LFIND -v -o $OST_UUID $OST_TEST_FILE|grep '\*$' | awk '{ print $2 }'` || exit 1
	if [ "$OST_TEST_FILE_OBJID" ]; then
		echo "REMOVING OBJID $OST_TEST_FILE_OBJID on $OST_UUID from $OST_TEST_FILE"
	fi
	OST_TEST_FILE_OBJIDS="$OST_TEST_FILE_OBJIDS $OST_TEST_FILE_OBJID"
done

MDS_FILES=""
for i in `seq 20 39`; do
	TEST_FILE=${TEST_DIR}/${file_name}.$i
	echo "REMOVING MDS FILE $TEST_FILE which has info:"
	$LFIND -v $TEST_FILE  || exit 1
	MDS_FILES="$MDS_FILES ${TESTNAME}/${file_name}.$i"
done

sh llmountcleanup.sh || exit 1

# Remove objects associated with files
echo "removing objects: $OST_TEST_FILE_OBJIDS"
for i in $OST_TEST_FILE_OBJIDS; do
	z=`expr $i % 32`
	debugfs -w -R "rm O/0/d$z/$i" "$OSTDEV" || exit 1
done

mount "-o" loop $MDSDEV $MDS_MOUNTPT

#Remove files from mds
for i in $MDS_FILES; do
	rm $MDS_MOUNTPT/ROOT/$i || (umount $MDS_MOUNTPT && exit 1)
done

#Create EAs on files so objects are referenced twice from different mds files
for i in `seq 0 19`; do
	touch $MDS_MOUNTPT/ROOT/${TESTNAME}/${TESTNAME}.bad.$i
	copy_attr $MDS_MOUNTPT/ROOT/${TESTNAME}/${TESTNAME}.$i $MDS_MOUNTPT/ROOT/${TESTNAME}/${TESTNAME}.bad.$i || (umount $MDS_MOUNTPT && exit 1) 
	i=`expr $i + 1`
done
umount $MDS_MOUNTPT 
rmdir $MDS_MOUNTPT
rmdir $OST_MOUNTPT

# Run e2fsck to get mds and ost info
# a return status of 1 indicates e2fsck successfuly fixed problems found

e2fsck -d -f -y --mdsdb $GPATH/mdsdb $MDSDEV
RET=$?
[ $RET -ne 0 -a $RET -ne 1 ] && exit 1
i=0
OSTDB_LIST=""
while [ $i -lt $NUM_OSTS ]; do
	e2fsck -d -f -y --mdsdb $GPATH/mdsdb --ostdb $GPATH/ostdb-$i $TMP/ost`expr $i + 1`-`hostname`
	RET=$?
	[ $RET -ne 0 -a $RET -ne 1 ] && exit 1
	if [ -z "${OSTDB_LIST}" ]; then
		OSTDB_LIST=${GPATH}/ostdb-$i
	else
		OSTDB_LIST=${GPATH}/ostdb-$i,${OSTDB_LIST}
	fi
	i=`expr $i + 1`
done

#Remount filesystem
sh llrmount.sh  || exit 1

lfsck -l --mdsdb $GPATH/mdsdb --ostdb ${OSTDB_LIST} ${MOUNT} || exit 1  

#Cleanup 
rm $GPATH/mdsdb
rm $GPATH/ostdb-*

sh llmountcleanup.sh || exit 1
