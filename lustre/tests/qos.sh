#!/bin/bash

set -e

export PATH=`dirname $0`/../utils:$PATH

LFS=${LFS:-lfs}
LCTL=${LCTL:-lctl}
MOUNT=${MOUNT:-/mnt/lustre}
MAXAGE=${MAXAGE:-1}

QOSFILE=$MOUNT/qos_file
TAB='--'

echo "remove all files on $MOUNT..."
rm -fr $MOUNT/*
sleep 1		# to ensure we get up-to-date statfs info

set_qos() {
	lctl set_param lov.*.qos_threshold=$(($1/1024))
	lctl set_param lov.*.qos_maxage=$2
}

# assume all osts has same free space 
OSTCOUNT=$(lctl get_param -n lov.*.activeobd | head -n 1)
TOTALAVAIL=$(lctl get_param -n llite.*.kbytesavail | head -n 1)
SINGLEAVAIL=$(($TOTALAVAIL/$OSTCOUNT))
MINFREE=$((1024 * 4))	# 4M
TOTALFFREE=$(lctl get_param -n llite.*.filesfree | head -n 1)

if [ $SINGLEAVAIL -lt $MINFREE ]; then
	echo "ERROR: single ost free size($SINGLEAVAIL kb) is too low!"
	exit 1;
fi
if [ $OSTCOUNT -lt 3 ]; then
	echo "WARN: ost count($OSTCOUNT) must be greater than 2!"
	exit 0;
fi

qos_test_1() {
	echo "[qos test 1]: creation skip almost full OST (avail space < threshold)"

	# set qos_threshold as half ost size
	THRESHOLD=$(($SINGLEAVAIL/2))
	set_qos $THRESHOLD $MAXAGE

	# set stripe number to 1
	$LFS setstripe $QOSFILE 65536 -1 1
	FULLOST=`$LFS getstripe -q $QOSFILE | awk '/\s*\d*/ {print $1}'`
	
	# floodfill the FULLOST
	echo "$TAB fill the OST $FULLOST to almost fullness..."
	dd if=/dev/zero of=$QOSFILE count=$(($SINGLEAVAIL - $THRESHOLD + 1500)) bs=1k > /dev/null 2>&1 || return 1
	echo "$TAB done"
	
	sleep $(($MAXAGE * 2))
	echo "$TAB create 10 files with 1 stripe"
	for i in `seq 10`; do
		rm -f $MOUNT/file-$i
		$LFS setstripe $MOUNT/file-$i 65536 -1 1
		idx=`$LFS getstripe -q $MOUNT/file-$i | awk '/\s*\d*/ {print $1}'`
		if [ $idx -eq $FULLOST ]; then
			echo "$TAB ERROR: create object on full OST $FULLOST"
			return 1
		fi
	done
	echo "$TAB no object created on OST $FULLOST"

	# cleanup
	for i in `seq 10`; do
		rm -f $MOUNT/file-$i
	done
	rm -f $QOSFILE
	# set threshold and maxage to normal value
	set_qos 10240 1
	
	sleep 1
	return 0
}

qos_test_2 () {
	echo "[qos test 2]: creation balancing over all OSTs by free space"

	if [ $OSTCOUNT -lt 3 ]; then
		echo "$TAB WARN: OST count < 3, test skipped"
		return 0
	fi
	
	WADSZ=$(($SINGLEAVAIL * 3 / 4))
	TOTALSZ=$(($WADSZ * $OSTCOUNT - 1))

	# fill all OST 0 to 3/4 fulness
	$LFS setstripe $QOSFILE 65536 0 1
	echo "$TAB fill the OST 0 to 3/4 fulness..."
	dd if=/dev/zero of=$QOSFILE count=$WADSZ bs=1k > /dev/null 2>&1 || return 1
	echo "$TAB done"

	# write 2 stripe files to fill up other OSTs
	LOOPCNT=500
	echo "$TAB create $LOOPCNT files with 2 stripe..."
	for i in `seq $LOOPCNT`; do
		rm -f $MOUNT/file-$i
		$LFS setstripe $MOUNT/file-$i 65536 -1 2
	done
	echo "$TAB done"

	# the objects created on OST 0 should be 1/4 of on other OSTs'
	CNT0=`$LFS getstripe -q /mnt/lustre | awk '/\s*\d*/ {print $1}'| grep -c 0`
	CNT0=$(($CNT0 - 1))
	echo "$TAB object created on OST 0: $CNT0"
	
	# the object count of other osts must be greater than 2 times 
	CNT0=$(($CNT0 * 2))
	for i in `seq $(($OSTCOUNT - 1))`; do
		CNT=`$LFS getstripe -q /mnt/lustre | awk '/\s*\d*/ {print $1}'| grep -c $i`
		echo "$TAB object created on OST $i: $CNT"
		if [ $CNT0 -gt $CNT ] ; then
			echo "$TAB ERROR: too much objects created on OST 0"
			return 1
		fi
	done
	echo "$TAB objects created on OST 0 is about 1/4 of others'"
	
	# cleanup
	for i in `seq $LOOPCNT`; do
		rm -f $MOUNT/file-$i
	done
	rm -f $QOSFILE
	return 0
}
	

# run tests
for j in `seq 2`; do
	qos_test_$j
	[ $? -ne 0 ] && exit 1 
done
exit 0
