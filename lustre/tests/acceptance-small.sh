#!/bin/sh
# script which _must_ complete successfully (at minimum) before checkins to
# the CVS HEAD are allowed.
set -vxe

[ "$CONFIGS" ] || CONFIGS="local lov"
[ "$THREADS" ] || THREADS=1
[ "$SIZE" ] || SIZE=20480
[ "$RSIZE" ] || RSIZE=64
[ "$UID" ] || UID=1000
[ "$MNT" ] || MNT=/mnt/lustre
[ "$TMP" ] || TMP=/tmp
[ "$COUNT" ] || COUNT=1000
[ "$DEBUG_OFF" ] || DEBUG_OFF="eval echo 0 > /proc/sys/portals/debug"

for NAME in $CONFIGS; do
	export NAME
	[ -e $NAME.sh ] && sh $NAME.sh
	[ ! -e $NAME.xml ] && echo "no config '$NAME.xml'" 1>&2 && exit 1

	if [ "$RUNTESTS" != "no" ]; then
		sh runtests
	fi

	mount | grep $MNT || sh llmount.sh
	[ "$SANITY" != "no" ] && sh sanity.sh
	if [ "$DBENCH" != "no" ]; then
		$DEBUG_OFF
		sh rundbench 1
		sh llmountcleanup.sh
		sh llrmount.sh
		if [ $THREADS -gt 1 ]; then
			sh rundbench $THREADS
			sh llmountcleanup.sh
			sh llrmount.sh
		fi
		rm -f /mnt/lustre/client.txt
	fi
	chown $UID $MNT && chmod 700 $MNT
	if [ "$BONNIE" != "no" ]; then
		$DEBUG_OFF
		bonnie++ -s 0 -n 10 -u $UID -d $MNT
		sh llmountcleanup.sh
		sh llrmount.sh
	fi
	IOZONE_OPTS="-i 0 -i 1 -i 2 -+d -r $RSIZE -s $SIZE"
	IOZONE_FILE="-f $MNT/iozone"
	if [ "$IOZONE" != "no" ]; then
		$DEBUG_OFF
		iozone $IOZONE_OPTS $IOZONE_FILE
		sh llmountcleanup.sh
		sh llrmount.sh
	fi
	if [ "$IOZONE_DIR" != "no" ]; then
		$DEBUG_OFF
		iozone -I $IOZONE_OPTS $IOZONE_FILE.odir
		IOZVER=`iozone -v | awk '/Revision:/ { print $3 }' | tr -d '.'`
		sh llmountcleanup.sh
		sh llrmount.sh
		if [ "$THREADS" -gt 1 -a "$IOZVER" -ge 3145 ]; then
			$DEBUG_OFF
			THREAD=1
			IOZONE_FILE="-F "
			SIZE=`expr $SIZE / $THREADS`
			while [ $THREAD -le $THREADS ]; do
				IOZONE_FILE="$IOZONE_FILE $MNT/iozone.$THREAD"
				THREAD=`expr $THREAD + 1`
			done
			iozone -I $IOZONE_OPTS -t $THREADS $IOZONE_FILE
			sh llmountcleanup.sh
			sh llrmount.sh
		elif [ $IOZVER -lt 3145 ]; then
			VER=`iozone -v | awk '/Revision:/ { print $3 }'`
			echo "iozone $VER too old for multi-threaded tests"
		fi
	fi
	if [ "$FSX" != "no" ]; then
		$DEBUG_OFF
		./fsx -c 50 -p 1000 -P $TMP -l 1024000 -N $(($COUNT * 100)) $MNT/fsxfile
		sh llmountcleanup.sh
		#sh llrmount.sh
	fi	
	mount | grep $MNT && sh llmountcleanup.sh
done
