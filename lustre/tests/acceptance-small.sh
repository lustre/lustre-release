#!/bin/sh
# script which _must_ complete successfully (at minimum) before checkins to
# the CVS HEAD are allowed.
set -vxe

[ "$CONFIGS" -a -z "$SANITYN" ] && SANITYN=no
[ "$CONFIGS" ] || CONFIGS="local-large-inode local lov"
[ "$MAX_THREADS" ] || MAX_THREADS=10
if [ -z "$THREADS" ]; then
	KB=`awk '/MemTotal:/ { print $2 }' /proc/meminfo`
	THREADS=`expr $KB / 16384`
	[ $THREADS -gt $MAX_THREADS ] && THREADS=$MAX_THREADS
fi
[ "$SIZE" ] || SIZE=20480
[ "$RSIZE" ] || RSIZE=64
[ "$UID" ] || UID=1000
[ "$MOUNT" ] || MOUNT=/mnt/lustre
[ "$TMP" ] || TMP=/tmp
[ "$COUNT" ] || COUNT=1000
#[ "$DEBUG_LVL" ] || DEBUG_LVL=0x370200
[ "$DEBUG_LVL" ] || DEBUG_LVL=0
[ "$DEBUG_OFF" ] || DEBUG_OFF="eval echo $DEBUG_LVL > /proc/sys/portals/debug"
[ "$DEBUG_ON" ] || DEBUG_ON="eval echo -1 > /proc/sys/portals/debug"

for NAME in $CONFIGS; do
	export NAME MOUNT
	[ -e $NAME.sh ] && sh $NAME.sh
	[ ! -e $NAME.xml ] && [ -z "$LDAPURL" ] && echo "no config '$NAME.xml'" 1>&2 && exit 1

	if [ "$RUNTESTS" != "no" ]; then
		sh runtests
	fi

	#[ "$SANITY" != "no" ] && sh sanity.sh
	if [ "$SANITY" != "no" ]; then
		SANITYLOG=/tmp/sanity.log START=: CLEAN=: sh sanity.sh
	fi

	if [ "$DBENCH" != "no" ]; then
		mount | grep $MOUNT || sh llmount.sh
		SPACE=`df $MOUNT | tail -1 | awk '{ print $4 }'`
		DB_THREADS=`expr $SPACE / 50000`
		[ $THREADS -lt $DB_THREADS ] && DB_THREADS=$THREADS

		$DEBUG_OFF
		sh rundbench 1
		$DEBUG_ON
		sh llmountcleanup.sh
		sh llrmount.sh
		if [ $DB_THREADS -gt 1 ]; then
			$DEBUG_OFF
			sh rundbench $DB_THREADS
			$DEBUG_ON
			sh llmountcleanup.sh
			sh llrmount.sh
		fi
		rm -f /mnt/lustre/`hostname`/client.txt
	fi
	chown $UID $MOUNT && chmod 700 $MOUNT
	if [ "$BONNIE" != "no" ]; then
		mount | grep $MOUNT || sh llmount.sh
		$DEBUG_OFF
		bonnie++ -s 0 -n 10 -u $UID -d $MOUNT
		$DEBUG_ON
		sh llmountcleanup.sh
		sh llrmount.sh
	fi
	IOZONE_OPTS="-i 0 -i 1 -i 2 -+d -r $RSIZE -s $SIZE"
	IOZONE_FILE="-f $MOUNT/iozone"
	if [ "$IOZONE" != "no" ]; then
		mount | grep $MOUNT || sh llmount.sh
		$DEBUG_OFF
		iozone $IOZONE_OPTS $IOZONE_FILE
		$DEBUG_ON
		sh llmountcleanup.sh
		sh llrmount.sh
	fi
	if [ "$IOZONE_DIR" != "no" ]; then
		mount | grep $MOUNT || sh llmount.sh
		SPACE=`df $MOUNT | tail -1 | awk '{ print $4 }'`
		IOZ_THREADS=`expr $SPACE / \( $SIZE + $SIZE / 1000 \)`
		[ $THREADS -lt $IOZ_THREADS ] && IOZ_THREADS=$THREADS

		$DEBUG_OFF
		iozone -I $IOZONE_OPTS $IOZONE_FILE.odir
		IOZVER=`iozone -v | awk '/Revision:/ { print $3 }' | tr -d '.'`
		$DEBUG_ON
		sh llmountcleanup.sh
		sh llrmount.sh
		if [ "$IOZ_THREADS" -gt 1 -a "$IOZVER" -ge 3145 ]; then
			$DEBUG_OFF
			THREAD=1
			IOZONE_FILE="-F "
			while [ $THREAD -le $IOZ_THREADS ]; do
				IOZONE_FILE="$IOZONE_FILE $MOUNT/iozone.$THREAD"
				THREAD=`expr $THREAD + 1`
			done
			iozone -I $IOZONE_OPTS -t $IOZ_THREADS $IOZONE_FILE
			$DEBUG_ON
			sh llmountcleanup.sh
			sh llrmount.sh
		elif [ $IOZVER -lt 3145 ]; then
			VER=`iozone -v | awk '/Revision:/ { print $3 }'`
			echo "iozone $VER too old for multi-threaded tests"
		fi
	fi
	if [ "$FSX" != "no" ]; then
		mount | grep $MOUNT || sh llmount.sh
		$DEBUG_OFF
		./fsx -W -c 50 -p 1000 -P $TMP -l 1024000 -N $(($COUNT * 100)) $MOUNT/fsxfile
		$DEBUG_ON
		sh llmountcleanup.sh
		#sh llrmount.sh
	fi	
	mount | grep $MOUNT && sh llmountcleanup.sh
done

if [ "$REPLAY_SINGLE" != "no" ]; then
	sh replay-single.sh
fi
if [ "$SANITYN" != "no" ]; then
	export NAME=mount2
	mount | grep $MOUNT || sh llmount.sh
	sh sanityN.sh
	mount | grep $MOUNT && sh llmountcleanup.sh
fi
