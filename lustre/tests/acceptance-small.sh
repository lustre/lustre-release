#!/bin/sh
# script which _must_ complete successfully (at minimum) before checkins to
# the CVS HEAD are allowed.
set -vxe

PATH=`dirname $0`/../utils:$PATH

[ "$CONFIGS" ] || CONFIGS="local"  #"local lov"
[ "$MAX_THREADS" ] || MAX_THREADS=10
if [ -z "$THREADS" ]; then
	KB=`awk '/MemTotal:/ { print $2 }' /proc/meminfo`
	THREADS=`expr $KB / 16384`
	[ $THREADS -gt $MAX_THREADS ] && THREADS=$MAX_THREADS
fi
[ "$SIZE" ] || SIZE=40960
[ "$RSIZE" ] || RSIZE=512
[ "$UID" ] || UID=1000
[ "$MOUNT" ] || MOUNT=/mnt/lustre
[ "$MOUNT2" ] || MOUNT2=${MOUNT}2
[ "$TMP" ] || TMP=/tmp
[ "$COUNT" ] || COUNT=1000
[ "$DEBUG_LVL" ] || DEBUG_LVL=0
[ "$DEBUG_OFF" ] || DEBUG_OFF="sysctl -w lnet.debug=$DEBUG_LVL"
[ "$DEBUG_ON" ] || DEBUG_ON="sysctl -w lnet.debug=0x33f0484"

LIBLUSTRE=${LIBLUSTRE:-../liblustre}
LIBLUSTRETESTS=${LIBLUSTRETESTS:-$LIBLUSTRE/tests}

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@

SETUP=${SETUP:-setupall}
FORMAT=${FORMAT:-formatall}
CLEANUP=${CLEANUP:-stopall}

for NAME in $CONFIGS; do
	export NAME MOUNT START CLEAN
	. $LUSTRE/tests/cfg/$NAME.sh
	
	assert_env mds_HOST MDS_MKFS_OPTS MDSDEV
	assert_env ost_HOST OST_MKFS_OPTS OSTCOUNT
	assert_env FSNAME

	if [ "$RUNTESTS" != "no" ]; then
		sh runtests
	fi

	if [ "$SANITY" != "no" ]; then
		SANITYLOG=/tmp/sanity.log sh sanity.sh
	fi

	if [ "$DBENCH" != "no" ]; then
 	        mount_client $MOUNT
		SPACE=`df -P $MOUNT | tail -n 1 | awk '{ print $4 }'`
		DB_THREADS=`expr $SPACE / 50000`
		[ $THREADS -lt $DB_THREADS ] && DB_THREADS=$THREADS

		$DEBUG_OFF
		sh rundbench 1
		$DEBUG_ON
		$CLEANUP
		$SETUP
		if [ $DB_THREADS -gt 1 ]; then
			$DEBUG_OFF
			sh rundbench $DB_THREADS
			$DEBUG_ON
			$CLEANUP
			$SETUP
		fi
		rm -f /mnt/lustre/`hostname`/client.txt
	fi

	chown $UID $MOUNT && chmod 700 $MOUNT
	if [ "$BONNIE" != "no" ]; then
 	        mount_client $MOUNT
		$DEBUG_OFF
		bonnie++ -f -r 0 -s $(($SIZE / 1024)) -n 10 -u $UID -d $MOUNT
		$DEBUG_ON
		$CLEANUP
		$SETUP
	fi

	IOZONE_OPTS="-i 0 -i 1 -i 2 -e -+d -r $RSIZE -s $SIZE"
	IOZFILE="-f $MOUNT/iozone"
	export O_DIRECT
	if [ "$IOZONE" != "no" ]; then
 	        mount_client $MOUNT
		$DEBUG_OFF
		iozone $IOZONE_OPTS $IOZFILE
		$DEBUG_ON
		$CLEANUP
		$SETUP

		# check if O_DIRECT support is implemented in kernel
		if [ -z "$O_DIRECT" ]; then
			touch $MOUNT/f.iozone
			if ! ./directio write $MOUNT/f.iozone 0 1; then
				O_DIRECT=no
			fi
			rm -f $MOUNT/f.iozone
		fi
		if [ "$O_DIRECT" != "no" -a "$IOZONE_DIR" != "no" ]; then
			$DEBUG_OFF
			iozone -I $IOZONE_OPTS $IOZFILE.odir
			$DEBUG_ON
			$CLEANUP
			$SETUP
		fi

		SPACE=`df -P $MOUNT | tail -n 1 | awk '{ print $4 }'`
		IOZ_THREADS=`expr $SPACE / \( $SIZE + $SIZE / 512 \)`
		[ $THREADS -lt $IOZ_THREADS ] && IOZ_THREADS=$THREADS
		IOZVER=`iozone -v|awk '/Revision:/ {print $3}'|tr -d .`
		if [ "$IOZ_THREADS" -gt 1 -a "$IOZVER" -ge 3145 ]; then
			$DEBUG_OFF
			THREAD=1
			IOZFILE="-F "
			while [ $THREAD -le $IOZ_THREADS ]; do
				IOZFILE="$IOZFILE $MOUNT/iozone.$THREAD"
				THREAD=`expr $THREAD + 1`
			done
			iozone $IOZONE_OPTS -t $IOZ_THREADS $IOZFILE
			$DEBUG_ON
			$CLEANUP
			$SETUP
		elif [ $IOZVER -lt 3145 ]; then
			VER=`iozone -v | awk '/Revision:/ { print $3 }'`
			echo "iozone $VER too old for multi-thread test"
		fi
	fi

	if [ "$FSX" != "no" ]; then
		mount | grep $MOUNT || $SETUP
		$DEBUG_OFF
		./fsx -c 50 -p 1000 -P $TMP -l $SIZE \
			-N $(($COUNT * 100)) $MOUNT/fsxfile
		$DEBUG_ON
		$CLEANUP
		$SETUP
	fi	

	mkdir -p $MOUNT2
	case $NAME in
	local|lov)
		MDSNODE=`hostname`
		MDSNAME=mds1
		CLIENT=client
		;;
	*)	# we could extract this from $NAME.xml somehow
		;;
	esac

	if [ "$SANITYN" != "no" ]; then
 	        mount_client $MOUNT
		$DEBUG_OFF

		if [ "$MDSNODE" -a "$MDSNAME" -a "$CLIENT" ]; then
		        mount_client $MOUNT2
			SANITYLOG=$TMP/sanity.log START=: CLEAN=: sh sanityN.sh
			umount $MOUNT2
		else
			echo "don't know \$MDSNODE, \$MDSNAME, \$CLIENT"
			echo "can't mount2 for '$NAME', skipping sanityN.sh"
		fi

		$DEBUG_ON
		$CLEANUP
		$SETUP
	fi

	if [ "$LIBLUSTRE" != "no" ]; then
 	        mount_client $MOUNT
		export LIBLUSTRE_MOUNT_POINT=$MOUNT2
		export LIBLUSTRE_MOUNT_TARGET=$MDSNODE:/$MDSNAME/$CLIENT
		export LIBLUSTRE_TIMEOUT=`cat /proc/sys/lustre/timeout`
		#export LIBLUSTRE_DEBUG_MASK=`cat /proc/sys/lnet/debug`
		if [ -x $LIBLUSTRETESTS/sanity ]; then
			$LIBLUSTRETESTS/sanity --target=$LIBLUSTRE_MOUNT_TARGET
		fi
		$CLEANUP
		#$SETUP
	fi

	$CLEANUP
done

if [ "$REPLAY_SINGLE" != "no" ]; then
	sh replay-single.sh
fi

if [ "$CONF_SANITY" != "no" ]; then
        sh conf-sanity.sh
fi

if [ "$RECOVERY_SMALL" != "no" ]; then
        sh recovery-small.sh
fi

if [ "$REPLAY_OST_SINGLE" != "no" ]; then
        sh replay-ost-single.sh
fi

if [ "$REPLAY_DUAL" != "no" ]; then
        sh replay-dual.sh
fi

if [ "$INSANITY" != "no" ]; then
        sh insanity.sh -r
fi

RC=$?
echo "completed with rc $RC" && exit $RC
