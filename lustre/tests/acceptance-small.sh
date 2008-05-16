#!/bin/bash
# script which _must_ complete successfully (at minimum) before checkins to
# the CVS HEAD are allowed.
#set -vx
set -e

PATH=`dirname $0`/../utils:$PATH

[ -z "$CONFIG" -a "$NAME" ] && CONFIGS=$NAME
[ "$CONFIGS" ] || CONFIGS="local"  #"local lov"
[ "$MAX_THREADS" ] || MAX_THREADS=20
RAMKB=`awk '/MemTotal:/ { print $2 }' /proc/meminfo`
if [ -z "$THREADS" ]; then
	THREADS=$((RAMKB / 16384))
	[ $THREADS -gt $MAX_THREADS ] && THREADS=$MAX_THREADS
fi
[ "$SIZE" ] || SIZE=$((RAMKB * 2))
[ "$RSIZE" ] || RSIZE=512
[ "$UID" ] || UID=1000
[ "$MOUNT" ] || MOUNT=/mnt/lustre
[ "$MOUNT2" ] || MOUNT2=${MOUNT}2
[ "$TMP" ] || TMP=/tmp
[ "$COUNT" ] || COUNT=1000
[ "$DEBUG_LVL" ] || DEBUG_LVL=0
[ "$DEBUG_OFF" ] || DEBUG_OFF="eval sysctl -w lnet.debug=\"$DEBUG_LVL\""
[ "$DEBUG_ON" ] || DEBUG_ON="eval sysctl -w lnet.debug=0x33f0484"

export TESTSUITE_LIST="RUNTESTS SANITY DBENCH BONNIE IOZONE FSX SANITYN LFSCK LIBLUSTRE REPLAY_SINGLE CONF_SANITY RECOVERY_SMALL REPLAY_OST_SINGLE REPLAY_DUAL INSANITY SANITY_QUOTA SANITY_SEC"

if [ "$ACC_SM_ONLY" ]; then
    for O in $TESTSUITE_LIST; do
	export ${O}="no"
    done
    for O in $ACC_SM_ONLY; do
	O=`echo $O | tr "[:lower:]" "[:upper:]"`
	export ${O}="yes"
    done
fi
LFSCK="no" # bug 13698

LIBLUSTRETESTS=${LIBLUSTRETESTS:-../liblustre/tests}

STARTTIME=`date +%s`
RANTEST=""

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@

if $GSS; then
    # liblustre doesn't support GSS
    export LIBLUSTRE=no
fi

SETUP=${SETUP:-setupall}
FORMAT=${FORMAT:-formatall}
CLEANUP=${CLEANUP:-stopall}

setup_if_needed() {
    mount | grep $MOUNT && return
    $FORMAT && $SETUP
}

title() {
    log "-----============= acceptance-small: "$*" ============----- `date`"
    RANTEST=${RANTEST}$*", "
}

for NAME in $CONFIGS; do
	export NAME MOUNT START CLEAN
	. $LUSTRE/tests/cfg/$NAME.sh

	if [ ! -f /lib/modules/$(uname -r)/kernel/fs/lustre/mds.ko -a \
	    ! -f `dirname $0`/../mds/mds.ko ]; then
	    export CLIENTMODSONLY=true
	fi
	
	assert_env mds_HOST MDS_MKFS_OPTS MDSDEV
	assert_env ost_HOST OST_MKFS_OPTS OSTCOUNT
	assert_env FSNAME MOUNT MOUNT2

	setup_if_needed

	if [ "$RUNTESTS" != "no" ]; then
	        title runtests
		bash runtests
		$CLEANUP
		$SETUP
		RUNTESTS="done"
	fi

	if [ "$SANITY" != "no" ]; then
	        title sanity
		MOUNT2="" bash sanity.sh
		$CLEANUP
		$SETUP
		SANITY="done"
	fi

	which dbench > /dev/null 2>&1 || DBENCH=no
	if [ "$DBENCH" != "no" ]; then
	        title dbench
		DBENCHDIR=$MOUNT/$HOSTNAME
		mkdir -p $DBENCHDIR
		SPACE=`df -P $MOUNT | tail -n 1 | awk '{ print $4 }'`
		DB_THREADS=$((SPACE / 50000))
		[ $THREADS -lt $DB_THREADS ] && DB_THREADS=$THREADS

		$DEBUG_OFF
		myUID=$RUNAS_ID
		myRUNAS=$RUNAS
		FAIL_ON_ERROR=false check_runas_id_ret $myUID $myRUNAS || { myRUNAS="" && myUID=$UID; }
		chown $myUID:$myUID $DBENCHDIR
		duration=""
		[ "$SLOW" = "no" ] && duration=" -t 120"
		if [ "$SLOW" != "no" -o $DB_THREADS -eq 1 ]; then
			DIR=$DBENCHDIR $myRUNAS bash rundbench 1 $duration
			$DEBUG_ON
			$CLEANUP
			$SETUP
		fi
		if [ $DB_THREADS -gt 1 ]; then
			$DEBUG_OFF
			DIR=$DBENCHDIR $myRUNAS bash rundbench $DB_THREADS $duration
			$DEBUG_ON
			$CLEANUP
			$SETUP
		fi
		rm -rf $DBENCHDIR
		DBENCH="done"
	fi

	which bonnie++ > /dev/null 2>&1 || BONNIE=no
	if [ "$BONNIE" != "no" ]; then
	        title bonnie
		BONDIR=$MOUNT/d0.bonnie
		mkdir -p $BONDIR
		$LFS setstripe -c -1 $BONDIR
		sync
		MIN=`cat /proc/fs/lustre/osc/*/kbytesavail | sort -n | head -n1`
		SPACE=$(( OSTCOUNT * MIN ))
		[ $SPACE -lt $SIZE ] && SIZE=$((SPACE * 3 / 4))
		log "min OST has ${MIN}kB available, using ${SIZE}kB file size"
		$DEBUG_OFF
		myUID=$RUNAS_ID
		myRUNAS=$RUNAS
		FAIL_ON_ERROR=false check_runas_id_ret $myUID $myRUNAS || { myRUNAS="" && myUID=$UID; }
		chown $myUID:$myUID $BONDIR		
		$myRUNAS bonnie++ -f -r 0 -s$((SIZE / 1024)) -n 10 -u$myUID:$myUID -d$BONDIR
		$DEBUG_ON
		$CLEANUP
		$SETUP
		BONNIE="done"
	fi

	export O_DIRECT
	[ "$SLOW" = "no" ] && export IOZONE=no # 5 minutes

	which iozone > /dev/null 2>&1 || IOZONE=no
	if [ "$IOZONE" != "no" ]; then
	        title iozone
		IOZDIR=$MOUNT/d0.iozone
		mkdir -p $IOZDIR
		$LFS setstripe -c -1 $IOZDIR
		sync
		MIN=`cat /proc/fs/lustre/osc/*/kbytesavail | sort -n | head -n1`
		SPACE=$(( OSTCOUNT * MIN ))
		[ $SPACE -lt $SIZE ] && SIZE=$((SPACE * 3 / 4))
		log "min OST has ${MIN}kB available, using ${SIZE}kB file size"
		IOZONE_OPTS="-i 0 -i 1 -i 2 -e -+d -r $RSIZE -s $SIZE"
		IOZFILE="$IOZDIR/iozone"
		# $SPACE was calculated with all OSTs
		$DEBUG_OFF
		myUID=$RUNAS_ID
		myRUNAS=$RUNAS
		FAIL_ON_ERROR=false check_runas_id_ret $myUID $myRUNAS || { myRUNAS="" && myUID=$UID; }
		chown $myUID:$myUID $IOZDIR
		$myRUNAS iozone $IOZONE_OPTS -f $IOZFILE
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
			# cd TMP to have write permission for tmp file iozone writes
			( cd $TMP && $myRUNAS iozone -I $IOZONE_OPTS $IOZFILE.odir )
			$DEBUG_ON
			$CLEANUP
			$SETUP
		fi

		SPACE=`df -P $MOUNT | tail -n 1 | awk '{ print $4 }'`
		IOZ_THREADS=$((SPACE / SIZE * 2 / 3 ))
		[ $THREADS -lt $IOZ_THREADS ] && IOZ_THREADS=$THREADS
		IOZVER=`iozone -v | awk '/Revision:/ {print $3}' | tr -d .`
		if [ "$IOZ_THREADS" -gt 1 -a "$IOZVER" -ge 3145 ]; then
			$LFS setstripe -c 1 $IOZDIR
			$DEBUG_OFF
			THREAD=1
			IOZFILE="-F "
			while [ $THREAD -le $IOZ_THREADS ]; do
				IOZFILE="$IOZFILE $IOZDIR/iozone.$THREAD"
				THREAD=$((THREAD + 1))
			done
			$myRUNAS iozone $IOZONE_OPTS -t $IOZ_THREADS $IOZFILE
			$DEBUG_ON
			$CLEANUP
			$SETUP
		elif [ $IOZVER -lt 3145 ]; then
			VER=`iozone -v | awk '/Revision:/ { print $3 }'`
			echo "iozone $VER too old for multi-thread test"
		fi
		IOZONE="done"
	fi

	if [ "$FSX" != "no" ]; then
	        title fsx
		SPACE=`df -P $MOUNT | tail -n 1 | awk '{ print $4 }'`
		[ $SPACE -lt $SIZE ] && SIZE=$((SPACE * 3 / 4))
		$DEBUG_OFF
		./fsx -c 50 -p 1000 -P $TMP -l $SIZE \
			-N $(($COUNT * 100)) $MOUNT/fsxfile
		$DEBUG_ON
		$CLEANUP
		$SETUP
		FSX="done"
	fi	

	if [ "$SANITYN" != "no" ]; then
	        title sanityN
		$DEBUG_OFF

		mkdir -p $MOUNT2
		mount_client $MOUNT2
		#echo "can't mount2 for '$NAME', skipping sanityN.sh"
		START=: CLEAN=: bash sanityN.sh
		umount $MOUNT2

		$DEBUG_ON
		$CLEANUP
		$SETUP
		SANITYN="done"
	fi

	if [ "$LFSCK" != "no" -a -x /usr/sbin/lfsck ]; then
	        title lfsck
		E2VER=`e2fsck -V 2>&1 | head -n 1 | cut -d' ' -f 2`
		if grep -q obdfilter /proc/fs/lustre/devices; then
			if [ `echo $E2VER | cut -d. -f2` -ge 39 ] && \
			   [ "`echo $E2VER | grep cfs`" -o \
				"`echo $E2VER | grep sun`" ]; then
			   		bash lfscktest.sh
			else
				e2fsck -V
				echo "e2fsck does not support lfsck, skipping"
			fi
		else
			echo "remote OST, skipping test"
		fi
		LFSCK="done"
	fi

	[ "$NETTYPE" = "tcp" -o "$NETTYPE" = "ptl" ] || LIBLUSTRE=no # bug 15660
	if [ "$LIBLUSTRE" != "no" ]; then
	        title liblustre
		assert_env MGSNID MOUNT2
		$CLEANUP
		unload_modules
		# Liblustre needs accept=all, noacl
		[ -f /etc/modprobe.conf ] && MODPROBECONF=/etc/modprobe.conf
		[ -f /etc/modprobe.d/Lustre ] && MODPROBECONF=/etc/modprobe.d/Lustre

		LNETOPTS="$(awk '/^options lnet/ { print $0}' $MODPROBECONF | \
			sed 's/^options lnet //g') accept=all" \
			MDS_MOUNT_OPTS=$(echo $MDS_MOUNT_OPTS | sed 's/^[ \t]*//;s/[ \t]*$//') \
			MDS_MOUNT_OPTS="${MDS_MOUNT_OPTS},noacl" \
			MDS_MOUNT_OPTS=${MDS_MOUNT_OPTS/#,/-o } \
			$SETUP
		export LIBLUSTRE_MOUNT_POINT=$MOUNT2
		export LIBLUSTRE_MOUNT_TARGET=$MGSNID:/$FSNAME
		export LIBLUSTRE_TIMEOUT=`cat /proc/sys/lustre/timeout`
		#export LIBLUSTRE_DEBUG_MASK=`cat /proc/sys/lnet/debug`
		if [ -x $LIBLUSTRETESTS/sanity ]; then
			mkdir -p $MOUNT2
			echo $LIBLUSTRETESTS/sanity --target=$LIBLUSTRE_MOUNT_TARGET
			$LIBLUSTRETESTS/sanity --target=$LIBLUSTRE_MOUNT_TARGET
		fi
		$CLEANUP
		#$SETUP
		LIBLUSTRE="done"
	fi

	$CLEANUP
done

if [ "$REPLAY_SINGLE" != "no" ]; then
        title replay-single
	bash replay-single.sh
	REPLAY_SINGLE="done"
fi

if [ "$CONF_SANITY" != "no" ]; then
        title conf-sanity
        bash conf-sanity.sh
        CONF_SANITY="done"
fi

if [ "$RECOVERY_SMALL" != "no" ]; then
        title recovery-small
        bash recovery-small.sh
        RECOVERY_SMALL="done"
fi

if [ "$REPLAY_OST_SINGLE" != "no" ]; then
        title replay-ost-single
        bash replay-ost-single.sh
        REPLAY_OST_SINGLE="done"
fi

if [ "$REPLAY_DUAL" != "no" ]; then
        title replay-dual
        bash replay-dual.sh
        REPLAY_DUAL="done"
fi

if [ "$INSANITY" != "no" ]; then
        title insanity
        bash insanity.sh -r
        INSANITY="done"
fi

if [ "$SANITY_QUOTA" != "no" ]; then
        title sanity-quota
        bash sanity-quota.sh
        SANITY_QUOTA="done"
fi

if [ "$SANITY_SEC" != "no" ]; then
        title sanity-sec
        bash sanity-sec.sh
fi

RC=$?
title FINISHED
echo "Finished at `date` in $((`date +%s` - $STARTTIME))s"
echo "Tests ran: $RANTEST"
print_summary
echo "$0: completed with rc $RC" && exit $RC
