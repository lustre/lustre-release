#!/bin/bash
# script which _must_ complete successfully (at minimum) before checkins to
# the CVS HEAD are allowed.
#set -vx
set -e

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
[ "$DEBUG_OFF" ] || DEBUG_OFF="eval lctl set_param debug=\"$DEBUG_LVL\""
[ "$DEBUG_ON" ] || DEBUG_ON="eval lctl set_param debug=0x33f0484"

export TESTSUITE_LIST="RUNTESTS SANITY DBENCH BONNIE IOZONE FSX SANITYN LFSCK LIBLUSTRE REPLAY_SINGLE CONF_SANITY RECOVERY_SMALL REPLAY_OST_SINGLE REPLAY_DUAL REPLAY_VBR INSANITY SANITY_QUOTA PERFORMANCE_SANITY LARGE_SCALE"

if [ "$ACC_SM_ONLY" ]; then
    for O in $TESTSUITE_LIST; do
	export ${O}="no"
    done
    for O in $ACC_SM_ONLY; do
	O=`echo ${O%.sh} | tr "-" "_"`
	O=`echo $O | tr "[:lower:]" "[:upper:]"`
	export ${O}="yes"
    done
fi

LIBLUSTRETESTS=${LIBLUSTRETESTS:-../liblustre/tests}

STARTTIME=`date +%s`
RANTEST=""

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@

SETUP=${SETUP:-setupall}
FORMAT=${FORMAT:-formatall}
CLEANUP=${CLEANUP:-stopall}

setup_if_needed() {
    mount | grep $MOUNT && return
    $FORMAT && $SETUP
}

title() {
    # update titlebar if stdin is attaached to an xterm
    if ${UPDATE_TITLEBAR:-false}; then
	if tty -s; then
	    case $TERM in 
		xterm*)
		    echo -ne "\033]2; acceptance-small: $* \007" >&0
		    ;;
	    esac
	fi
    fi 
    log "-----============= acceptance-small: "$*" ============----- `date`"
    RANTEST=${RANTEST}$*", "
}

skip_remost()
{
	remote_ost_nodsh && log "SKIP: $1: remote OST with nodsh" && return 0
	return 1
}

skip_remmds()
{
	remote_mds_nodsh && log "SKIP: $1: remote MDS with nodsh" && return 0
	return 1
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

	MSKIPPED=0
	OSKIPPED=0
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
			$myRUNAS bash rundbench -D $DBENCHDIR 1 $duration || error "dbench failed!"
			$DEBUG_ON
			$CLEANUP
			$SETUP
		fi
		if [ $DB_THREADS -gt 1 ]; then
			$DEBUG_OFF
			$myRUNAS bash rundbench -D $DBENCHDIR $DB_THREADS $duration
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
		MIN=`lctl get_param -n osc.*.kbytesavail | sort -n | head -n1`
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
		MIN=`lctl get_param -n osc.*.kbytesavail | sort -n | head -n1`
		SPACE=$(( OSTCOUNT * MIN ))
		[ $SPACE -lt $SIZE ] && SIZE=$((SPACE * 3 / 4))
		log "min OST has ${MIN}kB available, using ${SIZE}kB file size"
		IOZONE_OPTS="-i 0 -i 1 -i 2 -e -+d -r $RSIZE"
		IOZFILE="$IOZDIR/iozone"
		IOZLOG=$TMP/iozone.log
		# $SPACE was calculated with all OSTs
		$DEBUG_OFF
		myUID=$RUNAS_ID
		myRUNAS=$RUNAS
		FAIL_ON_ERROR=false check_runas_id_ret $myUID $myRUNAS || { myRUNAS="" && myUID=$UID; }
		chown $myUID:$myUID $IOZDIR
		$myRUNAS iozone $IOZONE_OPTS -s $SIZE -f $IOZFILE 2>&1 | tee $IOZLOG
		tail -1 $IOZLOG | grep -q complete || \
			{ error "iozone (1) failed" && false; }
		rm -f $IOZLOG
		$DEBUG_ON
		$CLEANUP
		$SETUP

		# check if O_DIRECT support is implemented in kernel
		if [ -z "$O_DIRECT" ]; then
			touch $MOUNT/f.iozone
			if ! ./directio write $MOUNT/f.iozone 0 1; then
				log "SKIP iozone DIRECT IO test"
				O_DIRECT=no
			fi
			rm -f $MOUNT/f.iozone
		fi
		if [ "$O_DIRECT" != "no" -a "$IOZONE_DIR" != "no" ]; then
			$DEBUG_OFF
			$myRUNAS iozone -I $IOZONE_OPTS -s $SIZE -f $IOZFILE.odir 2>&1 | tee $IOZLOG
			tail -1 $IOZLOG | grep -q complete || \
				{ error "iozone (2) failed" && false; }
			rm -f $IOZLOG
			$DEBUG_ON
			$CLEANUP
			$SETUP
		fi

		SPACE=`df -P $MOUNT | tail -n 1 | awk '{ print $4 }'`
		IOZ_THREADS=$((SPACE / SIZE * 2 / 3 ))
		[ $THREADS -lt $IOZ_THREADS ] && IOZ_THREADS=$THREADS
		IOZVER=`iozone -v | awk '/Revision:/ {print $3}' | tr -d .`
		if [ "$IOZ_THREADS" -gt 1 -a "$IOZVER" -ge 3145 ]; then
			$LFS setstripe -c -1 $IOZDIR
			$DEBUG_OFF
			THREAD=1
			IOZFILE=" "
			while [ $THREAD -le $IOZ_THREADS ]; do
				IOZFILE="$IOZFILE $IOZDIR/iozone.$THREAD"
				THREAD=$((THREAD + 1))
			done
			$myRUNAS iozone $IOZONE_OPTS -s $((SIZE / IOZ_THREADS)) -t $IOZ_THREADS -F $IOZFILE 2>&1 | tee $IOZLOG
			tail -1 $IOZLOG | grep -q complete || \
				{ error "iozone (3) failed" && false; }
			rm -f $IOZLOG
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
		FSX_SEED=${FSX_SEED:-$RANDOM}
		rm -f $MOUNT/fsxfile
		$LFS setstripe -c -1 $MOUNT/fsxfile
		./fsx -c 50 -p 1000 -S $FSX_SEED -P $TMP -l $SIZE \
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

	[ "$LFSCK" != "no" ] && remote_mds && log "Remote MDS, skipping LFSCK test" && LFSCK=no && MSKIPPED=1
	[ "$LFSCK" != "no" ] && remote_ost && log "Remote OST, skipping LFSCK test" && LFSCK=no && OSKIPPED=1
	if [ "$LFSCK" != "no" ]; then
	        title lfsck
		if [ -x /usr/sbin/lfsck ]; then
			bash lfscktest.sh
		else
			log "$(e2fsck -V)"
			log "SKIP: e2fsck does not support lfsck"
		fi
		LFSCK="done"
	fi

	[ "$NETTYPE" = "tcp" -o "$NETTYPE" = "ptl" ] || LIBLUSTRE=no # bug 15660
	if [ "$LIBLUSTRE" != "no" ]; then
	        title liblustre
		assert_env MGSNID MOUNT2
		export LIBLUSTRE_MOUNT_POINT=$MOUNT2
		export LIBLUSTRE_MOUNT_RETRY=5
		export LIBLUSTRE_MOUNT_TARGET=$MGSNID:/$FSNAME
		export LIBLUSTRE_TIMEOUT=`lctl get_param -n timeout`
		#export LIBLUSTRE_DEBUG_MASK=`lctl get_param -n debug`
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

[ "$REPLAY_SINGLE" != "no" ] && skip_remmds replay-single && REPLAY_SINGLE=no && MSKIPPED=1
if [ "$REPLAY_SINGLE" != "no" ]; then
        title replay-single
	bash replay-single.sh
	REPLAY_SINGLE="done"
fi

[ "$CONF_SANITY" != "no" ] && skip_remmds conf-sanity && CONF_SANITY=no && MSKIPPED=1
[ "$CONF_SANITY" != "no" ] && skip_remost conf-sanity && CONF_SANITY=no && OSKIPPED=1
if [ "$CONF_SANITY" != "no" ]; then
        title conf-sanity
        bash conf-sanity.sh
        CONF_SANITY="done"
fi

[ "$RECOVERY_SMALL" != "no" ] && skip_remmds recover-small && RECOVERY_SMALL=no && MSKIPPED=1
if [ "$RECOVERY_SMALL" != "no" ]; then
        title recovery-small
        bash recovery-small.sh
        RECOVERY_SMALL="done"
fi

[ "$REPLAY_OST_SINGLE" != "no" ] && skip_remost replay-ost-single && REPLAY_OST_SINGLE=no && OSKIPPED=1
if [ "$REPLAY_OST_SINGLE" != "no" ]; then
        title replay-ost-single
        bash replay-ost-single.sh
        REPLAY_OST_SINGLE="done"
fi

[ "$REPLAY_DUAL" != "no" ] && skip_remost replay-dual && REPLAY_DUAL=no && OSKIPPED=1
if [ "$REPLAY_DUAL" != "no" ]; then
        title replay-dual
        bash replay-dual.sh
        REPLAY_DUAL="done"
fi

[ "$REPLAY_VBR" != "no" ] && skip_remmds replay-vbr && REPLAY_VBR=no && MSKIPPED=1
if [ "$REPLAY_VBR" != "no" ]; then
        title replay-vbr
        bash replay-vbr.sh
        REPLAY_VBR="done"
fi

[ "$INSANITY" != "no" ] && skip_remmds insanity && INSANITY=no && MSKIPPED=1
[ "$INSANITY" != "no" ] && skip_remost insanity && INSANITY=no && OSKIPPED=1
if [ "$INSANITY" != "no" ]; then
        title insanity
        bash insanity.sh -r
        INSANITY="done"
fi

[ "$SANITY_QUOTA" != "no" ] && skip_remmds sanity-quota && SANITY_QUOTA=no && MSKIPPED=1
[ "$SANITY_QUOTA" != "no" ] && skip_remost sanity-quota && SANITY_QUOTA=no && OSKIPPED=1
if [ "$SANITY_QUOTA" != "no" ]; then
        title sanity-quota
        bash sanity-quota.sh
        SANITY_QUOTA="done"
fi


[ "$SLOW" = no ] && PERFORMANCE_SANITY="no"
[ -x "$MDSRATE" ] || PERFORMANCE_SANITY="no"
which mpirun > /dev/null 2>&1 || PERFORMANCE_SANITY="no"
if [ "$PERFORMANCE_SANITY" != "no" ]; then
        title performance-sanity
        bash performance-sanity.sh
        PERFORMANCE_SANITY="done"
fi

[ "$LARGE_SCALE" != "no" ] && skip_remmds large-scale && LARGE_SCALE=no && MSKIPPED=1
if [ "$LARGE_SCALE" != "no" ]; then
        title large-scale
        bash large-scale.sh
        LARGE_SCALE="done"
fi


RC=$?
title FINISHED
echo "Finished at `date` in $((`date +%s` - $STARTTIME))s"
echo "Tests ran: $RANTEST"
print_summary
[ "$MSKIPPED" = 1 ] && log "FAIL: remote MDS tests skipped" && RC=1
[ "$OSKIPPED" = 1 ] && log "FAIL: remote OST tests skipped" && RC=1
echo "$0: completed with rc $RC" && exit $RC
