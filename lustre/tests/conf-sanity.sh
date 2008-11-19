#!/bin/bash
# requirement:
#	add uml1 uml2 uml3 in your /etc/hosts

# FIXME - there is no reason to use all of these different
#   return codes, espcially when most of them are mapped to something
#   else anyway.  The combination of test number and return code
#   figure out what failed.

set -e

ONLY=${ONLY:-"$*"}

# bug number for skipped test:      13369
ALWAYS_EXCEPT=" $CONF_SANITY_EXCEPT 34a"
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

SRCDIR=`dirname $0`
PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$PATH

SAVE_PWD=$PWD
LUSTRE=${LUSTRE:-`dirname $0`/..}
RLUSTRE=${RLUSTRE:-$LUSTRE}
HOSTNAME=`hostname`

. $LUSTRE/tests/test-framework.sh
init_test_env $@
# STORED_MDSSIZE is used in test_18
if [ -n "$MDSSIZE" ]; then
    STORED_MDSSIZE=$MDSSIZE
fi
# use small MDS + OST size to speed formatting time
MDSSIZE=40000
OSTSIZE=40000
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

remote_mds_nodsh && skip "remote MDS with nodsh" && exit 0
remote_ost_nodsh && skip "remote OST with nodsh" && exit 0

#
[ "$SLOW" = "no" ] && EXCEPT_SLOW="0 1 2 3 6 7 15 18 24b 25 30 31 32 33 34a 45"

assert_DIR

reformat() {
        formatall
}

writeconf() {
    local facet=mds
    shift
    stop ${facet} -f
    rm -f ${facet}active
    # who knows if/where $TUNEFS is installed?  Better reformat if it fails...
    do_facet ${facet} "$TUNEFS --writeconf $MDSDEV" || echo "tunefs failed, reformatting instead" && reformat
}

gen_config() {
        reformat
        # The MGS must be started before the OSTs for a new fs, so start
        # and stop to generate the startup logs. 
	start_mds
	start_ost
	sleep 5
	stop_ost
	stop_mds
}

start_mds() {
	echo "start mds service on `facet_active_host mds`"
	start mds $MDSDEV $MDS_MOUNT_OPTS || return 94
}

stop_mds() {
	echo "stop mds service on `facet_active_host mds`"
	# These tests all use non-failover stop
	stop mds -f  || return 97
}

start_ost() {
	echo "start ost1 service on `facet_active_host ost1`"
	start ost1 `ostdevname 1` $OST_MOUNT_OPTS || return 95
}

stop_ost() {
	echo "stop ost1 service on `facet_active_host ost1`"
	# These tests all use non-failover stop
	stop ost1 -f  || return 98
}

start_ost2() {
	echo "start ost2 service on `facet_active_host ost2`"
	start ost2 `ostdevname 2` $OST_MOUNT_OPTS || return 92
}

stop_ost2() {
	echo "stop ost2 service on `facet_active_host ost2`"
	# These tests all use non-failover stop
	stop ost2 -f  || return 93
}

start_client() {
	echo "start client on `facet_active_host client`"
	start client || return 99 
}

stop_client() {
	echo "stop client on `facet_active_host client`"
	stop client || return 100 
}

mount_client() {
	local MOUNTPATH=$1
	echo "mount $FSNAME on ${MOUNTPATH}....."
	zconf_mount `hostname` $MOUNTPATH  || return 96
}

remount_client() {
	local SAVEMOUNTOPT=$MOUNTOPT
	MOUNTOPT="remount,$1"
	local MOUNTPATH=$2
	echo "remount '$1' lustre on ${MOUNTPATH}....."
	zconf_mount `hostname`  $MOUNTPATH  || return 96
	MOUNTOPT=$SAVEMOUNTOPT
}

umount_client() {
	local MOUNTPATH=$1
	echo "umount lustre on ${MOUNTPATH}....."
	zconf_umount `hostname` $MOUNTPATH || return 97
}

manual_umount_client(){
	local rc
	local FORCE=$1
	echo "manual umount lustre on ${MOUNT}...."
	do_facet client "umount -d ${FORCE} $MOUNT"
	rc=$?
	return $rc
}

setup() {
	start_ost
	start_mds
	mount_client $MOUNT
}

cleanup_nocli() {
	stop_mds || return 201
	stop_ost || return 202
	unload_modules || return 203
}

cleanup() {
 	umount_client $MOUNT || return 200
	cleanup_nocli || return $?
}

check_mount() {
	do_facet client "cp /etc/passwd $DIR/a" || return 71
	do_facet client "rm $DIR/a" || return 72
	# make sure lustre is actually mounted (touch will block, 
        # but grep won't, so do it after) 
        do_facet client "grep $MOUNT' ' /proc/mounts > /dev/null" || return 73
	echo "setup single mount lustre success"
}

check_mount2() {
	do_facet client "touch $DIR/a" || return 71	
	do_facet client "rm $DIR/a" || return 72	
	do_facet client "touch $DIR2/a" || return 73	
	do_facet client "rm $DIR2/a" || return 74	
	echo "setup double mount lustre success"
}

build_test_filter

if [ "$ONLY" == "setup" ]; then
	setup
	exit
fi

if [ "$ONLY" == "cleanup" ]; then
	cleanup
	exit
fi

#create single point mountpoint

gen_config


test_0() {
        setup
	check_mount || return 41
	cleanup || return $?
}
run_test 0 "single mount setup"

test_1() {
	start_ost
	echo "start ost second time..."
	setup
	check_mount || return 42
	cleanup || return $?
}
run_test 1 "start up ost twice (should return errors)"

test_2() {
	start_ost
	start_mds	
	echo "start mds second time.."
	start_mds
	mount_client $MOUNT
	check_mount || return 43
	cleanup || return $?
}
run_test 2 "start up mds twice (should return err)"

test_3() {
	setup
	#mount.lustre returns an error if already in mtab
	mount_client $MOUNT && return $?
	check_mount || return 44
	cleanup || return $?
}
run_test 3 "mount client twice (should return err)"

test_4() {
	setup
	touch $DIR/$tfile || return 85
	stop_ost -f
	cleanup
	eno=$?
	# ok for ost to fail shutdown
	if [ 202 -ne $eno ]; then
		return $eno;
	fi
	return 0
}
run_test 4 "force cleanup ost, then cleanup"

test_5a() {	# was test_5
	setup
	touch $DIR/$tfile || return 1
	fuser -m -v $MOUNT && echo "$MOUNT is in use by user space process."

	stop_mds -f || return 2

	# cleanup may return an error from the failed
	# disconnects; for now I'll consider this successful
	# if all the modules have unloaded.
 	umount -d $MOUNT &
	UMOUNT_PID=$!
	sleep 6
	echo "killing umount"
	kill -TERM $UMOUNT_PID
	echo "waiting for umount to finish"
	wait $UMOUNT_PID
	if grep " $MOUNT " /proc/mounts; then
		echo "test 5: /proc/mounts after failed umount"
		umount $MOUNT &
		UMOUNT_PID=$!
		sleep 2
		echo "killing umount"
		kill -TERM $UMOUNT_PID
		echo "waiting for umount to finish"
		wait $UMOUNT_PID
		grep " $MOUNT " /proc/mounts && echo "test 5: /proc/mounts after second umount" && return 11
	fi

	manual_umount_client
	# stop_mds is a no-op here, and should not fail
	cleanup_nocli || return $?
	# df may have lingering entry
	manual_umount_client
	# mtab may have lingering entry
	local WAIT=0
	local MAX_WAIT=20
	local sleep=1
	while [ "$WAIT" -ne "$MAX_WAIT" ]; do
		sleep $sleep
		grep -q $MOUNT" " /etc/mtab || break
        	echo "Waiting /etc/mtab updated ... "
		WAIT=$(( WAIT + sleep))
	done
	[ "$WAIT" -eq "$MAX_WAIT" ] && error "/etc/mtab is not updated in $WAIT secs"
	echo "/etc/mtab updated in $WAIT secs"
}
run_test 5a "force cleanup mds, then cleanup"

test_5b() {
	start_ost
	[ -d $MOUNT ] || mkdir -p $MOUNT
	grep " $MOUNT " /etc/mtab && echo "test 5b: mtab before mount" && return 10
	mount_client $MOUNT && return 1
	grep " $MOUNT " /etc/mtab && echo "test 5b: mtab after failed mount" && return 11
	umount_client $MOUNT	
	# stop_mds is a no-op here, and should not fail
	cleanup_nocli || return $?
	return 0
}
run_test 5b "mds down, cleanup after failed mount (bug 2712) (should return errs)"

test_5c() {
	start_ost
	start_mds
	[ -d $MOUNT ] || mkdir -p $MOUNT
	grep " $MOUNT " /etc/mtab && echo "test 5c: mtab before mount" && return 10
	local oldfs="${FSNAME}"
	FSNAME="wrong.${FSNAME}"
	mount_client $MOUNT || :
	FSNAME=${oldfs}
	grep " $MOUNT " /etc/mtab && echo "test 5c: mtab after failed mount" && return 11
	umount_client $MOUNT
	cleanup_nocli  || return $?
}
run_test 5c "cleanup after failed mount (bug 2712) (should return errs)"

test_5d() {
	start_ost
	start_mds
	stop_ost -f
	grep " $MOUNT " /etc/mtab && echo "test 5d: mtab before mount" && return 10
	mount_client $MOUNT || return 1
	cleanup  || return $?
	grep " $MOUNT " /etc/mtab && echo "test 5d: mtab after unmount" && return 11
	return 0
}
run_test 5d "mount with ost down"

test_5e() {
	start_ost
	start_mds

#define OBD_FAIL_PTLRPC_DELAY_SEND       0x506
	do_facet client "lctl set_param fail_loc=0x80000506"
	grep " $MOUNT " /etc/mtab && echo "test 5e: mtab before mount" && return 10
	mount_client $MOUNT || echo "mount failed (not fatal)"
	cleanup  || return $?
	grep " $MOUNT " /etc/mtab && echo "test 5e: mtab after unmount" && return 11
	return 0
}
run_test 5e "delayed connect, don't crash (bug 10268)"

test_6() {
	setup
	manual_umount_client
	mount_client ${MOUNT} || return 87
	touch $DIR/a || return 86
	cleanup  || return $?
}
run_test 6 "manual umount, then mount again"

test_7() {
	setup
	manual_umount_client
	cleanup_nocli || return $?
}
run_test 7 "manual umount, then cleanup"

test_8() {
	setup
	mount_client $MOUNT2
	check_mount2 || return 45
	umount_client $MOUNT2
	cleanup  || return $?
}
run_test 8 "double mount setup"

test_9() {
        start_ost

	do_facet ost1 lctl set_param debug=\'inode trace\' || return 1
	do_facet ost1 lctl set_param subsystem_debug=\'mds ost\' || return 1

        CHECK_PTLDEBUG="`do_facet ost1 lctl get_param -n debug`"
        if [ "$CHECK_PTLDEBUG" ] && [ "$CHECK_PTLDEBUG" = "trace inode" ];then
           echo "lnet.debug success"
        else
           echo "lnet.debug: want 'trace inode', have '$CHECK_PTLDEBUG'"
           return 1
        fi
        CHECK_SUBSYS="`do_facet ost1 lctl get_param -n subsystem_debug`"
        if [ "$CHECK_SUBSYS" ] && [ "$CHECK_SUBSYS" = "mds ost" ]; then
           echo "lnet.subsystem_debug success"
        else
           echo "lnet.subsystem_debug: want 'mds ost', have '$CHECK_SUBSYS'"
           return 1
        fi
        stop_ost || return $?
}

run_test 9 "test ptldebug and subsystem for mkfs"

test_16() {
        local TMPMTPT="${TMP}/conf16"

        if [ ! -e "$MDSDEV" ]; then
            log "no $MDSDEV existing, so mount Lustre to create one"
            setup
            check_mount || return 41
            cleanup || return $?
        fi

        [ -f "$MDSDEV" ] && LOOPOPT="-o loop"

        log "change the mode of $MDSDEV/OBJECTS,LOGS,PENDING to 555"
        do_facet mds "mkdir -p $TMPMTPT &&
                      mount $LOOPOPT -t $FSTYPE $MDSDEV $TMPMTPT &&
                      chmod 555 $TMPMTPT/{OBJECTS,LOGS,PENDING} &&
                      umount $TMPMTPT" || return $?

        log "mount Lustre to change the mode of OBJECTS/LOGS/PENDING, then umount Lustre"
	setup
        check_mount || return 41
        cleanup || return $?

        log "read the mode of OBJECTS/LOGS/PENDING and check if they has been changed properly"
        EXPECTEDOBJECTSMODE=`do_facet mds "debugfs -R 'stat OBJECTS' $MDSDEV 2> /dev/null" | grep 'Mode: ' | sed -e "s/.*Mode: *//" -e "s/ *Flags:.*//"`
        EXPECTEDLOGSMODE=`do_facet mds "debugfs -R 'stat LOGS' $MDSDEV 2> /dev/null" | grep 'Mode: ' | sed -e "s/.*Mode: *//" -e "s/ *Flags:.*//"`
        EXPECTEDPENDINGMODE=`do_facet mds "debugfs -R 'stat PENDING' $MDSDEV 2> /dev/null" | grep 'Mode: ' | sed -e "s/.*Mode: *//" -e "s/ *Flags:.*//"`

        if [ "$EXPECTEDOBJECTSMODE" = "0777" ]; then
                log "Success:Lustre change the mode of OBJECTS correctly"
        else
                error "Lustre does not change mode of OBJECTS properly"
        fi

        if [ "$EXPECTEDLOGSMODE" = "0777" ]; then
                log "Success:Lustre change the mode of LOGS correctly"
        else
                error "Lustre does not change mode of LOGS properly"
        fi

        if [ "$EXPECTEDPENDINGMODE" = "0777" ]; then
                log "Success:Lustre change the mode of PENDING correctly"
        else
                error "Lustre does not change mode of PENDING properly"
        fi
}
run_test 16 "verify that lustre will correct the mode of OBJECTS/LOGS/PENDING"

test_17() {
        if [ ! -e "$MDSDEV" ]; then
            echo "no $MDSDEV existing, so mount Lustre to create one"
	    setup
            check_mount || return 41
            cleanup || return $?
        fi

        echo "Remove mds config log"
        do_facet mds "debugfs -w -R 'unlink CONFIGS/$FSNAME-MDT0000' $MDSDEV || return \$?" || return $?

        start_ost
	start_mds && return 42
	gen_config
}
run_test 17 "Verify failed mds_postsetup won't fail assertion (2936) (should return errs)"

test_18() {
        [ "$FSTYPE" != "ldiskfs" ] && skip "not needed for FSTYPE=$FSTYPE" && return

        local MIN=2000000

        local OK=
        # check if current MDSSIZE is large enough
        [ $MDSSIZE -ge $MIN ] && OK=1 && myMDSSIZE=$MDSSIZE && \
                log "use MDSSIZE=$MDSSIZE"

        # check if the global config has a large enough MDSSIZE
        [ -z "$OK" -a ! -z "$STORED_MDSSIZE" ] && [ $STORED_MDSSIZE -ge $MIN ] && \
                OK=1 && myMDSSIZE=$STORED_MDSSIZE && \
                log "use STORED_MDSSIZE=$STORED_MDSSIZE"

        # check if the block device is large enough
        [ -z "$OK" -a -b $MDSDEV ] && \
                [ "$(dd if=$MDSDEV of=/dev/null bs=1k count=1 skip=$MIN 2>&1 |
                     awk '($3 == "in") { print $1 }')" = "1+0" ] && OK=1 && \
                myMDSSIZE=$MIN && log "use device $MDSDEV with MIN=$MIN"

        # check if a loopback device has enough space for fs metadata (5%)
        [ -z "$OK" ] && [ -f $MDSDEV -o ! -e $MDSDEV ] &&
                SPACE=$(df -P $(dirname $MDSDEV) |
                        awk '($1 != "Filesystem") {print $4}') &&
                [ $SPACE -gt $((MIN / 20)) ] && OK=1 && myMDSSIZE=$MIN && \
                        log "use file $MDSDEV with MIN=$MIN"

        [ -z "$OK" ] && skip "$MDSDEV too small for ${MIN}kB MDS" && return


        echo "mount mds with large journal..."
        local OLD_MDS_MKFS_OPTS=$MDS_MKFS_OPTS

        MDS_MKFS_OPTS="--mgs --mdt --fsname=$FSNAME --device-size=$myMDSSIZE --param sys.timeout=$TIMEOUT $MDSOPT"

        gen_config
        echo "mount lustre system..."
	setup
        check_mount || return 41

        echo "check journal size..."
        local FOUNDSIZE=`do_facet mds "debugfs -c -R 'stat <8>' $MDSDEV" | awk '/Size: / { print $NF; exit;}'`
        if [ $FOUNDSIZE -gt $((32 * 1024 * 1024)) ]; then
                log "Success: mkfs creates large journals. Size: $((FOUNDSIZE >> 20))M"
        else
                error "expected journal size > 32M, found $((FOUNDSIZE >> 20))M"
        fi

        cleanup || return $?

        MDS_MKFS_OPTS=$OLD_MDS_MKFS_OPTS
        gen_config
}
run_test 18 "check mkfs creates large journals"

test_19a() {
	start_mds || return 1
	stop_mds -f || return 2
}
run_test 19a "start/stop MDS without OSTs"

test_19b() {
	start_ost || return 1
	stop_ost -f || return 2
}
run_test 19b "start/stop OSTs without MDS"

test_20() {
	# first format the ost/mdt
	start_ost
	start_mds
	mount_client $MOUNT
	check_mount || return 43
	rm -f $DIR/$tfile
	remount_client ro $MOUNT || return 44
	touch $DIR/$tfile && echo "$DIR/$tfile created incorrectly" && return 45
	[ -e $DIR/$tfile ] && echo "$DIR/$tfile exists incorrectly" && return 46
	remount_client rw $MOUNT || return 47
	touch $DIR/$tfile
	[ ! -f $DIR/$tfile ] && echo "$DIR/$tfile missing" && return 48
	MCNT=`grep -c $MOUNT /etc/mtab`
	[ "$MCNT" -ne 1 ] && echo "$MOUNT in /etc/mtab $MCNT times" && return 49
	umount_client $MOUNT
	stop_mds
	stop_ost
}
run_test 20 "remount ro,rw mounts work and doesn't break /etc/mtab"

test_21a() {
        start_mds
	start_ost
	stop_ost
	stop_mds
}
run_test 21a "start mds before ost, stop ost first"

test_21b() {
        start_ost
	start_mds
	stop_mds
	stop_ost
}
run_test 21b "start ost before mds, stop mds first"

test_21c() {
        start_ost
	start_mds
	start_ost2
	stop_ost
	stop_ost2
	stop_mds
	#writeconf to remove all ost2 traces for subsequent tests
	writeconf
}
run_test 21c "start mds between two osts, stop mds last"

test_22() {
	start_mds

	echo Client mount with ost in logs, but none running
	start_ost
	stop_ost
	mount_client $MOUNT
	# check_mount will block trying to contact ost
	umount_client $MOUNT
	pass

	echo Client mount with a running ost
	start_ost
	mount_client $MOUNT
	check_mount || return 41
	pass

	cleanup
}
run_test 22 "start a client before osts (should return errs)"

test_23a() {	# was test_23
        setup
        # fail mds
	stop mds   
	# force down client so that recovering mds waits for reconnect
	local running=$(grep -c $MOUNT /proc/mounts) || true
    	if [ $running -ne 0 ]; then
        	echo "Stopping client $MOUNT (opts: -f)"
        	umount -f $MOUNT
    	fi

	# enter recovery on mds
	start_mds
	# try to start a new client
	mount_client $MOUNT &
	sleep 5
	MOUNT_PID=$(ps -ef | grep "t lustre" | grep -v grep | awk '{print $2}')
	MOUNT_LUSTRE_PID=`ps -ef | grep mount.lustre | grep -v grep | awk '{print $2}'`
	echo mount pid is ${MOUNT_PID}, mount.lustre pid is ${MOUNT_LUSTRE_PID}
	ps --ppid $MOUNT_PID
	ps --ppid $MOUNT_LUSTRE_PID
	# FIXME why o why can't I kill these? Manual "ctrl-c" works...
	kill -TERM $MOUNT_LUSTRE_PID
	echo "waiting for mount to finish"
	ps -ef | grep mount
	# we can not wait $MOUNT_PID because it is not a child of this shell
	local PID1
	local PID2
	local WAIT=0
	local MAX_WAIT=20
	local sleep=1
	while [ "$WAIT" -lt "$MAX_WAIT" ]; do
		sleep $sleep
		PID1=$(ps -ef | awk '{print $2}' | grep -w $MOUNT_PID)
		PID2=$(ps -ef | awk '{print $2}' | grep -w $MOUNT_LUSTRE_PID)
		echo PID1=$PID1
		echo PID2=$PID2
		[ -z "$PID1" -a -z "$PID2" ] && break
		echo "waiting for mount to finish ... "
		WAIT=$(( WAIT + sleep))
	done
	[ "$WAIT" -eq "$MAX_WAIT" ] && error "MOUNT_PID $MOUNT_PID and \
		MOUNT__LUSTRE_PID $MOUNT__LUSTRE_PID still not killed in $WAIT secs"
	ps -ef | grep mount
	stop_mds || error
	stop_ost || error
}
run_test 23a "interrupt client during recovery mount delay"

umount_client $MOUNT
cleanup_nocli

test_23b() {    # was test_23
	start_ost
	start_mds
	# Simulate -EINTR during mount OBD_FAIL_LDLM_CLOSE_THREAD
	lctl set_param fail_loc=0x80000313
	mount_client $MOUNT
	cleanup
}
run_test 23b "Simulate -EINTR during mount"

fs2mds_HOST=$mds_HOST
fs2ost_HOST=$ost_HOST

cleanup_24a() {
	trap 0
	echo "umount $MOUNT2 ..."
	umount $MOUNT2 || true
	echo "stopping fs2mds ..."
	stop fs2mds -f || true
	echo "stopping fs2ost ..."
	stop fs2ost -f || true
}

test_24a() {
	[ -n "$ost1_HOST" ] && fs2ost_HOST=$ost1_HOST
	if [ -z "$fs2ost_DEV" -o -z "$fs2mds_DEV" ]; then
		do_facet mds [ -b "$MDSDEV" ] && \
		skip "mixed loopback and real device not working" && return
	fi

	local fs2mdsdev=${fs2mds_DEV:-${MDSDEV}_2}
	local fs2ostdev=${fs2ost_DEV:-$(ostdevname 1)_2}

	# test 8-char fsname as well
	local FSNAME2=test1234
	add fs2mds $MDS_MKFS_OPTS --fsname=${FSNAME2} --nomgs --mgsnode=$MGSNID --reformat $fs2mdsdev || exit 10

	add fs2ost $OST_MKFS_OPTS --fsname=${FSNAME2} --reformat $fs2ostdev || exit 10

	setup
	start fs2mds $fs2mdsdev $MDS_MOUNT_OPTS && trap cleanup_24a EXIT INT
	start fs2ost $fs2ostdev $OST_MOUNT_OPTS
	mkdir -p $MOUNT2
	mount -t lustre $MGSNID:/${FSNAME2} $MOUNT2 || return 1
	# 1 still works
	check_mount || return 2
	# files written on 1 should not show up on 2
	cp /etc/passwd $DIR/$tfile
	sleep 10
	[ -e $MOUNT2/$tfile ] && error "File bleed" && return 7
	# 2 should work
	cp /etc/passwd $MOUNT2/b || return 3
	rm $MOUNT2/b || return 4
	# 2 is actually mounted
        grep $MOUNT2' ' /proc/mounts > /dev/null || return 5
	# failover 
	facet_failover fs2mds
	facet_failover fs2ost
	df
 	umount_client $MOUNT 
	# the MDS must remain up until last MDT
	stop_mds
	MDS=$(do_facet mds "lctl get_param -n devices" | awk '($3 ~ "mdt" && $4 ~ "MDS") { print $4 }')
	[ -z "$MDS" ] && error "No MDS" && return 8
	cleanup_24a
	cleanup_nocli || return 6
}
run_test 24a "Multiple MDTs on a single node"

test_24b() {
	if [ -z "$fs2mds_DEV" ]; then
		do_facet mds [ -b "$MDSDEV" ] && \
		skip "mixed loopback and real device not working" && return
	fi

	local fs2mdsdev=${fs2mds_DEV:-${MDSDEV}_2}

	add fs2mds $MDS_MKFS_OPTS --fsname=${FSNAME}2 --mgs --reformat $fs2mdsdev || exit 10 
	setup
	start fs2mds $fs2mdsdev $MDS_MOUNT_OPTS && return 2
	cleanup || return 6
}
run_test 24b "Multiple MGSs on a single node (should return err)"

test_25() {
	setup
	check_mount || return 2
	local MODULES=$($LCTL modules | awk '{ print $2 }')
	rmmod $MODULES 2>/dev/null || true
	cleanup || return 6
}
run_test 25 "Verify modules are referenced"

test_26() {
    load_modules
    # we need modules before mount for sysctl, so make sure...
    do_facet mds "lsmod | grep -q lustre || modprobe lustre"
#define OBD_FAIL_MDS_FS_SETUP            0x135
    do_facet mds "lctl set_param fail_loc=0x80000135"
    start_mds && echo MDS started && return 1
    lctl get_param -n devices
    DEVS=$(lctl get_param -n devices | wc -l)
    [ $DEVS -gt 0 ] && return 2
    unload_modules || return 203
}
run_test 26 "MDT startup failure cleans LOV (should return errs)"

wait_update () {
	local node=$1
	local TEST=$2
	local FINAL=$3

	local RESULT
	local MAX=90
	local WAIT=0
	local sleep=5
	while [ $WAIT -lt $MAX ]; do
	    RESULT=$(do_node $node "$TEST") 
	    if [ $RESULT -eq $FINAL ]; then
		echo "Updated config after $WAIT sec: wanted $FINAL got $RESULT"
		return 0
	    fi
	    WAIT=$((WAIT + sleep))
	    echo "Waiting $((MAX - WAIT)) secs for config update" 
	    sleep $sleep
	done
	echo "Config update not seen after $MAX sec: wanted $FINAL got $RESULT"
	return 3
}

set_and_check() {
	local myfacet=$1
	local TEST=$2
	local PARAM=$3
	local ORIG=$(do_facet $myfacet "$TEST") 
	if [ $# -gt 3 ]; then
	    local FINAL=$4
	else
	    local -i FINAL
	    FINAL=$(($ORIG + 5))
	fi
	echo "Setting $PARAM from $ORIG to $FINAL"
	do_facet mds "$LCTL conf_param $PARAM=$FINAL" || error conf_param failed

	wait_update $(facet_host $myfacet) "$TEST" $FINAL || error check failed!
}

test_27a() {
	start_ost || return 1
	start_mds || return 2
	echo "Requeue thread should have started: " 
	ps -e | grep ll_cfg_requeue 
	set_and_check ost1 "lctl get_param -n obdfilter.$FSNAME-OST0000.client_cache_seconds" "$FSNAME-OST0000.ost.client_cache_seconds" || return 3
	cleanup_nocli
}
run_test 27a "Reacquire MGS lock if OST started first"

test_27b() {
        setup
	facet_failover mds
	set_and_check mds "lctl get_param -n mds.$FSNAME-MDT0000.group_acquire_expire" "$FSNAME-MDT0000.mdt.group_acquire_expire" || return 3
	set_and_check client "lctl get_param -n mdc.$FSNAME-MDT0000-mdc-*.max_rpcs_in_flight" "$FSNAME-MDT0000.mdc.max_rpcs_in_flight" || return 4
	check_mount
	cleanup
}
run_test 27b "Reacquire MGS lock after failover"

test_28() {
        setup
	TEST="lctl get_param -n llite.$FSNAME-*.max_read_ahead_whole_mb"
	PARAM="$FSNAME.llite.max_read_ahead_whole_mb"
	ORIG=$($TEST)
	FINAL=$(($ORIG + 1))
	set_and_check client "$TEST" "$PARAM" $FINAL || return 3
	FINAL=$(($FINAL + 1))
	set_and_check client "$TEST" "$PARAM" $FINAL || return 4
 	umount_client $MOUNT || return 200
	mount_client $MOUNT
	RESULT=$($TEST)
	if [ $RESULT -ne $FINAL ]; then
	    echo "New config not seen: wanted $FINAL got $RESULT"
	    return 4
	else
	    echo "New config success: got $RESULT"
	fi
	set_and_check client "$TEST" "$PARAM" $ORIG || return 5
	cleanup
}
run_test 28 "permanent parameter setting"

test_29() {
	[ "$OSTCOUNT" -lt "2" ] && skip "$OSTCOUNT < 2, skipping" && return
        setup > /dev/null 2>&1
	start_ost2
	sleep 10

	local PARAM="$FSNAME-OST0001.osc.active"
	local PROC_ACT="osc.$FSNAME-OST0001-osc-*.active"
	local PROC_UUID="osc.$FSNAME-OST0001-osc-*.ost_server_uuid"

	ACTV=$(lctl get_param -n $PROC_ACT)
	DEAC=$((1 - $ACTV))
	set_and_check client "lctl get_param -n $PROC_ACT" "$PARAM" $DEAC || return 2
        # also check ost_server_uuid status
	RESULT=$(lctl get_param -n $PROC_UUID | grep DEACTIV)
	if [ -z "$RESULT" ]; then
	    echo "Live client not deactivated: $(lctl get_param -n $PROC_UUID)"
	    return 3
	else
	    echo "Live client success: got $RESULT"
	fi

	# check MDT too 
	local MPROC="osc.$FSNAME-OST0001-osc.active"
	local MAX=30
	local WAIT=0
	while [ 1 ]; do
	    sleep 5
	    RESULT=`do_facet mds " lctl get_param -n $MPROC"`
	    [ ${PIPESTATUS[0]} = 0 ] || error "Can't read $MPROC"
	    if [ $RESULT -eq $DEAC ]; then
		echo "MDT deactivated also after $WAIT sec (got $RESULT)"
		break
	    fi
	    WAIT=$((WAIT + 5))
	    if [ $WAIT -eq $MAX ]; then
		echo "MDT not deactivated: wanted $DEAC got $RESULT"
		return 4
	    fi
	    echo "Waiting $(($MAX - $WAIT)) secs for MDT deactivated"
	done

        # test new client starts deactivated
 	umount_client $MOUNT || return 200
	mount_client $MOUNT
	RESULT=$(lctl get_param -n $PROC_UUID | grep DEACTIV | grep NEW)
	if [ -z "$RESULT" ]; then
	    echo "New client not deactivated from start: $(lctl get_param -n $PROC_UUID)"
	    return 5
	else
	    echo "New client success: got $RESULT"
	fi

	# make sure it reactivates
	set_and_check client "lctl get_param -n $PROC_ACT" "$PARAM" $ACTV || return 6

 	umount_client $MOUNT
	stop_ost2
	cleanup_nocli
	#writeconf to remove all ost2 traces for subsequent tests
	writeconf
	start_mds
	start_ost
	cleanup
}
run_test 29 "permanently remove an OST"

test_30() {
	setup

	TEST="lctl get_param -n llite.$FSNAME-*.max_read_ahead_whole_mb"
	ORIG=$($TEST)
	LIST=(1 2 3 4 5 4 3 2 1 2 3 4 5 4 3 2 1 2 3 4 5)
	for i in ${LIST[@]}; do
	    set_and_check client "$TEST" "$FSNAME.llite.max_read_ahead_whole_mb" $i || return 3
	done
	# make sure client restart still works 
 	umount_client $MOUNT
	mount_client $MOUNT || return 4
	[ "$($TEST)" -ne "$i" ] && return 5   
	set_and_check client "$TEST" "$FSNAME.llite.max_read_ahead_whole_mb" $ORIG || return 6
	cleanup
}
run_test 30 "Big config llog"

test_31() { # bug 10734
        # ipaddr must not exist
        mount -t lustre 4.3.2.1@tcp:/lustre $MOUNT || true
	cleanup
}
run_test 31 "Connect to non-existent node (returns errors, should not crash)"

# Use these start32/stop32 fn instead of t-f start/stop fn,
# for local devices, to skip global facet vars init 
stop32 () {
	local facet=$1
	shift
	echo "Stopping local ${MOUNT%/*}/${facet} (opts:$@)"
	umount -d $@ ${MOUNT%/*}/${facet}
	losetup -a
}

start32 () {
	local facet=$1
	shift
	local device=$1
	shift
	mkdir -p ${MOUNT%/*}/${facet}

	echo "Starting local ${facet}: $@ $device ${MOUNT%/*}/${facet}"
	mount -t lustre $@ ${device} ${MOUNT%/*}/${facet}
	RC=$?
	if [ $RC -ne 0 ]; then
		echo "mount -t lustre $@ ${device} ${MOUNT%/*}/${facet}"
		echo "Start of ${device} of local ${facet} failed ${RC}"
	fi 
	losetup -a
	return $RC
}

cleanup_nocli32 () {
	stop32 mds -f
	stop32 ost1 -f
	wait_exit_ST client
}

cleanup_32() {
	trap 0
	echo "Cleanup test_32 umount $MOUNT ..."
	umount -f $MOUNT || true
	echo "Cleanup local mds ost1 ..."
	cleanup_nocli32
	unload_modules
}

test_32a() {
	# this test is totally useless on a client-only system
	[ -n "$CLIENTONLY" -o -n "$CLIENTMODSONLY" ] && skip "client only testing" && return 0
	[ "$NETTYPE" = "tcp" ] || { skip "NETTYPE != tcp" && return 0; }
	[ -z "$TUNEFS" ] && skip "No tunefs" && return 0

	local DISK1_4=$LUSTRE/tests/disk1_4.zip
	[ ! -r $DISK1_4 ] && skip "Cant find $DISK1_4, skipping" && return

	local tmpdir=$TMP/conf32a
	unzip -o -j -d $tmpdir $DISK1_4 || { skip "Cant unzip $DISK1_4, skipping" && return ; }
	load_modules
	lctl set_param debug=$PTLDEBUG

	$TUNEFS $tmpdir/mds || error "tunefs failed"

	# nids are wrong, so client wont work, but server should start
	start32 mds $tmpdir/mds "-o loop,exclude=lustre-OST0000" && \
		trap cleanup_32 EXIT INT || return 3
        
	local UUID=$(lctl get_param -n mds.lustre-MDT0000.uuid)
	echo MDS uuid $UUID
	[ "$UUID" == "mdsA_UUID" ] || error "UUID is wrong: $UUID" 

	$TUNEFS --mgsnode=`hostname` $tmpdir/ost1 || error "tunefs failed"
	start32 ost1 $tmpdir/ost1 "-o loop" || return 5
	UUID=$(lctl get_param -n obdfilter.lustre-OST0000.uuid)
	echo OST uuid $UUID
	[ "$UUID" == "ost1_UUID" ] || error "UUID is wrong: $UUID" 

	local NID=$($LCTL list_nids | head -1)

	echo "OSC changes should return err:" 
	$LCTL conf_param lustre-OST0000.osc.max_dirty_mb=15 && return 7
	$LCTL conf_param lustre-OST0000.failover.node=$NID && return 8
	echo "ok."
	echo "MDC changes should succeed:" 
	$LCTL conf_param lustre-MDT0000.mdc.max_rpcs_in_flight=9 || return 9
	$LCTL conf_param lustre-MDT0000.failover.node=$NID || return 10
	echo "ok."

	# With a new good MDT failover nid, we should be able to mount a client
	# (but it cant talk to OST)
	local mountopt="-o exclude=lustre-OST0000"

	local device=`h2$NETTYPE $HOSTNAME`:/lustre
	echo "Starting local client: $HOSTNAME: $mountopt $device $MOUNT"
	mount -t lustre $mountopt $device $MOUNT || return 1

	local old=$(lctl get_param -n mdc.*.max_rpcs_in_flight)
	local new=$((old + 5))
	lctl conf_param lustre-MDT0000.mdc.max_rpcs_in_flight=$new
	wait_update $HOSTNAME "lctl get_param -n mdc.*.max_rpcs_in_flight" $new || return 11

	cleanup_32

	# mount a second time to make sure we didnt leave upgrade flag on
	load_modules
	$TUNEFS --dryrun $tmpdir/mds || error "tunefs failed"
	start32 mds $tmpdir/mds "-o loop,exclude=lustre-OST0000" && \
		trap cleanup_32 EXIT INT || return 12

	cleanup_32

	rm -rf $tmpdir || true	# true is only for TMP on NFS
}
run_test 32a "Upgrade from 1.4 (not live)"

test_32b() {
	# this test is totally useless on a client-only system
	[ -n "$CLIENTONLY" -o -n "$CLIENTMODSONLY" ] && skip "client only testing" && return 0
	[ "$NETTYPE" = "tcp" ] || { skip "NETTYPE != tcp" && return 0; }
	[ -z "$TUNEFS" ] && skip "No tunefs" && return

	local DISK1_4=$LUSTRE/tests/disk1_4.zip
	[ ! -r $DISK1_4 ] && skip "Cant find $DISK1_4, skipping" && return

	local tmpdir=$TMP/conf32b
	unzip -o -j -d $tmpdir $DISK1_4 || { skip "Cant unzip $DISK1_4, skipping" && return ; }
	load_modules
	lctl set_param debug=$PTLDEBUG
	local NEWNAME=sofia

	# writeconf will cause servers to register with their current nids
	$TUNEFS --writeconf --fsname=$NEWNAME $tmpdir/mds || error "tunefs failed"
	start32 mds $tmpdir/mds "-o loop" && \
		trap cleanup_32 EXIT INT || return 3

	local UUID=$(lctl get_param -n mds.${NEWNAME}-MDT0000.uuid)
	echo MDS uuid $UUID
	[ "$UUID" == "mdsA_UUID" ] || error "UUID is wrong: $UUID" 

	$TUNEFS --mgsnode=`hostname` --fsname=$NEWNAME --writeconf $tmpdir/ost1 || error "tunefs failed"
	start32 ost1 $tmpdir/ost1 "-o loop" || return 5
	UUID=$(lctl get_param -n obdfilter.${NEWNAME}-OST0000.uuid)
	echo OST uuid $UUID
	[ "$UUID" == "ost1_UUID" ] || error "UUID is wrong: $UUID"

	echo "OSC changes should succeed:" 
	$LCTL conf_param ${NEWNAME}-OST0000.osc.max_dirty_mb=15 || return 7
	$LCTL conf_param ${NEWNAME}-OST0000.failover.node=$NID || return 8
	echo "ok."
	echo "MDC changes should succeed:" 
	$LCTL conf_param ${NEWNAME}-MDT0000.mdc.max_rpcs_in_flight=9 || return 9
	echo "ok."

	# MDT and OST should have registered with new nids, so we should have
	# a fully-functioning client
	echo "Check client and old fs contents"

	local device=`h2$NETTYPE $HOSTNAME`:/$NEWNAME
	echo "Starting local client: $HOSTNAME: $device $MOUNT"
	mount -t lustre $device $MOUNT || return 1

	local old=$(lctl get_param -n mdc.*.max_rpcs_in_flight)
	local new=$((old + 5))
	lctl conf_param ${NEWNAME}-MDT0000.mdc.max_rpcs_in_flight=$new
	wait_update $HOSTNAME "lctl get_param -n mdc.*.max_rpcs_in_flight" $new || return 11

	[ "$(cksum $MOUNT/passwd | cut -d' ' -f 1,2)" == "2479747619 779" ] || return 12  
	echo "ok."

	cleanup_32

	rm -rf $tmpdir || true  # true is only for TMP on NFS
}
run_test 32b "Upgrade from 1.4 with writeconf"

test_33a() { # bug 12333, was test_33
        local rc=0
        local FSNAME2=test-123
        [ -n "$ost1_HOST" ] && fs2ost_HOST=$ost1_HOST

        if [ -z "$fs2ost_DEV" -o -z "$fs2mds_DEV" ]; then
                do_facet mds [ -b "$MDSDEV" ] && \
                skip "mixed loopback and real device not working" && return
        fi

        local fs2mdsdev=${fs2mds_DEV:-${MDSDEV}_2}
        local fs2ostdev=${fs2ost_DEV:-$(ostdevname 1)_2}
        add fs2mds $MDS_MKFS_OPTS --fsname=${FSNAME2} --reformat $fs2mdsdev || exit 10
        add fs2ost $OST_MKFS_OPTS --fsname=${FSNAME2} --index=8191 --mgsnode=$MGSNID --reformat $fs2ostdev || exit 10

        start fs2mds $fs2mdsdev $MDS_MOUNT_OPTS && trap cleanup_24a EXIT INT
        start fs2ost $fs2ostdev $OST_MOUNT_OPTS
        do_facet mds "$LCTL conf_param $FSNAME2.sys.timeout=200" || rc=1
        mkdir -p $MOUNT2
        mount -t lustre $MGSNID:/${FSNAME2} $MOUNT2 || rc=2
        cp /etc/hosts $MOUNT2/. || rc=3
        echo "ok."

        cp /etc/hosts $MOUNT2/ || rc=3 
        $LFS getstripe $MOUNT2/hosts

        umount -d $MOUNT2
        stop fs2ost -f
        stop fs2mds -f
        rm -rf $MOUNT2 $fs2mdsdev $fs2ostdev
        cleanup_nocli || rc=6
        return $rc
}
run_test 33a "Mount ost with a large index number"

test_33b() {	# was test_33a
        setup

        do_facet client dd if=/dev/zero of=$MOUNT/24 bs=1024k count=1
        # Drop lock cancelation reply during umount
	#define OBD_FAIL_LDLM_CANCEL             0x304
        do_facet client lctl set_param fail_loc=0x80000304
        #lctl set_param debug=-1
        umount_client $MOUNT
        cleanup
}
run_test 33b "Drop cancel during umount"

test_34a() {
        setup
	do_facet client "sh runmultiop_bg_pause $DIR/file O_c"
	manual_umount_client
	rc=$?
	do_facet client killall -USR1 multiop
	if [ $rc -eq 0 ]; then
		error "umount not fail!"
	fi
	sleep 1
        cleanup
}
run_test 34a "umount with opened file should be fail"


test_34b() {
	setup
	touch $DIR/$tfile || return 1
	stop_mds --force || return 2

 	manual_umount_client --force
	rc=$?
	if [ $rc -ne 0 ]; then
		error "mtab after failed umount - rc $rc"
	fi

	cleanup
	return 0	
}
run_test 34b "force umount with failed mds should be normal"

test_34c() {
	setup
	touch $DIR/$tfile || return 1
	stop_ost --force || return 2

 	manual_umount_client --force
	rc=$?
	if [ $rc -ne 0 ]; then
		error "mtab after failed umount - rc $rc"
	fi

	cleanup
	return 0	
}
run_test 34c "force umount with failed ost should be normal"

test_35() { # bug 12459
	setup

	debugsave
	lctl set_param debug="ha"

	log "Set up a fake failnode for the MDS"
	FAKENID="127.0.0.2"
	do_facet mds $LCTL conf_param ${FSNAME}-MDT0000.failover.node=$FAKENID || return 4

	log "Wait for RECONNECT_INTERVAL seconds (10s)"
	sleep 10

	MSG="conf-sanity.sh test_35 `date +%F%kh%Mm%Ss`"
	$LCTL clear
	log "$MSG"
	log "Stopping the MDT:"
	stop_mds || return 5

	df $MOUNT > /dev/null 2>&1 &
	DFPID=$!
	log "Restarting the MDT:"
	start_mds || return 6
	log "Wait for df ($DFPID) ... "
	wait $DFPID
	log "done"
	debugrestore

	# retrieve from the log the first server that the client tried to
	# contact after the connection loss
	$LCTL dk $TMP/lustre-log-$TESTNAME.log
	NEXTCONN=`awk "/${MSG}/ {start = 1;}
		       /import_select_connection.*${FSNAME}-MDT0000-mdc.* using connection/ {
				if (start) {
					if (\\\$NF ~ /$FAKENID/)
						print \\\$NF;
					else
						print 0;
					exit;
				}
		       }" $TMP/lustre-log-$TESTNAME.log`
	[ "$NEXTCONN" != "0" ] && log "The client didn't try to reconnect to the last active server (tried ${NEXTCONN} instead)" && return 7
	cleanup
}
run_test 35 "Reconnect to the last active server first"

test_36() { # 12743
        local rc
        local FSNAME2=test1234
        local fs3ost_HOST=$ost_HOST

        [ -n "$ost1_HOST" ] && fs2ost_HOST=$ost1_HOST && fs3ost_HOST=$ost1_HOST
        rc=0

        if [ -z "$fs2ost_DEV" -o -z "$fs2mds_DEV" -o -z "$fs3ost_DEV" ]; then
		do_facet mds [ -b "$MDSDEV" ] && \
		skip "mixed loopback and real device not working" && return
        fi
        [ $OSTCOUNT -lt 2 ] && skip "skipping test for single OST" && return

	[ "$ost_HOST" = "`hostname`" -o "$ost1_HOST" = "`hostname`" ] || \
		{ skip "remote OST" && return 0; }

        local fs2mdsdev=${fs2mds_DEV:-${MDSDEV}_2}
        local fs2ostdev=${fs2ost_DEV:-$(ostdevname 1)_2}
        local fs3ostdev=${fs3ost_DEV:-$(ostdevname 2)_2}
        add fs2mds $MDS_MKFS_OPTS --fsname=${FSNAME2} --reformat $fs2mdsdev || exit 10
        # XXX after we support non 4K disk blocksize, change following --mkfsoptions with
        # other argument
        add fs2ost $OST_MKFS_OPTS --mkfsoptions='-b4096' --fsname=${FSNAME2} --mgsnode=$MGSNID --reformat $fs2ostdev || exit 10
        add fs3ost $OST_MKFS_OPTS --mkfsoptions='-b4096' --fsname=${FSNAME2} --mgsnode=$MGSNID --reformat $fs3ostdev || exit 10

        start fs2mds $fs2mdsdev $MDS_MOUNT_OPTS
        start fs2ost $fs2ostdev $OST_MOUNT_OPTS
        start fs3ost $fs3ostdev $OST_MOUNT_OPTS
        mkdir -p $MOUNT2
        mount -t lustre $MGSNID:/${FSNAME2} $MOUNT2 || return 1

        sleep 5 # until 11778 fixed

        dd if=/dev/zero of=$MOUNT2/$tfile bs=1M count=7 || return 2

        BKTOTAL=`lctl get_param -n obdfilter.*.kbytestotal | awk 'BEGIN{total=0}; {total+=$1}; END{print total}'`
        BKFREE=`lctl get_param -n obdfilter.*.kbytesfree | awk 'BEGIN{free=0}; {free+=$1}; END{print free}'`
        BKAVAIL=`lctl get_param -n obdfilter.*.kbytesavail | awk 'BEGIN{avail=0}; {avail+=$1}; END{print avail}'`
        STRING=`df -P $MOUNT2 | tail -n 1 | awk '{print $2","$3","$4}'`
        DFTOTAL=`echo $STRING | cut -d, -f1`
        DFUSED=`echo $STRING  | cut -d, -f2`
        DFAVAIL=`echo $STRING | cut -d, -f3`
        DFFREE=$(($DFTOTAL - $DFUSED))

        ALLOWANCE=$((64 * $OSTCOUNT))

        if [ $DFTOTAL -lt $(($BKTOTAL - $ALLOWANCE)) ] ||  
           [ $DFTOTAL -gt $(($BKTOTAL + $ALLOWANCE)) ] ; then
                echo "**** FAIL: df total($DFTOTAL) mismatch OST total($BKTOTAL)"
                rc=1
        fi
        if [ $DFFREE -lt $(($BKFREE - $ALLOWANCE)) ] || 
           [ $DFFREE -gt $(($BKFREE + $ALLOWANCE)) ] ; then
                echo "**** FAIL: df free($DFFREE) mismatch OST free($BKFREE)"
                rc=2
        fi
        if [ $DFAVAIL -lt $(($BKAVAIL - $ALLOWANCE)) ] || 
           [ $DFAVAIL -gt $(($BKAVAIL + $ALLOWANCE)) ] ; then
                echo "**** FAIL: df avail($DFAVAIL) mismatch OST avail($BKAVAIL)"
                rc=3
       fi

        umount -d $MOUNT2
        stop fs3ost -f || return 200
        stop fs2ost -f || return 201
        stop fs2mds -f || return 202
        rm -rf $MOUNT2 $fs2mdsdev $fs2ostdev $fs3ostdev
        unload_modules || return 203
        return $rc
}
run_test 36 "df report consistency on OSTs with different block size"

test_37() {
	[ -n "$CLIENTONLY" -o -n "$CLIENTMODSONLY" ] && skip "client only testing" && return 0
	LOCAL_MDSDEV="$TMP/mdt.img"
	SYM_MDSDEV="$TMP/sym_mdt.img"

	echo "MDS :     $LOCAL_MDSDEV"
	echo "SYMLINK : $SYM_MDSDEV"
	rm -f $LOCAL_MDSDEV

	touch $LOCAL_MDSDEV
	mkfs.lustre --reformat --fsname=lustre --mdt --mgs --device-size=9000 $LOCAL_MDSDEV ||
		error "mkfs.lustre $LOCAL_MDSDEV failed"
	ln -s $LOCAL_MDSDEV $SYM_MDSDEV

	echo "mount symlink device - $SYM_MDSDEV"

	mount_op=`mount -v -t lustre -o loop $SYM_MDSDEV ${MOUNT%/*}/mds 2>&1 | grep "unable to set tunable"`
	umount -d ${MOUNT%/*}/mds
	rm -f $LOCAL_MDSDEV $SYM_MDSDEV

	if [ -n "$mount_op" ]; then
		error "**** FAIL: set tunables failed for symlink device"
	fi
	return 0
}
run_test 37 "verify set tunables works for symlink device"

test_38() { # bug 14222
	setup
	# like runtests
	COUNT=10
	SRC="/etc /bin"
	FILES=`find $SRC -type f -mtime +1 | head -n $COUNT`
	log "copying $(echo $FILES | wc -w) files to $DIR/$tdir"
	mkdir -p $DIR/$tdir
	tar cf - $FILES | tar xf - -C $DIR/$tdir || \
		error "copying $SRC to $DIR/$tdir"
	sync
	umount_client $MOUNT
	stop_mds
	log "rename lov_objid file on MDS"
	rm -f $TMP/lov_objid.orig
	do_facet mds "debugfs -c -R \\\"dump lov_objid $TMP/lov_objid.orig\\\" $MDSDEV"
	do_facet mds "debugfs -w -R \\\"rm lov_objid\\\" $MDSDEV"

	do_facet mds "od -Ax -td8 $TMP/lov_objid.orig"
	# check create in mds_lov_connect
	start_mds
	mount_client $MOUNT
	for f in $FILES; do
		[ $V ] && log "verifying $DIR/$tdir/$f"
		diff -q $f $DIR/$tdir/$f || ERROR=y
	done
	do_facet mds "debugfs -c -R \\\"dump lov_objid $TMP/lov_objid.new\\\"  $MDSDEV"
	do_facet mds "od -Ax -td8 $TMP/lov_objid.new"
	[ "$ERROR" = "y" ] && error "old and new files are different after connect" || true
	
	
	# check it's updates in sync
	umount_client $MOUNT
	stop_mds
	
	do_facet mds dd if=/dev/zero of=$TMP/lov_objid.clear bs=4096 count=1
	do_facet mds "debugfs -w -R \\\"rm lov_objid\\\" $MDSDEV"
	do_facet mds "debugfs -w -R \\\"write $TMP/lov_objid.clear lov_objid\\\" $MDSDEV "

	start_mds
	mount_client $MOUNT
	for f in $FILES; do
		[ $V ] && log "verifying $DIR/$tdir/$f"
		diff -q $f $DIR/$tdir/$f || ERROR=y
	done
        do_facet mds "debugfs -c -R \\\"dump lov_objid $TMP/lov_objid.new1\\\" $MDSDEV"
	do_facet mds "od -Ax -td8 $TMP/lov_objid.new1"
	umount_client $MOUNT
	stop_mds
	[ "$ERROR" = "y" ] && error "old and new files are different after sync" || true
	
	log "files compared the same"
	cleanup
}
run_test 38 "MDS recreates missing lov_objid file from OST data"

test_39() { #bug 14413
        PTLDEBUG=+malloc
        setup
        cleanup
        perl $SRCDIR/leak_finder.pl $TMP/debug 2>&1 | egrep '*** Leak:' && 
                error "memory leak detected" || true
}
run_test 39 "leak_finder recognizes both LUSTRE and LNET malloc messages"

test_40() { # bug 15759
	start_ost
	#define OBD_FAIL_TGT_TOOMANY_THREADS     0x706
	do_facet mds "lctl set_param fail_loc=0x80000706"
	start_mds
	cleanup
}
run_test 40 "race during service thread startup"

test_41() { #bug 14134
        local rc
        start mds $MDSDEV $MDS_MOUNT_OPTS -o nosvc -n
        start ost1 `ostdevname 1` $OST_MOUNT_OPTS
        start mds $MDSDEV $MDS_MOUNT_OPTS -o nomgs
        mkdir -p $MOUNT
        mount_client $MOUNT || return 1
        sleep 5

        echo "blah blah" > $MOUNT/$tfile
        cat $MOUNT/$tfile

        umount_client $MOUNT
        stop ost1 -f || return 201
        stop mds -f || return 202
        stop mds -f || return 203
        unload_modules || return 204
        return $rc
}
run_test 41 "mount mds with --nosvc and --nomgs"

test_42() { #bug 14693
        setup
        check_mount || return 2
        do_facet client lctl conf_param lustre.llite.some_wrong_param=10
        umount_client $MOUNT
        mount_client $MOUNT || return 1
        cleanup
        return 0
}
run_test 42 "invalid config param should not prevent client from mounting"

test_43() { #bug 15993
        setup
        VERSION_1_8=$(do_facet mds $LCTL get_param version | grep ^lustre.*1\.[78])
        if [ -z "$VERSION_1_8" ]; then
                skip "skipping test for non 1.8 MDS"
                cleanup
                return 0
        fi

        check_mount || return 2
        testfile=$DIR/$tfile
        lma="this-should-be-removed-after-remount-and-accessed"
        touch $testfile
        echo "set/get trusted.lma"
        setfattr -n trusted.lma -v $lma $testfile || error "create common EA"
        ATTR=$(getfattr -n trusted.lma $testfile 2> /dev/null | grep trusted.lma)
        [ "$ATTR" = "trusted.lma=\"$lma\"" ] || error "check common EA"
        umount_client $MOUNT
        stop_mds
        sleep 5
        start_mds
        mount_client $MOUNT
        check_mount || return 3
#define OBD_FAIL_MDS_REMOVE_COMMON_EA    0x13e
        do_facet mds "lctl set_param fail_loc=0x13e"
        stat $testfile
        do_facet mds "lctl set_param fail_loc=0"
        getfattr -d -m trusted $testfile 2> /dev/null | \
            grep "trusted.lma" && error "common EA not removed" || true
        cleanup
        return 0
}
run_test 43 "remove common EA if it exists"

test_44() { # 16317
        setup
        check_mount || return 2
        UUID=$($LCTL get_param llite.${FSNAME}*.uuid | cut -d= -f2)
        STATS_FOUND=no
        UUIDS=$(do_facet mds "$LCTL get_param mds.${FSNAME}*.exports.*.uuid")
        for VAL in $UUIDS; do
                NID=$(echo $VAL | cut -d= -f1)
                CLUUID=$(echo $VAL | cut -d= -f2)
                [ "$UUID" = "$CLUUID" ] && STATS_FOUND=yes && break
        done
        [ "$STATS_FOUND" = "no" ] && error "stats not found for client"
        cleanup
        return 0
}
run_test 44 "mounted client proc entry exists"

test_45() { #17310
        setup
        check_mount || return 2
        stop_mds
        df -h $MOUNT &
        log "sleep 60 sec"
        sleep 60
#define OBD_FAIL_PTLRPC_LONG_UNLINK   0x50f
        do_facet client "lctl set_param fail_loc=0x50f"
        log "sleep 10 sec"
        sleep 10
        manual_umount_client --force || return 3
        do_facet client "lctl set_param fail_loc=0x0"
        start_mds
        mount_client $MOUNT || return 4
        cleanup
        return 0
}
run_test 45 "long unlink handling in ptlrpcd"

test_46a() {
	OSTCOUNT=6
	reformat
	start_mds || return 1
	#first client should see only one ost
	start_ost || return 2
	#start_client
	mount_client $MOUNT || return 3
	
	start_ost2 || return 4
	start ost3 `ostdevname 3` $OST_MOUNT_OPTS || return 5
	start ost4 `ostdevname 4` $OST_MOUNT_OPTS || return 6
	start ost5 `ostdevname 5` $OST_MOUNT_OPTS || return 7
	# wait until ost2-5 is sync
	sleep 5
	#second client see both ost's

	mount_client $MOUNT2 || return 8
	$LFS setstripe $MOUNT2 -c -1 || return 9
	$LFS getstripe $MOUNT2 || return 10

	echo "ok" > $MOUNT2/widestripe
	$LFS getstripe $MOUNT2/widestripe || return 11
	# fill acl buffer for avoid expand lsm to them
	awk -F : '{if (FNR < 25) { print "u:"$1":rwx" }}' /etc/passwd | while read acl; do  
	    setfacl -m $acl $MOUNT2/widestripe
	done

	# will be deadlock
	stat $MOUNT/widestripe || return 12

	umount_client $MOUNT2 || return 13
	umount_client $MOUNT || return 14
	stop ost5 -f || return 20
	stop ost4 -f || return 21
	stop ost3 -f || return 22
	stop_ost2 || return 23
	stop_ost || return 24
	stop_mds || return 25
}
run_test 46a "handle ost additional - wide striped file"

equals_msg `basename $0`: test complete
[ -f "$TESTSUITELOG" ] && cat $TESTSUITELOG || true
