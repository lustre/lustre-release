#!/bin/sh

#set -vx

# mountconf setup of MDS and two OSTs

export PATH=`dirname $0`/../utils:$PATH

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh

init_test_env $@

. ${CONFIG:=$LUSTRE/tests/cfg/local.sh}


unload_modules() {
    $LCTL dk $TMP/debug
    $LCTL modules | awk '{ print $2 }' | xargs rmmod >/dev/null 2>&1 
     # do it again, in case we tried to unload ksocklnd too early
    LNET=$(lsmod | grep -c lnet) 
    if [ $LNET -ne 0 ]; then
	$LCTL modules | awk '{ print $2 }' | xargs rmmod
    fi
    lsmod | grep lnet && echo "modules still loaded" && exit 1

    LEAK_LUSTRE=`dmesg | tail -n 30 | grep "obd mem.*leaked"`
    LEAK_PORTALS=`dmesg | tail -n 20 | grep "Portals memory leaked"`
    if [ "$LEAK_LUSTRE" -o "$LEAK_PORTALS" ]; then
	echo "$LEAK_LUSTRE" 1>&2
	echo "$LEAK_PORTALS" 1>&2
	mv $TMP/debug $TMP/debug-leak.`date +%s`
	echo "Memory leaks detected"
	exit 254
    fi
}

stop_all() {
    grep " $MOUNT " /proc/mounts && zconf_umount `hostname` $MOUNT
    stop ost -f
    stop ost2 -f
    stop mds -f
}

mccleanup() {
    echo "mountconf cleanup $*"
    stop_all
    unload_modules
}

mcformat() {
    stop_all
    echo Formatting mds, ost, ost2
    add mds $MDS_MKFS_OPTS --reformat $MDSDEV    > /dev/null || exit 10
    add ost $OST_MKFS_OPTS --reformat $OSTDEV    > /dev/null || exit 10
    add ost2 $OST2_MKFS_OPTS --reformat $OSTDEV2 > /dev/null || exit 10
}
export MCFORMAT=${MCFORMAT:-"mcformat"}

mount_client() {
    grep " $1 " /proc/mounts || zconf_mount `hostname` $*
}

mcsetup() {
    echo Setup mds, ost, ost2
    start mds $MDSDEV $MDS_MOUNT_OPTS
    start ost $OSTDEV $OST_MOUNT_OPTS
    start ost2 $OSTDEV2 $OST2_MOUNT_OPTS
    [ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE

    mount_client $MOUNT
    sleep 5
}

export MCSETUP=${MCSETUP:-"mcsetup"}
export MCCLEANUP=${MCCLEANUP:-"mccleanup"}


#${LCONF} $NOMOD $portals_opt $lustre_opt $debug_opt $node_opt ${REFORMAT:---reformat} $@ $conf_opt  || {
    # maybe acceptor error, dump tcp port usage
#    netstat -tpn
#    exit 2
#}

#if [ "$MOUNT2" ]; then
#	$LLMOUNT -v -o user_xattr,acl `hostname`:/mds1/client $MOUNT2 || exit 3
#fi
