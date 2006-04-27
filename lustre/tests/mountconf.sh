#!/bin/sh

#set -vx

# mountconf setup of MDS and two OSTs

#export PATH=`dirname $0`/../utils:$PATH
#LUSTRE=${LUSTRE:-`dirname $0`/..}
#. $LUSTRE/tests/test-framework.sh
#init_test_env $@

mcstopall() {
    # make sure we are using the primary server, so test-framework will
    # be able to clean up properly.
    activemds=`facet_active mds`
    if [ $activemds != "mds" ]; then
        fail mds
    fi

    grep " $MOUNT " /proc/mounts && zconf_umount `hostname` $MOUNT $*
    stop ost -f
    stop ost2 -f
    stop mds -f
    return 0
}

mccleanup() {
    echo "mountconf cleanup $*"
    mcstopall $*
    unload_modules
}

mcformat() {
    mcstopall
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

