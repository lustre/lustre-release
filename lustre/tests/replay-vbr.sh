#!/bin/bash

set -e

# bug number: 16356
ALWAYS_EXCEPT="2 3c 4b 4c 10 $REPLAY_VBR_EXCEPT"

SAVE_PWD=$PWD
PTLDEBUG=${PTLDEBUG:--1}
LUSTRE=${LUSTRE:-`dirname $0`/..}
SETUP=${SETUP:-""}
CLEANUP=${CLEANUP:-""}
. $LUSTRE/tests/test-framework.sh

init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

[ -n "$CLIENTS" ] || { skip_env "Need two or more clients" && exit 0; }
[ $CLIENTCOUNT -ge 2 ] || \
    { skip_env "Need two or more remote clients, have $CLIENTCOUNT" && exit 0; }

require_dsh_mds || exit 0

[ "$SLOW" = "no" ] && EXCEPT_SLOW=""


[ ! "$NAME" = "ncli" ] && ALWAYS_EXCEPT="$ALWAYS_EXCEPT"
[ "$NAME" = "ncli" ] && MOUNT_2=""
MOUNT_2=""
build_test_filter

check_and_setup_lustre
rm -rf $DIR/[df][0-9]*

[ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE

get_version() {
    local client=$1
    local file=$2
    local fid

    fid=$(do_node $client $LFS path2fid $file)
    do_facet mds $LCTL --device $mds_svc getobjversion $fid
}

# interop 18 <-> 20
lustre_version=$(get_lustre_version mds)
if [[ $lustre_version != 1.8* ]]; then
    mds20="yes"
fi

test_0a() {
    local file=$DIR/$tfile
    local pre
    local post

    do_node $CLIENT1 mcreate $file
    pre=$(get_version $CLIENT1 $file)
    do_node $CLIENT1 openfile -f O_RDWR $file
    post=$(get_version $CLIENT1 $file)
    if (($pre != $post)); then
        error "version changed unexpectedly: pre $pre, post $post"
    fi
}
run_test 0a "VBR: open and close do not change versions"

test_0b() {
    do_facet mds "$LCTL set_param *.${mds_svc}.sync_permission=0"
    do_node $CLIENT1 mkdir -p -m 755 $DIR/$tdir

    replay_barrier mds
    do_node $CLIENT2 chmod 777 $DIR/$tdir
    do_node $CLIENT1 openfile -f O_RDWR:O_CREAT $DIR/$tdir/$tfile
    zconf_umount $CLIENT2 $MOUNT
    facet_failover mds

    client_evicted $CLIENT1 || error "$CLIENT1 not evicted"
    wait_clients_import_state $CLIENT1 mds FULL || error "$CLIENT1 not up"
    if ! do_node $CLIENT1 $CHECKSTAT -a $DIR/$tdir/$tfile; then
        error "open succeeded unexpectedly"
    fi
    zconf_mount $CLIENT2 $MOUNT
}
run_test 0b "VBR: open (O_CREAT) checks version of parent"

test_0c() {
    do_facet mds "$LCTL set_param *.${mds_svc}.sync_permission=0"
    do_node $CLIENT1 mkdir -p -m 755 $DIR/$tdir
    do_node $CLIENT1 openfile -f O_RDWR:O_CREAT -m 0644 $DIR/$tdir/$tfile

    replay_barrier mds
    do_node $CLIENT2 chmod 777 $DIR/$tdir
    do_node $CLIENT2 chmod 666 $DIR/$tdir/$tfile
    rmultiop_start $CLIENT1 $DIR/$tdir/$tfile o_c
    zconf_umount $CLIENT2 $MOUNT
    facet_failover mds
    client_up $CLIENT1 || error "$CLIENT1 evicted"

    rmultiop_stop $CLIENT1 || error "close failed"
    zconf_mount $CLIENT2 $MOUNT
}
run_test 0c "VBR: open (non O_CREAT) does not checks versions"

test_0d() {
    local pre
    local post

    pre=$(get_version $CLIENT1 $DIR)
    do_node $CLIENT1 mkfifo $DIR/$tfile
    post=$(get_version $CLIENT1 $DIR)
    if (($pre == $post)); then
        [ -n "$mds20" ] || error "version not changed: pre $pre, post $post"
    fi
}
run_test 0d "VBR: create changes version of parent"

test_0e() {
    do_facet mds "$LCTL set_param *.${mds_svc}.sync_permission=0"
    do_node $CLIENT1 mkdir -p -m 755 $DIR/$tdir

    replay_barrier mds
    do_node $CLIENT2 chmod 777 $DIR/$tdir
    do_node $CLIENT1 mkfifo $DIR/$tdir/$tfile
    zconf_umount $CLIENT2 $MOUNT
    facet_failover mds

    client_evicted $CLIENT1 || error "$CLIENT1 not evicted"
    wait_clients_import_state $CLIENT1 mds FULL || error "$CLIENT1 not up"
    if ! do_node $CLIENT1 $CHECKSTAT -a $DIR/$tdir/$tfile; then
        error "create succeeded unexpectedly"
    fi
    zconf_mount $CLIENT2 $MOUNT
}
run_test 0e "VBR: create checks version of parent"

test_0f() {
    local pre
    local post

    do_node $CLIENT1 mcreate $DIR/$tfile
    pre=$(get_version $CLIENT1 $DIR)
    do_node $CLIENT1 rm $DIR/$tfile
    post=$(get_version $CLIENT1 $DIR)
    if (($pre == $post)); then
        [ -n "$mds20" ] || error "version not changed: pre $pre, post $post"
    fi
}
run_test 0f "VBR: unlink changes version of parent"

test_0g() {
    do_facet mds "$LCTL set_param *.${mds_svc}.sync_permission=0"
    do_node $CLIENT1 mkdir -p -m 755 $DIR/$tdir
    do_node $CLIENT1 mcreate $DIR/$tdir/$tfile

    replay_barrier mds
    do_node $CLIENT2 chmod 777 $DIR/$tdir
    do_node $CLIENT1 rm $DIR/$tdir/$tfile
    zconf_umount $CLIENT2 $MOUNT
    facet_failover mds

    client_evicted $CLIENT1 || error "$CLIENT1 not evicted"
    wait_clients_import_state $CLIENT1 mds FULL || error "$CLIENT1 not up"
    if do_node $CLIENT1 $CHECKSTAT -a $DIR/$tdir/$tfile; then
        error "unlink succeeded unexpectedly"
    fi
    zconf_mount $CLIENT2 $MOUNT
}
run_test 0g "VBR: unlink checks version of parent"

test_0h() {
    local file=$DIR/$tfile
    local pre
    local post

    do_node $CLIENT1 mcreate $file
    pre=$(get_version $CLIENT1 $file)
    do_node $CLIENT1 chown $RUNAS_ID:$RUNAS_GID $file
    post=$(get_version $CLIENT1 $file)
    if (($pre == $post)); then
        error "version not changed: pre $pre, post $post"
    fi
}
run_test 0h "VBR: setattr of UID changes versions"

test_0i() {
    local file=$DIR/$tfile
    local pre
    local post

    do_node $CLIENT1 mcreate $file
    pre=$(get_version $CLIENT1 $file)
    do_node $CLIENT1 chgrp $RUNAS_GID $file
    post=$(get_version $CLIENT1 $file)
    if (($pre == $post)); then
        error "version not changed: pre $pre, post $post"
    fi
}
run_test 0i "VBR: setattr of GID changes versions"

test_0j() {
    local file=$DIR/$tfile

    do_facet mds "$LCTL set_param *.${mds_svc}.sync_permission=0"
    do_node $CLIENT1 mcreate $file

    replay_barrier mds
    do_node $CLIENT2 chgrp $RUNAS_GID $file
    do_node $CLIENT1 chown $RUNAS_ID:$RUNAS_GID $file
    zconf_umount $CLIENT2 $MOUNT
    facet_failover mds

    client_evicted $CLIENT1 || error "$CLIENT1 not evicted"
    wait_clients_import_state $CLIENT1 mds FULL || error "$CLIENT1 not up"
    if ! do_node $CLIENT1 $CHECKSTAT -u \\\#$UID $file; then
        error "setattr of UID succeeded unexpectedly"
    fi
    zconf_mount $CLIENT2 $MOUNT
}
run_test 0j "VBR: setattr of UID checks versions"

test_0k() {
    local file=$DIR/$tfile

    do_facet mds "$LCTL set_param *.${mds_svc}.sync_permission=0"
    do_node $CLIENT1 mcreate $file

    replay_barrier mds
    do_node $CLIENT2 chown $RUNAS_ID:$RUNAS_GID $file
    do_node $CLIENT1 chgrp $RUNAS_GID $file
    zconf_umount $CLIENT2 $MOUNT
    facet_failover mds

    client_evicted $CLIENT1 || error "$CLIENT1 not evicted"
    wait_clients_import_state $CLIENT1 mds FULL || error "$CLIENT1 not up"
    if ! do_node $CLIENT1 $CHECKSTAT -g \\\#$UID $file; then
        error "setattr of GID succeeded unexpectedly"
    fi
    zconf_mount $CLIENT2 $MOUNT
}
run_test 0k "VBR: setattr of GID checks versions"

test_0l() {
    local file=$DIR/$tfile
    local pre
    local post

    do_node $CLIENT1 openfile -f O_RDWR:O_CREAT -m 0644 $file
    pre=$(get_version $CLIENT1 $file)
    do_node $CLIENT1 chmod 666 $file
    post=$(get_version $CLIENT1 $file)
    if (($pre == $post)); then
        error "version not changed: pre $pre, post $post"
    fi
}
run_test 0l "VBR: setattr of permission changes versions"

test_0m() {
    local file=$DIR/$tfile

    do_facet mds "$LCTL set_param *.${mds_svc}.sync_permission=0"
    do_node $CLIENT1 openfile -f O_RDWR:O_CREAT -m 0644 $file

    replay_barrier mds
    do_node $CLIENT2 chgrp $RUNAS_GID $file
    do_node $CLIENT1 chmod 666 $file
    zconf_umount $CLIENT2 $MOUNT
    facet_failover mds

    client_evicted $CLIENT1 || error "$CLIENT1 not evicted"
    wait_clients_import_state $CLIENT1 mds FULL || error "$CLIENT1 not up"
    if ! do_node $CLIENT1 $CHECKSTAT -p 0644 $file; then
        error "setattr of permission succeeded unexpectedly"
    fi
    zconf_mount $CLIENT2 $MOUNT
}
run_test 0m "VBR: setattr of permission checks versions"

test_0n() {
    local file=$DIR/$tfile
    local pre
    local post

    do_node $CLIENT1 mcreate $file
    pre=$(get_version $CLIENT1 $file)
    do_node $CLIENT1 chattr +i $file
    post=$(get_version $CLIENT1 $file)
    do_node $CLIENT1 chattr -i $file
    if (($pre == $post)); then
        error "version not changed: pre $pre, post $post"
    fi
}
run_test 0n "VBR: setattr of flags changes versions"

checkattr() {
    local client=$1
    local attr=$2
    local file=$3
    local rc

    if ((${#attr} != 1)); then
        error "checking multiple attributes not implemented yet"
    fi
    do_node $client lsattr $file | cut -d ' ' -f 1 | grep -q $attr
}

test_0o() {
    local file=$DIR/$tfile
    local rc

    do_facet mds "$LCTL set_param *.${mds_svc}.sync_permission=0"
    do_node $CLIENT1 openfile -f O_RDWR:O_CREAT -m 0644 $file

    replay_barrier mds
    do_node $CLIENT2 chmod 666 $file
    do_node $CLIENT1 chattr +i $file
    zconf_umount $CLIENT2 $MOUNT
    facet_failover mds

    client_evicted $CLIENT1 || error "$CLIENT1 not evicted"
    checkattr $CLIENT1 i $file
    rc=$?
    do_node $CLIENT1 chattr -i $file
    if [ $rc -eq 0 ]; then
        error "setattr of flags succeeded unexpectedly"
    fi
    zconf_mount $CLIENT2 $MOUNT
}
run_test 0o "VBR: setattr of flags checks versions"

test_0p() {
    local file=$DIR/$tfile
    local pre
    local post
    local ad_orig

    ad_orig=$(do_facet mds "$LCTL get_param *.${mds_svc}.atime_diff")
    do_facet mds "$LCTL set_param *.${mds_svc}.atime_diff=0"
    do_node $CLIENT1 mcreate $file
    pre=$(get_version $CLIENT1 $file)
    do_node $CLIENT1 touch $file
    post=$(get_version $CLIENT1 $file)
    #
    # We don't fail MDS in this test.  atime_diff shall be
    # restored to its original value.
    #
    do_facet mds "$LCTL set_param $ad_orig"
    if (($pre != $post)); then
        error "version changed unexpectedly: pre $pre, post $post"
    fi
}
run_test 0p "VBR: setattr of times does not change versions"

test_0q() {
    local file=$DIR/$tfile
    local pre
    local post

    do_node $CLIENT1 mcreate $file
    pre=$(get_version $CLIENT1 $file)
    do_node $CLIENT1 $TRUNCATE $file 1
    post=$(get_version $CLIENT1 $file)
    if (($pre != $post)); then
        error "version changed unexpectedly: pre $pre, post $post"
    fi
}
run_test 0q "VBR: setattr of size does not change versions"

test_0r() {
    local file=$DIR/$tfile
    local mtime_pre
    local mtime_post
    local mtime

    do_facet mds "$LCTL set_param *.${mds_svc}.sync_permission=0"
    do_facet mds "$LCTL set_param *.${mds_svc}.atime_diff=0"
    do_node $CLIENT1 openfile -f O_RDWR:O_CREAT -m 0644 $file

    replay_barrier mds
    do_node $CLIENT2 chmod 666 $file
    do_node $CLIENT1 $TRUNCATE $file 1
    sleep 1
    mtime_pre=$(do_node $CLIENT1 stat --format=%Y $file)
    do_node $CLIENT1 touch $file
    mtime_post=$(do_node $CLIENT1 stat --format=%Y $file)
    zconf_umount $CLIENT2 $MOUNT
    facet_failover mds

    client_up $CLIENT1 || error "$CLIENT1 evicted"
    if (($mtime_pre >= $mtime_post)); then
        error "time not changed: pre $mtime_pre, post $mtime_post"
    fi
    if ! do_node $CLIENT1 $CHECKSTAT -s 1 $file; then
        error "setattr of size failed"
    fi
    mtime=$(do_node $CLIENT1 stat --format=%Y $file)
    if (($mtime != $mtime_post)); then
        error "setattr of times failed: expected $mtime_post, got $mtime"
    fi
    zconf_mount $CLIENT2 $MOUNT
}
run_test 0r "VBR: setattr of times and size does not check versions"

test_0s() {
    local pre
    local post
    local tp_pre
    local tp_post

    do_node $CLIENT1 mcreate $DIR/$tfile
    do_node $CLIENT1 mkdir -p $DIR/$tdir
    pre=$(get_version $CLIENT1 $DIR/$tfile)
    tp_pre=$(get_version $CLIENT1 $DIR/$tdir)
    do_node $CLIENT1 link $DIR/$tfile $DIR/$tdir/$tfile
    post=$(get_version $CLIENT1 $DIR/$tfile)
    tp_post=$(get_version $CLIENT1 $DIR/$tdir)
    if (($pre == $post)); then
        error "version of source not changed: pre $pre, post $post"
    fi
    if (($tp_pre == $tp_post)); then
        [ -n "$mds20" ] || \
            error "version of target parent not changed: pre $tp_pre, post $tp_post"
    fi
}
run_test 0s "VBR: link changes versions of source and target parent"

test_0t() {
    do_facet mds "$LCTL set_param *.${mds_svc}.sync_permission=0"
    do_node $CLIENT1 mcreate $DIR/$tfile
    do_node $CLIENT1 mkdir -p -m 755 $DIR/$tdir

    replay_barrier mds
    do_node $CLIENT2 chmod 777 $DIR/$tdir
    do_node $CLIENT1 link $DIR/$tfile $DIR/$tdir/$tfile
    zconf_umount $CLIENT2 $MOUNT
    facet_failover mds

    client_evicted $CLIENT1 || error "$CLIENT1 not evicted"
    wait_clients_import_state $CLIENT1 mds FULL || error "$CLIENT1 not up"
    if ! do_node $CLIENT1 $CHECKSTAT -a $DIR/$tdir/$tfile; then
        error "link should fail"
    fi
    zconf_mount $CLIENT2 $MOUNT
}
run_test 0t "VBR: link checks version of target parent"

test_0u() {
    do_facet mds "$LCTL set_param *.${mds_svc}.sync_permission=0"
    do_node $CLIENT1 openfile -f O_RDWR:O_CREAT -m 0644 $DIR/$tfile
    do_node $CLIENT1 mkdir -p $DIR/$tdir

    replay_barrier mds
    do_node $CLIENT2 chmod 666 $DIR/$tfile
    do_node $CLIENT1 link $DIR/$tfile $DIR/$tdir/$tfile
    zconf_umount $CLIENT2 $MOUNT
    facet_failover mds

    client_evicted $CLIENT1 || error "$CLIENT1 not evicted"
    wait_clients_import_state $CLIENT1 mds FULL || error "$CLIENT1 not up"
    if ! do_node $CLIENT1 $CHECKSTAT -a $DIR/$tdir/$tfile; then
        error "link should fail"
    fi
    zconf_mount $CLIENT2 $MOUNT
}
run_test 0u "VBR: link checks version of source"

test_0v() {
    local sp_pre
    local tp_pre
    local sp_post
    local tp_post

    do_node $CLIENT1 mcreate $DIR/$tfile
    do_node $CLIENT1 mkdir -p $DIR/$tdir
    sp_pre=$(get_version $CLIENT1 $DIR)
    tp_pre=$(get_version $CLIENT1 $DIR/$tdir)
    do_node $CLIENT1 mv $DIR/$tfile $DIR/$tdir/$tfile
    sp_post=$(get_version $CLIENT1 $DIR)
    tp_post=$(get_version $CLIENT1 $DIR/$tdir)
    if (($sp_pre == $sp_post)); then
        [ -n "$mds20" ] || \
            error "version of source parent not changed: pre $sp_pre, post $sp_post"
    fi
    if (($tp_pre == $tp_post)); then
        [ -n "$mds20" ] || \
            error "version of target parent not changed: pre $tp_pre, post $tp_post"
    fi
}
run_test 0v "VBR: rename changes versions of source parent and target parent"

test_0w() {
    local pre
    local post

    do_node $CLIENT1 mcreate $DIR/$tfile
    pre=$(get_version $CLIENT1 $DIR)
    do_node $CLIENT1 mv $DIR/$tfile $DIR/$tfile-new
    post=$(get_version $CLIENT1 $DIR)
    if (($pre == $post)); then
        [ -n "$mds20" ] || \
            error "version of parent not changed: pre $pre, post $post"
    fi
}
run_test 0w "VBR: rename within same dir changes version of parent"

test_0x() {
    do_facet mds "$LCTL set_param *.${mds_svc}.sync_permission=0"
    do_node $CLIENT1 mcreate $DIR/$tfile
    do_node $CLIENT1 mkdir -p -m 755 $DIR/$tdir

    replay_barrier mds
    do_node $CLIENT2 chmod 777 $DIR
    do_node $CLIENT1 mv $DIR/$tfile $DIR/$tdir/$tfile
    zconf_umount $CLIENT2 $MOUNT
    facet_failover mds

    client_evicted $CLIENT1 || error "$CLIENT1 not evicted"
    wait_clients_import_state $CLIENT1 mds FULL || error "$CLIENT1 not up"
    if do_node $CLIENT1 $CHECKSTAT -a $DIR/$tfile; then
        error "rename should fail"
    fi
    zconf_mount $CLIENT2 $MOUNT
}
run_test 0x "VBR: rename checks version of source parent"

test_0y() {
    do_facet mds "$LCTL set_param *.${mds_svc}.sync_permission=0"
    do_node $CLIENT1 mcreate $DIR/$tfile
    do_node $CLIENT1 mkdir -p -m 755 $DIR/$tdir

    replay_barrier mds
    do_node $CLIENT2 chmod 777 $DIR/$tdir
    do_node $CLIENT1 mv $DIR/$tfile $DIR/$tdir/$tfile
    zconf_umount $CLIENT2 $MOUNT
    facet_failover mds

    client_evicted $CLIENT1 || error "$CLIENT1 not evicted"
    wait_clients_import_state $CLIENT1 mds FULL || error "$CLIENT1 not up"
    if do_node $CLIENT1 $CHECKSTAT -a $DIR/$tfile; then
        error "rename should fail"
    fi
    zconf_mount $CLIENT2 $MOUNT
}
run_test 0y "VBR: rename checks version of target parent"

[ "$CLIENTS" ] && zconf_umount_clients $CLIENTS $DIR

test_1() {
    echo "mount client $CLIENT1,$CLIENT2..."
    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    do_node $CLIENT2 mkdir -p $DIR/$tdir
    replay_barrier mds
    do_node $CLIENT1 createmany -o $DIR/$tfile- 25
    do_node $CLIENT2 createmany -o $DIR/$tdir/$tfile-2- 1
    do_node $CLIENT1 createmany -o $DIR/$tfile-3- 25
    zconf_umount $CLIENT2 $DIR

    facet_failover mds
    # recovery shouldn't fail due to missing client 2
    client_up $CLIENT1 || return 1

    # All 50 files should have been replayed
    do_node $CLIENT1 unlinkmany $DIR/$tfile- 25 || return 2
    do_node $CLIENT1 unlinkmany $DIR/$tfile-3- 25 || return 3

    zconf_mount $CLIENT2 $DIR || error "mount $CLIENT2 $DIR fail"
    [ -e $DIR/$tdir/$tfile-2-0 ] && error "$tfile-2-0 exists"

    zconf_umount_clients $CLIENTS $DIR
    return 0
}
run_test 1 "VBR: client during replay doesn't affect another one"

test_2a() { # was test_2
    #ls -al $DIR/$tdir/$tfile

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    do_node $CLIENT2 mkdir -p $DIR/$tdir
    replay_barrier mds
    do_node $CLIENT2 mcreate $DIR/$tdir/$tfile
    do_node $CLIENT1 createmany -o $DIR/$tfile- 25
    #do_node $CLIENT2 createmany -o $DIR/$tdir/$tfile-2- 1
    do_node $CLIENT1 $CHECKSTAT $DIR/$tdir/$tfile
    do_node $CLIENT1 createmany -o $DIR/$tfile-3- 25
    zconf_umount $CLIENT2 $DIR

    facet_failover mds
    # recovery shouldn't fail due to missing client 2
    client_up $CLIENT1 || return 1

    # All 50 files should have been replayed
    do_node $CLIENT1 unlinkmany $DIR/$tfile- 25 || return 2
    do_node $CLIENT1 unlinkmany $DIR/$tfile-3- 25 || return 3

    do_node $CLIENT1 $CHECKSTAT $DIR/$tdir/$tfile && return 4

    zconf_mount $CLIENT2 $DIR || error "mount $CLIENT2 $DIR fail"

    zconf_umount_clients $CLIENTS $DIR
    return 0
}
run_test 2a "VBR: lost data due to missed REMOTE client during replay"

#
# This test uses three Lustre clients on two hosts.
#
#   Lustre Client 1:    $CLIENT1:$MOUNT     ($DIR)
#   Lustre Client 2:    $CLIENT2:$MOUNT2    ($DIR2)
#   Lustre Client 3:    $CLIENT2:$MOUNT1    ($DIR1)
#
test_2b() {
    local pre
    local post

    do_facet mds "$LCTL set_param *.${mds_svc}.sync_permission=0"
    zconf_mount $CLIENT1 $MOUNT
    zconf_mount $CLIENT2 $MOUNT2
    zconf_mount $CLIENT2 $MOUNT1
    do_node $CLIENT1 openfile -f O_RDWR:O_CREAT -m 0644 $DIR/$tfile-a
    do_node $CLIENT1 openfile -f O_RDWR:O_CREAT -m 0644 $DIR/$tfile-b

    #
    # Save an MDT transaction number before recovery.
    #
    pre=$(get_version $CLIENT1 $DIR/$tfile-a)

    #
    # Comments on the replay sequence state the expected result
    # of each request.
    #
    #   "R"     Replayed.
    #   "U"     Unable to replay.
    #   "J"     Rejected.
    #
    replay_barrier mds
    do_node $CLIENT1 chmod 666 $DIR/$tfile-a            # R
    do_node $CLIENT2 chmod 666 $DIR1/$tfile-b           # R
    do_node $CLIENT2 chgrp $RUNAS_GID $DIR2/$tfile-a    # U
    do_node $CLIENT1 chown $RUNAS_ID:$RUNAS_GID $DIR/$tfile-a      # J
    do_node $CLIENT2 $TRUNCATE $DIR2/$tfile-b 1          # U
    do_node $CLIENT2 chgrp $RUNAS_GID $DIR1/$tfile-b    # R
    do_node $CLIENT1 chown $RUNAS_ID:$RUNAS_GID $DIR/$tfile-b      # R
    zconf_umount $CLIENT2 $MOUNT2
    facet_failover mds

    client_evicted $CLIENT1 || error "$CLIENT1:$MOUNT not evicted"
    client_up $CLIENT2 || error "$CLIENT2:$MOUNT1 evicted"

    #
    # Check the MDT epoch.  $post must be the first transaction
    # number assigned after recovery.
    #
    do_node $CLIENT2 touch $DIR1/$tfile
    post=$(get_version $CLIENT2 $DIR1/$tfile)
    if (($(($pre >> 32)) == $((post >> 32)))); then
        error "epoch not changed: pre $pre, post $post"
    fi
    if (($(($post & 0x00000000ffffffff)) != 1)); then
        error "transno should restart from one: got $post"
    fi

    do_node $CLIENT2 stat $DIR1/$tfile-a
    do_node $CLIENT2 stat $DIR1/$tfile-b

    do_node $CLIENT2 $CHECKSTAT -p 0666 -u \\\#$UID -g \\\#$UID \
            $DIR1/$tfile-a || error "$DIR/$tfile-a: unexpected state"
    do_node $CLIENT2 $CHECKSTAT -p 0666 -u \\\#$RUNAS_ID -g \\\#$RUNAS_GID \
            $DIR1/$tfile-b || error "$DIR/$tfile-b: unexpected state"

    zconf_umount $CLIENT2 $MOUNT1
    zconf_umount $CLIENT1 $MOUNT
}
run_test 2b "VBR: 3 clients: some, none, and all reqs replayed"

test_3a() {
    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    #make sure the time will change
    do_facet mds "$LCTL set_param *.${mds_svc}.atime_diff=0" || return
    do_node $CLIENT1 touch $DIR/$tfile
    do_node $CLIENT2 $CHECKSTAT $DIR/$tfile
    sleep 1
    replay_barrier mds
    #change time
    do_node $CLIENT2 touch $DIR/$tfile
    do_node $CLIENT2 $CHECKSTAT $DIR/$tfile
    #another change
    do_node $CLIENT1 touch $DIR/$tfile
    #remove file
    do_node $CLIENT2 rm $DIR/$tfile
    zconf_umount $CLIENT2 $DIR

    facet_failover mds
    # recovery shouldn't fail due to missing client 2
    client_up $CLIENT1 || return 1
    do_node $CLIENT1 $CHECKSTAT $DIR/$tfile && return 2

    zconf_mount $CLIENT2 $DIR || error "mount $CLIENT2 $DIR fail"

    zconf_umount_clients $CLIENTS $DIR

    return 0
}
run_test 3a "VBR: setattr of time/size doesn't change version"

test_3b() {
    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    #make sure the time will change
    do_facet mds "$LCTL set_param *.${mds_svc}.atime_diff=0" || return
    do_facet mds "$LCTL set_param *.${mds_svc}.sync_permission=0" || return
    do_node $CLIENT1 touch $DIR/$tfile
    do_node $CLIENT2 $CHECKSTAT $DIR/$tfile
    sleep 1
    replay_barrier mds
    #change mode
    do_node $CLIENT2 chmod +x $DIR/$tfile
    do_node $CLIENT2 $CHECKSTAT $DIR/$tfile
    #abother chmod
    do_node $CLIENT1 chmod -x $DIR/$tfile
    zconf_umount $CLIENT2 $DIR

    facet_failover mds
    # recovery should fail due to missing client 2
    client_evicted $CLIENT1 || return 1

    wait_clients_import_state $CLIENT1 mds FULL || error "$CLIENT1 not up"
    do_node $CLIENT1 $CHECKSTAT -p 0755 $DIR/$tfile && return 2
    zconf_mount $CLIENT2 $DIR || error "mount $CLIENT2 $DIR fail"

    zconf_umount_clients $CLIENTS $DIR

    return 0
}
run_test 3b "VBR: setattr of permissions changes version"

test_3c() {
    [ "$FAILURE_MODE" = HARD ] || \
        { skip "The HARD failure is needed" && return 0; }

    [ $RUNAS_ID -eq $UID ] && skip_env "RUNAS_ID = UID = $UID -- skipping" && return

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    # check that permission changes are synced
    do_facet mds "$LCTL set_param *.${mds_svc}.sync_permission=1"

    do_node $CLIENT1 mkdir -p $DIR/d3c/sub || error
    #chown -R $RUNAS_ID $MOUNT1/d3
    do_node $CLIENT1 ls -la $DIR/d3c

    # only HARD failure will work as we use sync operation
    replay_barrier mds
    do_node $CLIENT2 mcreate $DIR/d3c/$tfile-2
    #set permissions
    do_node $CLIENT1 chmod 0700 $UID $DIR/d3c
    #secret file
    do_node $CLIENT1 mcreate $DIR/d3c/sub/$tfile
    do_node $CLIENT1 echo "Top Secret" > $DIR/d3c/sub/$tfile
    #check user can't access new file
    do_node $CLIENT2 $RUNAS ls $DIR/d3c && return 3
    do_node $CLIENT1 $RUNAS ls $DIR/d3c && return 4
    do_node $CLIENT1 $RUNAS cat $DIR/d3c/sub/$tfile && return 5

    zconf_umount $CLIENT2 $DIR

    facet_failover mds
    # recovery shouldn't fail due to missing client 2
    client_up $CLIENT1 || return 1

    zconf_mount $CLIENT2 $DIR || error "mount $CLIENT2 $DIR fail"
    do_node $CLIENT1 $RUNAS cat $DIR/d3c/sub/$tfile && return 6
    do_node $CLIENT2 $RUNAS cat $DIR/d3c/sub/$tfile && return 7
    do_facet mds "$LCTL set_param mds.${mds_svc}.sync_permission=0"

    return 0
}
run_test 3c "VBR: permission dependency failure"

vbr_deactivate_client() {
    local client=$1
    echo "Deactivating client $client";
    do_node $client "sysctl -w lustre.fail_loc=0x50d"
}

vbr_activate_client() {
    local client=$1
    echo "Activating client $client";
    do_node $client "sysctl -w lustre.fail_loc=0x0"
}

remote_server ()
{
    local client=$1
    [ -z "$(do_node $client lctl dl | grep mdt)" ] && \
    [ -z "$(do_node $client lctl dl | grep ost)" ]
}

test_4a() {
    delayed_recovery_enabled || { skip "No delayed recovery support"; return 0; }

    remote_server $CLIENT2 || \
        { skip_env "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    do_node $CLIENT2 mkdir -p $DIR/$tdir
    replay_barrier mds
    do_node $CLIENT1 createmany -o $DIR/$tfile- 25
    do_node $CLIENT2 createmany -o $DIR/$tdir/$tfile-2- 25
    do_node $CLIENT1 createmany -o $DIR/$tfile-3- 25
    vbr_deactivate_client $CLIENT2

    facet_failover mds
    client_up $CLIENT1 || return 1

    # All 50 files should have been replayed
    do_node $CLIENT1 unlinkmany $DIR/$tfile- 25 || return 2
    do_node $CLIENT1 unlinkmany $DIR/$tfile-3- 25 || return 3

    vbr_activate_client $CLIENT2
    client_up $CLIENT2 || return 4
    # All 25 files from client2 should have been replayed
    do_node $CLIENT2 unlinkmany $DIR/$tdir/$tfile-2- 25 || return 5

    zconf_umount_clients $CLIENTS $DIR
    return 0
}
run_test 4a "fail MDS, delayed recovery"

test_4b() {
    delayed_recovery_enabled || { skip "No delayed recovery support"; return 0; }

    remote_server $CLIENT2 || \
        { skip_env "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    replay_barrier mds
    do_node $CLIENT1 createmany -o $DIR/$tfile- 25
    do_node $CLIENT2 createmany -o $DIR/$tdir/$tfile-2- 25
    vbr_deactivate_client $CLIENT2

    facet_failover mds
    client_up $CLIENT1 || return 1

    # create another set of files
    do_node $CLIENT1 createmany -o $DIR/$tfile-3- 25

    vbr_activate_client $CLIENT2
    client_up $CLIENT2 || return 2

    # All files from should have been replayed
    do_node $CLIENT1 unlinkmany $DIR/$tfile- 25 || return 3
    do_node $CLIENT1 unlinkmany $DIR/$tfile-3- 25 || return 4
    do_node $CLIENT2 unlinkmany $DIR/$tdir/$tfile-2- 25 || return 5

    zconf_umount_clients $CLIENTS $DIR
}
run_test 4b "fail MDS, normal operation, delayed open recovery"

test_4c() {
    delayed_recovery_enabled || { skip "No delayed recovery support"; return 0; }

    remote_server $CLIENT2 || \
        { skip_env "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    replay_barrier mds
    do_node $CLIENT1 createmany -m $DIR/$tfile- 25
    do_node $CLIENT2 createmany -m $DIR/$tdir/$tfile-2- 25
    vbr_deactivate_client $CLIENT2

    facet_failover mds
    client_up $CLIENT1 || return 1

    # create another set of files
    do_node $CLIENT1 createmany -m $DIR/$tfile-3- 25

    vbr_activate_client $CLIENT2
    client_up $CLIENT2 || return 2

    # All files from should have been replayed
    do_node $CLIENT1 unlinkmany $DIR/$tfile- 25 || return 3
    do_node $CLIENT1 unlinkmany $DIR/$tfile-3- 25 || return 4
    do_node $CLIENT2 unlinkmany $DIR/$tdir/$tfile-2- 25 || return 5

    zconf_umount_clients $CLIENTS $DIR
}
run_test 4c "fail MDS, normal operation, delayed recovery"

test_5a() {
    delayed_recovery_enabled || { skip "No delayed recovery support"; return 0; }

    remote_server $CLIENT2 || \
        { skip_env "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    replay_barrier mds
    do_node $CLIENT1 createmany -o $DIR/$tfile- 25
    do_node $CLIENT2 createmany -o $DIR/$tfile-2- 1
    do_node $CLIENT1 createmany -o $DIR/$tfile-3- 1
    vbr_deactivate_client $CLIENT2

    facet_failover mds
    client_evicted $CLIENT1 || return 1

    vbr_activate_client $CLIENT2
    client_up $CLIENT2 || return 2

    # First 25 files should have been replayed
    do_node $CLIENT1 unlinkmany $DIR/$tfile- 25 || return 3
    # Third file is failed due to missed client2
    do_node $CLIENT1 $CHECKSTAT $DIR/$tfile-3-0 && error "$tfile-3-0 exists"
    # file from client2 should exists
    do_node $CLIENT2 unlinkmany $DIR/$tfile-2- 1 || return 4

    zconf_umount_clients $CLIENTS $DIR
}
run_test 5a "fail MDS, delayed recovery should fail"

test_5b() {
    delayed_recovery_enabled || { skip "No delayed recovery support"; return 0; }

    remote_server $CLIENT2 || \
        { skip_env "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    replay_barrier mds
    do_node $CLIENT1 createmany -o $DIR/$tfile- 25
    do_node $CLIENT2 createmany -o $DIR/$tfile-2- 1
    vbr_deactivate_client $CLIENT2

    facet_failover mds
    client_up $CLIENT1 || return 1
    do_node $CLIENT1 $CHECKSTAT $DIR/$tfile-2-0 && error "$tfile-2-0 exists"

    # create another set of files
    do_node $CLIENT1 createmany -o $DIR/$tfile-3- 25

    vbr_activate_client $CLIENT2
    client_evicted $CLIENT2 || return 4
    # file from client2 should fail
    wait_clients_import_state $CLIENT2 mds FULL || error "$CLIENT2 not up"
    do_node $CLIENT2 $CHECKSTAT $DIR/$tfile-2-0 && error "$tfile-2-0 exists"

    # All 50 files from client 1 should have been replayed
    do_node $CLIENT1 unlinkmany $DIR/$tfile- 25 || return 2
    do_node $CLIENT1 unlinkmany $DIR/$tfile-3- 25 || return 3

    zconf_umount_clients $CLIENTS $DIR
}
run_test 5b "fail MDS, normal operation, delayed recovery should fail"

test_6a() {
    delayed_recovery_enabled || { skip "No delayed recovery support"; return 0; }

    remote_server $CLIENT2 || \
        { skip_env "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    do_node $CLIENT2 mkdir -p $DIR/$tdir
    replay_barrier mds
    do_node $CLIENT1 createmany -o $DIR/$tfile- 25
    do_node $CLIENT2 createmany -o $DIR/$tdir/$tfile-2- 25
    do_node $CLIENT1 createmany -o $DIR/$tfile-3- 25
    vbr_deactivate_client $CLIENT2

    facet_failover mds
    # replay only 5 requests
    do_node $CLIENT2 "sysctl -w lustre.fail_val=5"
#define OBD_FAIL_PTLRPC_REPLAY        0x50e
    do_node $CLIENT2 "sysctl -w lustre.fail_loc=0x2000050e"
    client_up $CLIENT2
    # vbr_activate_client $CLIENT2
    # need way to know that client stops replays
    sleep 5

    facet_failover mds
    client_up $CLIENT1 || return 1

    # All files should have been replayed
    do_node $CLIENT1 unlinkmany $DIR/$tfile- 25 || return 2
    do_node $CLIENT1 unlinkmany $DIR/$tfile-3- 25 || return 3
    do_node $CLIENT2 unlinkmany $DIR/$tdir/$tfile-2- 25 || return 5

    zconf_umount_clients $CLIENTS $DIR
    return 0
}
run_test 6a "fail MDS, delayed recovery, fail MDS"

test_7a() {
    delayed_recovery_enabled || { skip "No delayed recovery support"; return 0; }

    remote_server $CLIENT2 || \
        { skip_env "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    do_node $CLIENT2 mkdir -p $DIR/$tdir
    replay_barrier mds
    do_node $CLIENT1 createmany -o $DIR/$tfile- 25
    do_node $CLIENT2 createmany -o $DIR/$tdir/$tfile-2- 25
    do_node $CLIENT1 createmany -o $DIR/$tfile-3- 25
    vbr_deactivate_client $CLIENT2

    facet_failover mds
    vbr_activate_client $CLIENT2
    client_up $CLIENT2 || return 4

    facet_failover mds
    client_up $CLIENT1 || return 1

    # All files should have been replayed
    do_node $CLIENT1 unlinkmany $DIR/$tfile- 25 || return 2
    do_node $CLIENT1 unlinkmany $DIR/$tfile-3- 25 || return 3
    do_node $CLIENT2 unlinkmany $DIR/$tdir/$tfile-2- 25 || return 5

    zconf_umount_clients $CLIENTS $DIR
    return 0
}
run_test 7a "fail MDS, delayed recovery, fail MDS"

test_8a() {
    delayed_recovery_enabled || { skip "No delayed recovery support"; return 0; }

    remote_server $CLIENT2 || \
        { skip_env "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    rmultiop_start $CLIENT2 $DIR/$tfile O_tSc || return 1
    do_node $CLIENT2 rm -f $DIR/$tfile
    replay_barrier mds
    rmultiop_stop $CLIENT2 || return 2

    vbr_deactivate_client $CLIENT2
    facet_failover mds
    client_up $CLIENT1 || return 3
    #client1 is back and will try to open orphan
    vbr_activate_client $CLIENT2
    client_up $CLIENT2 || return 4

    do_node $CLIENT2 $CHECKSTAT $DIR/$tfile && error "$tfile exists"
    zconf_umount_clients $CLIENTS $DIR
    return 0
}
run_test 8a "orphans are kept until delayed recovery"

test_8b() {
    delayed_recovery_enabled || { skip "No delayed recovery support"; return 0; }

    remote_server $CLIENT2 || \
        { skip_env "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    rmultiop_start $CLIENT2 $DIR/$tfile O_tSc || return 1
    replay_barrier mds
    do_node $CLIENT1 rm -f $DIR/$tfile

    vbr_deactivate_client $CLIENT2
    facet_failover mds
    client_up $CLIENT1 || return 2
    #client1 is back and will try to open orphan
    vbr_activate_client $CLIENT2
    client_up $CLIENT2 || return 3

    rmultiop_stop $CLIENT2 || return 1
    do_node $CLIENT2 $CHECKSTAT $DIR/$tfile && error "$tfile exists"
    zconf_umount_clients $CLIENTS $DIR
    return 0
}
run_test 8b "open1 | unlink2 X delayed_replay1, close1"

test_8c() {
    delayed_recovery_enabled || { skip "No delayed recovery support"; return 0; }

    remote_server $CLIENT2 || \
        { skip_env "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    rmultiop_start $CLIENT2 $DIR/$tfile O_tSc || return 1
    replay_barrier mds
    do_node $CLIENT1 rm -f $DIR/$tfile
    rmultiop_stop $CLIENT2 || return 2

    vbr_deactivate_client $CLIENT2
    facet_failover mds
    client_up $CLIENT1 || return 3
    #client1 is back and will try to open orphan
    vbr_activate_client $CLIENT2
    client_up $CLIENT2 || return 4

    do_node $CLIENT2 $CHECKSTAT $DIR/$tfile && error "$tfile exists"
    zconf_umount_clients $CLIENTS $DIR
    return 0
}
run_test 8c "open1 | unlink2, close1 X delayed_replay1"

test_8d() {
    delayed_recovery_enabled || { skip "No delayed recovery support"; return 0; }

    remote_server $CLIENT2 || \
        { skip_env "Client $CLIENT2 is on the server node" && return 0; }

    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    rmultiop_start $CLIENT1 $DIR/$tfile O_tSc || return 1
    rmultiop_start $CLIENT2 $DIR/$tfile O_tSc || return 2
    replay_barrier mds
    do_node $CLIENT1 rm -f $DIR/$tfile
    rmultiop_stop $CLIENT2 || return 3
    rmultiop_stop $CLIENT1 || return 4

    vbr_deactivate_client $CLIENT2
    facet_failover mds
    client_up $CLIENT1 || return 6

    #client1 is back and will try to open orphan
    vbr_activate_client $CLIENT2
    client_up $CLIENT2 || return 8

    do_node $CLIENT2 $CHECKSTAT $DIR/$tfile && error "$tfile exists"
    zconf_umount_clients $CLIENTS $DIR
    return 0
}
run_test 8d "open1, open2 | unlink2, close1, close2 X delayed_replay1"

test_8e() {
    zconf_mount $CLIENT1 $DIR
    zconf_mount $CLIENT2 $DIR

    do_node $CLIENT1 mcreate $DIR/$tfile
    do_node $CLIENT1 mkdir $DIR/$tfile-2
    replay_barrier mds
    # missed replay from client1 will lead to recovery by versions
    do_node $CLIENT1 touch $DIR/$tfile-2/$tfile
    do_node $CLIENT2 rm $DIR/$tfile || return 1
    do_node $CLIENT2 touch $DIR/$tfile || return 2

    zconf_umount $CLIENT1 $DIR
    facet_failover mds
    client_up $CLIENT2 || return 6

    do_node $CLIENT2 rm $DIR/$tfile || error "$tfile doesn't exists"
    zconf_umount_clients $CLIENTS $DIR
    return 0
}
run_test 8e "create | unlink, create shouldn't fail"

test_8f() {
    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    do_node $CLIENT1 touch $DIR/$tfile
    do_node $CLIENT1 mkdir $DIR/$tfile-2
    replay_barrier mds
    # missed replay from client1 will lead to recovery by versions
    do_node $CLIENT1 touch $DIR/$tfile-2/$tfile
    do_node $CLIENT2 rm -f $DIR/$tfile || return 1
    do_node $CLIENT2 mcreate $DIR/$tfile || return 2

    zconf_umount $CLIENT1 $DIR
    facet_failover mds
    client_up $CLIENT2 || return 6

    do_node $CLIENT2 rm $DIR/$tfile || error "$tfile doesn't exists"
    zconf_umount $CLIENT2 $DIR
    return 0
}
run_test 8f "create | unlink, create shouldn't fail"

test_8g() {
    zconf_mount_clients $CLIENT1 $DIR
    zconf_mount_clients $CLIENT2 $DIR

    do_node $CLIENT1 touch $DIR/$tfile
    do_node $CLIENT1 mkdir $DIR/$tfile-2
    replay_barrier mds
    # missed replay from client1 will lead to recovery by versions
    do_node $CLIENT1 touch $DIR/$tfile-2/$tfile
    do_node $CLIENT2 rm -f $DIR/$tfile || return 1
    do_node $CLIENT2 mkdir $DIR/$tfile || return 2

    zconf_umount $CLIENT1 $DIR
    facet_failover mds
    do_node $CLIENT2 df $DIR || return 6

    do_node $CLIENT2 rmdir $DIR/$tfile || error "$tfile doesn't exists"
    zconf_umount $CLIENT2 $DIR
    return 0
}
run_test 8g "create | unlink, create shouldn't fail"

test_10 () {
    delayed_recovery_enabled || { skip "No delayed recovery support"; return 0; }

    [ -z "$DBENCH_LIB" ] && skip_env "DBENCH_LIB is not set" && return 0

    zconf_mount_clients $CLIENTS $DIR

    local duration="-t 60"
    local cmd="rundbench 1 $duration "
    local PID=""
    for CLIENT in ${CLIENTS//,/ }; do
        $PDSH $CLIENT "set -x; PATH=:$PATH:$LUSTRE/utils:$LUSTRE/tests/:${DBENCH_LIB} DBENCH_LIB=${DBENCH_LIB} $cmd" &
        PID=$!
        echo $PID >pid.$CLIENT
        echo "Started load PID=`cat pid.$CLIENT`"
    done

    replay_barrier mds
    sleep 3 # give clients a time to do operations

    vbr_deactivate_client $CLIENT2

    log "$TESTNAME fail mds 1"
    fail mds

# wait for client to reconnect to MDS
    sleep $TIMEOUT

    vbr_activate_client $CLIENT2
    client_up $CLIENT2 || return 4

    for CLIENT in ${CLIENTS//,/ }; do
        PID=`cat pid.$CLIENT`
        wait $PID
        rc=$?
        echo "load on ${CLIENT} returned $rc"
    done

    zconf_umount_clients $CLIENTS $DIR
}
run_test 10 "mds version recovery; $CLIENTCOUNT clients"

[ "$CLIENTS" ] && zconf_mount_clients $CLIENTS $DIR

complete $(basename $0) $SECONDS
check_and_cleanup_lustre
exit_status
