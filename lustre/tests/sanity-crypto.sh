#!/bin/sh

set -e

#
# This test needs to be run on the client
#

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh

init_test_env $@

. ${CONFIG:=$LUSTRE/tests/cfg/lmv.sh}

build_test_filter

assert_env MDSCOUNT

if [ `using_krb5_sec $SECURITY` == 'n' ] ; then
    ALWAYS_EXCEPT="0c $ALWAYS_EXCEPT"
fi


gen_config() {
    rm -f $XMLCONFIG

    if [ "$MDSCOUNT" -gt 1 ]; then
        add_lmv lmv1_svc
        for mds in `mds_list`; do
            MDSDEV=$TMP/${mds}-`hostname`
            add_mds $mds --dev $MDSDEV --size $MDSSIZE --lmv lmv1_svc
        done
        add_lov_to_lmv lov1 lmv1_svc --stripe_sz $STRIPE_BYTES \
	    --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
	MDS=lmv1
    else
        add_mds $SINGLEMDS --dev $MDSDEV --size $MDSSIZE
        if [ ! -z "$$SINGLEMDSfailover_HOST" ]; then
	     add_mdsfailover $SINGLEMDS --dev $MDSDEV --size $MDSSIZE
        fi
	add_lov lov1 $SINGLEMDS --stripe_sz $STRIPE_BYTES \
	    --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
	MDS=$SINGLEMDS_svc
    fi
    add_ost ost --lov lov1 --dev $OSTDEV --size $OSTSIZE
    add_ost ost2 --lov lov1 --dev ${OSTDEV}-2 --size $OSTSIZE
    add_gsk gsk     
    add_client client $MDS --lov lov1 --gss gsk_svc --path $MOUNT
}

build_test_filter

cleanup() {
    # make sure we are using the primary MDS, so the config log will
    # be able to clean up properly.
    activemds=`facet_active $SINGLEMDS`
    if [ $activemds != "$SINGLEMDS" ]; then
        fail $SINGLEMDS
    fi
    
    umount $MOUNT2 || true
    umount $MOUNT || true
    rmmod llite

    stop_gsk gsk 
    for mds in `mds_list`; do
	stop $mds ${FORCE} $MDSLCONFARGS
    done
    stop ost2 ${FORCE} --dump cleanup.log
    stop ost ${FORCE} --dump cleanup.log
    stop_lgssd
    stop_lsvcgssd
}

if [ "$ONLY" == "cleanup" ]; then
    sysctl -w portals.debug=0 || true
    cleanup
    exit
fi

SETUP=${SETUP:-"setup"}
CLEANUP=${CLEANUP:-"cleanup"}

setup() {
    gen_config

    start_krb5_kdc || exit 1
    start_lsvcgssd || exit 2
    start_lgssd || exit 3
    start ost --reformat $OSTLCONFARGS 
    start ost2 --reformat $OSTLCONFARGS 
    [ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE
    for mds in `mds_list`; do
	start $mds --reformat $MDSLCONFARGS
    done
    set -vx 
    start_gsk gsk || exit 4
    set -e
    grep " $MOUNT " /proc/mounts || zconf_mount `hostname` $MOUNT
    grep " $MOUNT2 " /proc/mounts || zconf_mount `hostname` $MOUNT2
}

$SETUP

if [ "$ONLY" == "setup" ]; then
    exit 0
fi

mkdir -p $DIR
$CLEANUP

