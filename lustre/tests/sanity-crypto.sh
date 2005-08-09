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

SETUP=${SETUP:-"setup"}
CLEANUP=${CLEANUP:-"cleanup"}

DIR1=${DIR1:-$MOUNT1}
DIR2=${DIR2:-$MOUNT2}
CRYPT_TYPE=${CRYPT_TYPE:-"gks"}
RUN_UID=${RUN_UID:-1000}
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
    add_gks gks     
    add_client client $MDS --lov lov1 --gks gks_svc --path $MOUNT
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

    stop_gks gks 
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
    start_gks gks || exit 4
    set -e
    grep " $MOUNT " /proc/mounts || zconf_mount `hostname` $MOUNT
    grep " $MOUNT2 " /proc/mounts || zconf_mount `hostname` $MOUNT2
}

$SETUP

if [ "$ONLY" == "setup" ]; then
    exit 0
fi
disable_encrypt() {
	NAME=$1
    	grep " $MOUNT " /proc/mounts && umount  $MOUNT
	zconf_mount `hostname` $NAME	
}
enable_encrypt() {
	NAME=$1
    	grep " $MOUNT " /proc/mounts || zconf_mount `hostname` $MOUNT
	$LCTL set_crypt $MOUNT $CRYPT_TYPE
}

mkdir -p $DIR

test_1a() {
	rm -rf $DIR1/1a*
	enable_encrypt $MOUNT
	echo aaaaaaaaaaaaaaaaaaaa >> $DIR1/1a0
	echo aaaaaaaaaaaaaaaaaaaa >> $DIR2/1a1
	diff -u $DIR1/1a0 $DIR2/1a1 || error "files are different"
	disable_encrypt $MOUNT
	diff -u $DIR1/1a0 $DIR2/1a1 && error "write encryption failed"
}
run_test 1a "read/write encryption============="

test_2a() {
	rm -rf $DIR1/2a*
	enable_encrypt $MOUNT
	touch $DIR1/2a0
        setfacl -m u:bin:rw $DIR1/2a0
	echo aaaaaaaaaaaaaaaaaaaa >> $DIR1/2a0
	echo aaaaaaaaaaaaaaaaaaaa >> $DIR2/2a1
	diff -u $DIR1/2a0 $DIR2/2a1 || error "files are different"
	disable_encrypt $MOUNT
	diff -u $DIR1/2a0 $DIR2/2a1 && error "write encryption failed"
}
run_test 2a "read/write encryption with acl============="

test_3a() {
	rm -rf $DIR1/3a*
	enable_encrypt $MOUNT	
	echo aaaaaaaaaaaaaaaaaaaa >> $DIR1/3a0
	echo aaaaaaaaaaaaaaaaaaaa >> $DIR2/3a1
	chown $RUN_UID $DIR1/3a0
	echo aaaaaaaaaaaaaaaaaaaa >> $DIR1/3a0 || error "chown write error"
	echo aaaaaaaaaaaaaaaaaaaa >> $DIR1/3a1 	
	diff -u $DIR1/3a0 $DIR2/3a1 || error "files are different"
	disable_encrypt $MOUNT
	diff -u $DIR1/3a0 $DIR2/3a1 && error "write encryption failed"
}
run_test 3a "write chmod encryption============="

test_4a() {
	rm -rf $DIR1/4a*
	enable_encrypt $MOUNT	
	echo aaaaaaaaaaaaaaaaaaaa >> $DIR1/4a0
	echo aaaaaaaaaaaaaaaaaaaa >> $DIR2/4a1
        setfacl -m u:bin:rw $DIR1/4a0
	echo aaaaaaaaaaaaaaaaaaaa >> $DIR1/4a0 || error "chown write error"
	echo aaaaaaaaaaaaaaaaaaaa >> $DIR1/4a1 	
	diff -u $DIR1/4a0 $DIR2/4a1 || error "files are different"
	disable_encrypt $MOUNT
	diff -u $DIR1/4a0 $DIR2/4a1 && error "write encryption failed"
}
run_test 4a "write chacl encryption============="

test_5a() {
	rm -rf $DIR1/5a*
	enable_encrypt $MOUNT	
	echo aaaaaaaaaaaaaaaaaaaa >> $DIR1/5a0
	echo aaaaaaaaaaaaaaaaaaaa >> $DIR2/5a1
        setfacl -m u:bin:rw $DIR1/5a0
	chown $RUN_UID $DIR1/3a0
	echo aaaaaaaaaaaaaaaaaaaa >> $DIR1/5a0 || error "chown write error"
	echo aaaaaaaaaaaaaaaaaaaa >> $DIR1/5a1 	
	diff -u $DIR1/5a0 $DIR2/5a1 || error "files are different"
	disable_encrypt $MOUNT
	diff -u $DIR1/5a0 $DIR2/5a1 && error "write encryption failed"
}
run_test 5a "write chacl encryption============="

$CLEANUP

