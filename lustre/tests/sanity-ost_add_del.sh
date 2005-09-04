#!/bin/sh

set -e

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh

init_test_env $@

. ${CONFIG:=$LUSTRE/tests/cfg/lmv.sh}

build_test_filter

assert_env MDSCOUNT

SETUP=${SETUP:-"setup"}
CLEANUP=${CLEANUP:-"cleanup"}

DIR1=${DIR1:-$MOUNT1}
LCTL=${LCTL:-"$LUSTRE/utils/lctl"}
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
   
    add_client client $MDS --lov lov1 --path $MOUNT
}

build_test_filter

cleanup() {
    # make sure we are using the primary MDS, so the config log will
    # be able to clean up properly.
    activemds=`facet_active $SINGLEMDS`
    if [ $activemds != "$SINGLEMDS" ]; then
        fail $SINGLEMDS
    fi
    
    umount $MOUNT || true
    rmmod llite
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
    grep " $MOUNT " /proc/mounts || zconf_mount `hostname` $MOUNT
}

mkdir -p $DIR
$SETUP

if [ "$ONLY" == "setup" ]; then
    exit 0
fi

online_ost_del() {
        cp -p $XMLCONFIG ${XMLCONFIG}.pre_del
	do_lmc --commit	
        do_lmc --delete ost --node ost_facet --ost ost_svc
	for mds in `mds_list`; do
        	do_facet ${mds} ${LCONF} --nomod --nosetup --write_conf --node ${mds}_facet  --ptldebug $PTLDEBUG $XMLCONFIG 
    	done
        
	for mds in `mds_list`; do
                MDS_CONFIG_UPDATE="/proc/fs/lustre/mds/${mds}_svc/config_update"
                echo \ > ${MDS_CONFIG_UPDATE} || rc=$?
        done
        echo \ > /proc/fs/lustre/llite/fs0/config_update || rc=$?
	cp -p $XMLCONFIG $XMLCONFIG.bak
	cp -p $XMLCONFIG.pre_del $XMLCONFIG 
	stop ost --force 
	cp -p $XMLCONFIG.bak $XMLCONFIG
}

online_ost_add() {
        do_lmc --commit
    	add_ost ost --lov lov1 --dev $OSTDEV --size $OSTSIZE || exit 3
	
	start ost --reformat $OSTLCONFARGS
	for mds in `mds_list`; do
        	do_facet ${mds} ${LCONF} --nomod --nosetup --write_conf --node ${mds}_facet --ptldebug $PTLDEBUG $XMLCONFIG 
    	done
	for mds in `mds_list`; do
                MDS_CONFIG_UPDATE="/proc/fs/lustre/mds/${mds}_svc/config_update"
                echo \ > ${MDS_CONFIG_UPDATE} || rc=$?
        done
        echo \ > /proc/fs/lustre/llite/fs0/config_update || rc=$?
}

test_1a() {
	dd if=/dev/urandom of=/mnt/lustre/a bs=1024 count=1024
	sync
	online_ost_del
	dd if=/dev/urandom of=/mnt/lustre/b bs=1024 count=1024
	sync
	online_ost_add
	dd if=/dev/urandom of=/mnt/lustre/c bs=1024 count=1024
}

run_test 1a "online ost add/del...."
$CLEANUP

