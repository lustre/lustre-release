#!/bin/sh

set -e

#
# This test needs to be run on the client
#

LUSTRE=${LUSTRE:-`dirname $0`/..}

. ${CONFIG:=$LUSTRE/tests/cfg/smfs.sh}

. $LUSTRE/tests/test-framework.sh

init_test_env $@


build_test_filter

assert_env MDSCOUNT

lsync() {
        name=$1
        device=`$LCTL device_list | grep " $name " | awk '{print $1}'`
        
        [ -z $device ] && {
                echo "Can't find device $name"
                return 1
        }
${LCTL} << EOF
device $device
lsync
EOF
        return $?
}
gen_config() {
	rm -f $XMLCONFIG

    	add_lmv cache_lmv_svc
	set -vx 
    	add_mds $CACHE_MDS --dev $MDS_CACHE_DEV --size $MDSSIZE --lmv cache_lmv_svc \
            --mountfsoptions $MDS_MOUNT_OPS  || exit 10
	set -e
    	add_lmv master_lmv_svc
    	add_mds $MASTER1_MDS --dev $MDS_MASTER1_DEV --size $MDSSIZE --lmv master_lmv_svc

    	add_lov_to_cache_master_lmv lov1 cache_lmv_svc master_lmv_svc --stripe_sz $STRIPE_BYTES \
				--stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0

    	add_ost ost --lov lov1 --dev $OSTDEV --size $OSTSIZE

    	add_cmobd cmobd_mds ${CACHE_MDS}_svc master_lmv_svc  

    	do_lmc --add cobd --node client_facet --cobd cobd_svc --cache_obd cache_lmv_svc \
		   --master_obd master_lmv_svc  
    
    	add_client client cobd --lov lov1 --path $MOUNT
}

build_test_filter

cleanup() {
    	zconf_umount `hostname` $MOUNT
    	stop $CACHE_MDS ${FORCE} $MDSLCONFARGS
    	stop $MASTER1_MDS ${FORCE} $MDSLCONFARGS
    	stop ost ${FORCE} --dump cleanup.log
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
    	start ost --reformat $OSTLCONFARGS 
    	[ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE
    
    	start $MASTER1_MDS --reformat $MDSLCONFARGS
    	start $CACHE_MDS   --reformat $MDSLCONFARGS
    
    	grep " $MOUNT " /proc/mounts || zconf_mount `hostname` $MOUNT
}

$SETUP

if [ "$ONLY" == "setup" ]; then
    exit 0
fi

mkdir -p $DIR

test_1a() {
        rm -fr $DIR/1a0 > /dev/null

        echo "mkdir $DIR/1a0"
	mkdir $DIR/1a0 || error
        echo "cache flush on $NAME"
        lsync $CMOBD_NAME >/dev/null || error
        
        echo "touch $DIR/1a0/f0"
        touch $DIR/1a0/f0 || error
        echo "cache flush on $NAME"
        lsync $CMOBD_NAME >/dev/null || error
        
        echo "chmod +x $DIR/1a0/f0"
        chmod +x $DIR/1a0/f0 || error
        echo "cache flush on $NAME"
        lsync $CMOBD_NAME >/dev/null || error
        
        echo "mv $DIR/1a0/f0 $DIR/1a0/f01"
        mv $DIR/1a0/f0 $DIR/1a0/f01 || error
        echo "cache flush on $NAME"
        lsync $CMOBD_NAME >/dev/null || error
        
        echo "rm $DIR/1a0/f01"
        rm $DIR/1a0/f01 || error
        echo "cache flush on $NAME"
        lsync $CMOBD_NAME >/dev/null || error
        
        echo "touch $DIR/1a0/f01"
        touch $DIR/1a0/f01 || error
        echo "cache flush on $NAME"
        lsync $CMOBD_NAME >/dev/null || error
        
        echo "ln $DIR/1a0/f01 $DIR/1a0/f01h"
        ln $DIR/1a0/f01 $DIR/1a0/f01h || error
        echo "cache flush on $NAME"
        lsync $CMOBD_NAMEN >/dev/null || error
        
        echo "ln -s $DIR/1a0/f01 $DIR/1a0/f01s"
        ln -s $DIR/1a0/f01 $DIR/1a0/f01s || error

        rm -fr $DIR/1a0 > /dev/null
        echo "cache flush on $NAME"
        lsync $CMOBD_NAME >/dev/null || error
}
run_test 1a " WB test (lsync after each MD operation)============="

test_1b() {
        echo "mkdir $DIR/1b0"
	mkdir $DIR/1b0 || error
        echo "touch $DIR/1b0/f0"
        touch $DIR/1b0/f0 || error
        echo "chmod +x $DIR/1b0/f0"
        chmod +x $DIR/1b0/f0 || error
        echo "mv $DIR/1b0/f0 $DIR/1b0/f01"
        mv $DIR/1b0/f0 $DIR/1b0/f01 || error
        echo "rm $DIR/1b0/f01"
        rm $DIR/1b0/f01 || error
        echo "touch $DIR/1b0/f01"
        touch $DIR/1b0/f01 || error
        echo "ln $DIR/1b0/f01 $DIR/1b0/f01h"
        ln $DIR/1b0/f01 $DIR/1b0/f01h || error
        echo "ln -s $DIR/1b0/f01 $DIR/1b0/f01s"
        ln -s $DIR/1b0/f01 $DIR/1b0/f01s || error

        rm -fr $DIR/1b0 > /dev/null
        echo "cache flush on $NAME"
        lsync $CMOBD_NAME >/dev/null || error
}
run_test 1b " WB test (lsync after bunch of MD operarions)============="

test_2a() {
        echo "mkdir $DIR/2a0"
	mkdir $DIR/2a0 || error 
        echo "createmany -o $DIR/2a0/f 4000"
	createmany -o $DIR/2a0/f 4000
        echo "cache flush on $NAME"
        lsync $CMOBD_NAME >/dev/null || error
}

run_test 2a " WB test (flush createmany on master LMV) ======================"
test_2b() {
        echo "find $DIR/2a0 -type f -exec rm -f {} \;"
	find $DIR/2a0 -type f -exec rm -f {} \;
	rmdir $DIR/2a0 || error
        echo "cache flush on $NAME"
        lsync $CMOBD_NAME >/dev/null || error
}
run_test 2b " WB test (flush delmany on master LMV) ========================="

$CLEANUP

