#!/bin/bash
# requirement:
#	add uml1 uml2 uml3 in your /etc/hosts

set -e

SRCDIR=`dirname $0`
PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$PATH

LUSTRE=${LUSTRE:-`dirname $0`/..}
RLUSTRE=${RLUSTRE:-$LUSTRE}

. $LUSTRE/tests/test-framework.sh

init_test_env $@

. ${CONFIG:=$LUSTRE/tests/cfg/local.sh}

FORCE=${FORCE:-" --force"}

gen_config() {
	rm -f $XMLCONFIG

	add_mds mds --dev $MDSDEV --size $MDSSIZE
	add_lov lov1 mds --stripe_sz $STRIPE_BYTES\
	    --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
	add_ost ost --lov lov1 --dev $OSTDEV --size $OSTSIZE
	add_client client mds --lov lov1 --path $MOUNT
}

gen_second_config() {
	rm -f $XMLCONFIG

	add_mds mds2 --dev $MDSDEV --size $MDSSIZE
	add_lov lov2 mds2 --stripe_sz $STRIPE_BYTES\
	    --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
	add_ost ost2 --lov lov2 --dev $OSTDEV --size $OSTSIZE
	add_client client mds2 --lov lov2 --path $MOUNT2
}

start_mds() {
	echo "start mds service on `facet_active_host mds`"
	start mds --reformat $MDSLCONFARGS > /dev/null || return 94
}
stop_mds() {
	echo "stop mds service on `facet_active_host mds`"
	stop mds $@ > /dev/null || return 97 
}

start_ost() {
	echo "start ost service on `facet_active_host ost`"
	start ost --reformat $OSTLCONFARGS > /dev/null || return 95
}

stop_ost() {
	echo "stop ost service on `facet_active_host ost`"
	stop ost $@ > /dev/null || return 98 
}

mount_client() {
	local MOUNTPATH=$1
	echo "mount lustre on ${MOUNTPATH}....."
	zconf_mount $MOUNTPATH > /dev/null || return 96
}

umount_client() {
	local MOUNTPATH=$1
	echo "umount lustre on ${MOUNTPATH}....."
	zconf_umount $MOUNTPATH > /dev/null || return 97
}

manual_umount_client(){
	echo "manual umount lustre on ${MOUNTPATH}...."
	do_facet  client "umount $MOUNT"
}

setup() {
	start_ost
	start_mds
	mount_client $MOUNT 
}

cleanup() {
 	umount_client $MOUNT || return -200
	stop_mds  || return -201
	stop_ost || return -202
}

check_mount() {
	do_facet client "touch $DIR/a" || return 71	
	do_facet client "rm $DIR/a" || return 72	
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

#create single point mountpoint

gen_config


test_0() {
	start_ost
	start_mds	
	mount_client $MOUNT  
	check_mount || return 41
	cleanup  
}
run_test 0 "single mount setup"

test_1() {
	start_ost
	echo "start ost second time..."
	start ost --reformat $OSTLCONFARGS > /dev/null 
	start_mds	
	mount_client $MOUNT
	check_mount || return 42
	cleanup 
}
run_test 1 "start up ost twice"

test_2() {
	start_ost
	start_mds	
	echo "start mds second time.."
	start mds --reformat $MDSLCONFARGS > /dev/null 
	
	mount_client $MOUNT  
	check_mount || return 43
	cleanup 
}
run_test 2 "start up mds twice"

test_3() {
        setup
	mount_client $MOUNT

	check_mount || return 44
	
 	umount_client $MOUNT 	
	cleanup  
}
run_test 3 "mount client twice"

test_4() {
	setup
	touch $DIR/$tfile || return 85
	stop_ost ${FORCE}

	# cleanup may return an error from the failed 
	# disconnects; for now I'll consider this successful 
	# if all the modules have unloaded.
	if ! cleanup ; then
	    lsmod | grep -q portals && return 1
        fi
	return 0
}
run_test 4 "force cleanup ost, then cleanup"

test_5() {
	setup
	touch $DIR/$tfile || return 86
	stop_mds ${FORCE} || return 98

	# cleanup may return an error from the failed 
	# disconnects; for now I'll consider this successful 
	# if all the modules have unloaded.
	if ! cleanup ; then
	    lsmod | grep -q portals && return 1
        fi
	return 0
}
run_test 5 "force cleanup mds, then cleanup"

test_6() {
	setup
	manual_umount_client
	mount_client ${MOUNT} || return 87
	touch $DIR/a || return 86
	cleanup 
}
run_test 6 "manual umount, then mount again"

test_7() {
	setup
	manual_umount_client
	cleanup 
}
run_test 7 "manual umount, then cleanup"

test_8() {
	start_ost
	start_mds

	mount_client $MOUNT  
	mount_client $MOUNT2 

	check_mount2 || return 45
	umount $MOUNT
	umount_client $MOUNT2  
	
	stop_mds
	stop_ost
}
run_test 8 "double mount setup"

test_9() {
        # backup the old values of PTLDEBUG and SUBSYSTEM
        OLDPTLDEBUG=$PTLDEBUG
        OLDSUBSYSTEM=$SUBSYSTEM
        
        # generate new configuration file with lmc --ptldebug and --subsystem
        PTLDEBUG="trace"
        SUBSYSTEM="mdc"
        gen_config

        # check the result of lmc --ptldebug/subsystem
        start_ost
        start_mds
        mount_client $MOUNT
        [ "`cat /proc/sys/portals/debug`" = "1" ] && \
           echo "lmc --debug success" || return 1
        [ "`cat /proc/sys/portals/subsystem_debug`" = "16777216" ] && \
           echo "lmc --subsystem success" || return 1
        check_mount || return 41
        cleanup

        # the new PTLDEBUG/SUBSYSTEM used for lconf --ptldebug/subsystem
        PTLDEBUG="inode"
        SUBSYSTEM="mds"

        # check lconf --ptldebug/subsystem overriding lmc --ptldebug/subsystem
        start_ost
        start_mds
        mount_client $MOUNT
        [ "`cat /proc/sys/portals/debug`" = "2" ] && \
           echo "lconf --debug overriding success" || return 1
        [ "`cat /proc/sys/portals/subsystem_debug`" = "33554432" ] && \
           echo "lconf --subsystem overriding success" || return 1
        check_mount || return 41
        cleanup

        # resume the old configuration
        PTLDEBUG=$OLDPTLDEBUG
        SUBSYSTEM=$OLDSUBSYSTEM
        gen_config
}
run_test 9 "test --ptldebug and --subsystem for lmc"

test_10() {
        OLDXMLCONFIG=$XMLCONFIG
        XMLCONFIG="broken.xml"
        [ -f "$XMLCONFIG" ] && rm -f $XMLCONFIG
        SAMENAME="mds1"
        do_lmc --add node --node $SAMENAME
        do_lmc --add net --node $SAMENAME --nid $SAMENAME --nettype tcp
        do_lmc --add mds --node $SAMENAME --mds $SAMENAME --nid $SAMENAME \
               --fstype ext3 --dev /dev/mds1 || return $?
        do_lmc --add lov --lov lov1 --mds $SAMENAME --stripe_sz 65536 \
               --stripe_cnt 1 --stripe_pattern 0 || return $?
        echo "Success!"
        XMLCONFIG=$OLDXMLCONFIG
}
run_test 10 "use lmc with the same name for node and mds"

test_11() {
        OLDXMLCONFIG=$XMLCONFIG
        XMLCONFIG="conf11.xml"

        [ -f "$XMLCONFIG" ] && rm -f $XMLCONFIG
        add_mds mds --dev $MDSDEV --size $MDSSIZE
        add_ost ost --dev $OSTDEV --size $OSTSIZE
        add_client client mds --path $MOUNT --ost ost_svc || return $?
        echo "Default lov config success!"
        
        [ -f "$XMLCONFIG" ] && rm -f $XMLCONFIG
        add_mds mds --dev $MDSDEV --size $MDSSIZE
        add_ost ost --dev $OSTDEV --size $OSTSIZE
        add_client client mds --path $MOUNT && return $?
        echo "--add mtpt with neither --lov nor --ost will return error"

        echo ""
        echo "Success!"
        XMLCONFIG=$OLDXMLCONFIG
}
run_test 11 "use default lov configuration (should return error)"

test_12() {
	setup
	$LCTL --device 1 probe
	$LCTL --device 2 probe
	check_mount
	cleanup
}
run_test 12 "enable local rpc, then cleanup"
	
equals_msg "Done"
