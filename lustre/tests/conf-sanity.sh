#!/bin/bash
# requirement:
#	add uml1 uml2 uml3 in your /etc/hosts

set -e

SRCDIR=`dirname $0`
PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$PATH

LUSTRE=${LUSTRE:-`dirname $0`/..}
RLUSTRE=${RLUSTRE:-$LUSTRE}
ONLY=${ONLY:-"$*"}

. $LUSTRE/tests/test-framework.sh

init_test_env

mds_HOST=${mds_HOST:-`hostname`}
mdsfailover_HOST=${mdsfailover_HOST}
ost_HOST=${ost_HOST:-`hostname`}
client_HOST=${client_HOST:-`hostname`}
NETTYPE=${NETTYPE:-tcp}

MOUNT=${MOUNT:-"/mnt/lustre"}
MOUNT2=${MOUNT2:-"/mnt/lustre2"}
DIR=${DIR:-$MOUNT}
DIR2=${DIR2:-$MOUNT2}
PDSH=${PDSH:-'pdsh -S -w'}
MDSDEV=${MDSDEV:-/tmp/mds-`hostname`}
MDSSIZE=${MDSSIZE:-10000}
OSTDEV=${OSTDEV:-/tmp/ost-`hostname`}
OSTSIZE=${OSTSIZE:-10000}
FSTYPE=${FSTYPE:-ext3}
TIMEOUT=${TIMEOUT:-5}
CONFIG=${CONFIG:-"$XMLCONFIG"}
LCONF=${LCONF:-"lconf"}
LCTL=${LCTL:-"lctl"}
FORCE=${FORCE:-" --force"}
DAEMONFILE=${DAEMONFILE:-"/r/tmp/debug-daemon"}
DAEMONSIZE=${DAEMONSIZE:-"40"}

STRIPE_BYTES=65536
STRIPES_PER_OBJ=0

do_command() {
    	local node=$1
	shift 
	$PDSH $node "PATH=\$PATH:$RLUSTRE/utils:$RLUSTRE/tests; cd $RPWD; $@" 
}

gen_config() {
	rm -f $XMLCONFIG
	add_facet mds 
        add_facet ost 	
	add_facet client 	

	do_lmc --add mds --node mds_facet --mds mds1 --dev $MDSDEV --size $MDSSIZE
	do_lmc --add lov --mds mds1 --lov lov1 --stripe_sz $STRIPE_BYTES --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
	do_lmc --add ost --lov lov1 --node ost_facet --ost ost1 --dev $OSTDEV --size $OSTSIZE
	do_lmc --add mtpt --node client_facet --path $MOUNT --mds mds1 --lov lov1
}

gen_second_config() {
	rm -f $XMLCONFIG
	add_facet mds 	 
	add_facet ost 	
	add_facet client 	

	do_lmc --add mds --node mds_facet --mds mds1 --dev $MDSDEV --size $MDSSIZE
	do_lmc --add lov --mds mds1 --lov lov2 --stripe_sz $STRIPE_BYTES --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
	do_lmc --add ost --lov lov2 --node ost_facet --ost ost1 --dev $OSTDEV --size $OSTSIZE
	do_lmc --add mtpt --node client_facet --path $MOUNT2 --mds mds1 --lov lov2
}
start_mds() {
	echo "start mds service on ${mds_HOST}...."
	start mds --reformat $MDSLCONFARGS > /dev/null || exit 94
}
stop_mds() {
	echo "stop mds service on ${mds_HOST}...."
	stop mds $@ > /dev/null || exit 97 
}

start_ost() {
	echo "start ost service on ${mds_HOST}...."
	start ost --reformat $OSTLCONFARGS > /dev/null || exit 95
}

stop_ost() {
	echo "stop ost service on ${mds_HOST}...."
	stop ost $@ > /dev/null || exit 98 
}

mount_client() {
	local MOUNTPATH=$1
	echo "mount lustre on ${MOUNTPATH}....."
	zconf_mount $MOUNTPATH > /dev/null || exit 96
}

umount_client() {
	local MOUNTPATH=$1
	echo "umount lustre on ${MOUNTPATH}....."
	zconf_umount $MOUNTPATH > /dev/null || exit 97
}

manual_umount_client(){
	echo "manual umount lustre on ${MOUNTPATH}...."
	do_command  $client_HOST "umount $MOUNT"
}

setup() {
	start_ost
	start_mds
	mount_client $MOUNT 
}

cleanup() {
 	umount_client $MOUNT 	
	stop_mds 
	stop_ost 
}

check_mount() {
	do_command $client_HOST "touch $DIR/a" || exit 71	
	do_command $client_HOST "rm $DIR/a" || exit 72	
	echo "setup single mount lustre success"
}

check_mount2() {
	do_command $client_HOST "touch $DIR/a" || exit 71	
	do_command $client_HOST "rm $DIR/a" || exit 72	
	do_command $client_HOST "touch $DIR2/a" || exit 73	
	do_command $client_HOST "rm $DIR2/a" || exit 74	
	echo "setup double mount lustre success"
}

build_test_filter

#create single point mountpoint

gen_config


test_0() {
	start_ost
	start_mds	
	mount_client $MOUNT  
	check_mount || exit 41
	cleanup  
}
run_test 0 "single mount setup"

test_1() {
	start_ost
	echo "start ost second time..."
	start ost --reformat $OSTLCONFARGS > /dev/null 
	start_mds	
	mount_client $MOUNT
	check_mount || exit 42
	cleanup 
}
run_test 1 "start up ost twice"

test_2() {
	start_ost
	start_mds	
	echo "start mds second time.."
	start mds --reformat $MDSLCONFARGS > /dev/null 
	
	mount_client $MOUNT  
	check_mount || exit 43
	cleanup 
}
run_test 2 "start up mds twice"

test_3() {
	start_ost
	start_mds

	mount_client $MOUNT  
	mount_client $MOUNT

	check_mount || exit 44
	
	cleanup  
}
run_test 3 "mount client twice"

test_4() {
	setup
	touch $DIR/a || exit 85
	stop_ost ${FORCE}

	cleanup  
}
run_test 4 "force cleanup ost, then cleanup"

test_5() {
	setup
	touch $DIR/a || exit 86
	stop_mds ${FORCE} || exit 98
	cleanup  
}
run_test 5 "force cleanup mds, then cleanup"

test_6() {
	setup
	manual_umount_client
	mount_client ${MOUNT} || exit 87
	touch $DIR/a || exit 86
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

	check_mount2 || exit 45
	umount $MOUNT
	umount_client $MOUNT2  
	
	stop_mds
	stop_ost

}
run_test 8 "double mount setup"

gen_config

