#!/bin/bash
#
# WARNING: these tests will delete all data on your
#          Lustre mount point!
#
# The QOS tests need two nodes. The first acts as server (variable SERVER),
# the second as client only.
# The principle behind the QOS unit test is:
# 1) create an unbalanced situation on SERVER
# 2) perform opertion on CLIENT to trigger QOS information update
# 3) verify usage of new QOS information on CLIENT
#
# The QOS trigger must be applied on the server and the client
# node, since LOV operations can be executed on the MDS
# or on the client.
#
SERVER=${SERVER:-`hostname`}
# must change client to a valid hostname
CLIENT=${CLIENT:-""}
#
# number of files created
ALOT=100
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# e.g. ONLY="22 23" or ONLY="`seq 32 39`" or EXCEPT="31"
set -e

ONLY=${ONLY:-"$*"}
# bug number for skipped test:
ALWAYS_EXCEPT=${ALWAYS_EXCEPT:-""}
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!


SRCDIR=`dirname $0`
PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$PATH

LFIND=${LFIND:-lfind}
LSTRIPE=${LSTRIPE:-lstripe}
LCTL=${LCTL:-lctl}
RSH=${RSH:-rsh}
CHECKSTAT=${CHECKSTAT:-"checkstat -v"}

QOSPROC="/proc/sys/lustre"

export NAME=${NAME:-qos-config}

SAVE_PWD=$PWD
FULL_SRCDIR=${SAVE_PWD}/${SRCDIR}

clean() {
	echo -n "cln.."
	${RSH} ${CLIENT} "cd ${FULL_SRCDIR}; NAME=${NAME} NODE=client sh ./llmountcleanup.sh" > /dev/null || exit 20
	sh llmountcleanup.sh > /dev/null || exit 21
	I_MOUNTED=no
}
CLEAN=${CLEAN:-clean}

start() {
	echo -n "mnt.."
	sh llrmount.sh > /dev/null || exit 10
	${RSH} ${CLIENT} "cd ${FULL_SRCDIR}; NAME=${NAME} NODE=client sh ./llrmount.sh" > /dev/null || exit 11
	I_MOUNTED=yes
	echo "done"
}
START=${START:-start}

log() {
	echo "$*"
	lctl mark "$*" 2> /dev/null || true
}

run_one() {
	if ! mount | grep -q $DIR; then
		$START
	fi
	log "== test $1: $2"
	test_$1 || error "test_$1: $?"
	pass
	cd $SAVE_PWD
	$CLEAN
}

build_test_filter() {
        for O in $ONLY; do
            eval ONLY_${O}=true
        done
        for E in $EXCEPT $ALWAYS_EXCEPT; do
            eval EXCEPT_${E}=true
        done
}

_basetest() {
    echo $*
}

basetest() {
    IFS=abcdefghijklmnopqrstuvwxyz _basetest $1
}

run_test() {
         base=`basetest $1`
         if [ "$ONLY" ]; then
                 testname=ONLY_$1
                 if [ ${!testname}x != x ]; then
 			run_one $1 "$2"
 			return $?
                 fi
                 testname=ONLY_$base
                 if [ ${!testname}x != x ]; then
                         run_one $1 "$2"
                         return $?
                 fi
                 echo -n "."
                 return 0
 	fi
        testname=EXCEPT_$1
        if [ ${!testname}x != x ]; then
                 echo "skipping excluded test $1"
                 return 0
        fi
        testname=EXCEPT_$base
        if [ ${!testname}x != x ]; then
                 echo "skipping excluded test $1 (base $base)"
                 return 0
        fi
        run_one $1 "$2"
 	return $?
}

error() { 
	log "FAIL: $@"
	exit 1
}

pass() { 
	echo PASS
}

[ -z "${CLIENT}" ] && echo "CLIENT must not be empty"  && exit 96

MOUNT="`mount | awk '/^'$NAME' .* lustre_lite / { print $3 }'`"
if [ -z "$MOUNT" ]; then
	sh llmount.sh
	MOUNT="`mount | awk '/^'$NAME' .* lustre_lite / { print $3 }'`"
	[ -z "$MOUNT" ] && error "NAME=$NAME not mounted"
	I_MOUNTED=yes
	${RSH} ${CLIENT} "cd ${FULL_SRCDIR}; NAME=${NAME} NODE=client sh ./llrmount.sh" || exit 97
	CLIENT_MOUNT="`${RSH} ${CLIENT} mount | awk '/^'$NAME' .* lustre_lite / { print $3 }'`"
	[ -z "${CLIENT_MOUNT}" ] && echo "NAME=${NAME} not mounted on remote client ${CLIENT}"  && exit 98
fi

[ `echo $MOUNT | wc -w` -gt 1 ] && error "NAME=$NAME mounted more than once"

DIR=${DIR:-$MOUNT}
[ -z "`echo $DIR | grep $MOUNT`" ] && echo "$DIR not in $MOUNT" && exit 99

LOVNAME=`cat /proc/fs/lustre/llite/fs0/lov/common_name`
STRIPECOUNT=`cat /proc/fs/lustre/lov/$LOVNAME/numobd`

rm -rf $DIR/[Rdfs][1-9]*

build_test_filter

# check whether the QOS tunable parameters
# are present, i.e. the QOS code is in the tree
test_0() {
    cat ${QOSPROC}/QoS_statfs_interval || error
    cat ${QOSPROC}/QoS_rescan_interval || error
    cat ${QOSPROC}/QoS_update_interval || error
    cat ${QOSPROC}/QoS_freeblock_imbalance || error
    cat ${QOSPROC}/QoS_freeblock_percent || error
    cat ${QOSPROC}/QoS_nobjects_imbalance || error
}
run_test 0 "cat ${QOSPROC}/QoS_*"

# check whether the QOS tunable parameters
# are present, i.e. the QOS code is in the tree
# also on the second node
test_1() {
    ${RSH} ${CLIENT} cat ${QOSPROC}/QoS_statfs_interval || error
    ${RSH} ${CLIENT} cat ${QOSPROC}/QoS_rescan_interval || error
    ${RSH} ${CLIENT} cat ${QOSPROC}/QoS_update_interval || error
    ${RSH} ${CLIENT} cat ${QOSPROC}/QoS_freeblock_imbalance || error
    ${RSH} ${CLIENT} cat ${QOSPROC}/QoS_freeblock_percent || error
    ${RSH} ${CLIENT} cat ${QOSPROC}/QoS_nobjects_imbalance || error
}
run_test 1 "${RSH} ${CLIENT} cat ${QOSPROC}/QoS_*"

qos_setval() {
    # use == not eq, since eq will fail on the large numbers
    if [ -z $3 ]; then
	echo $2 > ${QOSPROC}/$1
	[ `cat ${QOSPROC}/$1` == $2 ] || return 1
    else
	${RSH} $3 "echo $2 > ${QOSPROC}/$1"
	[ `${RSH} $3 cat ${QOSPROC}/$1` == $2 ] || return 1
    fi
    return 0
}

# check whether we can set the minum and maximum values
test_2() {
    qos_setval QoS_statfs_interval 0 || error
    qos_setval QoS_statfs_interval 86400 || error
    qos_setval QoS_rescan_interval 1 || error
    qos_setval QoS_rescan_interval 604800 || error
    qos_setval QoS_update_interval 0 || error
    qos_setval QoS_update_interval 86400 || error
    qos_setval QoS_freeblock_imbalance 0 || error
    qos_setval QoS_freeblock_imbalance 4294967295 || error
    qos_setval QoS_freeblock_percent 0 || error
    qos_setval QoS_freeblock_percent 100 || error
    qos_setval QoS_nobjects_imbalance 0 || error
    qos_setval QoS_nobjects_imbalance 4294967295 || error
}
run_test 2 "set min/max in ${QOSPROC}/QoS_*"

imbalance_setup() {
    # set statfs caching to 1 jiffie on server
    qos_setval QoS_statfs_interval 0 || error
    # make QOS updates immediate (1 jiffie) on MDS and client
    qos_setval QoS_update_interval 0 || error
    qos_setval QoS_update_interval 0 ${CLIENT} || error
    # disable nobjects and percent policies on MDS and client
    qos_setval QoS_freeblock_percent 100 || error
    qos_setval QoS_freeblock_percent 100 ${CLIENT} || error
    qos_setval QoS_nobjects_imbalance 4294967295 || error
    qos_setval QoS_nobjects_imbalance 4294967295 ${CLIENT} || error
    # enable freeblock policy on MDS and client
    qos_setval QoS_freeblock_imbalance 0 || error
    qos_setval QoS_freeblock_imbalance 0 ${CLIENT} || error
    # initialize QoS on MDS and client
    df $MOUNT > /dev/null
    ${RSH} ${CLIENT} df $MOUNT > /dev/null
    # create imbalance on local mount
    for ((i=0; $i<$ALOT; i=$i+1)); do
	${LSTRIPE} $1/imbalance$i 0 $2 1 || error
	echo "hello, world" > $1/imbalance$i
    done
}

imbalance_check() {
    # create a lot of files on the remote node
    for ((i=0; $i<$ALOT; i=$i+1)); do
	${RSH} ${CLIENT} "cd ${FULL_SRCDIR}; PATH=$FULL_SRCDIR/../utils:\$PATH ${LSTRIPE} $1/test$i 0 -1 1" || error
    done
    for ((i=0; $i<$ALOT; i=$i+1)); do
	# get the OST number for each new file
	obd=`${LFIND} $1/test$i | tail -2 | head -1 | awk '{ print $1 }'`
        # the file must not be on OST $2, since we are still imbalanced
	if [ $obd -eq $2 ]; then
	    echo "$1/test$i OST $obd"
	    error
	fi
    done
}

# check whether create updates QOS information
test_3a() {
    # create test directory
    mkdir $DIR/d3a || error
    imbalance_setup $DIR/d3a 0
    # create a file on the MDS and the remote node (this is the QOS update trigger)
    ${LSTRIPE} $DIR/d3a/trigger1 0 0 1 || error
    ${RSH} ${CLIENT} "cd ${FULL_SRCDIR}; PATH=$FULL_SRCDIR/../utils:\$PATH ${LSTRIPE} $DIR/d3a/trigger2 0 0 1" || error
    imbalance_check $DIR/d3a 0
    rm -rf $DIR/d3a
}
run_test 3a "check QOS propagation on create"

# check whether delete updates QOS information
test_3b() {
    # create test directory
    mkdir $DIR/d3b || error
    # create two files for later removal
    ${LSTRIPE} $DIR/d3b/trigger1 0 0 1 || error
    ${LSTRIPE} $DIR/d3b/trigger2 0 0 1 || error
    imbalance_setup $DIR/d3b 0
    # remove the trigger files (this is the QOS update trigger) on both nodes
    rm -f $DIR/d3b/trigger1 || error
    ${RSH} ${CLIENT} "rm -f $DIR/d3b/trigger2" || error
    imbalance_check $DIR/d3b 0
    rm -rf $DIR/d3b
}
run_test 3b "check QOS propagation on delete"

# check whether getattr updates QOS information
test_3c() {
    # create test directory
    mkdir $DIR/d3c || error
    # create two files for later stat
    ${LSTRIPE} $DIR/d3c/trigger1 0 0 1 || error
    ${LSTRIPE} $DIR/d3c/trigger2 0 0 1 || error
    imbalance_setup $DIR/d3c 0
    # stat the trigger files (this is the QOS update trigger) on both nodes
    stat $DIR/d3c/trigger1 > /dev/null || error
    ${RSH} ${CLIENT} "stat $DIR/d3c/trigger2 > /dev/null" || error
    imbalance_check $DIR/d3c 0
    rm -rf $DIR/d3c
}
run_test 3c "check QOS propagation on getattr"

# check whether setattr updates QOS information
test_3d() {
    # create test directory
    mkdir $DIR/d3d || error
    # create two files for later chmod
    ${LSTRIPE} $DIR/d3d/trigger1 0 0 1 || error
    ${LSTRIPE} $DIR/d3d/trigger2 0 0 1 || error
    imbalance_setup $DIR/d3d 0
    # chmod the trigger files (this is the QOS update trigger) on both nodes
    chmod 777 $DIR/d3d/trigger1 || error
    ${RSH} ${CLIENT} "chmod 777 $DIR/d3d/trigger2" || error
    imbalance_check $DIR/d3d 0
    rm -rf $DIR/d3d
}
run_test 3d "check QOS propagation on setattr"

# check whether open/close updates QOS information
test_3e() {
    # create test directory
    mkdir $DIR/d3e || error
    # create two files for later cat (open/close)
    ${LSTRIPE} $DIR/d3e/trigger1 0 0 1 || error
    ${LSTRIPE} $DIR/d3e/trigger2 0 0 1 || error
    imbalance_setup $DIR/d3e 0
    # cat (open/close) the trigger files (this is the QOS update trigger) on both nodes
    cat $DIR/d3e/trigger1 || error
    ${RSH} ${CLIENT} "cat $DIR/d3e/trigger2" || error
    imbalance_check $DIR/d3e 0
    rm -rf $DIR/d3e
}
run_test 3e "check QOS propagation on open/close"

# check whether punch updates QOS information
test_3f() {
    # create test directory
    mkdir $DIR/d3f || error
    # create two files for later truncate
    ${LSTRIPE} $DIR/d3f/trigger1 0 0 1 || error
    ${LSTRIPE} $DIR/d3f/trigger2 0 0 1 || error
    imbalance_setup $DIR/d3f 0
    # truncate the trigger files (this is the QOS update trigger) on both nodes
    ./truncate $DIR/d3f/trigger1 1 || error
    ${RSH} ${CLIENT} "cd ${FULL_SRCDIR}; ./truncate $DIR/d3f/trigger2 1" || error
    imbalance_check $DIR/d3f 0
    rm -rf $DIR/d3f
}
run_test 3f "check QOS propagation on punch"

TMPDIR=$OLDTMPDIR
TMP=$OLDTMP
HOME=$OLDHOME

log "cleanup: ======================================================"
CLIENT_MOUNT="`${RSH} ${CLIENT} mount | awk '/^'$NAME' .* lustre_lite / { print $3 }'`"
if [ "${CLIENT_MOUNT}" ]; then
	${RSH} ${CLIENT} "cd ${FULL_SRCDIR}; NAME=${NAME} NODE=client sh ./llmountcleanup.sh" || error
fi
if [ "$I_MOUNTED" = "yes" -a "`mount | grep ^$NAME`" ]; then
	rm -rf $DIR/[Rdfs][1-9]*
	sh llmountcleanup.sh || error
fi

echo '=========================== finished ==============================='
