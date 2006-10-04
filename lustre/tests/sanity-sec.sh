#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# TODO: support rootsquash test
set -e

SRCDIR=`dirname $0`
export PATH=$PWD/$SRCDIR:$SRCDIR:$PWD/$SRCDIR/../utils:$PATH:/sbin

ONLY=${ONLY:-"$*"}
ALWAYS_EXCEPT=${ALWAYS_EXCEPT:-""}
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

[ "$ALWAYS_EXCEPT$EXCEPT" ] && \
	echo "Skipping tests: `echo $ALWAYS_EXCEPT $EXCEPT`"

TMP=${TMP:-/tmp}

LFS=${LFS:-lfs}
LCTL=${LCTL:-lctl}
RUNAS=${RUNAS:-runas}

log() {
	echo "$*"
	$LCTL mark "$*" 2> /dev/null || true
}

run_one() {
	BEFORE=`date +%s`
	log "== test $2= `date +%H:%M:%S` ($BEFORE)"
	export TESTNAME=test_$1
	test_$1 || error "exit with rc=$?"
	unset TESTNAME
	pass "($((`date +%s` - $BEFORE))s)"
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

SANITYSECLOG=${SANITYSECLOG:-/tmp/sanity-sec.log}

[ "$SANITYSECLOG" ] && rm -f $SANITYSECLOG || true

error() { 
	sysctl -w lustre.fail_loc=0
	log "FAIL: $TESTNAME $@"
	if [ "$SANITYSECLOG" ]; then
		echo "FAIL: $TESTNAME $@" >> $SANITYSECLOG
	else
		exit 1
	fi
}

pass() { 
	echo PASS $@
}

mounted_lustre_filesystems() {
	awk '($3 ~ "lustre" && $1 ~ ":") { print $2 }' /proc/mounts
}
MOUNT="`mounted_lustre_filesystems`"
if [ -z "$MOUNT" ]; then
        formatall
        setupall
	MOUNT="`mounted_lustre_filesystems`"
	[ -z "$MOUNT" ] && error "NAME=$NAME not mounted"
	I_MOUNTED=yes
fi

[ `echo $MOUNT | wc -w` -gt 1 ] && error "NAME=$NAME mounted more than once"

DIR=${DIR:-$MOUNT}
[ -z "`echo $DIR | grep $MOUNT`" ] && echo "$DIR not in $MOUNT" && exit 99

if [ -z "`lsmod|grep mdt`" ]; then
	echo "skipping $TESTNAME (remote MDT)"
	exit 0
fi

LPROC=/proc/fs/lustre
ENABLE_IDENTITY=/usr/sbin/l_getidentity
DISABLE_IDENTITY=NONE
LOVNAME=`cat $LPROC/llite/*/lov/common_name | tail -n 1`
MDT=$(\ls $LPROC/mdt 2> /dev/null | grep -v num_refs | tail -n 1)
TSTDIR="$MOUNT/remote_user_dir"
LUSTRE_CONF_DIR=/etc/lustre
SETXID_CONF=$LUSTRE_CONF_DIR/setxid.conf
IDENTITY_UPCALL=$LPROC/mdt/$MDT/identity_upcall
IDENTITY_FLUSH=$LPROC/mdt/$MDT/identity_flush
ROOTSQUASH_UID=$LPROC/mdt/$MDT/rootsquash_uid
ROOTSQUASH_GID=$LPROC/mdt/$MDT/rootsquash_gid
ROOTSQUASH_SKIPS=$LPROC/mdt/$MDT/rootsquash_skips
KRB5_REALM=`cat /etc/krb5.conf |grep default_realm| awk '{ print $3 }'`
USER1=`cat /etc/passwd|grep :500:|cut -d: -f1`
USER2=`cat /etc/passwd|grep :501:|cut -d: -f1`

build_test_filter

setup() {
	rm -f $SETXID_CONF
	echo $ENABLE_IDENTITY > $IDENTITY_UPCALL
	echo 1 > $IDENTITY_FLUSH
	$RUNAS -u 500 ls $DIR
	$RUNAS -u 501 ls $DIR
}
setup

# run as different user
test_0() {
	rm -rf $DIR/d0
	mkdir $DIR/d0

	chown $USER1 $DIR/d0 || error
	$RUNAS -u 500 ls $DIR || error
	$RUNAS -u 500 touch $DIR/f0 && error
	$RUNAS -u 500 touch $DIR/d0/f1 || error
	$RUNAS -u 501 touch $DIR/d0/f2 && error
	touch $DIR/d0/f3 || error
	chown root $DIR/d0
	chgrp $USER1 $DIR/d0
	chmod 775 $DIR/d0
	$RUNAS -u 500 touch $DIR/d0/f4 || error
	$RUNAS -u 501 touch $DIR/d0/f5 && error
	touch $DIR/d0/f6 || error

	rm -rf $DIR/d0
}
run_test 0 "uid permission ============================="

# setuid/gid
test_1() {
	rm -rf $DIR/d1
	mkdir $DIR/d1

	chown $USER1 $DIR/d1 || error
	$RUNAS -u 501 -v 500 touch $DIR/d1/f0 && error
	echo "* 501 setuid" > $SETXID_CONF
	echo "enable uid 501 setuid"
	echo 1 > $IDENTITY_FLUSH
	$RUNAS -u 501 -v 500 touch $DIR/d1/f1 || error

	chown root $DIR/d1
	chgrp $USER1 $DIR/d1
	chmod 770 $DIR/d1
	$RUNAS -u 501 -g 501 touch $DIR/d1/f2 && error
	echo "* 501 setuid,setgid" > $SETXID_CONF
	echo "enable uid 501 setuid,setgid"
	echo 1 > $IDENTITY_FLUSH
	$RUNAS -u 501 -g 501 -j 500 touch $DIR/d1/f3 || error
	$RUNAS -u 501 -v 500 -g 501 -j 500 touch $DIR/d1/f4 || error

	rm -f $SETXID_CONF
	rm -rf $DIR/d1
	echo 1 > $IDENTITY_FLUSH
}
run_test 1 "setuid/gid ============================="

# lfs getfacl/setfacl
test_2() {
	rm -rf $DIR/d2
	mkdir $DIR/d2
	chmod 755 $DIR/d2
	echo xxx > $DIR/d2/f0
	chmod 644 $DIR/d2/f0

	$LFS getfacl $DIR/d2/f0 || error
	$RUNAS -u 500 cat $DIR/d2/f0 || error
	$RUNAS -u 500 touch $DIR/d2/f0 && error

	$LFS setfacl -m u:$USER1:w $DIR/d2/f0 || error
	$LFS getfacl $DIR/d2/f0 || error
	echo "set user $USER1 write permission on file $DIR/d2/fo"
	$RUNAS -u 500 touch $DIR/d2/f0 || error
	$RUNAS -u 500 cat $DIR/d2/f0 && error

	rm -rf $DIR/d2
}
run_test 2 "lfs getfacl/setfacl ============================="

# rootsquash
test_3() {
	[ -n "$SEC" ] && echo "ignore rootsquash test for single node" && return

	$LCTL conf_param $MDT security.rootsquash.skips=none
	while grep LNET_NID_ANY $ROOTSQUASH_SKIPS > /dev/null; do sleep 1; done
	$LCTL conf_param $MDT security.rootsquash.uid=0
	while [ "`cat $ROOTSQUASH_UID`" -ne 0 ]; do sleep 1; done
	$LCTL conf_param $MDT security.rootsquash.gid=0
	while [ "`cat $ROOTSQUASH_GID`" -ne 0 ]; do sleep 1; done

	rm -rf $DIR/d3
	mkdir $DIR/d3
	chown $USER1 $DIR/d3
	chmod 700 $DIR/d3
	$LCTL conf_param $MDT security.rootsquash.uid=500
	echo "set rootsquash uid = 500"
	while [ "`cat $ROOTSQUASH_UID`" -ne 500 ]; do sleep 1; done
	touch $DIR/f3_0 && error
	touch $DIR/d3/f3_1 || error

	$LCTL conf_param $MDT security.rootsquash.uid=0
	echo "disable rootsquash"
	while [ "`cat $ROOTSQUASH_UID`" -ne 0 ]; do sleep 1; done
	chown root $DIR/d3
	chgrp $USER2 $DIR/d3
	chmod 770 $DIR/d3

	$LCTL conf_param $MDT security.rootsquash.uid=500
	echo "set rootsquash uid = 500"
	while [ "`cat $ROOTSQUASH_UID`" -ne 500 ]; do sleep 1; done
	touch $DIR/d3/f3_2 && error
	$LCTL conf_param $MDT security.rootsquash.gid=501
	echo "set rootsquash gid = 501"
	while [ "`cat $ROOTSQUASH_GID`" -ne 501 ]; do sleep 1; done
	touch $DIR/d3/f3_3 || error

	$LCTL conf_param $MDT security.rootsquash.skips=*
	echo "add host in rootsquash skip list"
	while ! grep LNET_NID_ANY $ROOTSQUASH_SKIPS > /dev/null;
		do sleep 1;
	done
	touch $DIR/f3_4 || error

	$LCTL conf_param $MDT security.rootsquash.uid=0
	while [ "`cat $ROOTSQUASH_UID`" -ne 0 ]; do sleep 1; done
	$LCTL conf_param $MDT security.rootsquash.gid=0
	while [ "`cat $ROOTSQUASH_GID`" -ne 0 ]; do sleep 1; done
	$LCTL conf_param $MDT security.rootsquash.skips=none
	rm -rf $DIR/d3
	rm -f $DIR/f3_?
}
run_test 3 "rootsquash ============================="

# bug 3285 - supplementary group should always succeed (see do_init_ucred),
# NB: the supplementary groups are set for local client only, as for remote
# client, the groups of the specified uid on MDT will be obtained by
# upcall /sbin/l_getidentity and used.
test_4() {
        mkdir $DIR/d4
        chmod 771 $DIR/d4
        chgrp 500 $DIR/d4
	$RUNAS -u 500 -G1,2,500 ls $DIR/d4 || error "setgroups failed"
	rm -rf $DIR/d4
}
run_test 4 "set supplementary group ==============="

log "cleanup: ======================================================"
if [ "$I_MOUNTED" = "yes" ]; then
	cleanupall -f || error "cleanup failed"
fi

echo '=========================== finished ==============================='
