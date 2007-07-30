#!/bin/bash
#
# Run select tests by setting SEC_ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#

set -e

SRCDIR=`dirname $0`
export PATH=$PWD/$SRCDIR:$SRCDIR:$PWD/$SRCDIR/../utils:$PATH:/sbin

SEC_ONLY=${SEC_ONLY:-"$*"}
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

SANITYSECLOG=${SANITYSECLOG:-/tmp/sanity-sec.log}

[ "$SANITYSECLOG" ] && rm -f $SANITYSECLOG || true

sec_error() { 
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

ID1=500
ID2=501

USER1=`cat /etc/passwd|grep :$ID1:$ID1:|cut -d: -f1`
USER2=`cat /etc/passwd|grep :$ID2:$ID2:|cut -d: -f1`

if [ ! "$USER1" ]; then
	echo "===== Please add user1 (uid=$ID1 gid=$ID1)! Skip sanity-sec ====="
	sec_error "===== Please add user1 (uid=$ID1 gid=$ID1)! ====="
	exit 0
fi

if [ ! "$USER2" ]; then
	echo "===== Please add user2 (uid=$ID2 gid=$ID2)! Skip sanity-sec ====="
	sec_error "===== Please add user2 (uid=$ID2 gid=$ID2)! ====="
	exit 0
fi

export NAME=${NAME:-local}

LUSTRE=${LUSTRE:-`dirname $0`/..} 
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

if [ ! -z "$USING_KRB5" ]; then
    $RUNAS -u $ID1 krb5_login.sh || exit 1
    $RUNAS -u $ID2 krb5_login.sh || exit 1
fi

sec_run_one() {
	BEFORE=`date +%s`
	log "== test $1 $2= `date +%H:%M:%S` ($BEFORE)"
	export TESTNAME=test_$1
	test_$1 || sec_error "exit with rc=$?"
	unset TESTNAME
	pass "($((`date +%s` - $BEFORE))s)"
}

build_test_filter() {
        for O in $SEC_ONLY; do
            eval SEC_ONLY_${O}=true
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

sec_run_test() {
         base=`basetest $1`
         if [ "$SEC_ONLY" ]; then
                 testname=SEC_ONLY_$1
                 if [ ${!testname}x != x ]; then
 			sec_run_one $1 "$2"
 			return $?
                 fi
                 testname=SEC_ONLY_$base
                 if [ ${!testname}x != x ]; then
                         sec_run_one $1 "$2"
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
        sec_run_one $1 "$2"
 	return $?
}

mounted_lustre_filesystems() {
	awk '($3 ~ "lustre" && $1 ~ ":") { print $2 }' /proc/mounts
}

MOUNTED="`mounted_lustre_filesystems`"
if [ -z "$MOUNTED" ]; then
        formatall
        setupall
	MOUNTED="`mounted_lustre_filesystems`"
	[ -z "$MOUNTED" ] && sec_error "NAME=$NAME not mounted"
	S_MOUNTED=yes
fi

[ `echo $MOUNT | wc -w` -gt 1 ] && sec_error "NAME=$NAME mounted more than once"

DIR=${DIR:-$MOUNT}
[ -z "`echo $DIR | grep $MOUNT`" ] && echo "$DIR not in $MOUNT" && \
	sec_cleanup && exit 99

[ `ls -l $LPROC/ldlm 2> /dev/null | grep lustre-MDT | wc -l` -gt 1 ] \
	&& echo "skip multi-MDS test" && sec_cleanup && exit 0

if [ -z "`lsmod | grep mdt`" ]; then
	LOCAL_MDT=0
	echo "remote mdt"
	EXCEPT="$EXCEPT 1 3"
else
	LOCAL_MDT=1
	echo "local mdt"
	EXCEPT="$EXCEPT 1 2 3"
fi

LPROC=/proc/fs/lustre
ENABLE_IDENTITY=/usr/sbin/l_getidentity
DISABLE_IDENTITY=NONE
LUSTRE_CONF_DIR=/etc/lustre
SETXID_CONF=$LUSTRE_CONF_DIR/setxid.conf
SETXID_CONF_BAK=$LUSTRE_CONF_DIR/setxid.conf.bak

if [ $LOCAL_MDT -eq 1 ]; then
	MDT=$(\ls $LPROC/mdt 2> /dev/null | grep -v num_refs | tail -n 1)
	IDENTITY_UPCALL=$LPROC/mdt/$MDT/identity_upcall
	IDENTITY_UPCALL_BAK=`more $IDENTITY_UPCALL`
	IDENTITY_FLUSH=$LPROC/mdt/$MDT/identity_flush
	ROOTSQUASH_UID=$LPROC/mdt/$MDT/rootsquash_uid
	ROOTSQUASH_GID=$LPROC/mdt/$MDT/rootsquash_gid
	NOSQUASH_NIDS=$LPROC/mdt/$MDT/nosquash_nids
fi

CLIENT_TYPE=$LPROC/llite/*/client_type
grep "local client" $CLIENT_TYPE > /dev/null 2>&1 && EXCEPT="$EXCEPT 2"
grep "remote client" $CLIENT_TYPE > /dev/null 2>&1 && EXCEPT="$EXCEPT 1 3"

build_test_filter

setup() {
	if [ -f "$SETXID_CONF" ]; then
		mv -f $SETXID_CONF $SETXID_CONF_BAK
	else
		rm -f $SETXID_CONF_BAK
	fi

	if [ $LOCAL_MDT -eq 1 ]; then
		echo $ENABLE_IDENTITY > $IDENTITY_UPCALL
		echo -1 > $IDENTITY_FLUSH
	fi

	$RUNAS -u $ID1 ls $DIR
	$RUNAS -u $ID2 ls $DIR
}
setup

# run as different user
test_0() {
	rm -rf $DIR/d0
	mkdir $DIR/d0

	chown $USER1 $DIR/d0 || sec_error
	$RUNAS -u $ID1 ls $DIR || sec_error
	$RUNAS -u $ID1 touch $DIR/f0 && sec_error
	$RUNAS -u $ID1 touch $DIR/d0/f1 || sec_error
	$RUNAS -u $ID2 touch $DIR/d0/f2 && sec_error
	touch $DIR/d0/f3 || sec_error
	chown root $DIR/d0
	chgrp $USER1 $DIR/d0
	chmod 775 $DIR/d0
	$RUNAS -u $ID1 touch $DIR/d0/f4 || sec_error
	$RUNAS -u $ID2 touch $DIR/d0/f5 && sec_error
	touch $DIR/d0/f6 || sec_error

	rm -rf $DIR/d0
}
sec_run_test 0 "uid permission ============================="

# setuid/gid
test_1() {
	rm -rf $DIR/d1
	mkdir $DIR/d1

	chown $USER1 $DIR/d1 || sec_error
	$RUNAS -u $ID2 -v $ID1 touch $DIR/d1/f0 && sec_error
	echo "* $ID2 setuid" > $SETXID_CONF
	echo "enable uid $ID2 setuid"
	echo -1 > $IDENTITY_FLUSH
	$RUNAS -u $ID2 -v $ID1 touch $DIR/d1/f1 || sec_error

	chown root $DIR/d1
	chgrp $USER1 $DIR/d1
	chmod 770 $DIR/d1
	$RUNAS -u $ID2 -g $ID2 touch $DIR/d1/f2 && sec_error
	echo "* $ID2 setuid,setgid" > $SETXID_CONF
	echo "enable uid $ID2 setuid,setgid"
	echo -1 > $IDENTITY_FLUSH
	$RUNAS -u $ID2 -g $ID2 -j $ID1 touch $DIR/d1/f3 || sec_error
	$RUNAS -u $ID2 -v $ID1 -g $ID2 -j $ID1 touch $DIR/d1/f4 || sec_error

	rm -f $SETXID_CONF
	rm -rf $DIR/d1
	echo -1 > $IDENTITY_FLUSH
}
sec_run_test 1 "setuid/gid ============================="

# lfs getfacl/setfacl
test_2() {
	rm -rf $DIR/d2
	mkdir $DIR/d2
	chmod 755 $DIR/d2
	echo xxx > $DIR/d2/f0
	chmod 644 $DIR/d2/f0

	$LFS getfacl $DIR/d2/f0 || sec_error
	$RUNAS -u $ID1 cat $DIR/d2/f0 || sec_error
	$RUNAS -u $ID1 touch $DIR/d2/f0 && sec_error

	$LFS setfacl -m u:$USER1:w $DIR/d2/f0 || sec_error
	$LFS getfacl $DIR/d2/f0 || sec_error
	echo "set user $USER1 write permission on file $DIR/d2/fo"
	$RUNAS -u $ID1 touch $DIR/d2/f0 || sec_error
	$RUNAS -u $ID1 cat $DIR/d2/f0 && sec_error

	rm -rf $DIR/d2
}
sec_run_test 2 "lfs getfacl/setfacl ============================="

# rootsquash
test_3() {
	$LCTL conf_param $MDT.mdt.nosquash_nids=none
	while grep LNET_NID_ANY $NOSQUASH_NIDS > /dev/null; do sleep 1; done
	$LCTL conf_param $MDT.mdt.rootsquash_uid=0
	while [ "`cat $ROOTSQUASH_UID`" -ne 0 ]; do sleep 1; done
	$LCTL conf_param $MDT.mdt.rootsquash_gid=0
	while [ "`cat $ROOTSQUASH_GID`" -ne 0 ]; do sleep 1; done

	rm -rf $DIR/d3
	mkdir $DIR/d3
	chown $USER1 $DIR/d3
	chmod 700 $DIR/d3
	$LCTL conf_param $MDT.mdt.rootsquash_uid=$ID1
	echo "set rootsquash uid = $ID1"
	while [ "`cat $ROOTSQUASH_UID`" -ne $ID1 ]; do sleep 1; done
	touch $DIR/f3_0 && sec_error
	touch $DIR/d3/f3_1 || sec_error

	$LCTL conf_param $MDT.mdt.rootsquash_uid=0
	echo "disable rootsquash"
	while [ "`cat $ROOTSQUASH_UID`" -ne 0 ]; do sleep 1; done
	chown root $DIR/d3
	chgrp $USER2 $DIR/d3
	chmod 770 $DIR/d3

	$LCTL conf_param $MDT.mdt.rootsquash_uid=$ID1
	echo "set rootsquash uid = $ID1"
	while [ "`cat $ROOTSQUASH_UID`" -ne $ID1 ]; do sleep 1; done
	touch $DIR/d3/f3_2 && sec_error
	$LCTL conf_param $MDT.mdt.rootsquash_gid=$ID2
	echo "set rootsquash gid = $ID2"
	while [ "`cat $ROOTSQUASH_GID`" -ne $ID2 ]; do sleep 1; done
	touch $DIR/d3/f3_3 || sec_error

	$LCTL conf_param $MDT.mdt.nosquash_nids=*
	echo "add host in rootsquash skip list"
	while ! grep LNET_NID_ANY $NOSQUASH_NIDS > /dev/null;
		do sleep 1;
	done
	touch $DIR/f3_4 || sec_error

	$LCTL conf_param $MDT.mdt.rootsquash_uid=0
	while [ "`cat $ROOTSQUASH_UID`" -ne 0 ]; do sleep 1; done
	$LCTL conf_param $MDT.mdt.rootsquash_gid=0
	while [ "`cat $ROOTSQUASH_GID`" -ne 0 ]; do sleep 1; done
	$LCTL conf_param $MDT.mdt.nosquash_nids=none
	rm -rf $DIR/d3
	rm -f $DIR/f3_?
}
sec_run_test 3 "rootsquash ============================="

# bug 3285 - supplementary group should always succeed (see do_init_ucred),
# NB: the supplementary groups are set for local client only, as for remote
# client, the groups of the specified uid on MDT will be obtained by
# upcall /sbin/l_getidentity and used.
test_4() {
        mkdir $DIR/d4
        chmod 771 $DIR/d4
        chgrp $ID1 $DIR/d4
	$RUNAS -u $ID1 ls $DIR/d4 || sec_error "setgroups(1) failed"
	grep "local client" $CLIENT_TYPE > /dev/null 2>&1 && \
		($RUNAS -u $ID2 -G1,2,$ID1 ls $DIR/d4 || \
			sec_error "setgroups(2) failed")
	$RUNAS -u $ID2 -G1,2 ls $DIR/d4 && sec_error "setgroups(3) failed"
	rm -rf $DIR/d4
}
sec_run_test 4 "set supplementary group ==============="

log "cleanup: ======================================================"

unsetup() {
	if [ -f "$SETXID_CONF_BAK" ]; then
		mv -f $SETXID_CONF_BAK $SETXID_CONF
	fi

	if [ $LOCAL_MDT -eq 1 ]; then
		echo $IDENTITY_UPCALL_BAK > $IDENTITY_UPCALL
		echo -1 > $IDENTITY_FLUSH
	fi

	$RUNAS -u $ID1 ls $DIR
	$RUNAS -u $ID2 ls $DIR
}
unsetup

sec_cleanup() {
	if [ "$S_MOUNTED" = "yes" ]; then
		cleanupall -f || sec_error "cleanup failed"
	fi
}
sec_cleanup

echo '=========================== finished ==============================='
[ -f "$SANITYSECLOG" ] && cat $SANITYSECLOG && exit 1 || true
