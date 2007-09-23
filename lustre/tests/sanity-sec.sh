#!/bin/bash
#
# Run select tests by setting SEC_ONLY, or as arguments to the script.
# Skip specific tests by setting SEC_EXCEPT.
#

set -e

SRCDIR=`dirname $0`
export PATH=$PWD/$SRCDIR:$SRCDIR:$PWD/$SRCDIR/../utils:$PATH:/sbin

SEC_ONLY=${SEC_ONLY:-"$*"}
[ "$SEC_EXCEPT" ] && echo "Skipping tests: `echo $SEC_EXCEPT`"

TMP=${TMP:-/tmp}
LFS=${LFS:-lfs}
LCTL=${LCTL:-lctl}
RUNAS=${RUNAS:-runas}
WTL=${WTL:-write_time_limit}

LPROC=/proc/fs/lustre
ENABLE_IDENTITY=/usr/sbin/l_getidentity
DISABLE_IDENTITY=NONE
LUSTRE_CONF_DIR=/etc/lustre
PERM_CONF=$LUSTRE_CONF_DIR/perm.conf
LDLM_LPROC=$LPROC/ldlm
LLITE_LPROC=$LPROC/llite
MDC_LPROC=$LPROC/mdc
MDT_LPROC=$LPROC/mdt
OST_LPROC=$LPROC/obdfilter

sec_log() {
	echo "$*"
	$LCTL mark "$*" 2> /dev/null || true
}

SANITYSECLOG=${SANITYSECLOG:-/tmp/sanity-sec.log}
[ "$SANITYSECLOG" ] && rm -f $SANITYSECLOG || true

sec_error() { 
	sec_log "FAIL: $TESTNAME $@"
	if [ "$SANITYSECLOG" ]; then
		echo "FAIL: $TESTNAME $@" >> $SANITYSECLOG
	else
		exit 1
	fi
}

sec_pass() { 
	echo PASS $@
}

sec_skip () {
	sec_log "$0: SKIP: $TESTNAME $@"
	[ "$SANITYSECLOG" ] && echo "$0: SKIP: $TESTNAME $@" >> $SANITYSECLOG
}

ID1=500
ID2=501

USER1=`cat /etc/passwd|grep :$ID1:$ID1:|cut -d: -f1`
USER2=`cat /etc/passwd|grep :$ID2:$ID2:|cut -d: -f1`

if [ -z "$USER1" ]; then
	echo "===== Please add user1 (uid=$ID1 gid=$ID1)! Skip sanity-sec ====="
	sec_error "===== Please add user1 (uid=$ID1 gid=$ID1)! ====="
	exit 0
fi

if [ -z "$USER2" ]; then
	echo "===== Please add user2 (uid=$ID2 gid=$ID2)! Skip sanity-sec ====="
	sec_error "===== Please add user2 (uid=$ID2 gid=$ID2)! ====="
	exit 0
fi

export NAME=${NAME:-local}

LUSTRE=${LUSTRE:-`dirname $0`/..} 
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

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

[ `ls -l $LDLM_LPROC/namespaces 2>/dev/null | grep *-mdc-* | wc -l` -gt 1 ] \
	&& echo "skip multi-MDS test" && sec_cleanup && exit 0

OST_COUNT=$(ls -l $LDLM_LPROC/namespaces 2>/dev/null | grep osc | grep -v MDT | wc -l)

# for GSS_SUP
GSS_REF=$(lsmod | grep ^ptlrpc_gss | awk '{print $3}')
if [ ! -z "$GSS_REF" -a "$GSS_REF" != "0" ]; then
	GSS_SUP=1
	echo "with GSS support"
else
	GSS_SUP=0
	echo "without GSS support"
fi

# for MDT_TYPE
MDT_REF=$(lsmod | grep ^mdt | awk '{print $3}')
if [ ! -z "$MDT_REF" -a "$MDT_REF" != "0" ]; then
        MDT_TYPE="local"
        echo "local mdt"
else
        MDT_TYPE="remote"
        echo "remote mdt"
fi

MDT="`do_facet $SINGLEMDS ls -l $MDT_LPROC/ | grep MDT | awk '{print $9}'`"
if [ ! -z "$MDT" ]; then
	IDENTITY_UPCALL=$MDT_LPROC/$MDT/identity_upcall
	IDENTITY_UPCALL_BAK="`more $IDENTITY_UPCALL`"
	IDENTITY_FLUSH=$MDT_LPROC/$MDT/identity_flush
	ROOTSQUASH_UID=$MDT_LPROC/$MDT/rootsquash_uid
	ROOTSQUASH_GID=$MDT_LPROC/$MDT/rootsquash_gid
	NOSQUASH_NIDS=$MDT_LPROC/$MDT/nosquash_nids
	MDSCAPA=$MDT_LPROC/$MDT/capa
	CAPA_TIMEOUT=$MDT_LPROC/$MDT/capa_timeout
fi

# for CLIENT_TYPE
if [ -z "$(grep remote $LLITE_LPROC/*/client_type 2>/dev/null)" ]; then
	CLIENT_TYPE="local"
	echo "local client"
else
	CLIENT_TYPE="remote"
	echo "remote client"
fi

SAVE_PWD=$PWD

sec_run_one() {
	BEFORE=`date +%s`
	sec_log "== test $1 $2= `date +%H:%M:%S` ($BEFORE)"
	export TESTNAME=test_$1
	test_$1 || sec_error "exit with rc=$?"
	unset TESTNAME
	sec_pass "($((`date +%s` - $BEFORE))s)"
}

build_test_filter() {
        for O in $SEC_ONLY; do
            eval SEC_ONLY_${O}=true
        done
        for E in $SEC_EXCEPT; do
            eval SEC_EXCEPT_${E}=true
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
        testname=SEC_EXCEPT_$1
        if [ ${!testname}x != x ]; then
                 echo "skipping excluded test $1"
                 return 0
        fi
        testname=SEC_EXCEPT_$base
        if [ ${!testname}x != x ]; then
                 echo "skipping excluded test $1 (base $base)"
                 return 0
        fi
        sec_run_one $1 "$2"
 	return $?
}

build_test_filter

sec_login() {
	local user=$1
	local group=$2

	if ! $RUNAS -u $user krb5_login.sh; then
		echo "$user login kerberos failed."
		exit 1
	fi

	if ! $RUNAS -u $user -g $group ls $DIR > /dev/null; then
		$RUNAS -u $user lfs flushctx -k
		$RUNAS -u $user krb5_login.sh
                if ! $RUNAS -u $user -g $group ls $DIR > /dev/null; then
                        echo "init $user $group failed."
                        exit 2
                fi
	fi
}

setup() {
	if [ ! -z "$MDT" ]; then
		do_facet $SINGLEMDS echo $ENABLE_IDENTITY > $IDENTITY_UPCALL
		do_facet $SINGLEMDS echo -1 > $IDENTITY_FLUSH
	fi

	if ! $RUNAS -u $ID1 ls $DIR > /dev/null 2>&1; then
		sec_login $USER1 $USER1
	fi

	if ! $RUNAS -u $ID2 ls $DIR > /dev/null 2>&1; then
		sec_login $USER2 $USER2
	fi
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
	[ $GSS_SUP = 0 ] && sec_skip "without GSS support." && return
	[ -z "$MDT" ] && sec_skip "do not support do_facet operations." && return

	do_facet $SINGLEMDS rm -f $PERM_CONF
	do_facet $SINGLEMDS echo -1 > $IDENTITY_FLUSH

	rm -rf $DIR/d1
	mkdir $DIR/d1

	chown $USER1 $DIR/d1 || sec_error
	$RUNAS -u $ID2 -v $ID1 touch $DIR/d1/f0 && sec_error
	do_facet $SINGLEMDS echo "\* $ID2 setuid" > $PERM_CONF
	echo "enable uid $ID2 setuid"
	do_facet $SINGLEMDS echo -1 > $IDENTITY_FLUSH
	$RUNAS -u $ID2 -v $ID1 touch $DIR/d1/f1 || sec_error

	chown root $DIR/d1
	chgrp $USER1 $DIR/d1
	chmod 770 $DIR/d1
	$RUNAS -u $ID2 -g $ID2 touch $DIR/d1/f2 && sec_error
	$RUNAS -u $ID2 -g $ID2 -j $ID1 touch $DIR/d1/f3 && sec_error
	do_facet $SINGLEMDS echo "\* $ID2 setuid,setgid" > $PERM_CONF
	echo "enable uid $ID2 setuid,setgid"
	do_facet $SINGLEMDS echo -1 > $IDENTITY_FLUSH
	$RUNAS -u $ID2 -g $ID2 -j $ID1 touch $DIR/d1/f4 || sec_error
	$RUNAS -u $ID2 -v $ID1 -g $ID2 -j $ID1 touch $DIR/d1/f5 || sec_error

	rm -rf $DIR/d1

	do_facet $SINGLEMDS rm -f $PERM_CONF
	do_facet $SINGLEMDS echo -1 > $IDENTITY_FLUSH
}
sec_run_test 1 "setuid/gid ============================="

# remote_acl
# for remote client only
test_2 () {
	[ "$CLIENT_TYPE" = "local" ] && \
		sec_skip "remote_acl for remote client only" && return
    	[ -z "$(grep ^acl $MDC_LPROC/*-mdc-*/connect_flags)" ] && \
		sec_skip "must have acl enabled" && return
    	[ -z "$(which setfacl 2>/dev/null)" ] && \
		sec_skip "could not find setfacl" && return
	[ "$UID" != 0 ] && sec_skip "must run as root" && return

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
	echo "set user $USER1 write permission on file $DIR/d2/f0"
	$RUNAS -u $ID1 touch $DIR/d2/f0 || sec_error
	$RUNAS -u $ID1 cat $DIR/d2/f0 && sec_error

	rm -rf $DIR/d2
}
sec_run_test 2 "rmtacl ============================="

# rootsquash
# for remote mdt only
test_3() {
	[ $GSS_SUP = 0 ] && sec_skip "without GSS support." && return
	[ -z "$MDT" ] && sec_skip "do not support do_facet operations." && return
        [ "$MDT_TYPE" = "local" ] && sec_skip "rootsquash for remote mdt only" && return

	do_facet $SINGLEMDS echo "-\*" > $NOSQUASH_NIDS 
	do_facet $SINGLEMDS echo 0 > $ROOTSQUASH_UID
	do_facet $SINGLEMDS echo 0 > $ROOTSQUASH_GID

	rm -rf $DIR/d3
	mkdir $DIR/d3
	chown $USER1 $DIR/d3
	chmod 700 $DIR/d3
	do_facet $SINGLEMDS echo $ID1 > $ROOTSQUASH_UID
	echo "set rootsquash uid = $ID1"
	touch $DIR/f3_0 && sec_error
	touch $DIR/d3/f3_1 || sec_error

	do_facet $SINGLEMDS echo 0 > $ROOTSQUASH_UID
	echo "disable rootsquash"
	chown root $DIR/d3
	chgrp $USER2 $DIR/d3
	chmod 770 $DIR/d3

	do_facet $SINGLEMDS echo $ID1 > $ROOTSQUASH_UID
	echo "set rootsquash uid = $ID1"
	touch $DIR/d3/f3_2 && sec_error
	do_facet $SINGLEMDS echo $ID2 > $ROOTSQUASH_GID
	echo "set rootsquash gid = $ID2"
	touch $DIR/d3/f3_3 || sec_error

	do_facet $SINGLEMDS echo "+\*" > $NOSQUASH_NIDS
	echo "add host in rootsquash skip list"
	touch $DIR/f3_4 || sec_error

	do_facet $SINGLEMDS echo 0 > $ROOTSQUASH_UID
	do_facet $SINGLEMDS echo 0 > $ROOTSQUASH_GID
	do_facet $SINGLEMDS echo "-\*" > $NOSQUASH_NIDS
	rm -rf $DIR/d3
	rm -f $DIR/f3_?
}
sec_run_test 3 "rootsquash ============================="

# bug 3285 - supplementary group should always succeed.
# NB: the supplementary groups are set for local client only,
# as for remote client, the groups of the specified uid on MDT
# will be obtained by upcall /sbin/l_getidentity and used.
test_4() {
	rm -rf $DIR/d4
        mkdir $DIR/d4
        chmod 771 $DIR/d4
        chgrp $ID1 $DIR/d4
	$RUNAS -u $ID1 ls $DIR/d4 || sec_error "setgroups(1) failed"
	if [ "$CLIENT_TYPE" != "remote" ]; then
		if [ ! -z "$MDT" ]; then
			do_facet $SINGLEMDS echo "\* $ID2 setgrp" > $PERM_CONF
			do_facet $SINGLEMDS echo -1 > $IDENTITY_FLUSH
		fi
		$RUNAS -u $ID2 -G1,2,$ID1 ls $DIR/d4 || sec_error "setgroups(2) failed"
		if [ ! -z "$MDT" ]; then
			do_facet $SINGLEMDS rm -f $PERM_CONF
			do_facet $SINGLEMDS echo -1 > $IDENTITY_FLUSH
		fi
	fi
	$RUNAS -u $ID2 -G1,2 ls $DIR/d4 && sec_error "setgroups(3) failed"
	rm -rf $DIR/d4
}
sec_run_test 4 "set supplementary group ==============="

mds_capability_timeout() {
        [ $# -lt 1 ] && echo "Miss mds capability timeout value" && return 1

        echo "Set mds capability timeout as $1 seconds"
	do_facet $SINGLEMDS echo $1 > $CAPA_TIMEOUT
        return 0
}

mds_capability_switch() {
        [ $# -lt 1 ] && echo "Miss mds capability switch value" && return 1

        case $1 in
                0) echo "Turn off mds capability";;
                3) echo "Turn on mds capability";;
                *) echo "Invalid mds capability switch value" && return 2;;
        esac

	do_facet $SINGLEMDS echo $1 > $MDSCAPA
        return 0
}

oss_capability_switch() {
        [ $# -lt 1 ] && echo "Miss oss capability switch value" && return 1

        case $1 in
                0) echo "Turn off oss capability";;
                1) echo "Turn on oss capability";;
                *) echo "Invalid oss capability switch value" && return 2;;
        esac

	i=0;
	while [ $i -lt $OST_COUNT ]; do
		j=$i;
		i=`expr $i + 1`
		OST="`do_facet ost$i ls -l $OST_LPROC/ | grep OST | awk '{print $9}' | grep $j$`"
		do_facet ost$i echo $1 > $OST_LPROC/$OST/capa
	done
        return 0
}

turn_capability_on() {
        local capa_timeout=${1:-"1800"}

        # To turn on fid capability for the system,
        # there is a requirement that fid capability
        # is turned on on all MDS/OSS servers before
        # client mount.

        umount $MOUNT || return 1

        mds_capability_switch 3 || return 2
        oss_capability_switch 1 || return 3
        mds_capability_timeout $capa_timeout || return 4

        mount_client $MOUNT || return 5
        return 0
}

turn_capability_off() {
        # to turn off fid capability, you can just do
        # it in a live system. But, please turn off
        # capability of all OSS servers before MDS servers.

        oss_capability_switch 0 || return 1
        mds_capability_switch 0 || return 2
        return 0
}

# We demonstrate that access to the objects in the filesystem are not
# accessible without supplying secrets from the MDS by disabling a
# proc variable on the mds so that it does not supply secrets. We then
# try and access objects which result in failure.
test_5() {
        local file=$DIR/f5

	[ -z "$MDT" ] && sec_skip "do not support do_facet operations." && return
	turn_capability_off
	rm -f $file

        # Disable proc variable
        mds_capability_switch 0 || return 1
        oss_capability_switch 1 || return 2

        # proc variable disabled -- access to the objects in the filesystem
        # is not allowed 
        echo "Should get Write error here : (proc variable are disabled "\
	     "-- access to the objects in the filesystem is denied."
	$WTL $file 30
	if [ $? == 0 ]; then
        	echo "Write worked well even though secrets not supplied."
		return 3
        fi

        turn_capability_on || return 4
        sleep 5

        # proc variable enabled, secrets supplied -- write should work now
        echo "Should not fail here : (proc variable enabled, secrets supplied "\
	     "-- write should work now)."
	$WTL $file 30
	if [ $? != 0 ]; then
        	echo "Write failed even though secrets supplied."
		return 5
        fi

	turn_capability_off
	rm -f $file
}
sec_run_test 5 "capa secrets ========================="

# Expiry: A test program is performing I/O on a file. It has credential
# with an expiry half a minute later. While the program is running the
# credentials expire and no automatic extensions or renewals are
# enabled. The program will demonstrate an I/O failure.
test_6() {
        local file=$DIR/f6

	[ -z "$MDT" ] && sec_skip "do not support do_facet operations." && return
	turn_capability_off
	rm -f $file

        turn_capability_on 30 || return 1
        # Token expiry
	$WTL $file 60 || return 2

	# Reset MDS capability timeout
	mds_capability_timeout 30 || exit 3
	$WTL $file 60 &
	local PID=$!
	sleep 5

        # To disable automatic renew, only need turn capa off on MDS.
        mds_capability_switch 0 || return 4

	echo "We expect I/O failure."
        wait $PID
	if [ $? == 0 ]; then
		echo "no I/O failure got."
		return 5
	fi

	turn_capability_off
	rm -f $file
}
sec_run_test 6 "capa expiry ========================="

log "cleanup: ======================================================"

unsetup() {
	if [ ! -z "$MDT"  ]; then
		do_facet $SINGLEMDS echo $IDENTITY_UPCALL_BAK > $IDENTITY_UPCALL
		do_facet $SINGLEMDS echo -1 > $IDENTITY_FLUSH
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
[ -f "$SANITYSECLOG" ] && \
	cat $SANITYSECLOG && grep -q FAIL $SANITYSECLOG && exit 1 || true
echo "$0 completed"
