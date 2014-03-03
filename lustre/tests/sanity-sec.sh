#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#

set -e

ONLY=${ONLY:-"$*"}
# bug number for skipped test: 19430 LU-5423 19967 19967
ALWAYS_EXCEPT="                2     4       5     6    $SANITY_SEC_EXCEPT"
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

[ "$ALWAYS_EXCEPT$EXCEPT" ] && \
    echo "Skipping tests: $ALWAYS_EXCEPT $EXCEPT"

SRCDIR=`dirname $0`
export PATH=$PWD/$SRCDIR:$SRCDIR:$PWD/$SRCDIR/../utils:$PATH:/sbin
export NAME=${NAME:-local}

LUSTRE=${LUSTRE:-`dirname $0`/..} 
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

RUNAS="runas"

WTL=${WTL:-"$LUSTRE/tests/write_time_limit"}

CONFDIR=/etc/lustre
PERM_CONF=$CONFDIR/perm.conf
FAIL_ON_ERROR=false

HOSTNAME_CHECKSUM=$(hostname | sum | awk '{ print $1 }')
SUBNET_CHECKSUM=$(expr $HOSTNAME_CHECKSUM % 250 + 1)
NODEMAP_COUNT=16
NODEMAP_RANGE_COUNT=3
NODEMAP_IPADDR_COUNT=30
NODEMAP_MAX_ID=128

require_dsh_mds || exit 0
require_dsh_ost || exit 0

ID0=${ID0:-500}
ID1=${ID1:-501}
USER0=`cat /etc/passwd|grep :$ID0:$ID0:|cut -d: -f1`
USER1=`cat /etc/passwd|grep :$ID1:$ID1:|cut -d: -f1`

[ -z "$USER0" ] && \
	echo "Please add user0 (uid=$ID0 gid=$ID0)! Skip sanity-sec" && exit 0

[ -z "$USER1" ] && \
	echo "Please add user1 (uid=$ID1 gid=$ID1)! Skip sanity-sec" && exit 0

check_and_setup_lustre

sec_cleanup() {
	if [ "$I_MOUNTED" = "yes" ]; then
		cleanupall -f || error "sec_cleanup"
	fi
}

DIR=${DIR:-$MOUNT}
[ -z "`echo $DIR | grep $MOUNT`" ] && \
	error "$DIR not in $MOUNT" && sec_cleanup && exit 1

[ `echo $MOUNT | wc -w` -gt 1 ] && \
	echo "NAME=$MOUNT mounted more than once" && sec_cleanup && exit 0

[ $MDSCOUNT -gt 1 ] && \
	echo "skip multi-MDS test" && sec_cleanup && exit 0

# for GSS_SUP
GSS_REF=$(lsmod | grep ^ptlrpc_gss | awk '{print $3}')
if [ ! -z "$GSS_REF" -a "$GSS_REF" != "0" ]; then
	GSS_SUP=1
	echo "with GSS support"
else
	GSS_SUP=0
	echo "without GSS support"
fi

MDT=$(do_facet $SINGLEMDS lctl get_param -N "mdt.\*MDT0000" |
	cut -d. -f2 || true)
[ -z "$MDT" ] && error "fail to get MDT device" && exit 1
do_facet $SINGLEMDS "mkdir -p $CONFDIR"
IDENTITY_FLUSH=mdt.$MDT.identity_flush
MDSCAPA=mdt.$MDT.capa
CAPA_TIMEOUT=mdt.$MDT.capa_timeout
MDSSECLEVEL=mdt.$MDT.sec_level

# for CLIENT_TYPE
if [ -z "$(lctl get_param -n llite.*.client_type | grep remote 2>/dev/null)" ]; then
	CLIENT_TYPE="local"
	echo "local client"
else
	CLIENT_TYPE="remote"
	echo "remote client"
fi

SAVE_PWD=$PWD

build_test_filter

sec_login() {
	local user=$1
	local group=$2

	if ! $RUNAS -u $user krb5_login.sh; then
		error "$user login kerberos failed."
		exit 1
	fi

	if ! $RUNAS -u $user -g $group ls $DIR > /dev/null 2>&1; then
		$RUNAS -u $user lfs flushctx -k
		$RUNAS -u $user krb5_login.sh
                if ! $RUNAS -u $user -g $group ls $DIR > /dev/null 2>&1; then
                        error "init $user $group failed."
                        exit 2
                fi
	fi
}

declare -a identity_old

sec_setup() {
       	for num in `seq $MDSCOUNT`; do
       		switch_identity $num true || identity_old[$num]=$?
       	done

	if ! $RUNAS -u $ID0 ls $DIR > /dev/null 2>&1; then
		sec_login $USER0 $USER0
	fi

	if ! $RUNAS -u $ID1 ls $DIR > /dev/null 2>&1; then
		sec_login $USER1 $USER1
	fi
}
sec_setup

# run as different user
test_0() {
	umask 0022

	chmod 0755 $DIR || error "chmod (1)"
	rm -rf $DIR/$tdir || error "rm (1)"
	mkdir -p $DIR/$tdir || error "mkdir (1)"

	if [ "$CLIENT_TYPE" = "remote" ]; then
		do_facet $SINGLEMDS "echo '* 0 normtown' > $PERM_CONF"
	        do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
		chown $USER0 $DIR/$tdir && error "chown (1)"
		do_facet $SINGLEMDS "echo '* 0 rmtown' > $PERM_CONF"
	        do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
	else
		chown $USER0 $DIR/$tdir || error "chown (2)"
	fi

	$RUNAS -u $ID0 ls $DIR || error "ls (1)"
        rm -f $DIR/f0 || error "rm (2)"
	$RUNAS -u $ID0 touch $DIR/f0 && error "touch (1)"
	$RUNAS -u $ID0 touch $DIR/$tdir/f1 || error "touch (2)"
	$RUNAS -u $ID1 touch $DIR/$tdir/f2 && error "touch (3)"
	touch $DIR/$tdir/f3 || error "touch (4)"
	chown root $DIR/$tdir || error "chown (3)"
	chgrp $USER0 $DIR/$tdir || error "chgrp (1)"
	chmod 0775 $DIR/$tdir || error "chmod (2)"
	$RUNAS -u $ID0 touch $DIR/$tdir/f4 || error "touch (5)"
	$RUNAS -u $ID1 touch $DIR/$tdir/f5 && error "touch (6)"
	touch $DIR/$tdir/f6 || error "touch (7)"
	rm -rf $DIR/$tdir || error "rm (3)"

	if [ "$CLIENT_TYPE" = "remote" ]; then
		do_facet $SINGLEMDS "rm -f $PERM_CONF"
	        do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
	fi
}
run_test 0 "uid permission ============================="

# setuid/gid
test_1() {
	[ $GSS_SUP = 0 ] && skip "without GSS support." && return

	if [ "$CLIENT_TYPE" = "remote" ]; then
		do_facet $SINGLEMDS "echo '* 0 rmtown' > $PERM_CONF"
	        do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
	fi

	rm -rf $DIR/$tdir
	mkdir -p $DIR/$tdir

	chown $USER0 $DIR/$tdir || error "chown (1)"
	$RUNAS -u $ID1 -v $ID0 touch $DIR/$tdir/f0 && error "touch (2)"
	echo "enable uid $ID1 setuid"
	do_facet $SINGLEMDS "echo '* $ID1 setuid' >> $PERM_CONF"
	do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
	$RUNAS -u $ID1 -v $ID0 touch $DIR/$tdir/f1 || error "touch (3)"

	chown root $DIR/$tdir || error "chown (4)"
	chgrp $USER0 $DIR/$tdir || error "chgrp (5)"
	chmod 0770 $DIR/$tdir || error "chmod (6)"
	$RUNAS -u $ID1 -g $ID1 touch $DIR/$tdir/f2 && error "touch (7)"
	$RUNAS -u $ID1 -g $ID1 -j $ID0 touch $DIR/$tdir/f3 && error "touch (8)"
	echo "enable uid $ID1 setuid,setgid"
	do_facet $SINGLEMDS "echo '* $ID1 setuid,setgid' > $PERM_CONF"
	do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
	$RUNAS -u $ID1 -g $ID1 -j $ID0 touch $DIR/$tdir/f4 || error "touch (9)"
	$RUNAS -u $ID1 -v $ID0 -g $ID1 -j $ID0 touch $DIR/$tdir/f5 || error "touch (10)"

	rm -rf $DIR/$tdir

	do_facet $SINGLEMDS "rm -f $PERM_CONF"
	do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
}
run_test 1 "setuid/gid ============================="

run_rmtacl_subtest() {
    $SAVE_PWD/rmtacl/run $SAVE_PWD/rmtacl/$1.test
    return $?
}

# remote_acl
# for remote client only
test_2 () {
	[ "$CLIENT_TYPE" = "local" ] && \
		skip "remote_acl for remote client only" && return
    	[ -z "$(lctl get_param -n mdc.*-mdc-*.connect_flags | grep ^acl)" ] && \
		skip "must have acl enabled" && return
    	[ -z "$(which setfacl 2>/dev/null)" ] && \
		skip "could not find setfacl" && return
	[ "$UID" != 0 ] && skip "must run as root" && return

	do_facet $SINGLEMDS "echo '* 0 rmtacl,rmtown' > $PERM_CONF"
	do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"

	sec_login root root
	sec_login bin bin
	sec_login daemon daemon
	sec_login games users

    	SAVE_UMASK=`umask`
    	umask 0022
    	cd $DIR

        echo "performing cp ..."
        run_rmtacl_subtest cp || error "cp"
    	echo "performing getfacl-noacl..."
    	run_rmtacl_subtest getfacl-noacl || error "getfacl-noacl"
    	echo "performing misc..."
    	run_rmtacl_subtest misc || error "misc"
    	echo "performing permissions..."
    	run_rmtacl_subtest permissions || error "permissions"
    	echo "performing setfacl..."
    	run_rmtacl_subtest setfacl || error "setfacl"

    	# inheritance test got from HP
    	echo "performing inheritance..."
    	cp $SAVE_PWD/rmtacl/make-tree .
    	chmod +x make-tree
    	run_rmtacl_subtest inheritance || error "inheritance"
    	rm -f make-tree

    	cd $SAVE_PWD
    	umask $SAVE_UMASK

	do_facet $SINGLEMDS "rm -f $PERM_CONF"
	do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
}
run_test 2 "rmtacl ============================="

# rootsquash
# root_squash will be redesigned in Lustre 1.7
test_3() {
        skip "root_squash will be redesigned in Lustre 1.7" && return
}
run_test 3 "rootsquash ============================="

# bug 3285 - supplementary group should always succeed.
# NB: the supplementary groups are set for local client only,
# as for remote client, the groups of the specified uid on MDT
# will be obtained by upcall /sbin/l_getidentity and used.
test_4() {
	if [ "$CLIENT_TYPE" = "remote" ]; then
		do_facet $SINGLEMDS "echo '* 0 rmtown' > $PERM_CONF"
	        do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
	fi

	rm -rf $DIR/$tdir
        mkdir -p $DIR/$tdir
        chmod 0771 $DIR/$tdir
        chgrp $ID0 $DIR/$tdir
	$RUNAS -u $ID0 ls $DIR/$tdir || error "setgroups (1)"
	if [ "$CLIENT_TYPE" = "local" ]; then
		do_facet $SINGLEMDS "echo '* $ID1 setgrp' > $PERM_CONF"
		do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
		$RUNAS -u $ID1 -G1,2,$ID0 ls $DIR/$tdir || error "setgroups (2)"
	fi
	$RUNAS -u $ID1 -G1,2 ls $DIR/$tdir && error "setgroups (3)"
	rm -rf $DIR/$tdir

	do_facet $SINGLEMDS "rm -f $PERM_CONF"
	do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
}
run_test 4 "set supplementary group ==============="

mds_capability_timeout() {
        [ $# -lt 1 ] && echo "Miss mds capability timeout value" && return 1

        echo "Set mds capability timeout as $1 seconds"
	do_facet $SINGLEMDS "lctl set_param -n $CAPA_TIMEOUT=$1"
        return 0
}

mds_sec_level_switch() {
        [ $# -lt 1 ] && echo "Miss mds sec level switch value" && return 1

        case $1 in
                0) echo "Disable capa for all clients";;
                1) echo "Enable capa for remote client";;
		3) echo "Enable capa for all clients";;
                *) echo "Invalid mds sec level switch value" && return 2;;
        esac

	do_facet $SINGLEMDS "lctl set_param -n $MDSSECLEVEL=$1"
        return 0
}

oss_sec_level_switch() {
        [ $# -lt 1 ] && echo "Miss oss sec level switch value" && return 1

        case $1 in
                0) echo "Disable capa for all clients";;
                1) echo "Enable capa for remote client";;
		3) echo "Enable capa for all clients";;
                *) echo "Invalid oss sec level switch value" && return 2;;
        esac

	for i in `seq $OSTCOUNT`; do
		local j=`expr $i - 1`
		local OST="`do_facet ost$i "lctl get_param -N obdfilter.\*OST\*$j/stats 2>/dev/null | cut -d"." -f2" || true`"
                [ -z "$OST" ] && return 3
		do_facet ost$i "lctl set_param -n obdfilter.$OST.sec_level=$1"
	done
        return 0
}

mds_capability_switch() {
        [ $# -lt 1 ] && echo "Miss mds capability switch value" && return 1

        case $1 in
                0) echo "Turn off mds capability";;
                3) echo "Turn on mds capability";;
                *) echo "Invalid mds capability switch value" && return 2;;
        esac

	do_facet $SINGLEMDS "lctl set_param -n $MDSCAPA=$1"
        return 0
}

oss_capability_switch() {
        [ $# -lt 1 ] && echo "Miss oss capability switch value" && return 1

        case $1 in
                0) echo "Turn off oss capability";;
                1) echo "Turn on oss capability";;
                *) echo "Invalid oss capability switch value" && return 2;;
        esac

	for i in `seq $OSTCOUNT`; do
		local j=`expr $i - 1`
		local OST="`do_facet ost$i "lctl get_param -N obdfilter.\*OST\*$j/stats 2>/dev/null | cut -d"." -f2" || true`"
                [ -z "$OST" ] && return 3
		do_facet ost$i "lctl set_param -n obdfilter.$OST.capa=$1"
	done
        return 0
}

turn_mds_capa_on() {
        mds_capability_switch 3 || return 1
	mds_sec_level_switch 3	|| return 2
        return 0
}

turn_oss_capa_on() {
        oss_capability_switch 1 || return 1
	oss_sec_level_switch 3	|| return 2
        return 0
}

turn_capability_on() {
        local capa_timeout=${1:-"1800"}

        # To turn on fid capability for the system,
        # there is a requirement that fid capability
        # is turned on on all MDS/OSS servers before
        # client mount.

	turn_mds_capa_on || return 1
	turn_oss_capa_on || return 2
        mds_capability_timeout $capa_timeout || return 3
        remount_client $MOUNT || return 4
        return 0
}

turn_mds_capa_off() {
	mds_sec_level_switch 0	|| return 1
        mds_capability_switch 0 || return 2
        return 0
}

turn_oss_capa_off() {
	oss_sec_level_switch 0	|| return 1
        oss_capability_switch 0 || return 2
        return 0
}

turn_capability_off() {
        # to turn off fid capability, you can just do
        # it in a live system. But, please turn off
        # capability of all OSS servers before MDS servers.

	turn_oss_capa_off || return 1
	turn_mds_capa_off || return 2
        return 0
}

# We demonstrate that access to the objects in the filesystem are not
# accessible without supplying secrets from the MDS by disabling a
# proc variable on the mds so that it does not supply secrets. We then
# try and access objects which result in failure.
test_5() {
        local file=$DIR/f5

	[ $GSS_SUP = 0 ] && skip "without GSS support." && return
	if ! remote_mds; then
                skip "client should be separated from server."
                return
        fi

	rm -f $file

	turn_capability_off
	if [ $? != 0 ]; then
		error "turn_capability_off"
		return 1
	fi

        turn_oss_capa_on
	if [ $? != 0 ]; then
		error "turn_oss_capa_on"
		return 2
	fi

	if [ "$CLIENT_TYPE" = "remote" ]; then
		remount_client $MOUNT && return 3
		turn_oss_capa_off
		return 0
	else
        	remount_client $MOUNT || return 4
	fi

        # proc variable disabled -- access to the objects in the filesystem
        # is not allowed 
        echo "Should get Write error here : (proc variable are disabled "\
	     "-- access to the objects in the filesystem is denied."
	$WTL $file 30
	if [ $? == 0 ]; then
        	error "Write worked well even though secrets not supplied."
		return 5
        fi

        turn_capability_on
	if [ $? != 0 ]; then
		error "turn_capability_on"
		return 6
	fi

        sleep 5

        # proc variable enabled, secrets supplied -- write should work now
        echo "Should not fail here : (proc variable enabled, secrets supplied "\
	     "-- write should work now)."
	$WTL $file 30
	if [ $? != 0 ]; then
        	error "Write failed even though secrets supplied."
		return 7
        fi

	turn_capability_off
	if [ $? != 0 ]; then
		error "turn_capability_off"
		return 8
	fi
	rm -f $file
}
run_test 5 "capa secrets ========================="

# Expiry: A test program is performing I/O on a file. It has credential
# with an expiry half a minute later. While the program is running the
# credentials expire and no automatic extensions or renewals are
# enabled. The program will demonstrate an I/O failure.
test_6() {
        local file=$DIR/f6

	[ $GSS_SUP = 0 ] && skip "without GSS support." && return
	if ! remote_mds; then
                skip "client should be separated from server."
                return
        fi

	turn_capability_off
	if [ $? != 0 ]; then
		error "turn_capability_off"
		return 1
	fi

	rm -f $file

        turn_capability_on 30
	if [ $? != 0 ]; then
		error "turn_capability_on 30"
		return 2
	fi

        # Token expiry
	$WTL $file 60
	if [ $? != 0 ]; then
		error "$WTL $file 60"
		return 3
	fi

	# Reset MDS capability timeout
	mds_capability_timeout 30
	if [ $? != 0 ]; then
		error "mds_capability_timeout 30"
		return 4
	fi

	$WTL $file 60 &
	local PID=$!
	sleep 5

        # To disable automatic renew, only need turn capa off on MDS.
	turn_mds_capa_off
	if [ $? != 0 ]; then
		error "turn_mds_capa_off"
		return 5
	fi

	echo "We expect I/O failure."
        wait $PID
	if [ $? == 0 ]; then
		echo "no I/O failure got."
		return 6
	fi

	turn_capability_off
	if [ $? != 0 ]; then
		error "turn_capability_off"
		return 7
	fi
	rm -f $file
}
run_test 6 "capa expiry ========================="

create_nodemaps() {
	local i
	local out
	local rc

	for (( i = 0; i < NODEMAP_COUNT; i++ )); do
		if ! do_facet mgs $LCTL nodemap_add			\
		       	${HOSTNAME_CHECKSUM}_${i}; then
		       	return 1
		fi
		out=$(do_facet mgs $LCTL get_param			\
			nodemap.${HOSTNAME_CHECKSUM}_${i}.id)
		## This needs to return zero if the following statement is 1
		rc=$(echo $out | grep -c ${HOSTNAME_CHECKSUM}_${i})
		[[ $rc == 0 ]] && return 1
	done
	return 0
}

delete_nodemaps() {
	local i
	local out
	local rc

	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! do_facet mgs $LCTL nodemap_del 			\
			${HOSTNAME_CHECKSUM}_${i}; then
			error "nodemap_del ${HOSTNAME_CHECKSUM}_${i} 	\
				failed with $rc"
			return 3
		fi
		out=$(do_facet mgs $LCTL get_param 			\
			nodemap.${HOSTNAME_CHECKSUM}_${i}.id)
		rc=$(echo $out | grep -c ${HOSTNAME_CHECKSUM}_${i})
		[[ $rc != 0 ]] && return 1
	done
	return 0
}

add_range() {
	local j
	local cmd="$LCTL nodemap_add_range"
	local range
	local rc=0

	for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
		range="$SUBNET_CHECKSUM.${2}.${j}.[1-253]@tcp"
		if ! do_facet mgs $cmd --name $1	\
			--range $range; then
			rc=$(($rc + 1))
		fi
	done
	return $rc
}

delete_range() {
	local j
	local cmd="$LCTL nodemap_del_range"
	local range
	local rc=0

	for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
		range="$SUBNET_CHECKSUM.${2}.${j}.[1-253]@tcp"
		if ! do_facet mgs $cmd --name $1	\
			--range $range; then
			rc=$(($rc + 1))
		fi
	done

	return $rc
}

add_idmaps() {
	local i
	local j
	local client_id
	local fs_id
	local cmd="$LCTL nodemap_add_idmap"
	local rc=0

	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		for ((j = 500; j < NODEMAP_MAX_ID; j++)); do
			client_id=$j
			fs_id=$(($j + 1))
			if ! do_facet mgs $cmd				\
			--name ${HOSTNAME_CHECKSUM}_${i}		\
		       	--idtype uid --idmap $client_id:$fs_id; then
				rc=$(($rc + 1))
			fi
			if ! do_facet mgs $cmd				\
			--name ${HOSTNAME_CHECKSUM}_${i}		\
		       	--idtype gid --idmap $client_id:$fs_id; then
				rc=$(($rc + 1))
			fi
		done
	done

	return $rc
}

delete_idmaps() {
	local i
	local j
	local client_id
	local fs_id
	local cmd="$LCTL nodemap_del_idmap"
	local rc=0

	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		for ((j = 500; j < NODEMAP_MAX_ID; j++)); do
			client_id=$j
			fs_id=$(($j + 1))
			if ! do_facet mgs $cmd				\
			--name ${HOSTNAME_CHECKSUM}_${i}		\
		       	--idtype uid --idmap $client_id:$fs_id; then
				rc=$(($rc + 1))
			fi
			if ! do_facet mgs $cmd				\
			--name ${HOSTNAME_CHECKSUM}_${i}		\
		       	--idtype gid --idmap $client_id:$fs_id; then
				rc=$(($rc + 1))
			fi
		done
	done

	return $rc
}

modify_flags() {
	local i
	local proc
	local option
	local cmd="$LCTL nodemap_modify"
	local rc=0

	proc[0]="admin_nodemap"
	proc[1]="trusted_nodemap"
	option[0]="admin"
	option[1]="trusted"

	for ((idx = 0; idx < 2; idx++)); do
		if ! do_facet mgs $cmd --name $1	\
			--property ${option[$idx]}	\
			--value 1; then
			rc=$((rc + 1))
		fi

		if ! do_facet mgs $cmd --name $1	\
			--property ${option[$idx]}	\
			--value 0; then
			rc=$((rc + 1))
		fi
	done

	return $rc
}

squash_id() {
	local cmd

	cmd[0]="$LCTL nodemap_modify --property squash_uid"
	cmd[1]="$LCTL nodemap_modify --property squash_gid"

	if ! do_facet mgs ${cmd[$3]} --name $1 --value $2; then
		return 1
	fi
}

# ensure that the squash defaults are the expected defaults
squash_id default 99 0
squash_id default 99 1

test_nid() {
	local cmd

	cmd="$LCTL nodemap_test_nid"

	nid=$(do_facet mgs $cmd $1)

	if [ $nid == $2 ]; then
		return 0
	fi

	return 1
}

test_idmap() {
	local i
	local j
	local fs_id
	local cmd="$LCTL nodemap_test_id"
	local rc=0

	## nodemap deactivated
	if ! do_facet mgs lctl nodemap_activate 0; then
		return 1
	fi
	for ((id = 500; id < NODEMAP_MAX_ID; id++)); do
		for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
			nid="$SUBNET_CHECKSUM.0.${j}.100@tcp"
			fs_id=$(do_facet mgs $cmd --nid $nid	\
				--idtype uid --id $id)
			if [ $fs_id != $id ]; then
				rc=$((rc + 1))
			fi
		done
	done

	## nodemap activated
	if ! do_facet mgs lctl nodemap_activate 1; then
		return 2
	fi

	for ((id = 500; id < NODEMAP_MAX_ID; id++)); do
		for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
			nid="$SUBNET_CHECKSUM.0.${j}.100@tcp"
			fs_id=$(do_facet mgs $cmd --nid $nid	\
				--idtype uid --id $id)
			expected_id=$((id + 1))
			if [ $fs_id != $expected_id ]; then
				rc=$((rc + 1))
			fi
		done
	done

	## trust client ids
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! do_facet mgs $LCTL nodemap_modify			\
				--name ${HOSTNAME_CHECKSUM}_${i}	\
				--property trusted --value 1; then
			error "nodemap_modify ${HOSTNAME_CHECKSUM}_${i} "
				"failed with $rc"
			return 3
		fi
	done

	for ((id = 500; id < NODEMAP_MAX_ID; id++)); do
		for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
			nid="$SUBNET_CHECKSUM.0.${j}.100@tcp"
			fs_id=$(do_facet mgs $cmd --nid $nid	\
				--idtype uid --id $id)
			expected_id=$((id + 1))
			if [ $fs_id != $id ]; then
				rc=$((rc + 1))
			fi
		done
	done

	## ensure allow_root_access is enabled
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! do_facet mgs $LCTL nodemap_modify		\
			--name ${HOSTNAME_CHECKSUM}_${i}	\
			--property admin --value 1; then
			error "nodemap_modify ${HOSTNAME_CHECKSUM}_${i} "
				"failed with $rc"
			return 3
		fi
	done

	## check that root is mapped to 99
	for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
		nid="$SUBNET_CHECKSUM.0.${j}.100@tcp"
		fs_id=$(do_facet mgs $cmd --nid $nid --idtype uid --id 0)
		expected_id=$((id + 1))
		if [ $fs_id != 0 ]; then
			rc=$((rc + 1))
		fi
	done

	## ensure allow_root_access is disabled
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! do_facet mgs $LCTL nodemap_modify		\
				--name ${HOSTNAME_CHECKSUM}_${i}	\
				--property admin --value 0; then
			error "nodemap_modify ${HOSTNAME_CHECKSUM}_${i} "
				"failed with $rc"
			return 3
		fi
	done

	## check that root allowed
	for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
		nid="$SUBNET_CHECKSUM.0.${j}.100@tcp"
		fs_id=$(do_facet mgs $cmd --nid $nid --idtype uid --id 0)
		expected_id=$((id + 1))
		if [ $fs_id != 99 ]; then
			rc=$((rc + 1))
		fi
	done

	## reset client trust to 0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! do_facet mgs $LCTL nodemap_modify		\
			--name ${HOSTNAME_CHECKSUM}_${i}	\
			--property trusted --value 0; then
			error "nodemap_modify ${HOSTNAME_CHECKSUM}_${i} "
				"failed with $rc"
			return 3
		fi
	done

	return $rc
}

test_7() {
	local rc

	remote_mgs_nodsh && skip "remote MGS with nodsh" && return
	[ $(lustre_version_code $SINGLEMGS) -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $(get_lustre_version) MGS, need 2.5.53+" &&
		return

	create_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 1

	delete_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 2

	return 0
}
run_test 7 "nodemap create and delete"

test_8() {
	local rc

	remote_mgs_nodsh && skip "remote MGS with nodsh" && return
	[ $(lustre_version_code $SINGLEMGS) -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $(get_lustre_version) MGS, need 2.5.53+" &&
		return

	# Set up nodemaps

	create_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 1

	# Try duplicates

	create_nodemaps
	rc=$?
	[[ $rc == 0 ]] && error "duplicate nodemap_add allowed with $rc" &&
	return 2

	# Clean up
	delete_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 3

	return 0
}
run_test 8 "nodemap reject duplicates"

test_9() {
	local i
	local rc

	remote_mgs_nodsh && skip "remote MGS with nodsh" && return
	[ $(lustre_version_code $SINGLEMGS) -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $(get_lustre_version) MGS, need 2.5.53+" &&
		return

	rc=0
	create_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 1

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! add_range ${HOSTNAME_CHECKSUM}_${i} $i; then
			rc=$((rc + 1))
		fi
	done
	[[ $rc != 0 ]] && error "nodemap_add_range failed with $rc" && return 2

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! delete_range ${HOSTNAME_CHECKSUM}_${i} $i; then
			rc=$((rc + 1))
		fi
	done
	[[ $rc != 0 ]] && error "nodemap_del_range failed with $rc" && return 4

	rc=0
	delete_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 4

	return 0
}
run_test 9 "nodemap range add"

test_10() {
	local rc

	remote_mgs_nodsh && skip "remote MGS with nodsh" && return
	[ $(lustre_version_code $SINGLEMGS) -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $(get_lustre_version) MGS, need 2.5.53+" &&
		return

	rc=0
	create_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 1

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! add_range ${HOSTNAME_CHECKSUM}_${i} $i; then
			rc=$((rc + 1))
		fi
	done
	[[ $rc != 0 ]] && error "nodemap_add_range failed with $rc" && return 2

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! add_range ${HOSTNAME_CHECKSUM}_${i} $i; then
			rc=$((rc + 1))
		fi
	done
	[[ $rc == 0 ]] && error "nodemap_add_range duplicate add with $rc" &&
		return 2


	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! delete_range ${HOSTNAME_CHECKSUM}_${i} $i; then
			rc=$((rc + 1))
		fi
	done
	[[ $rc != 0 ]] && error "nodemap_del_range failed with $rc" && return 4

	delete_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 5

	return 0
}
run_test 10 "nodemap reject duplicate ranges"

test_11() {
	local rc

	remote_mgs_nodsh && skip "remote MGS with nodsh" && return
	[ $(lustre_version_code $SINGLEMGS) -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $(get_lustre_version) MGS, need 2.5.53+" &&
		return

	rc=0
	create_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 1

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! modify_flags ${HOSTNAME_CHECKSUM}_${i}; then
			rc=$((rc + 1))
		fi
	done
	[[ $rc != 0 ]] && error "nodemap_modify with $rc" && return 2

	rc=0
	delete_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_del failed with $rc" && return 3

	return 0
}
run_test 11 "nodemap modify"

test_12() {
	local rc

	remote_mgs_nodsh && skip "remote MGS with nodsh" && return
	[ $(lustre_version_code $SINGLEMGS) -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $(get_lustre_version) MGS, need 2.5.53+" &&
		return

	rc=0
	create_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 1

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! squash_id ${HOSTNAME_CHECKSUM}_${i} 88 0; then
			rc=$((rc + 1))
		fi
	done
	[[ $rc != 0 ]] && error "nodemap squash_uid with $rc" && return 2

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! squash_id ${HOSTNAME_CHECKSUM}_${i} 88 1; then
			rc=$((rc + 1))
		fi
	done
	[[ $rc != 0 ]] && error "nodemap squash_gid with $rc" && return 3

	rc=0
	delete_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_del failed with $rc" && return 4

	return 0
}
run_test 12 "nodemap set squash ids"

test_13() {
	local rc

	remote_mgs_nodsh && skip "remote MGS with nodsh" && return
	[ $(lustre_version_code $SINGLEMGS) -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $(get_lustre_version) MGS, need 2.5.53+" &&
		return

	rc=0
	create_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 1

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! add_range ${HOSTNAME_CHECKSUM}_${i} $i; then
			rc=$((rc + 1))
		fi
	done
	[[ $rc != 0 ]] && error "nodemap_add_range failed with $rc" && return 2

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
			for ((k = 1; k < 253; k++)); do
				if ! test_nid $SUBNET_CHECKSUM.$i.$j.$k	\
				       ${HOSTNAME_CHECKSUM}_${i}; then
					rc=$((rc + 1))
				fi
			done
		done
	done
	[[ $rc != 0 ]] && error "nodemap_test_nid failed with $rc" && return 3

	rc=0
	delete_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_del failed with $rc" && return 4

	return 0
}
run_test 13 "test nids"

test_14() {
	local rc

	remote_mgs_nodsh && skip "remote MGS with nodsh" && return
	[ $(lustre_version_code $SINGLEMGS) -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $(get_lustre_version) MGS, need 2.5.53+" &&
		return

	rc=0
	create_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 1

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
			for ((k = 1; k < 253; k++)); do
				if ! test_nid $SUBNET_CHECKSUM.$i.$j.$k \
					default; then
					rc=$((rc + 1))
				fi
			done
		done
	done
	[[ $rc != 0 ]] && error "nodemap_test_nid failed with $rc" && return 3

	rc=0
	delete_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_del failed with $rc" && return 4

	return 0
}
run_test 14 "test default nodemap nid lookup"

test_15() {
	local rc

	remote_mgs_nodsh && skip "remote MGS with nodsh" && return
	[ $(lustre_version_code $SINGLEMGS) -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $(get_lustre_version) MGS, need 2.5.53+" &&
		return

	rc=0
	create_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 1

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! add_range ${HOSTNAME_CHECKSUM}_${i} $i; then
			rc=$((rc + 1))
		fi
	done
	[[ $rc != 0 ]] && error "nodemap_add_range failed with $rc" && return 2

	rc=0
	add_idmaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add_idmap failed with $rc" && return 3

	rc=0
	test_idmap
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_test_id failed with $rc" && return 4

	rc=0
	delete_idmaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_del_idmap failed with $rc" && return 5

	rc=0
	delete_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_delete failed with $rc" && return 6

	return 0
}
run_test 15 "test id mapping"

log "cleanup: ======================================================"

sec_unsetup() {
	## nodemap deactivated
	do_facet mgs lctl nodemap_activate 0

	for num in $(seq $MDSCOUNT); do
		if [ "${identity_old[$num]}" = 1 ]; then
			switch_identity $num false || identity_old[$num]=$?
		fi
	done

	$RUNAS -u $ID0 ls $DIR
	$RUNAS -u $ID1 ls $DIR
}
sec_unsetup

sec_cleanup

complete $SECONDS
exit_status
