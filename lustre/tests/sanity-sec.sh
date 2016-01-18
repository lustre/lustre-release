#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#

set -e

ONLY=${ONLY:-"$*"}
# bug number for skipped test: 19430 19967 19967
ALWAYS_EXCEPT="                2     5     6    $SANITY_SEC_EXCEPT"
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

[ "$ALWAYS_EXCEPT$EXCEPT" ] && echo "Skipping tests: $ALWAYS_EXCEPT $EXCEPT"

SRCDIR=$(dirname $0)
export PATH=$PWD/$SRCDIR:$SRCDIR:$PWD/$SRCDIR/../utils:$PATH:/sbin
export NAME=${NAME:-local}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

RUNAS_CMD=${RUNAS_CMD:-runas}

WTL=${WTL:-"$LUSTRE/tests/write_time_limit"}

CONFDIR=/etc/lustre
PERM_CONF=$CONFDIR/perm.conf
FAIL_ON_ERROR=false

HOSTNAME_CHECKSUM=$(hostname | sum | awk '{ print $1 }')
SUBNET_CHECKSUM=$(expr $HOSTNAME_CHECKSUM % 250 + 1)
NODEMAP_COUNT=16
NODEMAP_RANGE_COUNT=3
NODEMAP_IPADDR_LIST="1 10 64 128 200 250"
NODEMAP_MAX_ID=128

require_dsh_mds || exit 0
require_dsh_ost || exit 0

clients=${CLIENTS//,/ }
num_clients=$(get_node_count ${clients})
clients_arr=($clients)

ID0=${ID0:-500}
ID1=${ID1:-501}
USER0=$(grep :$ID0:$ID0: /etc/passwd | cut -d: -f1)
USER1=$(grep :$ID1:$ID1: /etc/passwd | cut -d: -f1)

[ -z "$USER0" ] &&
	skip "need to add user0 ($ID0:$ID0) to /etc/passwd" && exit 0

[ -z "$USER1" ] &&
	skip "need to add user1 ($ID1:$ID1) to /etc/passwd" && exit 0

IDBASE=${IDBASE:-60000}

# changes to mappings must be reflected in test 23
FOPS_IDMAPS=(
	[0]="$((IDBASE+3)):$((IDBASE+0)) $((IDBASE+4)):$((IDBASE+2))"
	[1]="$((IDBASE+5)):$((IDBASE+1)) $((IDBASE+6)):$((IDBASE+2))"
	)

check_and_setup_lustre

sec_cleanup() {
	if [ "$I_MOUNTED" = "yes" ]; then
		cleanupall -f || error "sec_cleanup"
	fi
}

DIR=${DIR:-$MOUNT}
[ -z "$(echo $DIR | grep $MOUNT)" ] &&
	error "$DIR not in $MOUNT" && sec_cleanup && exit 1

[ $(echo $MOUNT | wc -w) -gt 1 ] &&
	echo "NAME=$MOUNT mounted more than once" && sec_cleanup && exit 0

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
IDENTITY_UPCALL=mdt.$MDT.identity_upcall
MDSSECLEVEL=mdt.$MDT.sec_level

# for CLIENT_TYPE
if [ -z "$(lctl get_param -n llite.*.client_type | grep remote 2>/dev/null)" ]
then
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

	if ! $RUNAS_CMD -u $user krb5_login.sh; then
		error "$user login kerberos failed."
		exit 1
	fi

	if ! $RUNAS_CMD -u $user -g $group ls $DIR > /dev/null 2>&1; then
		$RUNAS_CMD -u $user lfs flushctx -k
		$RUNAS_CMD -u $user krb5_login.sh
		if ! $RUNAS_CMD -u$user -g$group ls $DIR > /dev/null 2>&1; then
			error "init $user $group failed."
			exit 2
		fi
	fi
}

declare -a identity_old

sec_setup() {
	for num in $(seq $MDSCOUNT); do
		switch_identity $num true || identity_old[$num]=$?
	done

	if ! $RUNAS_CMD -u $ID0 ls $DIR > /dev/null 2>&1; then
		sec_login $USER0 $USER0
	fi

	if ! $RUNAS_CMD -u $ID1 ls $DIR > /dev/null 2>&1; then
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

	$RUNAS_CMD -u $ID0 ls $DIR || error "ls (1)"
	rm -f $DIR/f0 || error "rm (2)"
	$RUNAS_CMD -u $ID0 touch $DIR/f0 && error "touch (1)"
	$RUNAS_CMD -u $ID0 touch $DIR/$tdir/f1 || error "touch (2)"
	$RUNAS_CMD -u $ID1 touch $DIR/$tdir/f2 && error "touch (3)"
	touch $DIR/$tdir/f3 || error "touch (4)"
	chown root $DIR/$tdir || error "chown (3)"
	chgrp $USER0 $DIR/$tdir || error "chgrp (1)"
	chmod 0775 $DIR/$tdir || error "chmod (2)"
	$RUNAS_CMD -u $ID0 touch $DIR/$tdir/f4 || error "touch (5)"
	$RUNAS_CMD -u $ID1 touch $DIR/$tdir/f5 && error "touch (6)"
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
	$RUNAS_CMD -u $ID1 -v $ID0 touch $DIR/$tdir/f0 && error "touch (2)"
	echo "enable uid $ID1 setuid"
	do_facet $SINGLEMDS "echo '* $ID1 setuid' >> $PERM_CONF"
	do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
	$RUNAS_CMD -u $ID1 -v $ID0 touch $DIR/$tdir/f1 || error "touch (3)"

	chown root $DIR/$tdir || error "chown (4)"
	chgrp $USER0 $DIR/$tdir || error "chgrp (5)"
	chmod 0770 $DIR/$tdir || error "chmod (6)"
	$RUNAS_CMD -u $ID1 -g $ID1 touch $DIR/$tdir/f2 && error "touch (7)"
	$RUNAS_CMD -u$ID1 -g$ID1 -j$ID0 touch $DIR/$tdir/f3 && error "touch (8)"
	echo "enable uid $ID1 setuid,setgid"
	do_facet $SINGLEMDS "echo '* $ID1 setuid,setgid' > $PERM_CONF"
	do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
	$RUNAS_CMD -u $ID1 -g $ID1 -j $ID0 touch $DIR/$tdir/f4 ||
		error "touch (9)"
	$RUNAS_CMD -u $ID1 -v $ID0 -g $ID1 -j $ID0 touch $DIR/$tdir/f5 ||
		error "touch (10)"

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
	[ "$CLIENT_TYPE" = "local" ] &&
		skip "remote_acl for remote client only" && return
	[ -z "$(lctl get_param -n mdc.*-mdc-*.connect_flags | grep ^acl)" ] &&
		skip "must have acl enabled" && return
	[ -z "$(which setfacl 2>/dev/null)" ] &&
		skip "could not find setfacl" && return
	[ "$UID" != 0 ] && skip "must run as root" && return

	do_facet $SINGLEMDS "echo '* 0 rmtacl,rmtown' > $PERM_CONF"
	do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"

	sec_login root root
	sec_login bin bin
	sec_login daemon daemon
	sec_login games users

	SAVE_UMASK=$(umask)
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

# bug 3285 - supplementary group should always succeed.
# NB: the supplementary groups are set for local client only,
# as for remote client, the groups of the specified uid on MDT
# will be obtained by upcall /sbin/l_getidentity and used.
test_4() {
	local server_version=$(lustre_version_code $SINGLEMDS)

	[[ $server_version -ge $(version_code 2.6.93) ]] ||
	[[ $server_version -ge $(version_code 2.5.35) &&
	   $server_version -lt $(version_code 2.5.50) ]] ||
		{ skip "Need MDS version at least 2.6.93 or 2.5.35"; return; }

	if [ "$CLIENT_TYPE" = "remote" ]; then
		do_facet $SINGLEMDS "echo '* 0 rmtown' > $PERM_CONF"
	        do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
	fi

	rm -rf $DIR/$tdir
	mkdir -p $DIR/$tdir
	chmod 0771 $DIR/$tdir
	chgrp $ID0 $DIR/$tdir
	$RUNAS_CMD -u $ID0 ls $DIR/$tdir || error "setgroups (1)"
	if [ "$CLIENT_TYPE" = "local" ]; then
		do_facet $SINGLEMDS "echo '* $ID1 setgrp' > $PERM_CONF"
		do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
		$RUNAS_CMD -u $ID1 -G1,2,$ID0 ls $DIR/$tdir ||
			error "setgroups (2)"
	fi
	$RUNAS_CMD -u $ID1 -G1,2 ls $DIR/$tdir && error "setgroups (3)"
	rm -rf $DIR/$tdir

	do_facet $SINGLEMDS "rm -f $PERM_CONF"
	do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
}
run_test 4 "set supplementary group ==============="

create_nodemaps() {
	local i
	local out
	local rc

	squash_id default 99 0
	squash_id default 99 1
	for (( i = 0; i < NODEMAP_COUNT; i++ )); do
		local csum=${HOSTNAME_CHECKSUM}_${i}

		if ! do_facet mgs $LCTL nodemap_add $csum; then
		       	return 1
		fi

		out=$(do_facet mgs $LCTL get_param nodemap.$csum.id)
		## This needs to return zero if the following statement is 1
		[[ $(echo $out | grep -c $csum) == 0 ]] && return 1
	done
	return 0
}

delete_nodemaps() {
	local i
	local out

	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		local csum=${HOSTNAME_CHECKSUM}_${i}

		if ! do_facet mgs $LCTL nodemap_del $csum; then
			error "nodemap_del $csum failed with $?"
			return 3
		fi

		out=$(do_facet mgs $LCTL get_param nodemap.$csum.id)
		[[ $(echo $out | grep -c $csum) != 0 ]] && return 1
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
		if ! do_facet mgs $cmd --name $1 --range $range; then
			rc=$((rc + 1))
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
		if ! do_facet mgs $cmd --name $1 --range $range; then
			rc=$((rc + 1))
		fi
	done

	return $rc
}

add_idmaps() {
	local i
	local cmd="$LCTL nodemap_add_idmap"
	local rc=0

	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		local j

		for ((j = 500; j < NODEMAP_MAX_ID; j++)); do
			local csum=${HOSTNAME_CHECKSUM}_${i}
			local client_id=$j
			local fs_id=$((j + 1))

			if ! do_facet mgs $cmd --name $csum --idtype uid \
			     --idmap $client_id:$fs_id; then
				rc=$((rc + 1))
			fi
			if ! do_facet mgs $cmd --name $csum --idtype gid \
			     --idmap $client_id:$fs_id; then
				rc=$((rc + 1))
			fi
		done
	done

	return $rc
}

delete_idmaps() {
	local i
	local cmd="$LCTL nodemap_del_idmap"
	local rc=0

	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		local j

		for ((j = 500; j < NODEMAP_MAX_ID; j++)); do
			local csum=${HOSTNAME_CHECKSUM}_${i}
			local client_id=$j
			local fs_id=$((j + 1))

			if ! do_facet mgs $cmd --name $csum --idtype uid \
			     --idmap $client_id:$fs_id; then
				rc=$((rc + 1))
			fi
			if ! do_facet mgs $cmd --name $csum --idtype gid \
			     --idmap $client_id:$fs_id; then
				rc=$((rc + 1))
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
		if ! do_facet mgs $cmd --name $1 --property ${option[$idx]} \
		     --value 1; then
			rc=$((rc + 1))
		fi

		if ! do_facet mgs $cmd --name $1 --property ${option[$idx]} \
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
	local cmd="$LCTL nodemap_test_id"
	local rc=0

	## nodemap deactivated
	if ! do_facet mgs lctl nodemap_activate 0; then
		return 1
	fi
	for ((id = 500; id < NODEMAP_MAX_ID; id++)); do
		local j

		for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
			local nid="$SUBNET_CHECKSUM.0.${j}.100@tcp"
			local fs_id=$(do_facet mgs $cmd --nid $nid	\
				      --idtype uid --id $id)
			if [ $fs_id != $id ]; then
				echo "expected $id, got $fs_id"
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
				echo "expected $expected_id, got $fs_id"
				rc=$((rc + 1))
			fi
		done
	done

	## trust client ids
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		local csum=${HOSTNAME_CHECKSUM}_${i}

		if ! do_facet mgs $LCTL nodemap_modify --name $csum \
		     --property trusted --value 1; then
			error "nodemap_modify $csum failed with $?"
			return 3
		fi
	done

	for ((id = 500; id < NODEMAP_MAX_ID; id++)); do
		for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
			nid="$SUBNET_CHECKSUM.0.${j}.100@tcp"
			fs_id=$(do_facet mgs $cmd --nid $nid	\
				--idtype uid --id $id)
			if [ $fs_id != $id ]; then
				echo "expected $id, got $fs_id"
				rc=$((rc + 1))
			fi
		done
	done

	## ensure allow_root_access is enabled
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		local csum=${HOSTNAME_CHECKSUM}_${i}

		if ! do_facet mgs $LCTL nodemap_modify --name $csum	\
		     --property admin --value 1; then
			error "nodemap_modify $csum failed with $?"
			return 3
		fi
	done

	## check that root allowed
	for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
		nid="$SUBNET_CHECKSUM.0.${j}.100@tcp"
		fs_id=$(do_facet mgs $cmd --nid $nid --idtype uid --id 0)
		if [ $fs_id != 0 ]; then
			echo "root allowed expected 0, got $fs_id"
			rc=$((rc + 1))
		fi
	done

	## ensure allow_root_access is disabled
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		local csum=${HOSTNAME_CHECKSUM}_${i}

		if ! do_facet mgs $LCTL nodemap_modify --name $csum	\
				--property admin --value 0; then
			error "nodemap_modify ${HOSTNAME_CHECKSUM}_${i} "
				"failed with $rc"
			return 3
		fi
	done

	## check that root is mapped to 99
	for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
		nid="$SUBNET_CHECKSUM.0.${j}.100@tcp"
		fs_id=$(do_facet mgs $cmd --nid $nid --idtype uid --id 0)
		if [ $fs_id != 99 ]; then
			error "root squash expected 99, got $fs_id"
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
	[ $(lustre_version_code mgs) -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $(lustre_build_version mgs) MGS < 2.5.53" &&
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
	[ $(lustre_version_code mgs) -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $(lustre_build_version mgs) MGS < 2.5.53" &&
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
	[ $(lustre_version_code mgs) -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $(lustre_build_version mgs) MGS < 2.5.53" &&
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
	[ $(lustre_version_code mgs) -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $(lustre_build_version mgs) MGS < 2.5.53" &&
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
	[ $(lustre_version_code mgs) -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $(lustre_build_version mgs) MGS < 2.5.53" &&
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
	[ $(lustre_version_code mgs) -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $(lustre_build_version mgs) MGS < 2.5.53" &&
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
	[ $(lustre_version_code mgs) -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $(lustre_build_version mgs) MGS < 2.5.53" &&
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
			for k in $NODEMAP_IPADDR_LIST; do
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
	[ $(lustre_version_code mgs) -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $(lustre_build_version mgs) MGS < 2.5.53" &&
		return

	rc=0
	create_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 1

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
			for k in $NODEMAP_IPADDR_LIST; do
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
	[ $(lustre_version_code mgs) -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $(lustre_build_version mgs) MGS < 2.5.53" &&
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

# Until nodemaps are distributed by MGS, they need to be distributed manually
# This function and all calls to it should be removed once the MGS distributes
# nodemaps to the MDS and OSS nodes directly.
do_servers_not_mgs() {
	local mgs_ip=$(host_nids_address $mgs_HOST $NETTYPE)
	for node in $(all_server_nodes); do
		local node_ip=$(host_nids_address $node $NETTYPE)
		[ $node_ip == $mgs_ip ] && continue
		do_node $node_ip $*
	done
}

create_fops_nodemaps() {
	local i=0
	local client
	for client in $clients; do
		local client_ip=$(host_nids_address $client $NETTYPE)
		local client_nid=$(h2$NETTYPE $client_ip)
		do_facet mgs $LCTL nodemap_add c${i} || return 1
		do_facet mgs $LCTL nodemap_add_range 	\
			--name c${i} --range $client_nid || return 1
		do_servers_not_mgs $LCTL set_param nodemap.add_nodemap=c${i} ||
			return 1
		do_servers_not_mgs "$LCTL set_param " \
			"nodemap.add_nodemap_range='c${i} $client_nid'" ||
			return 1
		for map in ${FOPS_IDMAPS[i]}; do
			do_facet mgs $LCTL nodemap_add_idmap --name c${i} \
				--idtype uid --idmap ${map} || return 1
			do_servers_not_mgs "$LCTL set_param " \
				"nodemap.add_nodemap_idmap='c$i uid ${map}'" ||
				return 1
			do_facet mgs $LCTL nodemap_add_idmap --name c${i} \
				--idtype gid --idmap ${map} || return 1
			do_servers_not_mgs "$LCTL set_param " \
				" nodemap.add_nodemap_idmap='c$i gid ${map}'" ||
				return 1
		done
		out1=$(do_facet mgs $LCTL get_param nodemap.c${i}.idmap)
		out2=$(do_facet ost0 $LCTL get_param nodemap.c${i}.idmap)
		[ "$out1" != "$out2" ] && error "mgs and oss maps mismatch"
		i=$((i + 1))
	done
	return 0
}

delete_fops_nodemaps() {
	local i=0
	local client
	for client in $clients; do
		do_facet mgs $LCTL nodemap_del c${i} || return 1
		do_servers_not_mgs $LCTL set_param nodemap.remove_nodemap=c$i ||
			return 1
		i=$((i + 1))
	done
	return 0
}

fops_mds_index=0
nm_test_mkdir() {
	if [ $MDSCOUNT -le 1 ]; then
		do_node ${clients_arr[0]} mkdir -p $DIR/$tdir
	else
		# round-robin MDTs to test DNE nodemap support
		[ ! -d $DIR ] && do_node ${clients_arr[0]} mkdir -p $DIR
		do_node ${clients_arr[0]} $LFS setdirstripe -c 1 -i \
			$((fops_mds_index % MDSCOUNT)) $DIR/$tdir
		((fops_mds_index++))
	fi
}

# acl test directory needs to be initialized on a privileged client
fops_test_setup() {
	local admin=$(do_facet mgs $LCTL get_param -n nodemap.c0.admin_nodemap)
	local trust=$(do_facet mgs $LCTL get_param -n \
		nodemap.c0.trusted_nodemap)

	do_facet mgs $LCTL nodemap_modify --name c0 --property admin --value 1
	do_facet mgs $LCTL nodemap_modify --name c0 --property trusted --value 1
	do_servers_not_mgs $LCTL set_param nodemap.c0.admin_nodemap=1
	do_servers_not_mgs $LCTL set_param nodemap.c0.trusted_nodemap=1

	do_node ${clients_arr[0]} rm -rf $DIR/$tdir
	nm_test_mkdir
	do_node ${clients_arr[0]} chown $user $DIR/$tdir

	do_facet mgs $LCTL nodemap_modify --name c0 \
		--property admin --value $admin
	do_facet mgs $LCTL nodemap_modify --name c0 \
		--property trusted --value $trust
	do_servers_not_mgs $LCTL set_param nodemap.c0.admin_nodemap=$admin
	do_servers_not_mgs $LCTL set_param nodemap.c0.trusted_nodemap=$trust

	# flush MDT locks to make sure they are reacquired before test
	do_node ${clients_arr[0]} lctl set_param \
		ldlm.namespaces.$FSNAME-MDT*.lru_size=clear
}

do_create_delete() {
	local run_u=$1
	local key=$2
	local testfile=$DIR/$tdir/$tfile
	local rc=0
	local c=0 d=0
	local qused_new
	if $run_u touch $testfile >& /dev/null; then
		c=1
		$run_u rm $testfile && d=1
	fi >& /dev/null

	local res="$c $d"
	local expected=$(get_cr_del_expected $key)
	[ "$res" != "$expected" ] &&
		error "test $key, wanted $expected, got $res" && rc=$((rc + 1))
	return $rc
}

nodemap_check_quota() {
	local run_u="$1"
	$run_u lfs quota -q $DIR | awk '{ print $2; exit; }'
}

do_fops_quota_test() {
	local run_u=$1
	# fuzz quota used to account for possible indirect blocks, etc
	local quota_fuzz=$(fs_log_size)
	local qused_orig=$(nodemap_check_quota "$run_u")
	local qused_high=$((qused_orig + quota_fuzz))
	local qused_low=$((qused_orig - quota_fuzz))
	local testfile=$DIR/$tdir/$tfile
	chmod 777 $DIR/$tdir
	$run_u dd if=/dev/zero of=$testfile bs=1M count=1 >& /dev/null
	sync; sync_all_data || true

	local qused_new=$(nodemap_check_quota "$run_u")
	[ $((qused_new)) -lt $((qused_low + 1024)) -o \
	  $((qused_new)) -gt $((qused_high + 1024)) ] &&
		error "$qused_new != $qused_orig + 1M after write, " \
		      "fuzz is $quota_fuzz"
	$run_u rm $testfile && d=1
	$NODEMAP_TEST_QUOTA && wait_delete_completed_mds

	qused_new=$(nodemap_check_quota "$run_u")
	[ $((qused_new)) -lt $((qused_low)) \
		-o $((qused_new)) -gt $((qused_high)) ] &&
		error "quota not reclaimed, expect $qused_orig, " \
		      "got $qused_new, fuzz $quota_fuzz"
}

get_fops_mapped_user() {
	local cli_user=$1

	for ((i=0; i < ${#FOPS_IDMAPS[@]}; i++)); do
		for map in ${FOPS_IDMAPS[i]}; do
			if [ $(cut -d: -f1 <<< "$map") == $cli_user ]; then
				cut -d: -f2 <<< "$map"
				return
			fi
		done
	done
	echo -1
}

get_cr_del_expected() {
	local -a key
	IFS=":" read -a key <<< "$1"
	local mapmode="${key[0]}"
	local mds_user="${key[1]}"
	local cluster="${key[2]}"
	local cli_user="${key[3]}"
	local mode="0${key[4]}"
	local SUCCESS="1 1"
	local FAILURE="0 0"
	local noadmin=0
	local mapped=0
	local other=0

	[[ $mapmode == *mapped* ]] && mapped=1
	# only c1 is mapped in these test cases
	[[ $mapmode == mapped_trusted* ]] && [ "$cluster" == "c0" ] && mapped=0
	[[ $mapmode == *noadmin* ]] && noadmin=1

	# o+wx works as long as the user isn't mapped
	if [ $((mode & 3)) -eq 3 ]; then
		other=1
	fi

	# if client user is root, check if root is squashed
	if [ "$cli_user" == "0" ]; then
		# squash root succeed, if other bit is on
		case $noadmin in
			0) echo $SUCCESS;;
			1) [ "$other" == "1" ] && echo $SUCCESS
			   [ "$other" == "0" ] && echo $FAILURE;;
		esac
		return
	fi
	if [ "$mapped" == "0" ]; then
		[ "$other" == "1" ] && echo $SUCCESS
		[ "$other" == "0" ] && echo $FAILURE
		return
	fi

	# if mapped user is mds user, check for u+wx
	mapped_user=$(get_fops_mapped_user $cli_user)
	[ "$mapped_user" == "-1" ] &&
		error "unable to find mapping for client user $cli_user"

	if [ "$mapped_user" == "$mds_user" -a \
	     $(((mode & 0300) == 0300)) -eq 1 ]; then
		echo $SUCCESS
		return
	fi
	if [ "$mapped_user" != "$mds_user" -a "$other" == "1" ]; then
		echo $SUCCESS
		return
	fi
	echo $FAILURE
}

test_fops() {
	local mapmode="$1"
	local single_client="$2"
	local client_user_list=([0]="0 $((IDBASE+3)) $((IDBASE+4))"
				[1]="0 $((IDBASE+5)) $((IDBASE+6))")
	local mds_i
	local rc=0
	local perm_bit_list="0 3 $((0300)) $((0303))"
	# SLOW tests 000-007, 010-070, 100-700 (octal modes)
	[ "$SLOW" == "yes" ] &&
		perm_bit_list="0 $(seq 1 7) $(seq 8 8 63) $(seq 64 64 511) \
			       $((0303))"

	# step through mds users. -1 means root
	for mds_i in -1 0 1 2; do
		local user=$((mds_i + IDBASE))
		local client
		local x

		[ "$mds_i" == "-1" ] && user=0

		echo mkdir -p $DIR/$tdir
		fops_test_setup
		local cli_i=0
		for client in $clients; do
			local u
			local admin=$(do_facet mgs $LCTL get_param -n \
				      nodemap.c$cli_i.admin_nodemap)
			for u in ${client_user_list[$cli_i]}; do
				local run_u="do_node $client \
					     $RUNAS_CMD -u$u -g$u -G$u"
				for perm_bits in $perm_bit_list; do
					local mode=$(printf %03o $perm_bits)
					local key
					key="$mapmode:$user:c$cli_i:$u:$mode"
					do_facet mgs $LCTL nodemap_modify \
						--name c$cli_i		  \
						--property admin	  \
						--value 1
					do_servers_not_mgs $LCTL set_param \
						nodemap.c$cli_i.admin_nodemap=1
					do_node $client chmod $mode $DIR/$tdir \
						|| error unable to chmod $key
					do_facet mgs $LCTL nodemap_modify \
						--name c$cli_i		  \
						--property admin	  \
						--value $admin
					do_servers_not_mgs $LCTL set_param \
					    nodemap.c$cli_i.admin_nodemap=$admin

					do_create_delete "$run_u" "$key"
				done

				# check quota
				do_fops_quota_test "$run_u"
			done

			cli_i=$((cli_i + 1))
			[ "$single_client" == "1" ] && break
		done
		rm -rf $DIR/$tdir
	done
	return $rc
}

nodemap_version_check () {
	remote_mgs_nodsh && skip "remote MGS with nodsh" && return 1
	[ $(lustre_version_code mgs) -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $(lustre_build_version mgs) MGS < 2.5.53" &&
		return 1
	return 0
}

nodemap_test_setup() {
	local rc
	local active_nodemap=$1

	do_nodes $(comma_list $(all_mdts_nodes)) \
		$LCTL set_param mdt.*.identity_upcall=NONE

	rc=0
	create_fops_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "adding fops nodemaps failed $rc"

	if [ "$active_nodemap" == "0" ]; then
		do_facet mgs $LCTL set_param nodemap.active=0
		do_servers_not_mgs $LCTL set_param nodemap.active=0
		return
	fi

	do_facet mgs $LCTL nodemap_activate 1
	do_servers_not_mgs $LCTL set_param nodemap.active=1
	do_facet mgs $LCTL nodemap_modify --name default \
		--property admin --value 1
	do_facet mgs $LCTL nodemap_modify --name default \
		--property trusted --value 1
	do_servers_not_mgs $LCTL set_param nodemap.default.admin_nodemap=1
	do_servers_not_mgs $LCTL set_param nodemap.default.trusted_nodemap=1
}

nodemap_test_cleanup() {
	trap 0
	delete_fops_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "removing fops nodemaps failed $rc"

	return 0
}

nodemap_clients_admin_trusted() {
	local admin=$1
	local tr=$2
	local i=0
	for client in $clients; do
		do_facet mgs $LCTL nodemap_modify --name c0 \
			--property admin --value $admin
		do_servers_not_mgs $LCTL set_param \
			nodemap.c${i}.admin_nodemap=$admin
		do_facet mgs $LCTL nodemap_modify --name c0 \
			--property trusted --value $tr
		do_servers_not_mgs $LCTL set_param \
			nodemap.c${i}.trusted_nodemap=$tr
		i=$((i + 1))
	done
}

test_16() {
	nodemap_version_check || return 0
	nodemap_test_setup 0

	trap nodemap_test_cleanup EXIT
	test_fops all_off
	nodemap_test_cleanup
}
run_test 16 "test nodemap all_off fileops"

test_17() {
	nodemap_version_check || return 0
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	nodemap_clients_admin_trusted 0 1
	test_fops trusted_noadmin 1
	nodemap_test_cleanup
}
run_test 17 "test nodemap trusted_noadmin fileops"

test_18() {
	nodemap_version_check || return 0
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	nodemap_clients_admin_trusted 0 0
	test_fops mapped_noadmin 1
	nodemap_test_cleanup
}
run_test 18 "test nodemap mapped_noadmin fileops"

test_19() {
	nodemap_version_check || return 0
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	nodemap_clients_admin_trusted 1 1
	test_fops trusted_admin 1
	nodemap_test_cleanup
}
run_test 19 "test nodemap trusted_admin fileops"

test_20() {
	nodemap_version_check || return 0
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	nodemap_clients_admin_trusted 1 0
	test_fops mapped_admin 1
	nodemap_test_cleanup
}
run_test 20 "test nodemap mapped_admin fileops"

test_21() {
	nodemap_version_check || return 0
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	local x=1
	local i=0
	for client in $clients; do
		do_facet mgs $LCTL nodemap_modify --name c${i} \
			--property admin --value 0
		do_facet mgs $LCTL nodemap_modify --name c${i} \
			--property trusted --value $x
		do_servers_not_mgs $LCTL set_param \
			nodemap.c${i}.admin_nodemap=0
		do_servers_not_mgs $LCTL set_param \
			nodemap.c${i}.trusted_nodemap=$x
		x=0
		i=$((i + 1))
	done
	test_fops mapped_trusted_noadmin
	nodemap_test_cleanup
}
run_test 21 "test nodemap mapped_trusted_noadmin fileops"

test_22() {
	nodemap_version_check || return 0
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	local x=1
	local i=0
	for client in $clients; do
		do_facet mgs $LCTL nodemap_modify --name c${i} \
			--property admin --value 1
		do_facet mgs $LCTL nodemap_modify --name c${i} \
			--property trusted --value $x
		do_servers_not_mgs $LCTL set_param \
			nodemap.c${i}.admin_nodemap=1
		do_servers_not_mgs $LCTL set_param \
			nodemap.c${i}.trusted_nodemap=$x
		x=0
		i=$((i + 1))
	done
	test_fops mapped_trusted_admin
	nodemap_test_cleanup
}
run_test 22 "test nodemap mapped_trusted_admin fileops"

# acl test directory needs to be initialized on a privileged client
nodemap_acl_test_setup() {
	local admin=$(do_facet mgs $LCTL get_param -n nodemap.c0.admin_nodemap)
	local trust=$(do_facet mgs $LCTL get_param -n \
		      nodemap.c0.trusted_nodemap)

	do_facet mgs $LCTL nodemap_modify --name c0 --property admin --value 1
	do_facet mgs $LCTL nodemap_modify --name c0 --property trusted --value 1
	do_servers_not_mgs $LCTL set_param nodemap.c0.admin_nodemap=1
	do_servers_not_mgs $LCTL set_param nodemap.c0.trusted_nodemap=1

	do_node ${clients_arr[0]} rm -rf $DIR/$tdir
	nm_test_mkdir
	do_node ${clients_arr[0]} chmod a+rwx $DIR/$tdir ||
		error unable to chmod a+rwx test dir $DIR/$tdir

	do_facet mgs $LCTL nodemap_modify --name c0 \
		--property admin --value $admin
	do_facet mgs $LCTL nodemap_modify --name c0 \
		--property trusted --value $trust
	do_servers_not_mgs $LCTL set_param nodemap.c0.admin_nodemap=$admin
	do_servers_not_mgs $LCTL set_param nodemap.c0.trusted_nodemap=$trust

}

# returns 0 if the number of ACLs does not change on the second (mapped) client
# after being set on the first client
nodemap_acl_test() {
	local user="$1"
	local set_client="$2"
	local get_client="$3"
	local check_setfacl="$4"
	local setfacl_error=0
	local testfile=$DIR/$tdir/$tfile
	local RUNAS_USER="$RUNAS_CMD -u $user"
	local acl_count=0
	local acl_count_post=0

	nodemap_acl_test_setup
	sleep 5

	do_node $set_client $RUNAS_USER touch $testfile

	# ACL masks aren't filtered by nodemap code, so we ignore them
	acl_count=$(do_node $get_client getfacl $testfile | grep -v mask |
		wc -l)
	do_node $set_client $RUNAS_USER setfacl -m $user:rwx $testfile ||
		setfacl_error=1

	# if check setfacl is set to 1, then it's supposed to error
	if [ "$check_setfacl" == "1" ]; then
		[ "$setfacl_error" != "1" ] && return 1
		return 0
	fi
	[ "$setfacl_error" == "1" ] && echo "WARNING: unable to setfacl"

	acl_count_post=$(do_node $get_client getfacl $testfile | grep -v mask |
		wc -l)
	[ $acl_count -eq $acl_count_post ] && return 0
	return 1
}

test_23() {
	nodemap_version_check || return 0
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	# 1 trusted cluster, 1 mapped cluster
	local unmapped_fs=$((IDBASE+0))
	local unmapped_c1=$((IDBASE+5))
	local mapped_fs=$((IDBASE+2))
	local mapped_c0=$((IDBASE+4))
	local mapped_c1=$((IDBASE+6))

	do_facet mgs $LCTL nodemap_modify --name c0 --property admin --value 1
	do_facet mgs $LCTL nodemap_modify --name c0 --property trusted --value 1
	do_servers_not_mgs $LCTL set_param nodemap.c0.admin_nodemap=1
	do_servers_not_mgs $LCTL set_param nodemap.c0.trusted_nodemap=1

	do_facet mgs $LCTL nodemap_modify --name c1 --property admin --value 0
	do_facet mgs $LCTL nodemap_modify --name c1 --property trusted --value 0
	do_servers_not_mgs $LCTL set_param nodemap.c1.admin_nodemap=0
	do_servers_not_mgs $LCTL set_param nodemap.c1.trusted_nodemap=0

	# setfacl on trusted cluster to unmapped user, verify it's not seen
	nodemap_acl_test $unmapped_fs ${clients_arr[0]} ${clients_arr[1]} ||
		error "acl count (1)"

	# setfacl on trusted cluster to mapped user, verify it's seen
	nodemap_acl_test $mapped_fs ${clients_arr[0]} ${clients_arr[1]} &&
		error "acl count (2)"

	# setfacl on mapped cluster to mapped user, verify it's seen
	nodemap_acl_test $mapped_c1 ${clients_arr[1]} ${clients_arr[0]} &&
		error "acl count (3)"

	# setfacl on mapped cluster to unmapped user, verify error
	nodemap_acl_test $unmapped_fs ${clients_arr[1]} ${clients_arr[0]} 1 ||
		error "acl count (4)"

	# 2 mapped clusters
	do_facet mgs $LCTL nodemap_modify --name c0 --property admin --value 0
	do_facet mgs $LCTL nodemap_modify --name c0 --property trusted --value 0
	do_servers_not_mgs $LCTL set_param nodemap.c0.admin_nodemap=0
	do_servers_not_mgs $LCTL set_param nodemap.c0.trusted_nodemap=0

	# setfacl to mapped user on c1, also mapped to c0, verify it's seen
	nodemap_acl_test $mapped_c1 ${clients_arr[1]} ${clients_arr[0]} &&
		error "acl count (5)"

	# setfacl to mapped user on c1, not mapped to c0, verify not seen
	nodemap_acl_test $unmapped_c1 ${clients_arr[1]} ${clients_arr[0]} ||
		error "acl count (6)"

	nodemap_test_cleanup
}
run_test 23 "test mapped ACLs"

test_24() {
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	do_nodes $(comma_list $(all_server_nodes)) $LCTL get_param -R nodemap ||
		error "proc readable file read failed"

	nodemap_test_cleanup
}
run_test 24 "check nodemap proc files for LBUGs and Oopses"

log "cleanup: ======================================================"

sec_unsetup() {
	## nodemap deactivated
	do_facet mgs lctl nodemap_activate 0

	for num in $(seq $MDSCOUNT); do
		if [ "${identity_old[$num]}" = 1 ]; then
			switch_identity $num false || identity_old[$num]=$?
		fi
	done

	$RUNAS_CMD -u $ID0 ls $DIR
	$RUNAS_CMD -u $ID1 ls $DIR
}
sec_unsetup

sec_cleanup

complete $SECONDS
exit_status
