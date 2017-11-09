#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#

set -e

ONLY=${ONLY:-"$*"}
# bug number for skipped test: 19430 19967 19967
ALWAYS_EXCEPT="                2     5     6    $SANITY_SEC_EXCEPT"
if $SHARED_KEY; then
# bug number for skipped test: 9145 9145 9671 9145 9145 9145 9145 9245
	ALWAYS_EXCEPT="        17   18   19   20   21   22   23   27 $ALWAYS_EXCEPT"
fi
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

SRCDIR=$(dirname $0)
export PATH=$PWD/$SRCDIR:$SRCDIR:$PWD/$SRCDIR/../utils:$PATH:/sbin
export NAME=${NAME:-local}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

NODEMAP_TESTS=$(seq 7 26)

if ! check_versions; then
	echo "It is NOT necessary to test nodemap under interoperation mode"
	EXCEPT="$EXCEPT $NODEMAP_TESTS"
fi

[ "$SLOW" = "no" ] && EXCEPT_SLOW="26"

[ "$ALWAYS_EXCEPT$EXCEPT$EXCEPT_SLOW" ] &&
	echo "Skipping tests: $ALWAYS_EXCEPT $EXCEPT $EXCEPT_SLOW"

RUNAS_CMD=${RUNAS_CMD:-runas}

WTL=${WTL:-"$LUSTRE/tests/write_time_limit"}

CONFDIR=/etc/lustre
PERM_CONF=$CONFDIR/perm.conf
FAIL_ON_ERROR=false
HOSTNAME_CHECKSUM=$(hostname | sum | awk '{ print $1 }')
SUBNET_CHECKSUM=$(expr $HOSTNAME_CHECKSUM % 250 + 1)

require_dsh_mds || exit 0
require_dsh_ost || exit 0

clients=${CLIENTS//,/ }
num_clients=$(get_node_count ${clients})
clients_arr=($clients)

ID0=${ID0:-500}
ID1=${ID1:-501}
USER0=$(getent passwd | grep :$ID0:$ID0: | cut -d: -f1)
USER1=$(getent passwd | grep :$ID1:$ID1: | cut -d: -f1)

NODEMAP_COUNT=16
NODEMAP_RANGE_COUNT=3
NODEMAP_IPADDR_LIST="1 10 64 128 200 250"
NODEMAP_ID_COUNT=10
NODEMAP_MAX_ID=$((ID0 + NODEMAP_ID_COUNT))

[ -z "$USER0" ] &&
	skip "need to add user0 ($ID0:$ID0)" && exit 0

[ -z "$USER1" ] &&
	skip "need to add user1 ($ID1:$ID1)" && exit 0

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

SAVE_PWD=$PWD

build_test_filter

sec_login() {
	local user=$1
	local group=$2

	$GSS_KRB5 || return
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
	chown $USER0 $DIR/$tdir || error "chown (2)"
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
}
run_test 0 "uid permission ============================="

# setuid/gid
test_1() {
	[ $GSS_SUP = 0 ] && skip "without GSS support." && return

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

	rm -rf $DIR/$tdir
	mkdir -p $DIR/$tdir
	chmod 0771 $DIR/$tdir
	chgrp $ID0 $DIR/$tdir
	$RUNAS_CMD -u $ID0 ls $DIR/$tdir || error "setgroups (1)"
	do_facet $SINGLEMDS "echo '* $ID1 setgrp' > $PERM_CONF"
	do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
	$RUNAS_CMD -u $ID1 -G1,2,$ID0 ls $DIR/$tdir ||
		error "setgroups (2)"
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

		out=$(do_facet mgs $LCTL get_param nodemap.$csum.id 2>/dev/null)
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

	echo "Start to add idmaps ..."
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		local j

		for ((j = $ID0; j < NODEMAP_MAX_ID; j++)); do
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

update_idmaps() { #LU-10040
	[ $(lustre_version_code mgs) -lt $(version_code 2.10.55) ] &&
		skip "Need MGS >= 2.10.55" &&
		return
	local csum=${HOSTNAME_CHECKSUM}_0
	local old_id_client=$ID0
	local old_id_fs=$((ID0 + 1))
	local new_id=$((ID0 + 100))
	local tmp_id
	local cmd
	local run
	local idtype
	local rc=0

	echo "Start to update idmaps ..."

	#Inserting an existed idmap should return error
	cmd="$LCTL nodemap_add_idmap --name $csum --idtype uid"
	if do_facet mgs \
		$cmd --idmap $old_id_client:$old_id_fs 2>/dev/null; then
		error "insert idmap {$old_id_client:$old_id_fs} " \
			"should return error"
		rc=$((rc + 1))
		return rc
	fi

	#Update id_fs and check it
	if ! do_facet mgs $cmd --idmap $old_id_client:$new_id; then
		error "$cmd --idmap $old_id_client:$new_id failed"
		rc=$((rc + 1))
		return $rc
	fi
	tmp_id=$(do_facet mgs $LCTL get_param -n nodemap.$csum.idmap |
		awk '{ print $7 }' | sed -n '2p')
	[ $tmp_id != $new_id ] && { error "new id_fs $tmp_id != $new_id"; \
		rc=$((rc + 1)); return $rc; }

	#Update id_client and check it
	if ! do_facet mgs $cmd --idmap $new_id:$new_id; then
		error "$cmd --idmap $new_id:$new_id failed"
		rc=$((rc + 1))
		return $rc
	fi
	tmp_id=$(do_facet mgs $LCTL get_param -n nodemap.$csum.idmap |
		awk '{ print $5 }' | sed -n "$((NODEMAP_ID_COUNT + 1)) p")
	tmp_id=$(echo ${tmp_id%,*}) #e.g. "501,"->"501"
	[ $tmp_id != $new_id ] && { error "new id_client $tmp_id != $new_id"; \
		rc=$((rc + 1)); return $rc; }

	#Delete above updated idmap
	cmd="$LCTL nodemap_del_idmap --name $csum --idtype uid"
	if ! do_facet mgs $cmd --idmap $new_id:$new_id; then
		error "$cmd --idmap $new_id:$new_id failed"
		rc=$((rc + 1))
		return $rc
	fi

	#restore the idmaps to make delete_idmaps work well
	cmd="$LCTL nodemap_add_idmap --name $csum --idtype uid"
	if ! do_facet mgs $cmd --idmap $old_id_client:$old_id_fs; then
		error "$cmd --idmap $old_id_client:$old_id_fs failed"
		rc=$((rc + 1))
		return $rc
	fi

	return $rc
}

delete_idmaps() {
	local i
	local cmd="$LCTL nodemap_del_idmap"
	local rc=0

	echo "Start to delete idmaps ..."
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		local j

		for ((j = $ID0; j < NODEMAP_MAX_ID; j++)); do
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
	[ $(lustre_version_code mgs) -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $(lustre_build_version mgs) MGS < 2.5.53" &&
		return
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

	echo "Start to test idmaps ..."
	## nodemap deactivated
	if ! do_facet mgs $LCTL nodemap_activate 0; then
		return 1
	fi
	for ((id = $ID0; id < NODEMAP_MAX_ID; id++)); do
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
	if ! do_facet mgs $LCTL nodemap_activate 1; then
		return 2
	fi

	for ((id = $ID0; id < NODEMAP_MAX_ID; id++)); do
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

	for ((id = $ID0; id < NODEMAP_MAX_ID; id++)); do
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
	[[ $rc != 0 ]] && error "nodemap_del failed with $rc" && return 2

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
	[[ $rc != 0 ]] && error "nodemap_del failed with $rc" && return 3

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
	[[ $rc != 0 ]] && error "nodemap_del failed with $rc" && return 4

	return 0
}
run_test 9 "nodemap range add"

test_10a() {
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
	[[ $rc != 0 ]] && error "nodemap_del failed with $rc" && return 5

	return 0
}
run_test 10a "nodemap reject duplicate ranges"

test_10b() {
	[ $(lustre_version_code mgs) -lt $(version_code 2.10.53) ] &&
		skip "Need MGS >= 2.10.53" && return

	local nm1="nodemap1"
	local nm2="nodemap2"
	local nids="192.168.19.[0-255]@o2ib20"

	do_facet mgs $LCTL nodemap_del $nm1 2>/dev/null
	do_facet mgs $LCTL nodemap_del $nm2 2>/dev/null

	do_facet mgs $LCTL nodemap_add $nm1 || error "Add $nm1 failed"
	do_facet mgs $LCTL nodemap_add $nm2 || error "Add $nm2 failed"
	do_facet mgs $LCTL nodemap_add_range --name $nm1 --range $nids ||
		error "Add range $nids to $nm1 failed"
	[ -n "$(do_facet mgs $LCTL get_param nodemap.$nm1.* |
		grep start_nid)" ] || error "No range was found"
	do_facet mgs $LCTL nodemap_del_range --name $nm2 --range $nids &&
		error "Deleting range $nids from $nm2 should fail"
	[ -n "$(do_facet mgs $LCTL get_param nodemap.$nm1.* |
		grep start_nid)" ] || error "Range $nids should be there"

	do_facet mgs $LCTL nodemap_del $nm1 || error "Delete $nm1 failed"
	do_facet mgs $LCTL nodemap_del $nm2 || error "Delete $nm2 failed"
	return 0
}
run_test 10b "delete range from the correct nodemap"

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
	update_idmaps
	rc=$?
	[[ $rc != 0 ]] && error "update_idmaps failed with $rc" && return 5

	rc=0
	delete_idmaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_del_idmap failed with $rc" && return 6

	rc=0
	delete_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_delete failed with $rc" && return 7

	return 0
}
run_test 15 "test id mapping"

wait_nm_sync() {
	local nodemap_name=$1
	local key=$2
	local value=$3
	local proc_param="${nodemap_name}.${key}"
	[ "$nodemap_name" == "active" ] && proc_param="active"

	local is_active=$(do_facet mgs $LCTL get_param -n nodemap.active)
	(( is_active == 0 )) && [ "$proc_param" != "active" ] && return

	local max_retries=20
	local is_sync
	local out1=""
	local out2
	local mgs_ip=$(host_nids_address $mgs_HOST $NETTYPE | cut -d' ' -f1)
	local i

	if [ -z "$value" ]; then
		out1=$(do_facet mgs $LCTL get_param nodemap.${proc_param})
		echo "On MGS ${mgs_ip}, ${proc_param} = $out1"
	else
		out1=$value;
	fi

	# wait up to 10 seconds for other servers to sync with mgs
	for i in $(seq 1 10); do
		for node in $(all_server_nodes); do
		    local node_ip=$(host_nids_address $node $NETTYPE |
				    cut -d' ' -f1)

		    is_sync=true
		    if [ -z "$value" ]; then
			[ $node_ip == $mgs_ip ] && continue
		    fi

		    out2=$(do_node $node_ip $LCTL get_param \
				   nodemap.$proc_param 2>/dev/null)
		    echo "On $node ${node_ip}, ${proc_param} = $out2"
		    [ "$out1" != "$out2" ] && is_sync=false && break
		done
		$is_sync && break
		sleep 1
	done
	if ! $is_sync; then
		echo MGS
		echo $out1
		echo OTHER - IP: $node_ip
		echo $out2
		error "mgs and $nodemap_name ${key} mismatch, $i attempts"
	fi
	echo "waited $((i - 1)) seconds for sync"
}

create_fops_nodemaps() {
	local i=0
	local client
	for client in $clients; do
		local client_ip=$(host_nids_address $client $NETTYPE)
		local client_nid=$(h2nettype $client_ip)
		do_facet mgs $LCTL nodemap_add c${i} || return 1
		do_facet mgs $LCTL nodemap_add_range 	\
			--name c${i} --range $client_nid || return 1
		for map in ${FOPS_IDMAPS[i]}; do
			do_facet mgs $LCTL nodemap_add_idmap --name c${i} \
				--idtype uid --idmap ${map} || return 1
			do_facet mgs $LCTL nodemap_add_idmap --name c${i} \
				--idtype gid --idmap ${map} || return 1
		done

		wait_nm_sync c$i idmap

		i=$((i + 1))
	done
	return 0
}

delete_fops_nodemaps() {
	local i=0
	local client
	for client in $clients; do
		do_facet mgs $LCTL nodemap_del c${i} || return 1
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

	wait_nm_sync c0 admin_nodemap
	wait_nm_sync c0 trusted_nodemap

	do_node ${clients_arr[0]} rm -rf $DIR/$tdir
	nm_test_mkdir
	do_node ${clients_arr[0]} chown $user $DIR/$tdir

	do_facet mgs $LCTL nodemap_modify --name c0 \
		--property admin --value $admin
	do_facet mgs $LCTL nodemap_modify --name c0 \
		--property trusted --value $trust

	# flush MDT locks to make sure they are reacquired before test
	do_node ${clients_arr[0]} $LCTL set_param \
		ldlm.namespaces.$FSNAME-MDT*.lru_size=clear

	wait_nm_sync c0 admin_nodemap
	wait_nm_sync c0 trusted_nodemap
}

# fileset test directory needs to be initialized on a privileged client
fileset_test_setup() {
	local admin=$(do_facet mgs $LCTL get_param -n nodemap.c0.admin_nodemap)
	local trust=$(do_facet mgs $LCTL get_param -n \
		nodemap.c0.trusted_nodemap)

	do_facet mgs $LCTL nodemap_modify --name c0 --property admin --value 1
	do_facet mgs $LCTL nodemap_modify --name c0 --property trusted --value 1

	wait_nm_sync c0 admin_nodemap
	wait_nm_sync c0 trusted_nodemap

	# create directory and populate it for subdir mount
	do_node ${clients_arr[0]} mkdir $MOUNT/$subdir ||
		error "unable to create dir $MOUNT/$subdir"
	do_node ${clients_arr[0]} touch $MOUNT/$subdir/this_is_$subdir ||
		error "unable to create file $MOUNT/$subdir/this_is_$subdir"
	do_node ${clients_arr[0]} mkdir $MOUNT/$subdir/$subsubdir ||
		error "unable to create dir $MOUNT/$subdir/$subsubdir"
	do_node ${clients_arr[0]} touch \
			$MOUNT/$subdir/$subsubdir/this_is_$subsubdir ||
		error "unable to create file \
			$MOUNT/$subdir/$subsubdir/this_is_$subsubdir"

	do_facet mgs $LCTL nodemap_modify --name c0 \
		--property admin --value $admin
	do_facet mgs $LCTL nodemap_modify --name c0 \
		--property trusted --value $trust

	# flush MDT locks to make sure they are reacquired before test
	do_node ${clients_arr[0]} $LCTL set_param \
		ldlm.namespaces.$FSNAME-MDT*.lru_size=clear

	wait_nm_sync c0 admin_nodemap
	wait_nm_sync c0 trusted_nodemap
}

# fileset test directory needs to be initialized on a privileged client
fileset_test_cleanup() {
	local admin=$(do_facet mgs $LCTL get_param -n nodemap.c0.admin_nodemap)
	local trust=$(do_facet mgs $LCTL get_param -n \
		nodemap.c0.trusted_nodemap)

	do_facet mgs $LCTL nodemap_modify --name c0 --property admin --value 1
	do_facet mgs $LCTL nodemap_modify --name c0 --property trusted --value 1

	wait_nm_sync c0 admin_nodemap
	wait_nm_sync c0 trusted_nodemap

	# cleanup directory created for subdir mount
	do_node ${clients_arr[0]} rm -rf $MOUNT/$subdir ||
		error "unable to remove dir $MOUNT/$subdir"

	do_facet mgs $LCTL nodemap_modify --name c0 \
		--property admin --value $admin
	do_facet mgs $LCTL nodemap_modify --name c0 \
		--property trusted --value $trust

	# flush MDT locks to make sure they are reacquired before test
	do_node ${clients_arr[0]} $LCTL set_param \
		ldlm.namespaces.$FSNAME-MDT*.lru_size=clear

	wait_nm_sync c0 admin_nodemap
	wait_nm_sync c0 trusted_nodemap
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
	$run_u dd if=/dev/zero of=$testfile oflag=sync bs=1M count=1 \
		>& /dev/null || error "unable to write quota test file"
	sync; sync_all_data || true

	local qused_new=$(nodemap_check_quota "$run_u")
	[ $((qused_new)) -lt $((qused_low + 1024)) -o \
	  $((qused_new)) -gt $((qused_high + 1024)) ] &&
		error "$qused_new != $qused_orig + 1M after write, " \
		      "fuzz is $quota_fuzz"
	$run_u rm $testfile || error "unable to remove quota test file"
	wait_delete_completed_mds

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

test_fops_admin_cli_i=""
test_fops_chmod_dir() {
	local current_cli_i=$1
	local perm_bits=$2
	local dir_to_chmod=$3
	local new_admin_cli_i=""

	# do we need to set up a new admin client?
	[ "$current_cli_i" == "0" ] && [ "$test_fops_admin_cli_i" != "1" ] &&
		new_admin_cli_i=1
	[ "$current_cli_i" != "0" ] && [ "$test_fops_admin_cli_i" != "0" ] &&
		new_admin_cli_i=0

	# if only one client, and non-admin, need to flip admin everytime
	if [ "$num_clients" == "1" ]; then
		test_fops_admin_client=$clients
		test_fops_admin_val=$(do_facet mgs $LCTL get_param -n \
			nodemap.c0.admin_nodemap)
		if [ "$test_fops_admin_val" != "1" ]; then
			do_facet mgs $LCTL nodemap_modify \
				--name c0 \
				--property admin \
				--value 1
			wait_nm_sync c0 admin_nodemap
		fi
	elif [ "$new_admin_cli_i" != "" ]; then
		# restore admin val to old admin client
		if [ "$test_fops_admin_cli_i" != "" ] &&
				[ "$test_fops_admin_val" != "1" ]; then
			do_facet mgs $LCTL nodemap_modify \
				--name c${test_fops_admin_cli_i} \
				--property admin \
				--value $test_fops_admin_val
			wait_nm_sync c${test_fops_admin_cli_i} admin_nodemap
		fi

		test_fops_admin_cli_i=$new_admin_cli_i
		test_fops_admin_client=${clients_arr[$new_admin_cli_i]}
		test_fops_admin_val=$(do_facet mgs $LCTL get_param -n \
			nodemap.c${new_admin_cli_i}.admin_nodemap)

		if [ "$test_fops_admin_val" != "1" ]; then
			do_facet mgs $LCTL nodemap_modify \
				--name c${new_admin_cli_i} \
				--property admin \
				--value 1
			wait_nm_sync c${new_admin_cli_i} admin_nodemap
		fi
	fi

	do_node $test_fops_admin_client chmod $perm_bits $DIR/$tdir || return 1

	# remove admin for single client if originally non-admin
	if [ "$num_clients" == "1" ] && [ "$test_fops_admin_val" != "1" ]; then
		do_facet mgs $LCTL nodemap_modify --name c0 --property admin \
			--value 0
		wait_nm_sync c0 admin_nodemap
	fi

	return 0
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
			for u in ${client_user_list[$cli_i]}; do
				local run_u="do_node $client \
					     $RUNAS_CMD -u$u -g$u -G$u"
				for perm_bits in $perm_bit_list; do
					local mode=$(printf %03o $perm_bits)
					local key
					key="$mapmode:$user:c$cli_i:$u:$mode"
					test_fops_chmod_dir $cli_i $mode \
						$DIR/$tdir ||
							error cannot chmod $key
					do_create_delete "$run_u" "$key"
				done

				# check quota
				test_fops_chmod_dir $cli_i 777 $DIR/$tdir ||
					error cannot chmod $key
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
	local active_nodemap=1

	[ "$1" == "0" ] && active_nodemap=0

	do_nodes $(comma_list $(all_mdts_nodes)) \
		$LCTL set_param mdt.*.identity_upcall=NONE

	rc=0
	create_fops_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "adding fops nodemaps failed $rc"

	do_facet mgs $LCTL nodemap_activate $active_nodemap
	wait_nm_sync active

	do_facet mgs $LCTL nodemap_modify --name default \
		--property admin --value 1
	do_facet mgs $LCTL nodemap_modify --name default \
		--property trusted --value 1
	wait_nm_sync default trusted_nodemap
}

nodemap_test_cleanup() {
	trap 0
	delete_fops_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "removing fops nodemaps failed $rc"

	do_facet mgs $LCTL nodemap_modify --name default \
		 --property admin --value 0
	do_facet mgs $LCTL nodemap_modify --name default \
		 --property trusted --value 0
	wait_nm_sync default trusted_nodemap

	do_facet mgs $LCTL nodemap_activate 0
	wait_nm_sync active 0

	export SK_UNIQUE_NM=false
	return 0
}

nodemap_clients_admin_trusted() {
	local admin=$1
	local tr=$2
	local i=0
	for client in $clients; do
		do_facet mgs $LCTL nodemap_modify --name c0 \
			--property admin --value $admin
		do_facet mgs $LCTL nodemap_modify --name c0 \
			--property trusted --value $tr
		i=$((i + 1))
	done
	wait_nm_sync c$((i - 1)) admin_nodemap
	wait_nm_sync c$((i - 1)) trusted_nodemap
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
		x=0
		i=$((i + 1))
	done
	wait_nm_sync c$((i - 1)) trusted_nodemap

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
		x=0
		i=$((i + 1))
	done
	wait_nm_sync c$((i - 1)) trusted_nodemap

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

	wait_nm_sync c0 admin_nodemap
	wait_nm_sync c0 trusted_nodemap

	do_node ${clients_arr[0]} rm -rf $DIR/$tdir
	nm_test_mkdir
	do_node ${clients_arr[0]} chmod a+rwx $DIR/$tdir ||
		error unable to chmod a+rwx test dir $DIR/$tdir

	do_facet mgs $LCTL nodemap_modify --name c0 \
		--property admin --value $admin
	do_facet mgs $LCTL nodemap_modify --name c0 \
		--property trusted --value $trust

	wait_nm_sync c0 trusted_nodemap
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

test_23a() {
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

	do_facet mgs $LCTL nodemap_modify --name c1 --property admin --value 0
	do_facet mgs $LCTL nodemap_modify --name c1 --property trusted --value 0

	wait_nm_sync c1 trusted_nodemap

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

	wait_nm_sync c0 trusted_nodemap

	# setfacl to mapped user on c1, also mapped to c0, verify it's seen
	nodemap_acl_test $mapped_c1 ${clients_arr[1]} ${clients_arr[0]} &&
		error "acl count (5)"

	# setfacl to mapped user on c1, not mapped to c0, verify not seen
	nodemap_acl_test $unmapped_c1 ${clients_arr[1]} ${clients_arr[0]} ||
		error "acl count (6)"

	nodemap_test_cleanup
}
run_test 23a "test mapped regular ACLs"

test_23b() { #LU-9929
	remote_mgs_nodsh && skip "remote MGS with nodsh" && return
	[ $(lustre_version_code mgs) -lt $(version_code 2.10.53) ] &&
		skip "Need MGS >= 2.10.53" && return

	nodemap_test_setup
	trap nodemap_test_cleanup EXIT

	local testdir=$DIR/$tdir
	local fs_id=$((IDBASE+10))
	local unmapped_id
	local mapped_id
	local fs_user

	do_facet mgs $LCTL nodemap_modify --name c0 --property admin --value 1
	wait_nm_sync c0 admin_nodemap

	# Add idmap $ID0:$fs_id (500:60010)
	do_facet mgs $LCTL nodemap_add_idmap --name c0 --idtype gid \
		--idmap $ID0:$fs_id ||
		error "add idmap $ID0:$fs_id to nodemap c0 failed"

	# set/getfacl default acl on client0 (unmapped gid=500)
	rm -rf $testdir
	mkdir -p $testdir
	# Here, USER0=$(getent passwd | grep :$ID0:$ID0: | cut -d: -f1)
	setfacl -R -d -m group:$USER0:rwx $testdir ||
		error "setfacl $testdir on ${clients_arr[0]} failed"
	unmapped_id=$(getfacl $testdir | grep -E "default:group:.*:rwx" |
			awk -F: '{print $3}')
	[ "$unmapped_id" = "$USER0" ] ||
		error "gid=$ID0 was not unmapped correctly on ${clients_arr[0]}"

	# getfacl default acl on MGS (mapped gid=60010)
	zconf_mount $mgs_HOST $MOUNT
	do_rpc_nodes $mgs_HOST is_mounted $MOUNT ||
		error "mount lustre on MGS failed"
	mapped_id=$(do_node $mgs_HOST getfacl $testdir |
			grep -E "default:group:.*:rwx" | awk -F: '{print $3}')
	fs_user=$(do_facet mgs getent passwd |
			grep :$fs_id:$fs_id: | cut -d: -f1)
	[ $mapped_id -eq $fs_id -o "$mapped_id" = "$fs_user" ] ||
		error "Should return gid=$fs_id or $fs_user on MGS"

	rm -rf $testdir
	do_facet mgs umount $MOUNT
	nodemap_test_cleanup
}
run_test 23b "test mapped default ACLs"

test_24() {
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	do_nodes $(comma_list $(all_server_nodes)) $LCTL get_param -R nodemap ||
		error "proc readable file read failed"

	nodemap_test_cleanup
}
run_test 24 "check nodemap proc files for LBUGs and Oopses"

test_25() {
	local tmpfile=$(mktemp)
	local tmpfile2=$(mktemp)
	local tmpfile3=$(mktemp)
	local tmpfile4=$(mktemp)
	local subdir=c0dir
	local client

	nodemap_version_check || return 0

	# stop clients for this test
	zconf_umount_clients $CLIENTS $MOUNT ||
	    error "unable to umount clients $CLIENTS"

	export SK_UNIQUE_NM=true
	nodemap_test_setup

	# enable trusted/admin for setquota call in cleanup_and_setup_lustre()
	i=0
	for client in $clients; do
		do_facet mgs $LCTL nodemap_modify --name c${i} \
			--property admin --value 1
		do_facet mgs $LCTL nodemap_modify --name c${i} \
			--property trusted --value 1
		((i++))
	done
	wait_nm_sync c$((i - 1)) trusted_nodemap

	trap nodemap_test_cleanup EXIT

	# create a new, empty nodemap, and add fileset info to it
	do_facet mgs $LCTL nodemap_add test25 ||
		error "unable to create nodemap $testname"
	do_facet mgs $LCTL set_param -P nodemap.$testname.fileset=/$subdir ||
		error "unable to add fileset info to nodemap test25"

	wait_nm_sync test25 id

	do_facet mgs $LCTL nodemap_info > $tmpfile
	do_facet mds $LCTL nodemap_info > $tmpfile2

	if ! $SHARED_KEY; then
		# will conflict with SK's nodemaps
		cleanup_and_setup_lustre
	fi
	# stop clients for this test
	zconf_umount_clients $CLIENTS $MOUNT ||
	    error "unable to umount clients $CLIENTS"

	do_facet mgs $LCTL nodemap_info > $tmpfile3
	diff -q $tmpfile3 $tmpfile >& /dev/null ||
		error "nodemap_info diff on MGS after remount"

	do_facet mds $LCTL nodemap_info > $tmpfile4
	diff -q $tmpfile4 $tmpfile2 >& /dev/null ||
		error "nodemap_info diff on MDS after remount"

	# cleanup nodemap
	do_facet mgs $LCTL nodemap_del test25 ||
	    error "cannot delete nodemap test25 from config"
	nodemap_test_cleanup
	# restart clients previously stopped
	zconf_mount_clients $CLIENTS $MOUNT ||
	    error "unable to mount clients $CLIENTS"

	rm -f $tmpfile $tmpfile2
	export SK_UNIQUE_NM=false
}
run_test 25 "test save and reload nodemap config"

test_26() {
	nodemap_version_check || return 0

	local large_i=32000

	do_facet mgs "seq -f 'c%g' $large_i | xargs -n1 $LCTL nodemap_add"
	wait_nm_sync c$large_i admin_nodemap

	do_facet mgs "seq -f 'c%g' $large_i | xargs -n1 $LCTL nodemap_del"
	wait_nm_sync c$large_i admin_nodemap
}
run_test 26 "test transferring very large nodemap"

test_27() {
	local subdir=c0dir
	local subsubdir=c0subdir
	local fileset_on_mgs=""
	local loop=0

	nodemap_test_setup
	if $SHARED_KEY; then
		export SK_UNIQUE_NM=true
	else
		# will conflict with SK's nodemaps
		trap nodemap_test_cleanup EXIT
	fi

	fileset_test_setup

	# add fileset info to nodemap
	do_facet mgs $LCTL set_param -P nodemap.c0.fileset=/$subdir ||
		error "unable to add fileset info to nodemap c0"
	wait_nm_sync c0 fileset "nodemap.c0.fileset=/$subdir"

	# re-mount client
	zconf_umount_clients ${clients_arr[0]} $MOUNT ||
		error "unable to umount client ${clients_arr[0]}"
	# set some generic fileset to trigger SSK code
	export FILESET=/
	zconf_mount_clients ${clients_arr[0]} $MOUNT $MOUNT_OPTS ||
		error "unable to remount client ${clients_arr[0]}"
	unset FILESET

	# test mount point content
	do_node ${clients_arr[0]} test -f $MOUNT/this_is_$subdir ||
		error "fileset not taken into account"

	# re-mount client with sub-subdir
	zconf_umount_clients ${clients_arr[0]} $MOUNT ||
		error "unable to umount client ${clients_arr[0]}"
	export FILESET=/$subsubdir
	zconf_mount_clients ${clients_arr[0]} $MOUNT $MOUNT_OPTS ||
		error "unable to remount client ${clients_arr[0]}"
	unset FILESET

	# test mount point content
	do_node ${clients_arr[0]} test -f $MOUNT/this_is_$subsubdir ||
		error "subdir of fileset not taken into account"

	# remove fileset info from nodemap
	do_facet mgs $LCTL nodemap_set_fileset --name c0 --fileset \'\' ||
		error "unable to delete fileset info on nodemap c0"
	fileset_on_mgs=$(do_facet mgs $LCTL get_param nodemap.c0.fileset)
	while [ "${fileset_on_mgs}" != "nodemap.c0.fileset=" ]; do
	    if [ $loop -eq 10 ]; then
		error "On MGS, fileset cannnot be cleared"
		break;
	    else
		loop=$((loop+1))
		echo "On MGS, fileset is still ${fileset_on_mgs}, waiting..."
		sleep 20;
	    fi
	    fileset_on_mgs=$(do_facet mgs $LCTL get_param nodemap.c0.fileset)
	done
	do_facet mgs $LCTL set_param -P nodemap.c0.fileset=\'\' ||
		error "unable to reset fileset info on nodemap c0"
	wait_nm_sync c0 fileset

	# re-mount client
	zconf_umount_clients ${clients_arr[0]} $MOUNT ||
		error "unable to umount client ${clients_arr[0]}"
	zconf_mount_clients ${clients_arr[0]} $MOUNT $MOUNT_OPTS ||
		error "unable to remount client ${clients_arr[0]}"

	# test mount point content
	do_node ${clients_arr[0]} test -d $MOUNT/$subdir ||
		(ls $MOUNT ; error "fileset not cleared on nodemap c0")

	# back to non-nodemap setup
	if $SHARED_KEY; then
		export SK_UNIQUE_NM=false
		zconf_umount_clients ${clients_arr[0]} $MOUNT ||
			error "unable to umount client ${clients_arr[0]}"
	fi
	fileset_test_cleanup
	nodemap_test_cleanup
	if $SHARED_KEY; then
		zconf_mount_clients ${clients_arr[0]} $MOUNT $MOUNT_OPTS ||
			error "unable to remount client ${clients_arr[0]}"
	fi
}
run_test 27 "test fileset in nodemap"

test_28() {
	if ! $SHARED_KEY; then
		skip "need shared key feature for this test" && return
	fi
	mkdir -p $DIR/$tdir || error "mkdir failed"
	touch $DIR/$tdir/$tdir.out || error "touch failed"
	if [ ! -f $DIR/$tdir/$tdir.out ]; then
		error "read before rotation failed"
	fi
	# store top key identity to ensure rotation has occurred
	SK_IDENTITY_OLD=$(lctl get_param *.*.*srpc* | grep "expire" |
		head -1 | awk '{print $15}' | cut -c1-8)
	do_facet $SINGLEMDS lfs flushctx ||
		 error "could not run flushctx on $SINGLEMDS"
	sleep 5
	lfs flushctx || error "could not run flushctx on client"
	sleep 5
	# verify new key is in place
	SK_IDENTITY_NEW=$(lctl get_param *.*.*srpc* | grep "expire" |
		head -1 | awk '{print $15}' | cut -c1-8)
	if [ $SK_IDENTITY_OLD == $SK_IDENTITY_NEW ]; then
		error "key did not rotate correctly"
	fi
	if [ ! -f $DIR/$tdir/$tdir.out ]; then
		error "read after rotation failed"
	fi
}
run_test 28 "check shared key rotation method"

test_29() {
	if ! $SHARED_KEY; then
		skip "need shared key feature for this test" && return
	fi
	if [ $SK_FLAVOR != "ski" ] && [ $SK_FLAVOR != "skpi" ]; then
		skip "test only valid if integrity is active"
	fi
	rm -r $DIR/$tdir
	mkdir $DIR/$tdir || error "mkdir"
	touch $DIR/$tdir/$tfile || error "touch"
	zconf_umount_clients ${clients_arr[0]} $MOUNT ||
		error "unable to umount clients"
	keyctl show | awk '/lustre/ { print $1 }' |
		xargs -IX keyctl unlink X
	OLD_SK_PATH=$SK_PATH
	export SK_PATH=/dev/null
	if zconf_mount_clients ${clients_arr[0]} $MOUNT; then
		export SK_PATH=$OLD_SK_PATH
		if [ -e $DIR/$tdir/$tfile ]; then
			error "able to mount and read without key"
		else
			error "able to mount without key"
		fi
	else
		export SK_PATH=$OLD_SK_PATH
		keyctl show | awk '/lustre/ { print $1 }' |
			xargs -IX keyctl unlink X
	fi
}
run_test 29 "check for missing shared key"

test_30() {
	if ! $SHARED_KEY; then
		skip "need shared key feature for this test" && return
	fi
	if [ $SK_FLAVOR != "ski" ] && [ $SK_FLAVOR != "skpi" ]; then
		skip "test only valid if integrity is active"
	fi
	mkdir -p $DIR/$tdir || error "mkdir failed"
	touch $DIR/$tdir/$tdir.out || error "touch failed"
	zconf_umount_clients ${clients_arr[0]} $MOUNT ||
		error "unable to umount clients"
	# unload keys from ring
	keyctl show | awk '/lustre/ { print $1 }' |
		xargs -IX keyctl unlink X
	# invalidate the key with bogus filesystem name
	lgss_sk -w $SK_PATH/$FSNAME-bogus.key -f $FSNAME.bogus \
		-t client -d /dev/urandom || error "lgss_sk failed (1)"
	do_facet $SINGLEMDS lfs flushctx || error "could not run flushctx"
	OLD_SK_PATH=$SK_PATH
	export SK_PATH=$SK_PATH/$FSNAME-bogus.key
	if zconf_mount_clients ${clients_arr[0]} $MOUNT; then
		SK_PATH=$OLD_SK_PATH
		if [ -a $DIR/$tdir/$tdir.out ]; then
			error "mount and read file with invalid key"
		else
			error "mount with invalid key"
		fi
	fi
	SK_PATH=$OLD_SK_PATH
	zconf_umount_clients ${clients_arr[0]} $MOUNT ||
		error "unable to umount clients"
}
run_test 30 "check for invalid shared key"

log "cleanup: ======================================================"

sec_unsetup() {
	## nodemap deactivated
	do_facet mgs $LCTL nodemap_activate 0

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
