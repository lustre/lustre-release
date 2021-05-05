#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#

set -e

ONLY=${ONLY:-"$*"}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@

init_logging

ALWAYS_EXCEPT="$SANITY_SEC_EXCEPT "
# bug number for skipped test:
ALWAYS_EXCEPT+=" "
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

[ "$SLOW" = "no" ] && EXCEPT_SLOW="26"

NODEMAP_TESTS=$(seq 7 26)

if ! check_versions; then
	echo "It is NOT necessary to test nodemap under interoperation mode"
	EXCEPT="$EXCEPT $NODEMAP_TESTS"
fi

build_test_filter

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

if [ "$SLOW" == "yes" ]; then
	NODEMAP_COUNT=16
	NODEMAP_RANGE_COUNT=3
	NODEMAP_IPADDR_LIST="1 10 64 128 200 250"
	NODEMAP_ID_COUNT=10
else
	NODEMAP_COUNT=3
	NODEMAP_RANGE_COUNT=2
	NODEMAP_IPADDR_LIST="1 250"
	NODEMAP_ID_COUNT=3
fi
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

assert_DIR

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
	[[ "$MDS1_VERSION" -ge $(version_code 2.6.93) ]] ||
	[[ "$MDS1_VERSION" -ge $(version_code 2.5.35) &&
	   "$MDS1_VERSION" -lt $(version_code 2.5.50) ]] ||
		skip "Need MDS version at least 2.6.93 or 2.5.35"

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
	local rc

	squash_id default 99 0
	wait_nm_sync default squash_uid '' inactive
	squash_id default 99 1
	wait_nm_sync default squash_gid '' inactive
	for (( i = 0; i < NODEMAP_COUNT; i++ )); do
		local csum=${HOSTNAME_CHECKSUM}_${i}

		do_facet mgs $LCTL nodemap_add $csum
		rc=$?
		if [ $rc -ne 0 ]; then
			echo "nodemap_add $csum failed with $rc"
			return $rc
		fi

		wait_update_facet --verbose mgs \
			"$LCTL get_param nodemap.$csum.id 2>/dev/null | \
			grep -c $csum || true" 1 30 ||
		    return 1
	done
	for (( i = 0; i < NODEMAP_COUNT; i++ )); do
		local csum=${HOSTNAME_CHECKSUM}_${i}

		wait_nm_sync $csum id '' inactive
	done
	return 0
}

delete_nodemaps() {
	local i

	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		local csum=${HOSTNAME_CHECKSUM}_${i}

		if ! do_facet mgs $LCTL nodemap_del $csum; then
			error "nodemap_del $csum failed with $?"
			return 3
		fi

		wait_update_facet --verbose mgs \
			"$LCTL get_param nodemap.$csum.id 2>/dev/null | \
			grep -c $csum || true" 0 30 ||
		    return 1
	done
	for (( i = 0; i < NODEMAP_COUNT; i++ )); do
		local csum=${HOSTNAME_CHECKSUM}_${i}

		wait_nm_sync $csum id '' inactive
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
	[ "$MGS_VERSION" -lt $(version_code 2.10.55) ] &&
		skip "Need MGS >= 2.10.55"

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
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53"

	local cmd

	cmd[0]="$LCTL nodemap_modify --property squash_uid"
	cmd[1]="$LCTL nodemap_modify --property squash_gid"

	if ! do_facet mgs ${cmd[$3]} --name $1 --value $2; then
		return 1
	fi
}

wait_nm_sync() {
	local nodemap_name=$1
	local key=$2
	local value=$3
	local opt=$4
	local proc_param
	local is_active=$(do_facet mgs $LCTL get_param -n nodemap.active)
	local max_retries=20
	local is_sync
	local out1=""
	local out2
	local mgs_ip=$(host_nids_address $mgs_HOST $NETTYPE | cut -d' ' -f1)
	local i

	if [ "$nodemap_name" == "active" ]; then
		proc_param="active"
	elif [ -z "$key" ]; then
		proc_param=${nodemap_name}
	else
		proc_param="${nodemap_name}.${key}"
	fi
	if [ "$opt" == "inactive" ]; then
		# check nm sync even if nodemap is not activated
		is_active=1
		opt=""
	fi
	(( is_active == 0 )) && [ "$proc_param" != "active" ] && return

	if [ -z "$value" ]; then
		out1=$(do_facet mgs $LCTL get_param $opt \
			nodemap.${proc_param} 2>/dev/null)
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

		    out2=$(do_node $node_ip $LCTL get_param $opt \
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

# ensure that the squash defaults are the expected defaults
squash_id default 99 0
wait_nm_sync default squash_uid '' inactive
squash_id default 99 1
wait_nm_sync default squash_gid '' inactive

test_nid() {
	local cmd

	cmd="$LCTL nodemap_test_nid"

	nid=$(do_facet mgs $cmd $1)

	if [ $nid == $2 ]; then
		return 0
	fi

	return 1
}

cleanup_active() {
	# restore activation state
	do_facet mgs $LCTL nodemap_activate 0
	wait_nm_sync active
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

	remote_mgs_nodsh && skip "remote MGS with nodsh"
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53"

	create_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc"

	delete_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_del failed with $rc"

	return 0
}
run_test 7 "nodemap create and delete"

test_8() {
	local rc

	remote_mgs_nodsh && skip "remote MGS with nodsh"
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53"

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

	remote_mgs_nodsh && skip "remote MGS with nodsh"
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53"

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

	remote_mgs_nodsh && skip "remote MGS with nodsh"
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53"

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
	[ "$MGS_VERSION" -lt $(version_code 2.10.53) ] &&
		skip "Need MGS >= 2.10.53"

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

test_10c() { #LU-8912
	[ "$MGS_VERSION" -lt $(version_code 2.10.57) ] &&
		skip "Need MGS >= 2.10.57"

	local nm="nodemap_lu8912"
	local nid_range="10.210.[32-47].[0-255]@o2ib3"
	local start_nid="10.210.32.0@o2ib3"
	local end_nid="10.210.47.255@o2ib3"
	local start_nid_found
	local end_nid_found

	do_facet mgs $LCTL nodemap_del $nm 2>/dev/null
	do_facet mgs $LCTL nodemap_add $nm || error "Add $nm failed"
	do_facet mgs $LCTL nodemap_add_range --name $nm --range $nid_range ||
		error "Add range $nid_range to $nm failed"

	start_nid_found=$(do_facet mgs $LCTL get_param nodemap.$nm.* |
		awk -F '[,: ]' /start_nid/'{ print $9 }')
	[ "$start_nid" == "$start_nid_found" ] ||
		error "start_nid: $start_nid_found != $start_nid"
	end_nid_found=$(do_facet mgs $LCTL get_param nodemap.$nm.* |
		awk -F '[,: ]' /end_nid/'{ print $13 }')
	[ "$end_nid" == "$end_nid_found" ] ||
		error "end_nid: $end_nid_found != $end_nid"

	do_facet mgs $LCTL nodemap_del $nm || error "Delete $nm failed"
	return 0
}
run_test 10c "verfify contiguous range support"

test_10d() { #LU-8913
	[ "$MGS_VERSION" -lt $(version_code 2.10.59) ] &&
		skip "Need MGS >= 2.10.59"

	local nm="nodemap_lu8913"
	local nid_range="*@o2ib3"
	local start_nid="0.0.0.0@o2ib3"
	local end_nid="255.255.255.255@o2ib3"
	local start_nid_found
	local end_nid_found

	do_facet mgs $LCTL nodemap_del $nm 2>/dev/null
	do_facet mgs $LCTL nodemap_add $nm || error "Add $nm failed"
	do_facet mgs $LCTL nodemap_add_range --name $nm --range $nid_range ||
		error "Add range $nid_range to $nm failed"

	start_nid_found=$(do_facet mgs $LCTL get_param nodemap.$nm.* |
		awk -F '[,: ]' /start_nid/'{ print $9 }')
	[ "$start_nid" == "$start_nid_found" ] ||
		error "start_nid: $start_nid_found != $start_nid"
	end_nid_found=$(do_facet mgs $LCTL get_param nodemap.$nm.* |
		awk -F '[,: ]' /end_nid/'{ print $13 }')
	[ "$end_nid" == "$end_nid_found" ] ||
		error "end_nid: $end_nid_found != $end_nid"

	do_facet mgs $LCTL nodemap_del $nm || error "Delete $nm failed"
	return 0
}
run_test 10d "verfify nodemap range format '*@<net>' support"

test_11() {
	local rc

	remote_mgs_nodsh && skip "remote MGS with nodsh"
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53"

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

	remote_mgs_nodsh && skip "remote MGS with nodsh"
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53"

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

	remote_mgs_nodsh && skip "remote MGS with nodsh"
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53"

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

	remote_mgs_nodsh && skip "remote MGS with nodsh"
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53"

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

	remote_mgs_nodsh && skip "remote MGS with nodsh"
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53"

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

	activedefault=$(do_facet mgs $LCTL get_param -n nodemap.active)
	if [[ "$activedefault" != "1" ]]; then
		stack_trap cleanup_active EXIT
	fi

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
	local nm=$1

	if [ -n "$FILESET" -a -z "$SKIP_FILESET" ]; then
		cleanup_mount $MOUNT
		FILESET="" zconf_mount_clients $CLIENTS $MOUNT
	fi

	local admin=$(do_facet mgs $LCTL get_param -n \
		nodemap.${nm}.admin_nodemap)
	local trust=$(do_facet mgs $LCTL get_param -n \
		nodemap.${nm}.trusted_nodemap)

	do_facet mgs $LCTL nodemap_modify --name $nm --property admin --value 1
	do_facet mgs $LCTL nodemap_modify --name $nm --property trusted \
		--value 1

	wait_nm_sync $nm admin_nodemap
	wait_nm_sync $nm trusted_nodemap

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

	do_facet mgs $LCTL nodemap_modify --name $nm \
		--property admin --value $admin
	do_facet mgs $LCTL nodemap_modify --name $nm \
		--property trusted --value $trust

	# flush MDT locks to make sure they are reacquired before test
	do_node ${clients_arr[0]} $LCTL set_param \
		ldlm.namespaces.$FSNAME-MDT*.lru_size=clear

	wait_nm_sync $nm admin_nodemap
	wait_nm_sync $nm trusted_nodemap
}

# fileset test directory needs to be initialized on a privileged client
fileset_test_cleanup() {
	local nm=$1
	local admin=$(do_facet mgs $LCTL get_param -n \
		nodemap.${nm}.admin_nodemap)
	local trust=$(do_facet mgs $LCTL get_param -n \
		nodemap.${nm}.trusted_nodemap)

	do_facet mgs $LCTL nodemap_modify --name $nm --property admin --value 1
	do_facet mgs $LCTL nodemap_modify --name $nm --property trusted \
		--value 1

	wait_nm_sync $nm admin_nodemap
	wait_nm_sync $nm trusted_nodemap

	# cleanup directory created for subdir mount
	do_node ${clients_arr[0]} rm -rf $MOUNT/$subdir ||
		error "unable to remove dir $MOUNT/$subdir"

	do_facet mgs $LCTL nodemap_modify --name $nm \
		--property admin --value $admin
	do_facet mgs $LCTL nodemap_modify --name $nm \
		--property trusted --value $trust

	# flush MDT locks to make sure they are reacquired before test
	do_node ${clients_arr[0]} $LCTL set_param \
		ldlm.namespaces.$FSNAME-MDT*.lru_size=clear

	wait_nm_sync $nm admin_nodemap
	wait_nm_sync $nm trusted_nodemap
	if [ -n "$FILESET" -a -z "$SKIP_FILESET" ]; then
		cleanup_mount $MOUNT
		zconf_mount_clients $CLIENTS $MOUNT
	fi
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
	local client_user_list=([0]="0 $((IDBASE+3))"
				[1]="0 $((IDBASE+5))")
	local mds_users="-1 0"
	local mds_i
	local rc=0
	local perm_bit_list="3 $((0300))"
	# SLOW tests 000-007, 010-070, 100-700 (octal modes)
	if [ "$SLOW" == "yes" ]; then
		perm_bit_list="0 $(seq 1 7) $(seq 8 8 63) $(seq 64 64 511) \
			       $((0303))"
		client_user_list=([0]="0 $((IDBASE+3)) $((IDBASE+4))"
				  [1]="0 $((IDBASE+5)) $((IDBASE+6))")
		mds_users="-1 0 1 2"
	fi

	# force single_client to speed up test
	[ "$SLOW" == "yes" ] ||
		single_client=1
	# step through mds users. -1 means root
	for mds_i in $mds_users; do
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
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53" &&
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
	wait_nm_sync default admin_nodemap
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
	wait_nm_sync default admin_nodemap
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
	if $SHARED_KEY &&
	[ "$MDS1_VERSION" -lt $(version_code 2.11.55) ]; then
		skip "Need MDS >= 2.11.55"
	fi

	nodemap_version_check || return 0
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	nodemap_clients_admin_trusted 0 1
	test_fops trusted_noadmin 1
	nodemap_test_cleanup
}
run_test 17 "test nodemap trusted_noadmin fileops"

test_18() {
	if $SHARED_KEY &&
	[ "$MDS1_VERSION" -lt $(version_code 2.11.55) ]; then
		skip "Need MDS >= 2.11.55"
	fi

	nodemap_version_check || return 0
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	nodemap_clients_admin_trusted 0 0
	test_fops mapped_noadmin 1
	nodemap_test_cleanup
}
run_test 18 "test nodemap mapped_noadmin fileops"

test_19() {
	if $SHARED_KEY &&
	[ "$MDS1_VERSION" -lt $(version_code 2.11.55) ]; then
		skip "Need MDS >= 2.11.55"
	fi

	nodemap_version_check || return 0
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	nodemap_clients_admin_trusted 1 1
	test_fops trusted_admin 1
	nodemap_test_cleanup
}
run_test 19 "test nodemap trusted_admin fileops"

test_20() {
	if $SHARED_KEY &&
	[ "$MDS1_VERSION" -lt $(version_code 2.11.55) ]; then
		skip "Need MDS >= 2.11.55"
	fi

	nodemap_version_check || return 0
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	nodemap_clients_admin_trusted 1 0
	test_fops mapped_admin 1
	nodemap_test_cleanup
}
run_test 20 "test nodemap mapped_admin fileops"

test_21() {
	if $SHARED_KEY &&
	[ "$MDS1_VERSION" -lt $(version_code 2.11.55) ]; then
		skip "Need MDS >= 2.11.55"
	fi

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
	if $SHARED_KEY &&
	[ "$MDS1_VERSION" -lt $(version_code 2.11.55) ]; then
		skip "Need MDS >= 2.11.55"
	fi

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
	local admin=$(do_facet mgs $LCTL get_param -n \
		      nodemap.c0.admin_nodemap)
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
	[ $num_clients -lt 2 ] && skip "Need 2 clients at least" && return
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
	[ $num_clients -lt 2 ] && skip "Need 2 clients at least"
	[ "$MGS_VERSION" -lt $(version_code 2.10.53) ] &&
		skip "Need MGS >= 2.10.53"

	export SK_UNIQUE_NM=true
	nodemap_test_setup
	trap nodemap_test_cleanup EXIT

	local testdir=$DIR/$tdir
	local fs_id=$((IDBASE+10))
	local unmapped_id
	local mapped_id
	local fs_user

	do_facet mgs $LCTL nodemap_modify --name c0 --property admin --value 1
	wait_nm_sync c0 admin_nodemap
	do_facet mgs $LCTL nodemap_modify --name c1 --property admin --value 1
	wait_nm_sync c1 admin_nodemap
	do_facet mgs $LCTL nodemap_modify --name c1 --property trusted --value 1
	wait_nm_sync c1 trusted_nodemap

	# Add idmap $ID0:$fs_id (500:60010)
	do_facet mgs $LCTL nodemap_add_idmap --name c0 --idtype gid \
		--idmap $ID0:$fs_id ||
		error "add idmap $ID0:$fs_id to nodemap c0 failed"
	wait_nm_sync c0 idmap

	# set/getfacl default acl on client 1 (unmapped gid=500)
	do_node ${clients_arr[0]} rm -rf $testdir
	do_node ${clients_arr[0]} mkdir -p $testdir
	# Here, USER0=$(getent passwd | grep :$ID0:$ID0: | cut -d: -f1)
	do_node ${clients_arr[0]} setfacl -R -d -m group:$USER0:rwx $testdir ||
		error "setfacl $testdir on ${clients_arr[0]} failed"
	unmapped_id=$(do_node ${clients_arr[0]} getfacl $testdir |
			grep -E "default:group:.*:rwx" | awk -F: '{print $3}')
	[ "$unmapped_id" = "$USER0" ] ||
		error "gid=$ID0 was not unmapped correctly on ${clients_arr[0]}"

	# getfacl default acl on client 2 (mapped gid=60010)
	mapped_id=$(do_node ${clients_arr[1]} getfacl $testdir |
			grep -E "default:group:.*:rwx" | awk -F: '{print $3}')
	fs_user=$(do_node ${clients_arr[1]} getent passwd |
			grep :$fs_id:$fs_id: | cut -d: -f1)
	[ -z "$fs_user" ] && fs_user=$fs_id
	[ $mapped_id -eq $fs_id -o "$mapped_id" = "$fs_user" ] ||
		error "Should return gid=$fs_id or $fs_user on client2"

	rm -rf $testdir
	nodemap_test_cleanup
	export SK_UNIQUE_NM=false
}
run_test 23b "test mapped default ACLs"

test_24() {
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	do_nodes $(comma_list $(all_server_nodes)) $LCTL get_param -R nodemap

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

nodemap_exercise_fileset() {
	local nm="$1"
	local loop=0

	# setup
	if [ "$nm" == "default" ]; then
		do_facet mgs $LCTL nodemap_activate 1
		wait_nm_sync active
	else
		nodemap_test_setup
	fi
	if $SHARED_KEY; then
		export SK_UNIQUE_NM=true
	else
		# will conflict with SK's nodemaps
		trap "fileset_test_cleanup $nm" EXIT
	fi
	fileset_test_setup "$nm"

	# add fileset info to $nm nodemap
	if ! combined_mgs_mds; then
	    do_facet mgs $LCTL set_param nodemap.${nm}.fileset=/$subdir ||
		error "unable to add fileset info to $nm nodemap on MGS"
	fi
	do_facet mgs $LCTL set_param -P nodemap.${nm}.fileset=/$subdir ||
	       error "unable to add fileset info to $nm nodemap for servers"
	wait_nm_sync $nm fileset "nodemap.${nm}.fileset=/$subdir"

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
	do_facet mgs $LCTL nodemap_set_fileset --name $nm --fileset clear ||
		error "unable to delete fileset info on $nm nodemap"
	wait_update_facet mgs "$LCTL get_param nodemap.${nm}.fileset" \
			  "nodemap.${nm}.fileset=" ||
		error "fileset info still not cleared on $nm nodemap"
	do_facet mgs $LCTL set_param -P nodemap.${nm}.fileset=clear ||
		error "unable to reset fileset info on $nm nodemap"
	wait_nm_sync $nm fileset "nodemap.${nm}.fileset="

	# re-mount client
	zconf_umount_clients ${clients_arr[0]} $MOUNT ||
		error "unable to umount client ${clients_arr[0]}"
	zconf_mount_clients ${clients_arr[0]} $MOUNT $MOUNT_OPTS ||
		error "unable to remount client ${clients_arr[0]}"

	# test mount point content
	if ! $(do_node ${clients_arr[0]} test -d $MOUNT/$subdir); then
		ls $MOUNT
		error "fileset not cleared on $nm nodemap"
	fi

	# back to non-nodemap setup
	if $SHARED_KEY; then
		export SK_UNIQUE_NM=false
		zconf_umount_clients ${clients_arr[0]} $MOUNT ||
			error "unable to umount client ${clients_arr[0]}"
	fi
	fileset_test_cleanup "$nm"
	if [ "$nm" == "default" ]; then
		do_facet mgs $LCTL nodemap_activate 0
		wait_nm_sync active 0
		trap 0
		export SK_UNIQUE_NM=false
	else
		nodemap_test_cleanup
	fi
	if $SHARED_KEY; then
		zconf_mount_clients ${clients_arr[0]} $MOUNT $MOUNT_OPTS ||
			error "unable to remount client ${clients_arr[0]}"
	fi
}

test_27a() {
	[ "$MDS1_VERSION" -lt $(version_code 2.11.50) ] &&
		skip "Need MDS >= 2.11.50"

	for nm in "default" "c0"; do
		local subdir="subdir_${nm}"
		local subsubdir="subsubdir_${nm}"

		if [ "$nm" == "default" ] && [ "$SHARED_KEY" == "true" ]; then
			echo "Skipping nodemap $nm with SHARED_KEY";
			continue;
		fi

		echo "Exercising fileset for nodemap $nm"
		nodemap_exercise_fileset "$nm"
	done
}
run_test 27a "test fileset in various nodemaps"

test_27b() { #LU-10703
	[ "$MDS1_VERSION" -lt $(version_code 2.11.50) ] &&
		skip "Need MDS >= 2.11.50"
	[[ $MDSCOUNT -lt 2 ]] && skip "needs >= 2 MDTs"

	nodemap_test_setup
	trap nodemap_test_cleanup EXIT

	# Add the nodemaps and set their filesets
	for i in $(seq 1 $MDSCOUNT); do
		do_facet mgs $LCTL nodemap_del nm$i 2>/dev/null
		do_facet mgs $LCTL nodemap_add nm$i ||
			error "add nodemap nm$i failed"
		wait_nm_sync nm$i "" "" "-N"

		if ! combined_mgs_mds; then
			do_facet mgs \
				$LCTL set_param nodemap.nm$i.fileset=/dir$i ||
				error "set nm$i.fileset=/dir$i failed on MGS"
		fi
		do_facet mgs $LCTL set_param -P nodemap.nm$i.fileset=/dir$i ||
			error "set nm$i.fileset=/dir$i failed on servers"
		wait_nm_sync nm$i fileset "nodemap.nm$i.fileset=/dir$i"
	done

	# Check if all the filesets are correct
	for i in $(seq 1 $MDSCOUNT); do
		fileset=$(do_facet mds$i \
			  $LCTL get_param -n nodemap.nm$i.fileset)
		[ "$fileset" = "/dir$i" ] ||
			error "nm$i.fileset $fileset != /dir$i on mds$i"
		do_facet mgs $LCTL nodemap_del nm$i ||
			error "delete nodemap nm$i failed"
	done

	nodemap_test_cleanup
}
run_test 27b "The new nodemap won't clear the old nodemap's fileset"

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
	do_node ${clients_arr[0]} "keyctl show |
		awk '/lustre/ { print \\\$1 }' | xargs -IX keyctl unlink X"
	OLD_SK_PATH=$SK_PATH
	export SK_PATH=/dev/null
	if zconf_mount_clients ${clients_arr[0]} $MOUNT; then
		export SK_PATH=$OLD_SK_PATH
		do_node ${clients_arr[0]} "ls $DIR/$tdir/$tfile"
		if [ $? -eq 0 ]; then
			error "able to mount and read without key"
		else
			error "able to mount without key"
		fi
	else
		export SK_PATH=$OLD_SK_PATH
		do_node ${clients_arr[0]} "keyctl show |
			awk '/lustre/ { print \\\$1 }' |
			xargs -IX keyctl unlink X"
	fi
	zconf_mount_clients ${clients_arr[0]} $MOUNT ||
		error "unable to mount clients"
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
	do_node ${clients_arr[0]} "keyctl show |
		awk '/lustre/ { print \\\$1 }' | xargs -IX keyctl unlink X"
	# generate key with bogus filesystem name
	do_node ${clients_arr[0]} "lgss_sk -w $SK_PATH/$FSNAME-bogus.key \
		-f $FSNAME.bogus -t client -d /dev/urandom" ||
		error "lgss_sk failed (1)"
	do_facet $SINGLEMDS lfs flushctx || error "could not run flushctx"
	OLD_SK_PATH=$SK_PATH
	export SK_PATH=$SK_PATH/$FSNAME-bogus.key
	if zconf_mount_clients ${clients_arr[0]} $MOUNT; then
		SK_PATH=$OLD_SK_PATH
		do_node ${clients_arr[0]} "ls $DIR/$tdir/$tdir.out"
		if [ $? -eq 0 ]; then
			error "mount and read file with invalid key"
		else
			error "mount with invalid key"
		fi
	fi
	zconf_umount_clients ${clients_arr[0]} $MOUNT ||
		error "unable to umount clients"
	# unload keys from ring
	do_node ${clients_arr[0]} "keyctl show |
		awk '/lustre/ { print \\\$1 }' | xargs -IX keyctl unlink X"
	rm -f $SK_PATH
	SK_PATH=$OLD_SK_PATH
	zconf_mount_clients ${clients_arr[0]} $MOUNT ||
		error "unable to mount clients"
}
run_test 30 "check for invalid shared key"

basic_ios() {
	local flvr=$1

	mkdir -p $DIR/$tdir || error "mkdir $flvr"
	touch $DIR/$tdir/f0 || error "touch $flvr"
	ls $DIR/$tdir || error "ls $flvr"
	dd if=/dev/zero of=$DIR/$tdir/f0 conv=fsync bs=1M count=10 \
		>& /dev/null || error "dd $flvr"
	rm -f $DIR/$tdir/f0 || error "rm $flvr"
	rmdir $DIR/$tdir || error "rmdir $flvr"

	sync ; sync
	echo 3 > /proc/sys/vm/drop_caches
}

test_30b() {
	local save_flvr=$SK_FLAVOR

	if ! $SHARED_KEY; then
		skip "need shared key feature for this test"
	fi

	stack_trap restore_to_default_flavor EXIT

	for flvr in skn ska ski skpi; do
		# set flavor
		SK_FLAVOR=$flvr
		restore_to_default_flavor || error "cannot set $flvr flavor"
		SK_FLAVOR=$save_flvr

		basic_ios $flvr
	done
}
run_test 30b "basic test of all different SSK flavors"

cleanup_31() {
	# unmount client
	zconf_umount $HOSTNAME $MOUNT || error "unable to umount client"

	# remove ${NETTYPE}999 network on all nodes
	do_nodes $(comma_list $(all_nodes)) \
		 "$LNETCTL net del --net ${NETTYPE}999 && \
		  $LNETCTL lnet unconfigure 2>/dev/null || true"

	# necessary to do writeconf in order to de-register
	# @${NETTYPE}999 nid for targets
	KZPOOL=$KEEP_ZPOOL
	export KEEP_ZPOOL="true"
	stopall
	export SK_MOUNTED=false
	writeconf_all
	setupall || echo 1
	export KEEP_ZPOOL="$KZPOOL"
}

test_31() {
	local nid=$(lctl list_nids | grep ${NETTYPE} | head -n1)
	local addr=${nid%@*}
	local net=${nid#*@}

	export LNETCTL=$(which lnetctl 2> /dev/null)

	[ -z "$LNETCTL" ] && skip "without lnetctl support." && return
	local_mode && skip "in local mode."

	stack_trap cleanup_31 EXIT

	# umount client
	if [ "$MOUNT_2" ] && $(grep -q $MOUNT2' ' /proc/mounts); then
		umount_client $MOUNT2 || error "umount $MOUNT2 failed"
	fi
	if $(grep -q $MOUNT' ' /proc/mounts); then
		umount_client $MOUNT || error "umount $MOUNT failed"
	fi

	# check exports on servers are empty for client
	do_facet mgs "lctl get_param -n *.MGS*.exports.'$nid'.uuid 2>/dev/null |
		      grep -q -" && error "export on MGS should be empty"
	do_nodes $(comma_list $(mdts_nodes) $(osts_nodes)) \
		 "lctl get_param -n *.${FSNAME}*.exports.'$nid'.uuid \
		  2>/dev/null | grep -q -" &&
		error "export on servers should be empty"

	# add network ${NETTYPE}999 on all nodes
	do_nodes $(comma_list $(all_nodes)) \
		 "$LNETCTL lnet configure && $LNETCTL net add --if \
		  \$($LNETCTL net show --net $net | awk 'BEGIN{inf=0} \
		  {if (inf==1) print \$2; fi; inf=0} /interfaces/{inf=1}') \
		  --net ${NETTYPE}999" ||
		error "unable to configure NID ${NETTYPE}999"

	# necessary to do writeconf in order to register
	# new @${NETTYPE}999 nid for targets
	KZPOOL=$KEEP_ZPOOL
	export KEEP_ZPOOL="true"
	stopall
	export SK_MOUNTED=false
	writeconf_all
	setupall server_only || echo 1
	export KEEP_ZPOOL="$KZPOOL"

	# backup MGSNID
	local mgsnid_orig=$MGSNID
	# compute new MGSNID
	MGSNID=$(do_facet mgs "$LCTL list_nids | grep ${NETTYPE}999")

	# on client, turn LNet Dynamic Discovery on
	lnetctl set discovery 1

	# mount client with -o network=${NETTYPE}999 option:
	# should fail because of LNet Dynamic Discovery
	mount_client $MOUNT ${MOUNT_OPTS},network=${NETTYPE}999 &&
		error "client mount with '-o network' option should be refused"

	# on client, reconfigure LNet and turn LNet Dynamic Discovery off
	$LNETCTL net del --net ${NETTYPE}999 && lnetctl lnet unconfigure
	lustre_rmmod
	modprobe lnet
	lnetctl set discovery 0
	modprobe ptlrpc
	$LNETCTL lnet configure && $LNETCTL net add --if \
	  $($LNETCTL net show --net $net | awk 'BEGIN{inf=0} \
	  {if (inf==1) print $2; fi; inf=0} /interfaces/{inf=1}') \
	  --net ${NETTYPE}999 ||
	error "unable to configure NID ${NETTYPE}999 on client"

	# mount client with -o network=${NETTYPE}999 option
	mount_client $MOUNT ${MOUNT_OPTS},network=${NETTYPE}999 ||
		error "unable to remount client"

	# restore MGSNID
	MGSNID=$mgsnid_orig

	# check export on MGS
	do_facet mgs "lctl get_param -n *.MGS*.exports.'$nid'.uuid 2>/dev/null |
		      grep -q -"
	[ $? -ne 0 ] ||	error "export for $nid on MGS should not exist"

	do_facet mgs \
		"lctl get_param -n *.MGS*.exports.'${addr}@${NETTYPE}999'.uuid \
		 2>/dev/null | grep -q -"
	[ $? -eq 0 ] ||
		error "export for ${addr}@${NETTYPE}999 on MGS should exist"

	# check {mdc,osc} imports
	lctl get_param mdc.${FSNAME}-*.import | grep current_connection |
	    grep -q ${NETTYPE}999
	[ $? -eq 0 ] ||
		error "import for mdc should use ${addr}@${NETTYPE}999"
	lctl get_param osc.${FSNAME}-*.import | grep current_connection |
	    grep -q ${NETTYPE}999
	[ $? -eq 0 ] ||
		error "import for osc should use ${addr}@${NETTYPE}999"
}
run_test 31 "client mount option '-o network'"

cleanup_32() {
	# umount client
	zconf_umount_clients ${clients_arr[0]} $MOUNT

	# disable sk flavor enforcement on MGS
	set_rule _mgs any any null

	# stop gss daemon on MGS
	if ! combined_mgs_mds ; then
		send_sigint $mgs_HOST lsvcgssd
	fi

	# re-mount client
	MOUNT_OPTS=$(add_sk_mntflag $MOUNT_OPTS)
	mountcli

	restore_to_default_flavor
}

test_32() {
	if ! $SHARED_KEY; then
		skip "need shared key feature for this test"
	fi

	stack_trap cleanup_32 EXIT

	# restore to default null flavor
	save_flvr=$SK_FLAVOR
	SK_FLAVOR=null
	restore_to_default_flavor || error "cannot set null flavor"
	SK_FLAVOR=$save_flvr

	# umount client
	if [ "$MOUNT_2" ] && $(grep -q $MOUNT2' ' /proc/mounts); then
		umount_client $MOUNT2 || error "umount $MOUNT2 failed"
	fi
	if $(grep -q $MOUNT' ' /proc/mounts); then
	umount_client $MOUNT || error "umount $MOUNT failed"
	fi

	# start gss daemon on MGS
	if combined_mgs_mds ; then
		send_sigint $mds_HOST lsvcgssd
	fi
	start_gss_daemons $mgs_HOST "$LSVCGSSD -vvv -s -g"

	# add mgs key type and MGS NIDs in key on MGS
	do_nodes $mgs_HOST "lgss_sk -t mgs,server -g $MGSNID -m \
				$SK_PATH/$FSNAME.key >/dev/null 2>&1" ||
		error "could not modify keyfile on MGS"

	# load modified key file on MGS
	do_nodes $mgs_HOST "lgss_sk -l $SK_PATH/$FSNAME.key >/dev/null 2>&1" ||
		error "could not load keyfile on MGS"

	# add MGS NIDs in key on client
	do_nodes ${clients_arr[0]} "lgss_sk -g $MGSNID -m \
				$SK_PATH/$FSNAME.key >/dev/null 2>&1" ||
		error "could not modify keyfile on MGS"

	# set perms for per-nodemap keys else permission denied
	do_nodes $(comma_list $(all_nodes)) \
		 "keyctl show | grep lustre | cut -c1-11 |
				sed -e 's/ //g;' |
				xargs -IX keyctl setperm X 0x3f3f3f3f"

	# re-mount client with mgssec=skn
	save_opts=$MOUNT_OPTS
	if [ -z "$MOUNT_OPTS" ]; then
		MOUNT_OPTS="-o mgssec=skn"
	else
		MOUNT_OPTS="$MOUNT_OPTS,mgssec=skn"
	fi
	zconf_mount_clients ${clients_arr[0]} $MOUNT $MOUNT_OPTS ||
		error "mount ${clients_arr[0]} with mgssec=skn failed"
	MOUNT_OPTS=$save_opts

	# umount client
	zconf_umount_clients ${clients_arr[0]} $MOUNT ||
		error "umount ${clients_arr[0]} failed"

	# enforce ska flavor on MGS
	set_rule _mgs any any ska

	# re-mount client without mgssec
	zconf_mount_clients ${clients_arr[0]} $MOUNT $MOUNT_OPTS &&
		error "mount ${clients_arr[0]} without mgssec should fail"

	# re-mount client with mgssec=skn
	save_opts=$MOUNT_OPTS
	if [ -z "$MOUNT_OPTS" ]; then
		MOUNT_OPTS="-o mgssec=skn"
	else
		MOUNT_OPTS="$MOUNT_OPTS,mgssec=skn"
	fi
	zconf_mount_clients ${clients_arr[0]} $MOUNT $MOUNT_OPTS &&
		error "mount ${clients_arr[0]} with mgssec=skn should fail"
	MOUNT_OPTS=$save_opts

	# re-mount client with mgssec=ska
	save_opts=$MOUNT_OPTS
	if [ -z "$MOUNT_OPTS" ]; then
		MOUNT_OPTS="-o mgssec=ska"
	else
		MOUNT_OPTS="$MOUNT_OPTS,mgssec=ska"
	fi
	zconf_mount_clients ${clients_arr[0]} $MOUNT $MOUNT_OPTS ||
		error "mount ${clients_arr[0]} with mgssec=ska failed"
	MOUNT_OPTS=$save_opts

	exit 0
}
run_test 32 "check for mgssec"

cleanup_33() {
	# disable sk flavor enforcement
	set_rule $FSNAME any cli2mdt null
	wait_flavor cli2mdt null

	# umount client
	zconf_umount_clients ${clients_arr[0]} $MOUNT

	# stop gss daemon on MGS
	if ! combined_mgs_mds ; then
		send_sigint $mgs_HOST lsvcgssd
	fi

	# re-mount client
	MOUNT_OPTS=$(add_sk_mntflag $MOUNT_OPTS)
	mountcli

	restore_to_default_flavor
}

test_33() {
	if ! $SHARED_KEY; then
		skip "need shared key feature for this test"
	fi

	stack_trap cleanup_33 EXIT

	# restore to default null flavor
	save_flvr=$SK_FLAVOR
	SK_FLAVOR=null
	restore_to_default_flavor || error "cannot set null flavor"
	SK_FLAVOR=$save_flvr

	# umount client
	if [ "$MOUNT_2" ] && $(grep -q $MOUNT2' ' /proc/mounts); then
		umount_client $MOUNT2 || error "umount $MOUNT2 failed"
	fi
	if $(grep -q $MOUNT' ' /proc/mounts); then
	umount_client $MOUNT || error "umount $MOUNT failed"
	fi

	# start gss daemon on MGS
	if combined_mgs_mds ; then
		send_sigint $mds_HOST lsvcgssd
	fi
	start_gss_daemons $mgs_HOST "$LSVCGSSD -vvv -s -g"

	# add mgs key type and MGS NIDs in key on MGS
	do_nodes $mgs_HOST "lgss_sk -t mgs,server -g $MGSNID -m \
				$SK_PATH/$FSNAME.key >/dev/null 2>&1" ||
		error "could not modify keyfile on MGS"

	# load modified key file on MGS
	do_nodes $mgs_HOST "lgss_sk -l $SK_PATH/$FSNAME.key >/dev/null 2>&1" ||
		error "could not load keyfile on MGS"

	# add MGS NIDs in key on client
	do_nodes ${clients_arr[0]} "lgss_sk -g $MGSNID -m \
				$SK_PATH/$FSNAME.key >/dev/null 2>&1" ||
		error "could not modify keyfile on MGS"

	# set perms for per-nodemap keys else permission denied
	do_nodes $(comma_list $(all_nodes)) \
		 "keyctl show | grep lustre | cut -c1-11 |
				sed -e 's/ //g;' |
				xargs -IX keyctl setperm X 0x3f3f3f3f"

	# re-mount client with mgssec=skn
	save_opts=$MOUNT_OPTS
	if [ -z "$MOUNT_OPTS" ]; then
		MOUNT_OPTS="-o mgssec=skn"
	else
		MOUNT_OPTS="$MOUNT_OPTS,mgssec=skn"
	fi
	zconf_mount_clients ${clients_arr[0]} $MOUNT $MOUNT_OPTS ||
		error "mount ${clients_arr[0]} with mgssec=skn failed"
	MOUNT_OPTS=$save_opts

	# enforce ska flavor for cli2mdt
	set_rule $FSNAME any cli2mdt ska
	wait_flavor cli2mdt ska

	# check error message
	$LCTL dk | grep "faked source" &&
		error "MGS connection srpc flags incorrect"

	exit 0
}
run_test 33 "correct srpc flags for MGS connection"

cleanup_34_deny() {
	# restore deny_unknown
	do_facet mgs $LCTL nodemap_modify --name default \
			   --property deny_unknown --value $denydefault
	if [ $? -ne 0 ]; then
		error_noexit "cannot reset deny_unknown on default nodemap"
		return
	fi

	wait_nm_sync default deny_unknown
}

test_34() {
	local denynew
	local activedefault

	[ $MGS_VERSION -lt $(version_code 2.12.51) ] &&
		skip "deny_unknown on default nm not supported before 2.12.51"

	activedefault=$(do_facet mgs $LCTL get_param -n nodemap.active)

	if [[ "$activedefault" != "1" ]]; then
		do_facet mgs $LCTL nodemap_activate 1
		wait_nm_sync active
		stack_trap cleanup_active EXIT
	fi

	denydefault=$(do_facet mgs $LCTL get_param -n \
		      nodemap.default.deny_unknown)
	[ -z "$denydefault" ] &&
		error "cannot get deny_unknown on default nodemap"
	if [ "$denydefault" -eq 0 ]; then
		denynew=1;
	else
		denynew=0;
	fi

	do_facet mgs $LCTL nodemap_modify --name default \
			--property deny_unknown --value $denynew ||
		error "cannot set deny_unknown on default nodemap"

	[ "$(do_facet mgs $LCTL get_param -n nodemap.default.deny_unknown)" \
			-eq $denynew ] ||
		error "setting deny_unknown on default nodemap did not work"

	stack_trap cleanup_34_deny EXIT

	wait_nm_sync default deny_unknown
}
run_test 34 "deny_unknown on default nodemap"

test_35() {
	[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.13.50) ] ||
		skip "Need MDS >= 2.13.50"

	# activate changelogs
	changelog_register || error "changelog_register failed"
	local cl_user="${CL_USERS[$SINGLEMDS]%% *}"
	changelog_users $SINGLEMDS | grep -q $cl_user ||
		error "User $cl_user not found in changelog_users"
	changelog_chmask ALL

	# do some IOs
	mkdir $DIR/$tdir || error "failed to mkdir $tdir"
	touch $DIR/$tdir/$tfile || error "failed to touch $tfile"

	# access changelogs with root
	changelog_dump || error "failed to dump changelogs"
	changelog_clear 0 || error "failed to clear changelogs"

	# put clients in non-admin nodemap
	nodemap_test_setup
	stack_trap nodemap_test_cleanup EXIT
	for i in $(seq 0 $((num_clients-1))); do
		do_facet mgs $LCTL nodemap_modify --name c${i} \
			 --property admin --value 0
	done
	for i in $(seq 0 $((num_clients-1))); do
		wait_nm_sync c${i} admin_nodemap
	done

	# access with mapped root
	changelog_dump && error "dump changelogs should have failed"
	changelog_clear 0 && error "clear changelogs should have failed"

	exit 0
}
run_test 35 "Check permissions when accessing changelogs"

setup_for_enc_tests() {
	# remount client with test_dummy_encryption option
	if is_mounted $MOUNT; then
		umount_client $MOUNT || error "umount $MOUNT failed"
	fi
	mount_client $MOUNT ${MOUNT_OPTS},test_dummy_encryption ||
		error "mount with '-o test_dummy_encryption' failed"

	# this directory will be encrypted, because of dummy mode
	mkdir $DIR/$tdir
}

cleanup_for_enc_tests() {
	# remount client normally
	if is_mounted $MOUNT; then
		umount_client $MOUNT || error "umount $MOUNT failed"
	fi
	mount_client $MOUNT ${MOUNT_OPTS} ||
		error "remount failed"

	if is_mounted $MOUNT2; then
		umount_client $MOUNT2 || error "umount $MOUNT2 failed"
	fi
	if [ "$MOUNT_2" ]; then
		mount_client $MOUNT2 ${MOUNT_OPTS} ||
			error "remount failed"
	fi
}

cleanup_nodemap_after_enc_tests() {
	do_facet mgs $LCTL nodemap_modify --name default \
		--property forbid_encryption --value 0
	wait_nm_sync default forbid_encryption
	do_facet mgs $LCTL nodemap_activate 0
	wait_nm_sync active
}

test_36() {
	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT

	# first make sure it is possible to enable encryption
	# when nodemap is not active
	setup_for_enc_tests
	rmdir $DIR/$tdir
	umount_client $MOUNT || error "umount $MOUNT failed (1)"

	# then activate nodemap, and retry
	# should succeed as encryption is not forbidden on default nodemap
	# by default
	stack_trap cleanup_nodemap_after_enc_tests EXIT
	do_facet mgs $LCTL nodemap_activate 1
	wait_nm_sync active
	forbid=$(do_facet mgs lctl get_param -n nodemap.default.forbid_encryption)
	[ $forbid -eq 0 ] || error "wrong default value for forbid_encryption"
	mount_client $MOUNT ${MOUNT_OPTS},test_dummy_encryption ||
		error "mount '-o test_dummy_encryption' failed with default"
	umount_client $MOUNT || error "umount $MOUNT failed (2)"

	# then forbid encryption, and retry
	do_facet mgs $LCTL nodemap_modify --name default \
		--property forbid_encryption --value 1
	wait_nm_sync default forbid_encryption
	mount_client $MOUNT ${MOUNT_OPTS},test_dummy_encryption &&
		error "mount '-o test_dummy_encryption' should have failed"
	return 0
}
run_test 36 "control if clients can use encryption"

test_37() {
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/abc
	local objdump=$TMP/objdump
	local objid

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	[ "$ost1_FSTYPE" = ldiskfs ] || skip "ldiskfs only test (using debugfs)"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	# write a few bytes in file
	echo "abc" > $tmpfile
	$LFS setstripe -c1 -i0 $testfile
	dd if=$tmpfile of=$testfile bs=4 count=1 conv=fsync
	do_facet ost1 "sync; sync"

	# check that content on ost is encrypted
	objid=$($LFS getstripe $testfile | awk '/obdidx/{getline; print $2}')
	do_facet ost1 "$DEBUGFS -c -R 'cat O/0/d$(($objid % 32))/$objid' \
		 $(ostdevname 1)" > $objdump
	cmp -s $objdump $tmpfile &&
		error "file $testfile is not encrypted on ost"

	# check that in-memory representation of file is correct
	cmp -bl ${tmpfile} ${testfile} ||
		error "file $testfile is corrupted in memory"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl ${tmpfile} ${testfile} ||
		error "file $testfile is corrupted on server"

	rm -f $tmpfile $objdump
}
run_test 37 "simple encrypted file"

test_38() {
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/abc
	local objid
	local blksz
	local srvsz=0
	local filesz
	local bsize
	local pagesz=$(getconf PAGE_SIZE)

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	# get block size on ost
	blksz=$($LCTL get_param osc.$FSNAME*.import |
		awk '/grant_block_size:/ { print $2; exit; }')
	# write a few bytes in file at offset $blksz
	echo "abc" > $tmpfile
	$LFS setstripe -c1 -i0 $testfile
	dd if=$tmpfile of=$testfile bs=4 count=1 seek=$blksz \
		oflag=seek_bytes conv=fsync

	blksz=$(($blksz > $pagesz ? $blksz : $pagesz))
	# check that in-memory representation of file is correct
	bsize=$(stat --format=%B $testfile)
	filesz=$(stat --format=%b $testfile)
	filesz=$((filesz*bsize))
	[ $filesz -le $blksz ] ||
		error "file $testfile is $filesz long in memory"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	bsize=$(stat --format=%B $testfile)
	filesz=$(stat --format=%b $testfile)
	filesz=$((filesz*bsize))
	[ $filesz -le $blksz ] ||
		error "file $testfile is $filesz long on server"

	rm -f $tmpfile
}
run_test 38 "encrypted file with hole"

test_39() {
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/abc

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	# write a few bytes in file
	echo "abc" > $tmpfile
	$LFS setstripe -c1 -i0 $testfile
	dd if=$tmpfile of=$testfile bs=4 count=1 conv=fsync

	# write a few more bytes in the same page
	dd if=$tmpfile of=$testfile bs=4 count=1 seek=1024 oflag=seek_bytes \
		conv=fsync,notrunc

	dd if=$tmpfile of=$tmpfile bs=4 count=1 seek=1024 oflag=seek_bytes \
		conv=fsync,notrunc

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted in memory"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted on server"

	rm -f $tmpfile
}
run_test 39 "rewrite data in already encrypted page"

test_40() {
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/abc
	local tmpfile2=$TMP/abc2
	local seek

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	[[ $OSTCOUNT -lt 2 ]] && skip_env "needs >= 2 OSTs"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	# write a few bytes in file
	echo "abc" > $tmpfile
	$LFS setstripe -c1 -i0 $testfile
	dd if=$tmpfile of=$testfile bs=4 count=1 conv=fsync

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted in memory (1)"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted on server (1)"

	# write a few other bytes in same page
	dd if=$tmpfile of=$testfile bs=4 count=1 seek=256 oflag=seek_bytes \
		conv=fsync,notrunc

	dd if=$tmpfile of=$tmpfile bs=4 count=1 seek=256 oflag=seek_bytes \
		conv=fsync,notrunc

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted in memory (2)"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted on server (2)"

	rm -f $testfile $tmpfile
	cancel_lru_locks osc ; cancel_lru_locks mdc

	# write a few bytes in file, at end of first page
	echo "abc" > $tmpfile
	$LFS setstripe -c1 -i0 $testfile
	seek=$(getconf PAGESIZE)
	seek=$((seek - 4))
	dd if=$tmpfile of=$testfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc

	# write a few other bytes at beginning of first page
	dd if=$tmpfile of=$testfile bs=4 count=1 conv=fsync,notrunc

	dd if=$tmpfile of=$tmpfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted in memory (3)"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted on server (3)"

	rm -f $testfile $tmpfile
	cancel_lru_locks osc ; cancel_lru_locks mdc

	# write a few bytes in file, at beginning of second page
	echo "abc" > $tmpfile
	$LFS setstripe -c1 -i0 $testfile
	seek=$(getconf PAGESIZE)
	dd if=$tmpfile of=$testfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc
	dd if=$tmpfile of=$tmpfile2 bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc

	# write a few other bytes at end of first page
	seek=$((seek - 4))
	dd if=$tmpfile of=$testfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc
	dd if=$tmpfile of=$tmpfile2 bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile2 $testfile ||
		error "file $testfile is corrupted in memory (4)"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl $tmpfile2 $testfile ||
		error "file $testfile is corrupted on server (4)"

	rm -f $testfile $tmpfile $tmpfile2
	cancel_lru_locks osc ; cancel_lru_locks mdc

	# write a few bytes in file, at beginning of first stripe
	echo "abc" > $tmpfile
	$LFS setstripe -S 256k -c2 $testfile
	dd if=$tmpfile of=$testfile bs=4 count=1 conv=fsync,notrunc

	# write a few other bytes, at beginning of second stripe
	dd if=$tmpfile of=$testfile bs=4 count=1 seek=262144 oflag=seek_bytes \
		conv=fsync,notrunc
	dd if=$tmpfile of=$tmpfile bs=4 count=1 seek=262144 oflag=seek_bytes \
		conv=fsync,notrunc

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted in memory (5)"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted on server (5)"

	rm -f $tmpfile
}
run_test 40 "exercise size of encrypted file"

test_41() {
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/abc
	local tmpfile2=$TMP/abc2
	local seek

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	echo "abc" > $tmpfile
	seek=$(getconf PAGESIZE)
	seek=$((seek - 204))
	dd if=$tmpfile of=$tmpfile2 bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync
	seek=$(getconf PAGESIZE)
	seek=$((seek + 1092))
	dd if=$tmpfile of=$tmpfile2 bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc

	# write a few bytes in file
	$LFS setstripe -c1 -i0 -S 256k $testfile
	seek=$(getconf PAGESIZE)
	seek=$((seek - 204))
	#define OBD_FAIL_OST_WR_ATTR_DELAY	 0x250
	do_facet ost1 "$LCTL set_param fail_loc=0x250 fail_val=15"
	dd if=$tmpfile of=$testfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync &

	sleep 5
	# write a few other bytes, at a different offset
	seek=$(getconf PAGESIZE)
	seek=$((seek + 1092))
	dd if=$tmpfile of=$testfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc &
	wait
	do_facet ost1 "$LCTL set_param fail_loc=0x0"

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile2 $testfile ||
		error "file $testfile is corrupted in memory (1)"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl $tmpfile2 $testfile ||
		error "file $testfile is corrupted on server (1)"

	rm -f $tmpfile $tmpfile2
}
run_test 41 "test race on encrypted file size (1)"

test_42() {
	local testfile=$DIR/$tdir/$tfile
	local testfile2=$DIR2/$tdir/$tfile
	local tmpfile=$TMP/abc
	local tmpfile2=$TMP/abc2
	local pagesz=$(getconf PAGESIZE)
	local seek

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	if is_mounted $MOUNT2; then
		umount_client $MOUNT2 || error "umount $MOUNT2 failed"
	fi
	mount_client $MOUNT2 ${MOUNT_OPTS},test_dummy_encryption ||
		error "mount2 with '-o test_dummy_encryption' failed"

	# create file by writting one whole page
	$LFS setstripe -c1 -i0 -S 256k $testfile
	dd if=/dev/zero of=$testfile bs=$pagesz count=1 conv=fsync

	# read file from 2nd mount point
	cat $testfile2 > /dev/null

	echo "abc" > $tmpfile
	dd if=/dev/zero of=$tmpfile2 bs=$pagesz count=1 conv=fsync
	seek=$((2*pagesz - 204))
	dd if=$tmpfile of=$tmpfile2 bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc
	seek=$((2*pagesz + 1092))
	dd if=$tmpfile of=$tmpfile2 bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc

	# write a few bytes in file from 1st mount point
	seek=$((2*pagesz - 204))
	#define OBD_FAIL_OST_WR_ATTR_DELAY	 0x250
	do_facet ost1 "$LCTL set_param fail_loc=0x250 fail_val=15"
	dd if=$tmpfile of=$testfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc &

	sleep 5
	# write a few other bytes, at a different offset from 2nd mount point
	seek=$((2*pagesz + 1092))
	dd if=$tmpfile of=$testfile2 bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc &
	wait
	do_facet ost1 "$LCTL set_param fail_loc=0x0"

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile2 $testfile ||
		error "file $testfile is corrupted in memory (1)"

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile2 $testfile2 ||
		error "file $testfile is corrupted in memory (2)"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl $tmpfile2 $testfile ||
		error "file $testfile is corrupted on server (1)"

	rm -f $tmpfile $tmpfile2
}
run_test 42 "test race on encrypted file size (2)"

test_43() {
	local testfile=$DIR/$tdir/$tfile
	local testfile2=$DIR2/$tdir/$tfile
	local tmpfile=$TMP/abc
	local tmpfile2=$TMP/abc2
	local resfile=$TMP/res
	local pagesz=$(getconf PAGESIZE)
	local seek

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	if is_mounted $MOUNT2; then
		umount_client $MOUNT2 || error "umount $MOUNT2 failed"
	fi
	mount_client $MOUNT2 ${MOUNT_OPTS},test_dummy_encryption ||
		error "mount2 with '-o test_dummy_encryption' failed"

	# create file
	tr '\0' '1' < /dev/zero |
		dd of=$tmpfile bs=1 count=$pagesz conv=fsync
	$LFS setstripe -c1 -i0 -S 256k $testfile
	cp $tmpfile $testfile

	# read file from 2nd mount point
	cat $testfile2 > /dev/null

	# write a few bytes in file from 1st mount point
	echo "abc" > $tmpfile2
	seek=$((2*pagesz - 204))
	#define OBD_FAIL_OST_WR_ATTR_DELAY	 0x250
	do_facet ost1 "$LCTL set_param fail_loc=0x250 fail_val=15"
	dd if=$tmpfile2 of=$testfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc &

	sleep 5
	# read file from 2nd mount point
	dd if=$testfile2 of=$resfile bs=$pagesz count=1 conv=fsync,notrunc
	cmp -bl $tmpfile $resfile ||
		error "file $testfile is corrupted in memory (1)"

	wait
	do_facet ost1 "$LCTL set_param fail_loc=0x0"

	# check that in-memory representation of file is correct
	dd if=$tmpfile2 of=$tmpfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc
	cmp -bl $tmpfile $testfile2 ||
		error "file $testfile is corrupted in memory (2)"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted on server (1)"

	rm -f $tmpfile $tmpfile2
}
run_test 43 "test race on encrypted file size (3)"

test_44() {
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/abc
	local resfile=$TMP/resfile
	local pagesz=$(getconf PAGESIZE)
	local respage

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	which vmtouch || skip "This test needs vmtouch utility"

	# Direct I/O is now supported on encrypted files.

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	$LFS setstripe -c1 -i0 $testfile
	dd if=/dev/urandom of=$tmpfile bs=$pagesz count=2 conv=fsync
	dd if=$tmpfile of=$testfile bs=$pagesz count=2 oflag=direct ||
		error "could not write to file with O_DIRECT (1)"

	respage=$(vmtouch $testfile | awk '/Resident Pages:/ {print $3}')
	[ "$respage" == "0/2" ] ||
		error "write to enc file fell back to buffered IO"

	cancel_lru_locks

	dd if=$testfile of=$resfile bs=$pagesz count=2 iflag=direct ||
		error "could not read from file with O_DIRECT (1)"

	respage=$(vmtouch $testfile | awk '/Resident Pages:/ {print $3}')
	[ "$respage" == "0/2" ] ||
		error "read from enc file fell back to buffered IO"

	cmp -bl $tmpfile $resfile ||
		error "file $testfile is corrupted (1)"

	rm -f $resfile

	$TRUNCATE $tmpfile $pagesz
	dd if=$tmpfile of=$testfile bs=$pagesz count=1 seek=13 oflag=direct ||
		error "could not write to file with O_DIRECT (2)"

	cancel_lru_locks

	dd if=$testfile of=$resfile bs=$pagesz count=1 skip=13 iflag=direct ||
		error "could not read from file with O_DIRECT (2)"
	cmp -bl $tmpfile $resfile ||
		error "file $testfile is corrupted (2)"

	rm -f $testfile $resfile
	$LFS setstripe -c1 -i0 $testfile

	$TRUNCATE $tmpfile $((pagesz/2 - 5))
	cp $tmpfile $testfile

	cancel_lru_locks

	dd if=$testfile of=$resfile bs=$pagesz count=1 iflag=direct ||
		error "could not read from file with O_DIRECT (3)"
	cmp -bl $tmpfile $resfile ||
		error "file $testfile is corrupted (3)"

	rm -f $tmpfile $resfile
}
run_test 44 "encrypted file access semantics: direct IO"

test_45() {
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/junk

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	$LFS setstripe -c1 -i0 $testfile
	dd if=/dev/zero of=$testfile bs=512K count=1
	$MULTIOP $testfile OSMRUc || error "$MULTIOP $testfile failed (1)"
	$MULTIOP $testfile OSMWUc || error "$MULTIOP $testfile failed (2)"

	dd if=/dev/zero of=$tmpfile bs=512K count=1
	$MULTIOP $tmpfile OSMWUc || error "$MULTIOP $tmpfile failed"
	$MMAP_CAT $tmpfile > ${tmpfile}2

	cancel_lru_locks

	$MULTIOP $testfile OSMRUc
	$MMAP_CAT $testfile > ${testfile}2
	cmp -bl ${tmpfile}2 ${testfile}2 ||
		error "file $testfile is corrupted"

	rm -f $tmpfile ${tmpfile}2
}
run_test 45 "encrypted file access semantics: MMAP"

test_46() {
	local testdir=$DIR/$tdir/mydir
	local testfile=$testdir/myfile
	local lsfile=$TMP/lsfile
	local scrambleddir
	local scrambledfile

	local testfile2=$DIR/$tdir/${tfile}.2
	local tmpfile=$DIR/junk

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	touch $DIR/onefile
	touch $DIR/$tdir/$tfile
	mkdir $testdir
	echo test > $testfile
	sync ; echo 3 > /proc/sys/vm/drop_caches

	# remove fscrypt key from keyring
	keyctl revoke $(keyctl show | awk '$7 ~ "^fscrypt:" {print $1}')
	keyctl reap

	scrambleddir=$(find $DIR/$tdir/ -maxdepth 1 -mindepth 1 -type d)
	ls -1 $scrambleddir > $lsfile || error "ls $testdir failed"

	scrambledfile=$scrambleddir/$(head -n 1 $lsfile)
	stat $scrambledfile || error "stat $scrambledfile failed"
	rm -f $lsfile

	cat $scrambledfile && error "cat $scrambledfile should have failed"

	touch $scrambleddir/otherfile &&
		error "touch otherfile should have failed"
	ls $scrambleddir/otherfile && error "otherfile should not exist"
	mkdir $scrambleddir/otherdir &&
		error "mkdir otherdir should have failed"
	ls -d $scrambleddir/otherdir && error "otherdir should not exist"

	rm -f $scrambledfile || error "rm $scrambledfile failed"
	rmdir $scrambleddir || error "rmdir $scrambleddir failed"

	rm -f $DIR/onefile
}
run_test 46 "encrypted file access semantics without key"

test_47() {
	local testfile=$DIR/$tdir/$tfile
	local testfile2=$DIR/$tdir/${tfile}.2
	local tmpfile=$DIR/junk
	local scrambleddir
	local scrambledfile

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	dd if=/dev/zero of=$tmpfile bs=512K count=1
	mrename $tmpfile $testfile &&
		error "rename from unencrypted to encrypted dir should fail"

	ln $tmpfile $testfile &&
		error "link from unencrypted to encrypted dir should fail"

	cp $tmpfile $testfile ||
		error "cp from unencrypted to encrypted dir should succeed"
	rm -f $tmpfile

	mrename $testfile $testfile2 ||
		error "rename from within encrypted dir should succeed"

	ln $testfile2 $testfile ||
		error "link from within encrypted dir should succeed"
	rm -f $testfile

	ln $testfile2 $tmpfile ||
		error "link from encrypted to unencrypted dir should succeed"
	rm -f $tmpfile

	mrename $testfile2 $tmpfile ||
		error "rename from encrypted to unencrypted dir should succeed"

	dd if=/dev/zero of=$testfile bs=512K count=1
	mkdir $DIR/$tdir/mydir
	sync ; echo 3 > /proc/sys/vm/drop_caches

	# remove fscrypt key from keyring
	keyctl revoke $(keyctl show | awk '$7 ~ "^fscrypt:" {print $1}')
	keyctl reap

	scrambleddir=$(find $DIR/$tdir/ -maxdepth 1 -mindepth 1 -type d)
	scrambledfile=$(find $DIR/$tdir/ -maxdepth 1 -type f)
	ln $scrambledfile $scrambleddir/linkfile &&
		error "ln linkfile should have failed"
	mrename $scrambledfile $DIR/onefile2 &&
		error "mrename from $scrambledfile should have failed"
	touch $DIR/onefile
	mrename $DIR/onefile $scrambleddir/otherfile &&
		error "mrename to $scrambleddir should have failed"

	rm -f $tmpfile $DIR/onefile
}
run_test 47 "encrypted file access semantics: rename/link"

test_48a() {
	local save="$TMP/$TESTSUITE-$TESTNAME.parameters"
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/111
	local tmpfile2=$TMP/abc
	local pagesz=$(getconf PAGESIZE)
	local sz
	local seek
	local scrambledfile

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	# create file, 4 x PAGE_SIZE long
	tr '\0' '1' < /dev/zero |
		dd of=$tmpfile bs=1 count=4x$pagesz conv=fsync
	$LFS setstripe -c1 -i0 $testfile
	cp $tmpfile $testfile
	echo "abc" > $tmpfile2

	# decrease size: truncate to PAGE_SIZE
	$TRUNCATE $tmpfile $pagesz
	$TRUNCATE $testfile $pagesz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (1)"

	# increase size: truncate to 2 x PAGE_SIZE
	sz=$((pagesz*2))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (2)"

	# write in 2nd page
	seek=$((pagesz+100))
	dd if=$tmpfile2 of=$tmpfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc
	dd if=$tmpfile2 of=$testfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (3)"

	# truncate to PAGE_SIZE / 2
	sz=$((pagesz/2))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (4)"

	# lockless truncate should be turned into regular truncate for enc file
	save_lustre_params client "osc.*.lockless_truncate" > $save
	# restore lockless_truncate default values on exit
	stack_trap "restore_lustre_params < $save; rm -f $save" EXIT
	cancel_lru_locks osc ; cancel_lru_locks mdc
	lctl set_param -n osc.*.lockless_truncate 1
	cancel_lru_locks osc
	clear_stats osc.*.osc_stats
	$TRUNCATE $testfile 8000000 || error "truncate failed (1)"
	[ $(calc_stats osc.*.osc_stats lockless_truncate) -eq 0 ] ||
		error "lockless truncate should be turned into regular truncate"
	lctl set_param -n osc.*.lockless_truncate 0

	# truncate to a smaller, non-multiple of PAGE_SIZE, non-multiple of 16
	sz=$((sz-7))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (5)"

	# truncate to a larger, non-multiple of PAGE_SIZE, non-multiple of 16
	sz=$((sz+18))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (6)"

	# truncate to a larger, non-multiple of PAGE_SIZE, in a different page
	sz=$((sz+pagesz+30))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (7)"

	sync ; echo 3 > /proc/sys/vm/drop_caches

	# remove fscrypt key from keyring
	keyctl revoke $(keyctl show | awk '$7 ~ "^fscrypt:" {print $1}')
	keyctl reap

	scrambledfile=$(find $DIR/$tdir/ -maxdepth 1 -type f)
	$TRUNCATE $scrambledfile 0 &&
		error "truncate $scrambledfile should have failed without key"

	rm -f $tmpfile $tmpfile2
}
run_test 48a "encrypted file access semantics: truncate"

cleanup_for_enc_tests_othercli() {
	local othercli=$1

	# remount othercli normally
	zconf_umount $othercli $MOUNT ||
		error "umount $othercli $MOUNT failed"
	zconf_mount $othercli $MOUNT ||
		error "remount $othercli $MOUNT failed"
}

test_48b() {
	local othercli

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	[ "$num_clients" -ge 2 ] || skip "Need at least 2 clients"

	if [ "$HOSTNAME" == ${clients_arr[0]} ]; then
		othercli=${clients_arr[1]}
	else
		othercli=${clients_arr[0]}
	fi

	stack_trap cleanup_for_enc_tests EXIT
	stack_trap "cleanup_for_enc_tests_othercli $othercli" EXIT
	setup_for_enc_tests
	zconf_umount $othercli $MOUNT ||
		error "umount $othercli $MOUNT failed"

	cp /bin/sleep $DIR/$tdir/
	cancel_lru_locks osc ; cancel_lru_locks mdc
	$DIR/$tdir/sleep 30 &
	# mount and IOs must be done in the same shell session, otherwise
	# encryption key in session keyring is missing
	do_node $othercli "$MOUNT_CMD -o ${MOUNT_OPTS},test_dummy_encryption \
			   $MGSNID:/$FSNAME $MOUNT && \
			   $TRUNCATE $DIR/$tdir/sleep 7"
	wait || error "wait error"
	cmp --silent /bin/sleep $DIR/$tdir/sleep ||
		error "/bin/sleep and $DIR/$tdir/sleep differ"
}
run_test 48b "encrypted file: concurrent truncate"

trace_cmd() {
	local cmd="$@"
	local xattr_name="security.c"

	cancel_lru_locks
	$LCTL set_param debug=+info
	$LCTL clear

	echo $cmd
	eval $cmd
	[ $? -eq 0 ] || error "$cmd failed"

	$LCTL dk | grep -E "get xattr '${xattr_name}'|get xattrs"
	[ $? -ne 0 ] || error "get xattr event was triggered"
}

test_49() {
	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	local dirname=$DIR/$tdir/subdir

	mkdir $dirname

	trace_cmd stat $dirname
	trace_cmd touch $dirname/f1
	trace_cmd stat $dirname/f1
	trace_cmd cat $dirname/f1
	dd if=/dev/zero of=$dirname/f1 bs=1M count=10 conv=fsync
	trace_cmd $TRUNCATE $dirname/f1 10240
	trace_cmd $LFS setstripe -E -1 -S 4M $dirname/f2
	trace_cmd $LFS migrate -E -1 -S 256K $dirname/f2

	if [[ $MDSCOUNT -gt 1 ]]; then
		trace_cmd $LFS setdirstripe -i 1 $dirname/d2
		trace_cmd $LFS migrate -m 0 $dirname/d2
		touch $dirname/d2/subf
		# migrate a non-empty encrypted dir
		trace_cmd $LFS migrate -m 1 $dirname/d2

		$LFS setdirstripe -i 1 -c 1 $dirname/d3
		dirname=$dirname/d3/subdir
		mkdir $dirname

		trace_cmd stat $dirname
		trace_cmd touch $dirname/f1
		trace_cmd stat $dirname/f1
		trace_cmd cat $dirname/f1
		dd if=/dev/zero of=$dirname/f1 bs=1M count=10 conv=fsync
		trace_cmd $TRUNCATE $dirname/f1 10240
		trace_cmd $LFS setstripe -E -1 -S 4M $dirname/f2
		trace_cmd $LFS migrate -E -1 -S 256K $dirname/f2
	else
		skip_noexit "2nd part needs >= 2 MDTs"
	fi
}
run_test 49 "Avoid getxattr for encryption context"

test_50() {
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/abc
	local pagesz=$(getconf PAGESIZE)
	local sz

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	# write small file, data on MDT only
	tr '\0' '1' < /dev/zero |
	    dd of=$tmpfile bs=1 count=5000 conv=fsync
	$LFS setstripe -E 1M -L mdt -E EOF $testfile
	cp $tmpfile $testfile

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted in memory"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted on server"

	# decrease size: truncate to PAGE_SIZE
	$TRUNCATE $tmpfile $pagesz
	$TRUNCATE $testfile $pagesz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (1)"

	# increase size: truncate to 2 x PAGE_SIZE
	sz=$((pagesz*2))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (2)"

	# truncate to PAGE_SIZE / 2
	sz=$((pagesz/2))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (3)"

	# truncate to a smaller, non-multiple of PAGE_SIZE, non-multiple of 16
	sz=$((sz-7))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (4)"

	# truncate to a larger, non-multiple of PAGE_SIZE, non-multiple of 16
	sz=$((sz+18))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (5)"

	# truncate to a larger, non-multiple of PAGE_SIZE, in a different page
	sz=$((sz+pagesz+30))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (6)"

	rm -f $testfile
	cancel_lru_locks osc ; cancel_lru_locks mdc

	# write hole in file, data spread on MDT and OST
	tr '\0' '2' < /dev/zero |
	    dd of=$tmpfile bs=1 count=1539 seek=1539074 conv=fsync,notrunc
	$LFS setstripe -E 1M -L mdt -E EOF $testfile
	cp --sparse=always $tmpfile $testfile

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted in memory"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted on server"

	# truncate to a smaller, non-multiple of PAGE_SIZE, non-multiple of 16,
	# inside OST part of data
	sz=$((1024*1024+13))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (7)"

	# truncate to a smaller, non-multiple of PAGE_SIZE, non-multiple of 16,
	# inside MDT part of data
	sz=7
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (8)"

	# truncate to a larger, non-multiple of PAGE_SIZE, non-multiple of 16,
	# inside MDT part of data
	sz=$((1024*1024-13))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (9)"

	# truncate to a larger, non-multiple of PAGE_SIZE, non-multiple of 16,
	# inside OST part of data
	sz=$((1024*1024+7))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (10)"

	rm -f $tmpfile
}
run_test 50 "DoM encrypted file"

test_51() {
	[ "$MDS1_VERSION" -gt $(version_code 2.13.53) ] ||
		skip "Need MDS version at least 2.13.53"

	mkdir $DIR/$tdir || error "mkdir $tdir"

	touch $DIR/$tdir/$tfile || error "touch $tfile"
	cp $(which chown) $DIR/$tdir || error "cp chown"
	$RUNAS_CMD -u $ID0 $DIR/$tdir/chown $ID0 $DIR/$tdir/$tfile &&
		error "chown $tfile should fail"
	setcap 'CAP_CHOWN=ep' $DIR/$tdir/chown || error "setcap CAP_CHOWN"
	$RUNAS_CMD -u $ID0 $DIR/$tdir/chown $ID0 $DIR/$tdir/$tfile ||
		error "chown $tfile"
	rm $DIR/$tdir/$tfile || error "rm $tfile"

	touch $DIR/$tdir/$tfile || error "touch $tfile"
	cp $(which touch) $DIR/$tdir || error "cp touch"
	$RUNAS_CMD -u $ID0 $DIR/$tdir/touch $DIR/$tdir/$tfile &&
		error "touch should fail"
	setcap 'CAP_FOWNER=ep' $DIR/$tdir/touch || error "setcap CAP_FOWNER"
	$RUNAS_CMD -u $ID0 $DIR/$tdir/touch $DIR/$tdir/$tfile ||
		error "touch $tfile"
	rm $DIR/$tdir/$tfile || error "rm $tfile"

	local cap
	for cap in "CAP_DAC_OVERRIDE" "CAP_DAC_READ_SEARCH"; do
		touch $DIR/$tdir/$tfile || error "touch $tfile"
		chmod 600 $DIR/$tdir/$tfile || error "chmod $tfile"
		cp $(which cat) $DIR/$tdir || error "cp cat"
		$RUNAS_CMD -u $ID0 $DIR/$tdir/cat $DIR/$tdir/$tfile &&
			error "cat should fail"
		setcap $cap=ep $DIR/$tdir/cat || error "setcap $cap"
		$RUNAS_CMD -u $ID0 $DIR/$tdir/cat $DIR/$tdir/$tfile ||
			error "cat $tfile"
		rm $DIR/$tdir/$tfile || error "rm $tfile"
	done
}
run_test 51 "FS capabilities ==============="

test_52() {
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/$tfile
	local mirror1=$TMP/$tfile.mirror1
	local mirror2=$TMP/$tfile.mirror2

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	[[ $OSTCOUNT -lt 2 ]] && skip_env "needs >= 2 OSTs"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	dd if=/dev/urandom of=$tmpfile bs=5000 count=1 conv=fsync

	$LFS mirror create -N -i0 -N -i1 $testfile ||
		error "could not create mirror"

	dd if=$tmpfile of=$testfile bs=5000 count=1 conv=fsync ||
		error "could not write to $testfile"

	$LFS mirror resync $testfile ||
		error "could not resync mirror"

	$LFS mirror verify -v $testfile ||
		error "verify mirror failed"

	$LFS mirror read -N 1 -o $mirror1 $testfile ||
		error "could not read from mirror 1"

	cmp -bl $tmpfile $mirror1 ||
		error "mirror 1 is corrupted"

	$LFS mirror read -N 2 -o $mirror2 $testfile ||
		error "could not read from mirror 2"

	cmp -bl $tmpfile $mirror2 ||
		error "mirror 2 is corrupted"

	tr '\0' '2' < /dev/zero |
	    dd of=$tmpfile bs=1 count=9000 conv=fsync

	$LFS mirror write -N 1 -i $tmpfile $testfile ||
		error "could not write to mirror 1"

	$LFS mirror verify -v $testfile &&
		error "mirrors should be different"

	rm -f $tmpfile $mirror1 $mirror2
}
run_test 52 "Mirrored encrypted file"

test_53() {
	local testfile=$DIR/$tdir/$tfile
	local testfile2=$DIR2/$tdir/$tfile
	local tmpfile=$TMP/$tfile.tmp
	local resfile=$TMP/$tfile.res
	local pagesz
	local filemd5

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	pagesz=$(getconf PAGESIZE)
	[[ $pagesz == 65536 ]] || skip "Need 64K PAGE_SIZE client"

	do_node $mds1_HOST \
		"mount.lustre --help |& grep -q 'test_dummy_encryption:'" ||
			skip "need dummy encryption support on MDS client mount"

	# this test is probably useless now, but may turn out to be useful when
	# Lustre supports servers with PAGE_SIZE != 4KB
	pagesz=$(do_node $mds1_HOST getconf PAGESIZE)
	[[ $pagesz == 4096 ]] || skip "Need 4K PAGE_SIZE MDS client"

	stack_trap cleanup_for_enc_tests EXIT
	stack_trap "zconf_umount $mds1_HOST $MOUNT2" EXIT
	setup_for_enc_tests

	$LFS setstripe -c1 -i0 $testfile

	# write from 1st client
	cat /dev/urandom | tr -dc 'a-zA-Z0-9' |
		dd of=$tmpfile bs=$((pagesz+3)) count=2 conv=fsync
	dd if=$tmpfile of=$testfile bs=$((pagesz+3)) count=2 conv=fsync ||
		error "could not write to $testfile (1)"

	# read from 2nd client
	# mount and IOs must be done in the same shell session, otherwise
	# encryption key in session keyring is missing
	do_node $mds1_HOST "mkdir -p $MOUNT2"
	do_node $mds1_HOST \
		"$MOUNT_CMD -o ${MOUNT_OPTS},test_dummy_encryption \
		 $MGSNID:/$FSNAME $MOUNT2 && \
		 dd if=$testfile2 of=$resfile bs=$((pagesz+3)) count=2" ||
		error "could not read from $testfile2 (1)"

	# compare
	filemd5=$(do_node $mds1_HOST md5sum $resfile | awk '{print $1}')
	[ $filemd5 = $(md5sum $tmpfile | awk '{print $1}') ] ||
		error "file is corrupted (1)"
	do_node $mds1_HOST rm -f $resfile
	cancel_lru_locks

	# truncate from 2nd client
	$TRUNCATE $tmpfile $((pagesz+3))
	zconf_umount $mds1_HOST $MOUNT2 ||
		error "umount $mds1_HOST $MOUNT2 failed (1)"
	do_node $mds1_HOST "$MOUNT_CMD -o ${MOUNT_OPTS},test_dummy_encryption \
			   $MGSNID:/$FSNAME $MOUNT2 && \
			   $TRUNCATE $testfile2 $((pagesz+3))" ||
		error "could not truncate $testfile2 (1)"

	# compare
	cmp -bl $tmpfile $testfile ||
		error "file is corrupted (2)"
	rm -f $tmpfile $testfile
	cancel_lru_locks
	zconf_umount $mds1_HOST $MOUNT2 ||
		error "umount $mds1_HOST $MOUNT2 failed (2)"

	# do conversly
	do_node $mds1_HOST \
	      dd if=/dev/urandom of=$tmpfile bs=$((pagesz+3)) count=2 conv=fsync
	# write from 2nd client
	do_node $mds1_HOST \
	   "$MOUNT_CMD -o ${MOUNT_OPTS},test_dummy_encryption \
	    $MGSNID:/$FSNAME $MOUNT2 && \
	    dd if=$tmpfile of=$testfile2 bs=$((pagesz+3)) count=2 conv=fsync" ||
		error "could not write to $testfile2 (2)"

	# read from 1st client
	dd if=$testfile of=$resfile bs=$((pagesz+3)) count=2 ||
		error "could not read from $testfile (2)"

	# compare
	filemd5=$(do_node $mds1_HOST md5sum -b $tmpfile | awk '{print $1}')
	[ $filemd5 = $(md5sum -b $resfile | awk '{print $1}') ] ||
		error "file is corrupted (3)"
	rm -f $resfile
	cancel_lru_locks

	# truncate from 1st client
	do_node $mds1_HOST "$TRUNCATE $tmpfile $((pagesz+3))"
	$TRUNCATE $testfile $((pagesz+3)) ||
		error "could not truncate $testfile (2)"

	# compare
	zconf_umount $mds1_HOST $MOUNT2 ||
		error "umount $mds1_HOST $MOUNT2 failed (3)"
	do_node $mds1_HOST "$MOUNT_CMD -o ${MOUNT_OPTS},test_dummy_encryption \
			   $MGSNID:/$FSNAME $MOUNT2 && \
			   cmp -bl $tmpfile $testfile2" ||
		error "file is corrupted (4)"

	do_node $mds1_HOST rm -f $tmpfile
	rm -f $tmpfile
}
run_test 53 "Mixed PAGE_SIZE clients"

test_54() {
	local testdir=$DIR/$tdir/$ID0
	local testfile=$testdir/$tfile
	local testfile2=$testdir/${tfile}2
	local tmpfile=$TMP/${tfile}.tmp
	local resfile=$TMP/${tfile}.res

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	which fscrypt || skip "This test needs fscrypt userspace tool"

	fscrypt setup --force --verbose || error "fscrypt global setup failed"
	sed -i 's/\(.*\)policy_version\(.*\):\(.*\)\"[0-9]*\"\(.*\)/\1policy_version\2:\3"2"\4/' \
		/etc/fscrypt.conf
	fscrypt setup --verbose $MOUNT || error "fscrypt setup $MOUNT failed"
	mkdir -p $testdir
	chown -R $ID0:$ID0 $testdir

	echo -e 'mypass\nmypass' | su - $USER0 -c "fscrypt encrypt --verbose \
		--source=custom_passphrase --name=protector $testdir" ||
		error "fscrypt encrypt failed"

	echo -e 'mypass\nmypass' | su - $USER0 -c "fscrypt encrypt --verbose \
		--source=custom_passphrase --name=protector2 $testdir" &&
		error "second fscrypt encrypt should have failed"

	mkdir -p ${testdir}2 || error "mkdir ${testdir}2 failed"
	touch ${testdir}2/f || error "mkdir ${testdir}2/f failed"
	cancel_lru_locks

	echo -e 'mypass\nmypass' | fscrypt encrypt --verbose \
		--source=custom_passphrase --name=protector3 ${testdir}2 &&
		error "fscrypt encrypt on non-empty dir should have failed"

	$RUNAS dd if=/dev/urandom of=$testfile bs=127 count=1 conv=fsync ||
		error "write to encrypted file $testfile failed"
	cp $testfile $tmpfile
	$RUNAS dd if=/dev/urandom of=$testfile2 bs=127 count=1 conv=fsync ||
		error "write to encrypted file $testfile2 failed"
	$RUNAS mkdir $testdir/subdir || error "mkdir subdir failed"
	$RUNAS touch $testdir/subdir/subfile || error "mkdir subdir failed"

	$RUNAS fscrypt lock --verbose $testdir ||
		error "fscrypt lock $testdir failed (1)"

	$RUNAS ls -R $testdir || error "ls -R $testdir failed"
	local filecount=$($RUNAS find $testdir -type f | wc -l)
	[ $filecount -eq 3 ] || error "found $filecount files"

	$RUNAS hexdump -C $testfile &&
		error "reading $testfile should have failed without key"

	$RUNAS touch ${testfile}.nokey &&
		error "touch ${testfile}.nokey should have failed without key"

	echo mypass | $RUNAS fscrypt unlock --verbose $testdir ||
		error "fscrypt unlock $testdir failed (1)"

	$RUNAS cat $testfile > $resfile ||
		error "reading $testfile failed"

	cmp -bl $tmpfile $resfile || error "file read differs from file written"

	$RUNAS fscrypt lock --verbose $testdir ||
		error "fscrypt lock $testdir failed (2)"

	$RUNAS hexdump -C $testfile2 &&
		error "reading $testfile2 should have failed without key"

	echo mypass | $RUNAS fscrypt unlock --verbose $testdir ||
		error "fscrypt unlock $testdir failed (2)"

	rm -rf $testdir/*
	$RUNAS fscrypt lock --verbose $testdir ||
		error "fscrypt lock $testdir failed (3)"

	rm -f $tmpfile $resfile
}
run_test 54 "Encryption policies with fscrypt"

cleanup_55() {
	# unmount client
	if is_mounted $MOUNT; then
		umount_client $MOUNT || error "umount $MOUNT failed"
	fi

	do_facet mgs $LCTL nodemap_del c0
	do_facet mgs $LCTL nodemap_modify --name default \
		 --property admin --value 0
	do_facet mgs $LCTL nodemap_modify --name default \
		 --property trusted --value 0
	wait_nm_sync default admin_nodemap
	wait_nm_sync default trusted_nodemap

	do_facet mgs $LCTL nodemap_activate 0
	wait_nm_sync active 0

	if $SHARED_KEY; then
		export SK_UNIQUE_NM=false
	fi

	# remount client
	mount_client $MOUNT ${MOUNT_OPTS} || error "remount failed"
	if [ "$MOUNT_2" ]; then
		mount_client $MOUNT2 ${MOUNT_OPTS} || error "remount failed"
	fi
}

test_55() {
	local client_ip
	local client_nid

	mkdir -p $DIR/$tdir/$USER0/testdir_groups
	chown root:$ID0 $DIR/$tdir/$USER0
	chmod 770 $DIR/$tdir/$USER0
	chmod g+s $DIR/$tdir/$USER0
	chown $ID0:$ID0 $DIR/$tdir/$USER0/testdir_groups
	chmod 770 $DIR/$tdir/$USER0/testdir_groups
	chmod g+s $DIR/$tdir/$USER0/testdir_groups

	# unmount client completely
	umount_client $MOUNT || error "umount $MOUNT failed"
	if is_mounted $MOUNT2; then
		umount_client $MOUNT2 || error "umount $MOUNT2 failed"
	fi

	do_nodes $(comma_list $(all_mdts_nodes)) \
		$LCTL set_param mdt.*.identity_upcall=NONE

	stack_trap cleanup_55 EXIT

	do_facet mgs $LCTL nodemap_activate 1
	wait_nm_sync active

	do_facet mgs $LCTL nodemap_del c0 || true
	wait_nm_sync c0 id ''

	do_facet mgs $LCTL nodemap_modify --name default \
		--property admin --value 1
	do_facet mgs $LCTL nodemap_modify --name default \
		--property trusted --value 1
	wait_nm_sync default admin_nodemap
	wait_nm_sync default trusted_nodemap

	client_ip=$(host_nids_address $HOSTNAME $NETTYPE)
	client_nid=$(h2nettype $client_ip)
	do_facet mgs $LCTL nodemap_add c0
	do_facet mgs $LCTL nodemap_add_range \
		 --name c0 --range $client_nid
	do_facet mgs $LCTL nodemap_modify --name c0 \
		 --property admin --value 0
	do_facet mgs $LCTL nodemap_modify --name c0 \
		 --property trusted --value 1
	wait_nm_sync c0 admin_nodemap
	wait_nm_sync c0 trusted_nodemap

	if $SHARED_KEY; then
		export SK_UNIQUE_NM=true
		# set some generic fileset to trigger SSK code
		export FILESET=/
	fi

	# remount client to take nodemap into account
	zconf_mount_clients $HOSTNAME $MOUNT $MOUNT_OPTS ||
		error "remount failed"
	unset FILESET

	euid_access $USER0 $DIR/$tdir/$USER0/testdir_groups/file
}
run_test 55 "access with seteuid"

test_56() {
	local testfile=$DIR/$tdir/$tfile

	[[ $(facet_fstype ost1) == zfs ]] && skip "skip ZFS backend"

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	[[ $OSTCOUNT -lt 2 ]] && skip_env "needs >= 2 OSTs"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	$LFS setstripe -c1 $testfile
	dd if=/dev/urandom of=$testfile bs=1M count=3 conv=fsync
	filefrag -v $testfile || error "filefrag $testfile failed"
	(( $(filefrag -v $testfile | grep -c encrypted) >= 1 )) ||
		error "filefrag $testfile does not show encrypted flag"
	(( $(filefrag -v $testfile | grep -c encoded) >= 1 )) ||
		error "filefrag $testfile does not show encoded flag"
}
run_test 56 "FIEMAP on encrypted file"

test_57() {
	local testdir=$DIR/$tdir/mytestdir
	local testfile=$DIR/$tdir/$tfile

	[[ $(facet_fstype ost1) == zfs ]] && skip "skip ZFS backend"

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	mkdir $DIR/$tdir
	mkdir $testdir
	setfattr -n security.c -v myval $testdir &&
		error "setting xattr on $testdir should have failed (1)"
	touch $testfile
	setfattr -n security.c -v myval $testfile &&
		error "setting xattr on $testfile should have failed (1)"

	rm -rf $DIR/$tdir

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	mkdir $testdir
	setfattr -n security.c -v myval $testdir &&
		error "setting xattr on $testdir should have failed (2)"
	touch $testfile
	setfattr -n security.c -v myval $testfile &&
		error "setting xattr on $testfile should have failed (2)"
	return 0
}
run_test 57 "security.c xattr protection"

log "cleanup: ======================================================"

sec_unsetup() {
	for num in $(seq $MDSCOUNT); do
		if [ "${identity_old[$num]}" = 1 ]; then
			switch_identity $num false || identity_old[$num]=$?
		fi
	done

	$RUNAS_CMD -u $ID0 ls $DIR
	$RUNAS_CMD -u $ID1 ls $DIR
}
sec_unsetup

complete $SECONDS
check_and_cleanup_lustre
exit_status
