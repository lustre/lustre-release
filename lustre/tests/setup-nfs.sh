#!/bin/bash

DEFAULT_NFS_OPTIONS=${DEFAULT_NFS_OPTIONS:-"rw,async,no_root_squash"}
DEFAULT_EXPORTS_FILE=${DEFAULT_EXPORTS_FILE:-"/etc/exports.d/lustre.exports"}

setup_nfs() {
	local LUSTRE_CLIENT=$1
	local LUSTRE_MOUNT_POINT=$2
	local NFS_CLIENTS=$3
	local NFS_MOUNT_POINT=$4
	local NFS_VERSION=$5
	local EXPORTS_FILE=$DEFAULT_EXPORTS_FILE
	local NFS_OPTIONS=$DEFAULT_NFS_OPTIONS

	echo "Exporting Lustre filesystem via NFS version $NFS_VERSION"
	do_nodes "$LUSTRE_CLIENT" \
		"echo '$LUSTRE_MOUNT_POINT *($NFS_OPTIONS)' | \
		tee $EXPORTS_FILE" || return 1
	do_nodes "$LUSTRE_CLIENT" "systemctl restart nfs-server" || return 1
	do_nodes "$LUSTRE_CLIENT" "systemctl restart nfs-idmapd" || return 1

	echo "Mounting NFS clients version $NFS_VERSION"
	do_nodes "$NFS_CLIENTS" "systemctl restart nfs-idmapd" || return 1
	do_nodes "$NFS_CLIENTS" "mkdir -p $NFS_MOUNT_POINT" || return 1
	do_nodes "$NFS_CLIENTS" \
		"mount -v -t nfs -o nfsvers=$NFS_VERSION,async \
		$LUSTRE_CLIENT:$LUSTRE_MOUNT_POINT \
		$NFS_MOUNT_POINT" || return 1

	return 0
}

cleanup_nfs() {
	local LUSTRE_CLIENT=$1
	local LUSTRE_MOUNT_POINT=$2
	local NFS_CLIENTS=$3
	local NFS_MOUNT_POINT=$4
	local EXPORTS_FILE=$DEFAULT_EXPORTS_FILE

	echo "Unmounting NFS clients"
	do_nodes "$NFS_CLIENTS" "umount -v -f $NFS_MOUNT_POINT" || return 1
	do_nodes "$NFS_CLIENTS" "systemctl stop nfs-idmapd" || return 1

	echo "Unexporting Lustre filesystem"
	do_nodes "$LUSTRE_CLIENT" "systemctl stop nfs-server" || return 1
	do_nodes "$LUSTRE_CLIENT" "systemctl stop nfs-idmapd" || return 1
	do_nodes "$LUSTRE_CLIENT" "rm -v $EXPORTS_FILE" || return 1
}
