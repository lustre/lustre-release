#!/bin/bash
#set -x
EXPORT_OPTS=${EXPORT_OPTS:-"rw,async,no_root_squash"}

setup_nfs() {
	local NFS_VER=${1}
	local MNTPNT=${2}
	local LUSTRE_CLIENT=${3}
	local NFS_CLIENTS=${4}
	local nfs_climntpt=${5:-$MNTPNT}

    local export_opts_v=$EXPORT_OPTS

    echo "Exporting Lustre filesystem..."

    if [ "$NFS_VER" = "4" ]; then
        export_opts_v="$EXPORT_OPTS,fsid=0"
        do_nodes $LUSTRE_CLIENT "mkdir -p /var/lib/nfs/v4recovery"
    fi

    do_nodes $LUSTRE_CLIENT,$NFS_CLIENTS "grep -q rpc_pipefs' ' /proc/mounts ||\
        { mkdir -p /var/lib/nfs/rpc_pipefs && \
        mount -t rpc_pipefs sunrpc /var/lib/nfs/rpc_pipefs; }" || return 1
    sleep 5

	do_nodes $LUSTRE_CLIENT "chkconfig --list nfsserver > /dev/null 2>&1 &&
				 service nfsserver restart ||
				 service nfs restart" || return 1

	do_nodes $NFS_CLIENTS "chkconfig --list rpcidmapd 2>/dev/null |
			       grep -q rpcidmapd && service rpcidmapd restart ||
			       true"

    do_nodes $LUSTRE_CLIENT "exportfs -o $export_opts_v *:$MNTPNT \
        && exportfs -v" || return 1

    echo -e "\nMounting NFS clients (version $NFS_VER)..."

	do_nodes $NFS_CLIENTS "mkdir -p $nfs_climntpt" || return 1
	if [ "$NFS_VER" = "4" ]; then
		do_nodes $NFS_CLIENTS \
			"mount -t nfs$NFS_VER -o async \
			$LUSTRE_CLIENT:/ $nfs_climntpt" || return 1
	else
		do_nodes $NFS_CLIENTS \
			"mount -t nfs -o nfsvers=$NFS_VER,async \
			$LUSTRE_CLIENT:$MNTPNT $nfs_climntpt" || return 1
	fi
	return 0
}

cleanup_nfs() {
	local MNTPNT=${1}
	local LUSTRE_CLIENT=${2}
	local NFS_CLIENTS=${3}

	echo -e "\nUnmounting NFS clients..."
	do_nodes $NFS_CLIENTS "umount -f $MNTPNT" || true

	echo -e "\nUnexporting Lustre filesystem..."
	do_nodes $NFS_CLIENTS "chkconfig --list rpcidmapd 2>/dev/null |
			       grep -q rpcidmapd && service rpcidmapd stop ||
			       true"

	do_nodes $LUSTRE_CLIENT "chkconfig --list nfsserver > /dev/null 2>&1 &&
				 service nfsserver stop || service nfs stop" ||
				return 1

    do_nodes $LUSTRE_CLIENT "exportfs -u *:$MNTPNT"

    do_nodes $LUSTRE_CLIENT "exportfs -v"
}
