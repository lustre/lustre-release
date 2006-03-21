#!/bin/bash

export PATH=`dirname $0`/../utils:$PATH

config=${1:-`basename $0 .sh`.xml}

LMC=echo 
TMP=${TMP:-/tmp}

FSNAME=lustre
HOSTNAME=`hostname`
MDSDEV=${MDSDEV:-$TMP/mdt-${FSNAME}}
MDSSIZE=${MDSSIZE:-400000}
MOUNT=${MOUNT:-/mnt/${FSNAME}}
MOUNT2=${MOUNT2:-${MOUNT}2}
NETTYPE=${NETTYPE:-tcp}
[ "$ACCEPTOR_PORT" ] && PORT_OPT="--port $ACCEPTOR_PORT"

OSTDEV=${OSTDEV:-$TMP/ost0-${FSNAME}}
OSTSIZE=${OSTSIZE:-400000}
OSTDEV2=${OSTDEV2:-$TMP/ost1-${FSNAME}}

MDS_MOUNT_OPTS="user_xattr,acl,${MDS_MOUNT_OPTS:-""}"
CLIENTOPT="user_xattr,acl,${CLIENTOPT:-""}"

# specific journal size for the ost, in MB
JSIZE=${JSIZE:-0}
[ "$JSIZE" -gt 0 ] && OST_MKFS_OPTS=$OST_MKFS_OPTS" -J size=$JSIZE"
MDSISIZE=${MDSISIZE:-0}
[ "$MDSISIZE" -gt 0 ] && MDS_MKFS_OPTS=$MDS_MKFS_OPTS" -i $MDSISIZE"

STRIPE_BYTES=${STRIPE_BYTES:-1048576}
STRIPES_PER_OBJ=1	# 0 means stripe over all OSTs

rm -f $config

h2tcp () {
	case $1 in
	client) echo '\*' ;;
	*) echo $1 ;;
	esac
}

h2elan () {
	case $1 in
	client) echo '\*' ;;
	*) echo $1 | sed "s/[^0-9]*//" ;;
	esac
}

h2gm () {
	echo `gmlndnid -n$1`
}

h2iib () {
	case $1 in
	client) echo '\*' ;;
	*) echo $1 | sed "s/[^0-9]*//" ;;
	esac
}

MGSNID=`h2$NETTYPE $HOSTNAME`

# configure mds server
[ "x$MDS_MOUNT_OPTS" != "x" ] &&
    MDS_MOUNT_OPTS="--mountfsoptions=$MDS_MOUNT_OPTS"
[ "x$MDS_MKFS_OPTS" != "x" ] &&
    MDS_MOUNT_OPTS="--mkfsoptions=\"$MDS_MOUNT_OPTS\""
[ "x$QUOTA_OPTS" != "x" ] &&
    QUOTA_OPTS="--quota $QUOTA_OPTS"
[ ! -z "$mdsfailover_HOST" ] && MDS_FAIL_OPT="--failnode=$mdsfailover_HOST"    

MDS_OPTS="--mgs $MDS_FAIL_OPT --device-size=$MDSSIZE $MDS_MOUNT_OPTS $MDS_MKFS_OPTS"
echo mkfs.lustre --mdt $MDS_OPTS --reformat $MDSDEV

[ "x$OST_MOUNT_OPTS" != "x" ] &&
    OST_MOUNT_OPTS="--mountfsoptions=$OST_MOUNT_OPTS"
[ "x$OST_MKFS_OPTS" != "x" ] &&
    OST_MOUNT_OPTS="--mkfsoptions=\"$OST_MOUNT_OPTS\""

OST_OPTS="--mgsnode=`h2$NETTYPE $HOSTNAME` $OST_FAIL_OPT --device-size=$OSTSIZE $OST_MOUNT_OPTS $OST_MKFS_OPTS"
echo mkfs.lustre --ost $OST_OPTS --reformat $OSTDEV

OST2_OPTS="--mgsnode=`h2$NETTYPE $HOSTNAME` $OST_FAIL_OPT --device-size=$OSTSIZE $OST_MOUNT_OPTS $OST_MKFS_OPTS"
echo mkfs.lustre --ost $OST2_OPTS --reformat $OSTDEV2

