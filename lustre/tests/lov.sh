#!/bin/bash

set -e

export PATH=`dirname $0`/../utils:$PATH

config=${1:-`basename $0 .sh`.xml}

LMC="${LMC:-lmc} -m $config"
TMP=${TMP:-/tmp}

HOSTNAME=`hostname`
MDSDEV=${MDSDEV:-$TMP/mds1-`hostname`}
MDSSIZE=${MDSSIZE:-400000}
FSTYPE=${FSTYPE:-ext3}
MOUNT=${MOUNT:-/mnt/lustre}
MOUNT2=${MOUNT2:-${MOUNT}2}
NETTYPE=${NETTYPE:-tcp}
[ "$ACCEPTOR_PORT" ] && PORT_OPT="--port $ACCEPTOR_PORT"

OSTCOUNT=${OSTCOUNT:-5}
# OSTDEVn will still override the device for OST n

OSTSIZE=${OSTSIZE:-150000}
# 1 to config an echo client instead of llite
ECHO_CLIENT=${ECHO_CLIENT:-}

STRIPE_BYTES=${STRIPE_BYTES:-1048576}
STRIPES_PER_OBJ=${STRIPES_PER_OBJ:-$((OSTCOUNT -1))}

MDS_MOUNT_OPTS="user_xattr,acl,${MDS_MOUNT_OPTS:-""}"
CLIENTOPT="user_xattr,acl,${CLIENTOPT:-""}"

# specific journal size for the ost, in MB
JSIZE=${JSIZE:-0}
JARG=""
[ "$JSIZE" -gt 0 ] && JARG="--journal_size $JSIZE"

rm -f $config

# create nodes
${LMC} --add node --node $HOSTNAME || exit 10
${LMC} --add net --node $HOSTNAME --nid $HOSTNAME \
    --nettype $NETTYPE $PORT_OPT || exit 11
${LMC} --add net --node client --nid '*' --nettype $NETTYPE $PORT_OPT || exit 12

[ "x$QUOTA_OPTS" != "x" ] &&
    QUOTA_OPTS="--quota $QUOTA_OPTS"

# configure mds server
[ "x$MDS_MOUNT_OPTS" != "x" ] &&
    MDS_MOUNT_OPTS="--mountfsoptions $MDS_MOUNT_OPTS"

${LMC} --format --add mds --node $HOSTNAME --mds mds1 --fstype $FSTYPE \
	--dev $MDSDEV $MDS_MOUNT_OPTS $QUOTA_OPTS --size $MDSSIZE $MDSOPT || exit 20

# configure ost
${LMC} --add lov --lov lov1 --mds mds1 --stripe_sz $STRIPE_BYTES \
	--stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0 $LOVOPT || exit 20

for num in `seq $OSTCOUNT`; do
    OST=ost$num
    DEVPTR=OSTDEV$num
    eval $DEVPTR=${!DEVPTR:=$TMP/$OST-`hostname`}
    ${LMC} --add ost --node $HOSTNAME --lov lov1 --ost $OST --fstype $FSTYPE \
    	--dev ${!DEVPTR} --size $OSTSIZE $JARG $OSTOPT $QUOTA_OPTS|| exit 30
done


if [ -z "$ECHO_CLIENT" ]; then
	# create client config
	[ "x$CLIENTOPT" != "x" ] && CLIENTOPT="--clientoptions $CLIENTOPT"
	${LMC} --add mtpt --node $HOSTNAME --path $MOUNT \
		--mds mds1 --lov lov1 $CLIENTOPT || exit 40
	${LMC} --add mtpt --node client --path $MOUNT2 \
		--mds mds1 --lov lov1 $CLIENTOPT || exit 41
else
	${LMC} --add echo_client --node $HOSTNAME --ost lov1 || exit 42
fi
