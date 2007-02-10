#!/bin/sh -vx

set -e

export PATH=`dirname $0`/../utils:$PATH

config=${1:-`basename $0 .sh`.xml}

BATCH=/tmp/lmc-batch.$$
save_cmd() {
    echo "$@" >> $BATCH
}

LMC_REAL="${LMC:-lmc} -m $config"
LMC="save_cmd"

TMP=${TMP:-/tmp}

MOUNT=${MOUNT:-/mnt/lustre}

STRIPE_BYTES=$((1024*1024))
STRIPES_PER_OBJ=1

# specific journal size for the ost, in MB
JSIZE=${JSIZE:-0}
JARG=""
[ "$JSIZE" -gt 0 ] && JARG="--journal_size $JSIZE"

MDSNODE=${MDSNODE:-srv1}
MDSDEV=${MDSDEV:-$TMP/mds1-$MDSNODE}
MDSSIZE=${MDSSIZE:-400000}
OSTNODES=${OSTNODES:-"srv2 srv3 srv2 srv3"}
OSTSIZE=${OSTSIZE:-150000}
# OSTDEVN will still override the device for OST N
OSTFAILOVER=${OSTFAILOVER:---failover}
ROUTERS=${ROUTERS:-"cli1 cli2"}
CLIENT_NETTYPE=elan
CLIENT_CLUSTER=${CLIENT_CLUSTER:-0x0000}
CLIENT_LO=${CLIENT_LO:-cli3}
CLIENT_HI=${CLIENT_HI:-cli4}
CLIENTS=${CLIENTS:-client}
SERVER_NETTYPE=tcp
SERVER_CLUSTER=${SERVER_CLUSTER:-0x1000}
FSNAME=fs1

h2tcp () {
	case $1 in
	client) echo '\*' ;;
	*) echo $1 ;;
	esac
}

h2elan () { # assumes node names of the form fooN, where N is elan node ID
	case $1 in
	client) echo '\*' ;;
	*) echo $1 | sed "s/[^0-9]*//" ;;
	esac
}

rm -f $config $BATCH

# MDSNODE
echo; echo -n "adding MDS on: $MDSNODE"
eval "NODE$MDSNODE=y"
$LMC --add net --node $MDSNODE --nid `h2$SERVER_NETTYPE $MDSNODE` \
	--nettype $SERVER_NETTYPE --cluster_id $SERVER_CLUSTER
$LMC --add mds --node $MDSNODE --mds mds-$FSNAME --dev $MDSDEV $MDSOPT  \
	--size $MDSSIZE
$LMC --add lov --lov lov-$FSNAME --mds mds-$FSNAME --stripe_sz $STRIPE_BYTES \
	--stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
# MDS route to elan client
for R in $ROUTERS; do
	echo -n " [r=$R]"
	$LMC --node $MDSNODE --add route --nettype $SERVER_NETTYPE	\
		--gw `h2$CLIENT_NETTYPE $R` 				\
		--lo `h2$CLIENT_NETTYPE $CLIENT_LO`			\
		--hi `h2$CLIENT_NETTYPE $CLIENT_HI`			\
		--gateway_cluster_id $SERVER_CLUSTER			\
		--target_cluster_id $SERVER_CLUSTER
done

# OSTNODE
COUNT=1
for OSTNODE in $OSTNODES; do
	OST=ost$COUNT
	eval OSTDEV=\$OSTDEV$COUNT
	if [ -z "$OSTDEV" ]; then
		eval OSTDEV=${!OSTDEV:=$TMP/$OST-$OSTNODE}
	fi
	DEV=`basename $OSTDEV`
	echo; echo -n "adding OST on: $OSTNODE[$DEV]"
	if [ "`eval echo \\$NODE$OSTNODE`" != "y" ]; then
		$LMC --add net --node $OSTNODE --nid $OSTNODE		\
			--nettype $SERVER_NETTYPE --cluster_id $SERVER_CLUSTER
		# OST route to elan clients
		for R in $ROUTERS; do
			echo -n " [r=$R]"
			$LMC --node $OSTNODE --add route 		\
				--nettype $SERVER_NETTYPE		\
				--gw `h2$CLIENT_NETTYPE $R`		\
				--lo `h2$CLIENT_NETTYPE $CLIENT_LO`	\
				--hi `h2$CLIENT_NETTYPE $CLIENT_HI`	\
				--gateway_cluster_id $SERVER_CLUSTER	\
				--target_cluster_id $SERVER_CLUSTER
		done
		eval "NODE$OSTNODE=y"
	fi

	$LMC --add ost --node $OSTNODE --ost ost-$FSNAME-$OSTNODE-$DEV	\
		--lov lov-$FSNAME $OSTFAILOVER --dev $OSTDEV --size $OSTSIZE \
		$OSTOPT
	COUNT=`expr $COUNT + 1`
done

# ROUTER
echo; echo -n "adding ROUTER on: "
for ROUTER in $ROUTERS; do
	echo -n " $ROUTER"
	$LMC --node $ROUTER --add net --nid `h2$CLIENT_NETTYPE $ROUTER`	\
		--cluster_id $SERVER_CLUSTER --nettype $SERVER_NETTYPE	\
		--hostaddr $ROUTER --router
	$LMC --node $ROUTER --add net --nid `h2$CLIENT_NETTYPE $ROUTER`	\
		--cluster_id $CLIENT_CLUSTER --nettype $CLIENT_NETTYPE 	\
		--router
	# ROUTER route to OSTs and MDS
	for NODE in `echo $MDSNODE $OSTNODES | tr -s " " "\n" | sort -u`; do
		$LMC --node $ROUTER --add route 			\
			--nettype $SERVER_NETTYPE			\
			--gw `h2$CLIENT_NETTYPE $ROUTER` 		\
			--lo `h2$SERVER_NETTYPE $NODE`			\
			--gateway_cluster_id $SERVER_CLUSTER 		\
			--target_cluster_id $SERVER_CLUSTER
	done
	# ROUTER route to clients
	$LMC --node $ROUTER --add route --nettype $CLIENT_NETTYPE 	\
		--gw `h2$CLIENT_NETTYPE $ROUTER` 			\
		--lo `h2$CLIENT_NETTYPE $CLIENT_LO`			\
		--hi `h2$CLIENT_NETTYPE $CLIENT_HI`			\
		--gateway_cluster_id $CLIENT_CLUSTER 			\
		--target_cluster_id $CLIENT_CLUSTER
done

# CLIENT
echo; echo -n "adding CLIENT on: "
for CLIENT in $CLIENTS; do
	echo -n " $CLIENT"
	$LMC --node $CLIENT --add net --nid `h2$CLIENT_NETTYPE $CLIENT`	\
		--cluster_id $CLIENT_CLUSTER --nettype $CLIENT_NETTYPE
	$LMC --node $CLIENT --add mtpt --path $MOUNT --mds mds-$FSNAME	\
		--lov lov-$FSNAME $CLIENTOPT
done
echo

set -vx
echo "generating config $config from $BATCH"
$LMC_REAL --batch $BATCH
