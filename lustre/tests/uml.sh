#!/bin/bash

config=${1-uml.xml}
LMC=${LMC-../utils/lmc}
TMP=${TMP:-/tmp}

MDSDEV=$TMP/mds1
MDSSIZE=50000

OSTDEV1=$TMP/ost1
OSTDEV2=$TMP/ost2
OSTSIZE=100000

# NOTE - You can't have different MDS/OST nodes and also have clients on the
#        MDS/OST nodes without using --endlevel and --startlevel during lconf.
#        You can put both MDS/OST on one node and client can be there too.
#        CLIENTS is a space-separated list of client nodes.
#
#        The rule is that both the MDS and the OST must be set up before any
#        of the clients can be started, so plan accordingly.

# Three separate systems
MDSNODE=uml1
OSTNODE=uml2
CLIENTS="uml3"

# Single system with additional clients
#MDSNODE=uml1
#OSTNODE=uml1
#CLIENTS="$MDSNODE client"

# Two systems with client on MDS, and additional clients (set up OST first)
#MDSNODE=uml1
#OSTNODE=uml2
#CLIENTS="$MDSNODE client"

# Two systems with client on OST, and additional clients (set up MDS first)
#MDSNODE=uml1
#OSTNODE=uml2
#CLIENTS="$OSTNODE client"

rm -f $config

# create nodes
for NODE in $MDSNODE $OSTNODE $CLIENTS; do
	eval [ \$$NODE ] && continue
	${LMC} -m $config --add net --node $NODE --nid $NODE --nettype tcp || exit 1
	eval "$NODE=done"
done

# configure mds server
${LMC} -m $config --add mds --format --node $MDSNODE --mds mds1 --dev $MDSDEV --size $MDSSIZE ||exit 10

# configure ost
${LMC} -m $config --add lov --lov lov1 --mds mds1 --stripe_sz 65536 --stripe_cnt 0 --stripe_pattern 0 || exit 20
${LMC} -m $config --add ost --node $OSTNODE --lov lov1 --dev $OSTDEV1 --size $OSTSIZE || exit 21
${LMC} -m $config --add ost --node $OSTNODE --lov lov1 --dev $OSTDEV2 --size $OSTSIZE || exit 22

# create client config(s)
for NODE in $CLIENTS; do
	${LMC} -m $config --add mtpt --node $NODE --path /mnt/lustre --mds mds1 --lov lov1 || exit 30
done

