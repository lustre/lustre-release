#!/bin/bash

export PATH=`dirname $0`/../utils:$PATH

config=${1:-uml.xml}
LMC=${LMC:-lmc}
TMP=${TMP:-/tmp}

MDSDEV=${MDSDEV:-$TMP/mds1}
MDSSIZE=${MDSSIZE:-50000}

OSTDEVBASE=$TMP/ost
#OSTDEV1=${OSTDEV1:-${OSTDEVBASE}1}
#OSTDEV2=${OSTDEV2:-${OSTDEVBASE}2}
#etc
OSTSIZE=${OSTSIZE:-100000}
STRIPECNT=${STRIPECNT:-1}

FSTYPE=${FSTYPE:-ext3}

NETTYPE=${NETTYPE:-tcp}

# NOTE - You can't have different MDS/OST nodes and also have clients on the
#        MDS/OST nodes without using --endlevel and --startlevel during lconf.
#        You can put both MDS/OST on one node and client can be there too.
#        CLIENTS is a space-separated list of client nodes.
#
#        The rule is that both the MDS and the OST must be set up before any
#        of the clients can be started, so plan accordingly.

# Three separate systems
MDSNODE=${MDSNODE:-uml1}
OSTNODES=${OSTNODES:-"uml2 uml2"}
CLIENTS=${CLIENTS:-"uml3"}

# Single system with additional clients
#MDSNODE=uml1
#OSTNODES="uml1 uml1"
#CLIENTS="$MDSNODE client"

# Two systems with client on MDS, and additional clients (set up OST first)
#MDSNODE=uml1
#OSTNODES="uml2 uml2"
#CLIENTS="$MDSNODE client"

# Two systems with client on OST, and additional clients (set up MDS first)
#MDSNODE=uml1
#OSTNODES="uml2 uml2"
#CLIENTS="$OSTNODES client"

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

# create nodes
echo -n "adding NET for:"
for NODE in `echo $MDSNODE $OSTNODES $CLIENTS | tr -s " " "\n" | sort -u`; do
	echo -n " $NODE"
	${LMC} -m $config --add net --node $NODE --nid `h2$NETTYPE $NODE` --nettype $NETTYPE || exit 1
done

# configure mds server
echo; echo "adding MDS on: $MDSNODE"
${LMC} -m $config --add mds --format --node $MDSNODE --mds mds1 --fstype $FSTYPE --dev $MDSDEV --size $MDSSIZE ||exit 10

# configure ost
${LMC} -m $config --add lov --lov lov1 --mds mds1 --stripe_sz 65536 --stripe_cnt $STRIPECNT --stripe_pattern 0 || exit 20
COUNT=1
echo -n "adding OST on:"
for NODE in $OSTNODES; do
	eval OSTDEV=\$OSTDEV$COUNT
	echo -n " $NODE"
	OSTDEV=${OSTDEV:-$OSTDEVBASE$COUNT}
        ${LMC} -m $config --add ost --node $NODE --lov lov1 --fstype $FSTYPE --dev $OSTDEV --size $OSTSIZE || exit 21
	COUNT=`expr $COUNT + 1`
done

# create client config(s)
echo; echo -n "adding CLIENT on:"
for NODE in $CLIENTS; do
	echo -n " $NODE"
	${LMC} -m $config --add mtpt --node $NODE --path /mnt/lustre --mds mds1 --lov lov1 || exit 30
done
echo
