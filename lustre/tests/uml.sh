#!/bin/bash

export PATH=`dirname $0`/../utils:$PATH

config=${1:-uml.xml}
LMC=${LMC:-lmc}
TMP=${TMP:-/tmp}

#MDSDEV=${MDSDEV:-$TMP/mds1-`hostname`}
MDSDEV=${MDSDEV:-/r/work/backup/tmp/mds1-`hostname`}
MDSSIZE=${MDSSIZE:-1000000}

#OSTDEVBASE=$TMP/ost
OSTDEVBASE=/r/work/backup/tmp/ost
#OSTDEV1=${OSTDEV1:-${OSTDEVBASE}1}
#OSTDEV2=${OSTDEV2:-${OSTDEVBASE}2}
#etc
OSTSIZE=${OSTSIZE:-1000000}
STRIPECNT=${STRIPECNT:-1}
OSDTYPE=${OSDTYPE:-obdfilter}
OSTFAILOVER=${OSTFAILOVER:-}

FSTYPE=${FSTYPE:-ext3}

NETTYPE=${NETTYPE:-tcp}
NIDTYPE=${NIDTYPE:-$NETTYPE}

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

h2localhost () {
	echo localhost
}
	
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
	echo `gmnalnid -n$1`
}

# create nodes
echo -n "adding NET for:"
for NODE in `echo $MDSNODE $OSTNODES $CLIENTS | tr -s " " "\n" | sort -u`; do
	echo -n " $NODE"
	${LMC} -m $config --add net --node $NODE --nid `h2$NIDTYPE $NODE` --nettype $NETTYPE || exit 1
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
	OSTDEV=${OSTDEV:-$OSTDEVBASE$COUNT-`hostname`}
	case "$OSDTYPE" in
		obdfilter)
			OSTARGS="--fstype $FSTYPE --dev $OSTDEV --size $OSTSIZE"
			;;
		obdecho)
			OSTARGS="--osdtype=obdecho"
			;;
	esac
        ${LMC} -m $config --add ost --node $NODE --lov lov1 $OSTARGS $OSTFAILOVER || exit 21
	COUNT=`expr $COUNT + 1`
done

# create client config(s)
echo; echo -n "adding CLIENT on:"
for NODE in $CLIENTS; do
	echo -n " $NODE"
	${LMC} -m $config --add mtpt --node $NODE --path /mnt/lustre --mds mds1 --lov lov1 || exit 30
done
echo
