#!/bin/bash

set -e

export PATH=`dirname $0`/../utils:$PATH

config=${1:-lmv.xml}

LMC=${LMC:-lmc}
TMP=${TMP:-/r/tmp}

MDSSIZE=${MDSSIZE:-100000}
FSTYPE=${FSTYPE:-ext3}
MDSCOUNT=${MDSCOUNT:-2}
NODECOUNT=${NODECOUNT:-3}

OSTDEV=${OSTDEV:-$TMP/ost1-`hostname`}
OSTSIZE=${OSTSIZE:-200000}

# 1 to config an echo client instead of llite
ECHO_CLIENT=${ECHO_CLIENT:-}

STRIPE_BYTES=65536
STRIPES_PER_OBJ=0

MOUNT=${MOUNT:-/mnt/lustre}

# specific journal size for the ost, in MB
JSIZE=${JSIZE:-0}
JARG=""
[ "$JSIZE" -gt 0 ] && JARG="--journal_size $JSIZE"

rm -f $config

upcall="/r/home/umka/work/cfs/lustre/tests/upcall"

# configuring nodes
nodes_with_client=$NODECOUNT
if test $NODECOUNT -le 2; then
        let nodes_with_client=nodes_with_client+1
fi

for nodenum in `seq $nodes_with_client`; do 
        options=""
        nodename=uml$nodenum
        
#        if test $nodenum -eq $nodes_with_client; then
#                options="--lustre_upcall $upcall"
#        fi
        
        ${LMC} -m $config --add node --node $nodename || exit 10
        ${LMC} -m $config --add net --node $nodename --nid $nodename \
        --nettype tcp $options || exit 11
done

# configuring metadata bits
${LMC} -m $config --add lmv --lmv lmv1 || exit 12

fonum=1

for nodenum in `seq $NODECOUNT`; do
        nodename=uml$nodenum
        for mdsnum in `seq $MDSCOUNT`; do
                options=""
                mdsid=mds$mdsnum
                
                if test $mdsnum -le 2 && test $nodenum -le 2; then
                        mdsname="$nodename-$mdsid"
                        mdsdev=$TMP/$nodename-$mdsid
                else
                        options="--failover"
                        mdsname="failover$fonum"
                        mdsdev="$TMP/failover$fonum"
                        let fonum=fonum+1
                fi
                
                ${LMC} -m $config --format --add mds --node $nodename \
                --mds $mdsname --lmv lmv1 --fstype $FSTYPE --dev $mdsdev \
                --size $MDSSIZE $options || exit 13
        done
done

# configuring object storage bits
${LMC} -m $config --add lov --lmv lmv1 --lov lov1 --stripe_sz $STRIPE_BYTES --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0 || exit 20
${LMC} -m $config --add ost --ost ost1 --nspath /mnt/ost_ns --node uml2 --lov lov1 --fstype $FSTYPE --dev $OSTDEV --size $OSTSIZE $JARG || exit 30

# configuring client
${LMC} -m $config --add mtpt --node uml3 --path $MOUNT --lmv lmv1 --lov lov1 || exit 40
