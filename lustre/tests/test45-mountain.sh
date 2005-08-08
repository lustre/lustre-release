#!/bin/bash

export PATH="$PATH:`dirname $0`/../utils"

config=${1:-test45-mountain.xml}
LMC=${LMC:-lmc}
TMP=${TMP:-/tmp}

MDS_MASTER_DEV=/dev/mdtdev1_sh
OST_MASTER_DEV=/dev/ostdev1_sh

MDS_CACHE_DEV=$TMP/mds-cache-localhost
OST_CACHE_DEV=$TMP/ost-cache-localhost

MDSSIZE=${MDSSIZE:-200000}
OSTSIZE=${OSTSIZE:-200000}

FSTYPE=${FSTYPE:-smfs}
BACK_FSTYPE=${BACK_FSTYPE:-ldiskfs}

NETTYPE=${NETTYPE:-tcp}
NIDTYPE=${NIDTYPE:-$NETTYPE}

# define clients related stuff
for i in `seq 0 33`; do
    CLIENT[$i]="mnt$((i+3))"
    COBD_MDS[$i]="cobd_mds$((i+1))"
    CMOBD_MDS[$i]="cmobd_mds$((i+1))"
    CACHE_MDS[$i]="cache_mds$((i+1))"
    CACHE_OST[$i]="cache_ost$((i+1))"
    CACHE_LOV[$i]="cache_lov$((i+1))"
    CACHE_MDS_MOUNT_OPT[$i]="kml"
    CACHE_MDS_MKFS_OPT[$i]="-b 4096"
    CACHE_OST_MKFS_OPT[$i]="-b 4096"
done

CACHE_LOV_STRIPE_COUNT="1"
CACHE_LOV_STRIPE_SIZE="1048576"

# define MDS related stuff
for i in `seq 0 3`; do
    MDS[$i]="mnt$((i+51))"
    MASTER_MDS[$i]="master_mds$((i+1))"
    MASTER_MDS_MKFS_OPT[$i]="-b 4096"
done

MASTER_LMV="master_lmv"

# define OST related stuff
for i in `seq 0 7`; do
    OST[$i]="mnt$((i+61))"
    MASTER_OST[$i]="master_ost$((i+1))"
    MASTER_OST_MKFS_OPT[$i]="-b 4096"
done

MASTER_LOV="master_lov"
MASTER_LOV_STRIPE_COUNT="8"
MASTER_LOV_STRIPE_SIZE="1048576"

rm -f $config

h2tcp () {
	case $1 in
	client) echo '\*' ;;
	*) echo $1 ;;
	esac
}

# add OST nodes
echo "adding OST nodes..."
for node in "${OST[@]}"; do
    ${LMC} -m $config --add node --node $node || exit 1
    ${LMC} -m $config --add net --node $node --nid `h2$NIDTYPE $node` --nettype $NETTYPE || exit 1
done

# add master LMV
${LMC} -m $config --add lmv --lmv $MASTER_LMV || exit 2

# add master OSTs
echo "adding master OSTs..."
${LMC} -m $config --add lov --lov $MASTER_LOV --lmv $MASTER_LMV \
--stripe_sz $MASTER_LOV_STRIPE_SIZE --stripe_cnt $MASTER_LOV_STRIPE_COUNT \
--stripe_pattern 0 || exit 3

for ((i=0;i<${#MASTER_OST[@]};i++)); do
    ${LMC} -m $config --add ost --ost ${MASTER_OST[i]} --node ${OST[i]} --lov $MASTER_LOV \
--fstype $BACK_FSTYPE --dev $OST_MASTER_DEV --size $OSTSIZE --mkfsoptions "${MASTER_OST_MKFS_OPT[i]}" || exit 4
done

# add MDS nodes
echo "adding MDS nodes..."
for node in "${MDS[@]}"; do 
    ${LMC} -m $config --add node --node $node || exit 1
    ${LMC} -m $config --add net --node $node --nid `h2$NIDTYPE $node` --nettype $NETTYPE || exit 5
done

# add master MDSs
echo "adding master MDSs..."
for ((i=0;i<${#MASTER_MDS[@]};i++)); do
    ${LMC} -m $config --add mds --node ${MDS[i]} --mds ${MASTER_MDS[i]} \
--fstype $BACK_FSTYPE --dev $MDS_MASTER_DEV --size $MDSSIZE \
--lmv $MASTER_LMV --format --mkfsoptions "${MASTER_MDS_MKFS_OPT[i]}" || exit 6
done

# add client nodes
echo "adding client nodes..."
for node in "${CLIENT[@]}"; do 
    ${LMC} -m $config --add node --node $node || exit 1
    ${LMC} -m $config --add net --node $node --nid `h2$NIDTYPE $node` --nettype $NETTYPE || exit 7
done

# add cache stuff
echo "adding cache MDSs, OSTs and clients..."
for ((i=0;i<${#CACHE_MDS[@]};i++)); do
    ${LMC} -m $config --add mds --node ${CLIENT[i]} --mds ${CACHE_MDS[i]} \
--fstype $FSTYPE --backfstype $BACK_FSTYPE --dev $MDS_CACHE_DEV \
--mountfsoptions ${CACHE_MDS_MOUNT_OPT[i]} --mkfsoptions "${CACHE_MDS_MKFS_OPT[i]}" \
--size $MDSSIZE --format || exit 8

    ${LMC} -m $config --add cmobd --node ${CLIENT[i]} --cmobd ${CMOBD_MDS[i]} \
--master_obd $MASTER_LMV --cache_obd ${CACHE_MDS[i]} || exit 9

    ${LMC} -m $config --add lov --lov ${CACHE_LOV[i]} --mds ${CACHE_MDS[i]} \
--stripe_sz $CACHE_LOV_STRIPE_SIZE --stripe_cnt $CACHE_LOV_STRIPE_COUNT \
--stripe_pattern 0 || exit 10

    ${LMC} -m $config --add ost --ost ${CACHE_OST[i]} --node ${CLIENT[i]} \
--lov ${CACHE_LOV[i]} --fstype $BACK_FSTYPE --dev $OST_CACHE_DEV \
--size $OSTSIZE --mkfsoptions "${CACHE_OST_MKFS_OPT[i]}" || exit 11

    ${LMC} -m $config --add cobd --node ${CLIENT[i]} --cobd ${COBD_MDS[i]} \
--master_obd $MASTER_LMV --cache_obd ${CACHE_MDS[i]} || exit 12

    ${LMC} -m $config --add mtpt --node ${CLIENT[i]} --path /mnt/lustre \
--lmv ${COBD_MDS[i]} --lov ${CACHE_LOV[i]} || exit 13
done
