export TESTNAME="lfscktest"
export TESTDESC="Test of lfsck functionality"

export LUSTRE=${LUSTRE:-".."}
export LCONF=${LCONF:-"$LUSTRE/utils/lconf"}
export LMC=${LMC:-"$LUSTRE/utils/lmc"}
export LCTL=${LCTL:-"$LUSTRE/utils/lctl"}
export LFIND=${LFIND:-"$LUSTRE/utils/lfind"}

export LFSCK_PATH=${E2FSCK_PATH:-"/home/yangjun/e2fsprogs-1.35.lfsck2/build/e2fsck"}
export TMP=${TMP:-"/tmp"}
export LOG=${LOG:-"${TMP}/lfscktest.log"}
export LUSTRE_TAG=${LUSTRE_TAG:="HEAD"}

export GPATH=`pwd`
export OST_UUID="OST_localhost_2_UUID"

export MDS_MOUNTPT="/mnt/mds_${TESTNAME}"
export OST_MOUNTPT="/mnt/ost_${TESTNAME}"
export MOUNT="/mnt/lustre"
export TEST_DIR="${MOUNT}/${TESTNAME}"
export MDSDEV=${MDSDEV:-$TMP/mds1-`hostname`}
export NUM_OSTS=${NUM_OSTS:-1}
