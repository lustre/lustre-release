export TESTNAME="lfscktest"
export TESTDESC="Test of lfsck functionality"

export LFSCK_PATH=${E2FSCK_PATH:-"/usr/src/e2fsprogs-1.34"}
export TMP=${TMP:-"/tmp"}
export LOG=${LOG:-"${TMP}/lfscktest.log"}
export LUSTRE_TAG=${LUSTRE_TAG:="HEAD"}

export GPATH=`pwd`
export OST_UUID="OST_localhost_2_UUID"

export MDS_MOUNTPT="/mnt/mds_${TESTNAME}"
export OST_MOUNTPT="/mnt/ost_${TESTNAME}"
export MOUNT="/mnt/lustre"
export TEST_DIR="${MOUNT}/${TESTNAME}"
