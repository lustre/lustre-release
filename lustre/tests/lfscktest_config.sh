export TESTNAME="lfscktest"
export TESTDESC="Test of lfsck functionality"

export LUSTRE=${LUSTRE:-"../.."}
export LCONF=${LCONF:-"$LUSTRE/utils/lconf"}
export LMC=${LMC:-"$LUSTRE/utils/lmc"}
export LCTL=${LCTL:-"$LUSTRE/utils/lctl"}
export LFIND=${LFIND:-"$LUSTRE/utils/lfind"}
export E2FSCK_PATH=${E2FSCK_PATH:-"/usr/src/e2fsprogs-1.34"}
export TMP=${TMP:-"/tmp"}
export CONFIG=${CONFIG:-"./lfsck_config.sh"}
export LOG=${LOG:-"${TMP}/lfscktest.log"}
export CONFIGXML=${CONFIGXML:-"./lfsck_config.xml"}
export LUSTRE_TAG=${LUSTRE_TAG:="HEAD"}
export MACHINENAME=`hostname | sed -e 's/[0-9]\+//'`
export TESTGROUP=${TESTGROUP:-"unspecified"}
export CONFIGDESC=${CONFIGDESC:-"local"}
export TESTARCH=${TESTARCH:-`uname -m`}
export NETTYPE=${NETTYPE:-"tcp"}
export MDSDEV=${MDSDEV:-$TMP/mds1-`hostname`}
export MDSNODES=${MDSNODES:-`hostname`}
export OSTDEV=${OSTDEV:-$TMP/ost1-`hostname`}
export OSTNODES=${OSTNODES:-`hostname`}
export CLIENTNODES=${CLIENTNODES:-`hostname`}
export RECIPIENTS=${RECIPIENTS:-"liam.kelleher@hp.com"}
export SENDER=${SENDER:-"liam.kelleher@hp.com"}
export NUM_OSTS=${NUM_OSTS:-5}
export DEBUGFS=${DEBUGFS:-"debugfs"}

export GPATH=`pwd`
export OST_UUID="OST_localhost_2_UUID"

export MDS_MOUNTPT="/mnt/mds_${TESTNAME}"
export OST_MOUNTPT="/mnt/ost_${TESTNAME}"
export MOUNT="/mnt/lustre"
export TEST_DIR="${MOUNT}/${TESTNAME}"
