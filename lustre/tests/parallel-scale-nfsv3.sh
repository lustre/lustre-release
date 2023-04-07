#!/bin/bash

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@

export ALWAYS_EXCEPT="$PARALLEL_SCALE_NFSV3_EXCEPT "
# Bug number for skipped test: LU-16163
ALWAYS_EXCEPT+="               racer_on_nfs "
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

$LUSTRE/tests/parallel-scale-nfs.sh 3
