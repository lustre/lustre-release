#!/bin/bash

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env "$@"

export ALWAYS_EXCEPT="$PARALLEL_SCALE_NFSV3_EXCEPT "
always_except LU-16163 racer_on_nfs
$LUSTRE/tests/parallel-scale-nfs.sh 3
