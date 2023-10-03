#!/bin/bash

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env "$@"

export ALWAYS_EXCEPT="$PARALLEL_SCALE_NFSV4_EXCEPT "
always_except LU-17154 racer_on_nfs

$LUSTRE/tests/parallel-scale-nfs.sh 4
