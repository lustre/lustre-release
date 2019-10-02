#!/bin/bash

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@

sh $LUSTRE/tests/parallel-scale-nfs.sh 3
