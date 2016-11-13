#!/bin/bash
trap 'kill $(jobs -p)' EXIT

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/../..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

while /bin/true; do
	lsnapshot_create -n lss_$RANDOM || true
	sleep $((RANDOM % 9 + 11))
done
