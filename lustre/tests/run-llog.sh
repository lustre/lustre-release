#!/bin/bash

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@

TMP=${TMP:-/tmp}

set -x
MGS=$($LCTL dl | awk '/mgs/ { print $4 }')
[ -z "$MGS" ] && echo "$0: SKIP: no MGS available, skipping llog test" && exit 0

load_module obdclass/llog_test || exit 1
$LCTL modules > $TMP/ogdb-$(hostname)
echo "NOW reload debugging syms.."

RC=0
# Using ignore_errors will allow lctl to cleanup even if the test fails.
eval "$LCTL <<-EOF || RC=2
	attach llog_test llt_name llt_uuid
	ignore_errors
	setup $MGS
	device llt_name
	cleanup
	detach
EOF"
rmmod -v llog_test || RC2=3
[ $RC -eq 0 -a "$RC2" ] && RC=$RC2

exit $RC
