#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#
# lustre/tests/run-llog.sh
#
# Script to run the llog_test unit tests
#

LUSTRE=${LUSTRE:-$(dirname "$0")/..}
. "$LUSTRE/tests/test-framework.sh"
init_test_env "$@"

TMP=${TMP:-/tmp}

set -x
MGS=$($LCTL dl | awk '/mgs/ { print $4 }')
[ -z "$MGS" ] && echo "$0: SKIP: no MGS available, skipping llog test" && exit 0

load_module obdclass/llog_test || exit 1
$LCTL modules > "$TMP/ogdb-$(hostname)"
echo "NOW reload debugging syms.."

RC=0

# Using ignore_errors will allow lctl to cleanup even if the test fails.
eval "$LCTL <<-EOF || RC=2
	attach llog_test llt_name llt_uuid
	ignore_errors
	setup $MGS
	--device llt_name cleanup
	--device llt_name detach
EOF"

$LCTL dl

rmmod -v llog_test || RC2=3
[ $RC -eq 0 ] && [ "$RC2" ] && RC=$RC2

exit $RC
