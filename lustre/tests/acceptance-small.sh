#!/bin/bash
#
# usage: acceptance-small.sh [test list]
#	if no tests are specified, they are taken from test-groups/regression
#	if {TEST_NAME}=no is set, that test script is skipped
DEFAULT_SUITES="${@:-$ACC_SM_ONLY}"
DEFAULT_SUITES="${DEFAULT_SUITES:-$(cat test-groups/regression)}"
for SUB in $DEFAULT_SUITES; do
	ENV=$(echo $SUB | tr "[:lower:]-" "[:upper:]_")
	[ "$(eval echo \$$ENV)" = "no" ] && continue
	SUITES="$SUITES $SUB"
done
sh auster -r -R -v -f ${NAME:-lustre} $SUITES
