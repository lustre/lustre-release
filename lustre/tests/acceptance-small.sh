#!/bin/bash
#
# usage: acceptance-small.sh [test list]
#	if no tests are specified, they are taken from test-groups/regression
#	if {TEST_NAME}=no is set, that test script is skipped
DEFAULT_SUITES="${*:-$ACC_SM_ONLY}"
DEFAULT_SUITES="${DEFAULT_SUITES:-$(cat "$LUSTRE/tests/test-groups/regression")}"

for SUB in $DEFAULT_SUITES; do
	ENV=${SUB^^}
	ENV=${ENV//-/_}
	[[ "${!ENV}" != "no" ]] || continue
	SUITES="$SUITES $SUB"
done

echo "SUITES: $SUITES"

./auster -r -R -v -f "${NAME:-lustre}" $SUITES
