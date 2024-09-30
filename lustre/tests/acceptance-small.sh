#!/bin/bash
#
# usage: acceptance-small.sh [test list]
#	if no tests are specified, they are taken from test-groups/regression
#	if {TEST_NAME}=no is set, that test script is skipped
LUSTRE=${LUSTRE:-$(dirname $0)/..}
NAME=${NAME:-local} # name of config file eg lustre/tests/cfg/local.sh
DEFAULT_SUITES="${*:-$ACC_SM_ONLY}"
DEFAULT_SUITES="${DEFAULT_SUITES:-$(cat "$LUSTRE/tests/test-groups/regression")}"
AUSTER=$LUSTRE/tests/auster

for SUB in $DEFAULT_SUITES; do
	ENV=${SUB^^}
	ENV=${ENV//-/_}
	[[ "${!ENV}" != "no" ]] || continue
	SUITES="$SUITES $SUB"
done

echo "SUITES: $SUITES"

# check config file is available
if [ -e "$LUSTRE/tests/cfg/$NAME.sh" ]; then
	echo "Running with config $LUSTRE/tests/cfg/${NAME}.sh"
	$AUSTER -r -R -v -f "${NAME}" $SUITES
else # fall back to default lustre.cfg
	echo "Running with config $LUSTRE/tests/cfg/lustre.sh"
	$AUSTER -r -R -v -f "lustre" $SUITES
fi

