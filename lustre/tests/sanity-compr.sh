#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#

set -e

ONLY=${ONLY:-"$*"}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env "$@"
init_logging

# bug number for skipped test:
ALWAYS_EXCEPT="$SANITY_COMPR_EXCEPT"

build_test_filter

FAIL_ON_ERROR=false

check_and_setup_lustre

# $RUNAS_ID may get set incorrectly somewhere else
if [[ $UID -eq 0 && $RUNAS_ID -eq 0 ]]; then
	skip_env "\$RUNAS_ID set to 0, but \$UID is also 0!" && exit
fi
check_runas_id $RUNAS_ID $RUNAS_GID $RUNAS

save_layout_restore_at_exit $MOUNT
# Set file system with different layout
COMPR_EXTRA_LAYOUT=${COMPR_EXTRA_LAYOUT:-"-E EOF -c 1"}
$LFS setstripe $COMPR_EXTRA_LAYOUT $MOUNT

test_sanity()
{
	always_except LU-16928 56wb
	local rc=0

	SANITY_EXCEPT=$ALWAYS_EXCEPT bash sanity.sh
	rc=$?
	return $rc
}
run_test sanity "Run sanity with PFL layout"

test_sanityn()
{
	local rc=0

	bash sanityn.sh
	rc=$?
	return $rc
}
run_test sanityn "Run sanityn with PFL layout"

complete_test $SECONDS
check_and_cleanup_lustre
declare -a logs=($ONLY)
logs=("${logs[@]/#/$TMP/}")
exit_status "$(echo "${logs[@]/%/.log}")"
