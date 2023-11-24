#!/bin/bash
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#

# Sourcing this script will log you out from your shell
if [[ -n "${PS1}" ]]; then
	echo "Do not source this script. Run using ./lutf.sh instead."
	return 1
fi

export ONLY=${ONLY:-"$*"}
export SUITE=${SUITE:-"$*"}
export PATTERN=${PATTERN:-"$*"}

[ "$SLOW" = "no" ] && EXCEPT_SLOW=""
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

LUSTRE=${LUSTRE:-$(dirname "$0")/..}

. "$LUSTRE/tests/test-framework.sh"
init_test_env "$@"
. "${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}"
init_logging

# bug number for skipped test:
ALWAYS_EXCEPT="$SANITY_LNET_EXCEPT "

export LNETCTL=${LNETCTL:-"$LUSTRE/../lnet/utils/lnetctl"}
[ ! -f "$LNETCTL" ] &&
	export LNETCTL=$(which lnetctl 2> /dev/null)
[[ -z $LNETCTL ]] && skip "Need lnetctl"

restore_mounts=false
if is_mounted "$MOUNT" || is_mounted "$MOUNT2"; then
	cleanupall || error "Failed cleanup prior to test execution"
	restore_mounts=true
fi

cleanup_lnet() {
	echo "Cleaning up LNet"
	lsmod | grep -q lnet &&
		$LNETCTL lnet unconfigure 2>/dev/null
	unload_modules
}

restore_modules=false
if module_loaded lnet ; then
	cleanup_lnet || error "Failed to unload modules before test execution"
	restore_modules=true
fi

cleanup_testsuite() {
	trap "" EXIT
	cleanup_lnet
	if $restore_mounts; then
		setupall || error "Failed to setup Lustre after test execution"
	elif $restore_modules; then
		load_modules ||
			error "Couldn't load modules after test execution"
	fi
	return 0
}

set_env_vars_on_remote() {
	local list=$(comma_list $(all_nodes))
	do_rpc_nodes "$list" "echo $PATH; echo $LUSTRE; echo $LNETCTL; echo $LCTL"
}

set_env_vars_on_remote

rm -f /tmp/tf.skip

# do not exit if LUTF fails
set +e

echo "+++++++++++STARTING LUTF"
export LUTF_ENV_VARS="$CONFIG"
"$LUSTRE/tests/lutf/python/config/lutf_start.py"
rc=$?
echo "-----------STOPPING LUTF: $rc"

if [ -d /tmp/lutf/ ]; then
	tar -czf /tmp/lutf.tar.gz /tmp/lutf
	mv /tmp/lutf.tar.gz "$LOGDIR"
fi


complete_test $SECONDS

cleanup_testsuite

exit $rc
