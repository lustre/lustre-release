#!/bin/bash

LUSTRE=${LUSTRE:-$(dirname "$0")/..}

if [[ ! -f "$LUSTRE/tests/rpc.sh" ]]; then
	FILE_PATH=$(which "$0")
	DIRECTORY=$(dirname "$FILE_PATH")
	LUSTRE=$(dirname "$DIRECTORY")
fi

. "$LUSTRE/tests/test-framework.sh"
RPC_MODE=true init_test_env

# Reset the trap on ERR set by the framework.  Noticing this failure is the
# framework's job.
trap - ERR

log "$HOSTNAME: executing $*"
# Execute the command
"$@"
