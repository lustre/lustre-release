#!/bin/bash
#
#set -vx

set -e

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

LIBLUSTRETESTS=${LIBLUSTRETESTS:-$LUSTRE/liblustre/tests}

assert_env MGSNID MOUNT2
export LIBLUSTRE_MOUNT_POINT=$MOUNT2
export LIBLUSTRE_MOUNT_RETRY=5
export LIBLUSTRE_MOUNT_TARGET=$MGSNID:/$FSNAME
export LIBLUSTRE_TIMEOUT=`lctl get_param -n timeout`
#export LIBLUSTRE_DEBUG_MASK=`lctl get_param -n debug`

test_1() {
    if ! check_versions; then
	skip "liblustre version mismatch: cli $(lustre_version_code client), \
              mds $(lustre_version_code $SINGLEMDS), ost $(lustre_version_code ost1)"
    elif ! [ "$NETTYPE" = "tcp" -o "$NETTYPE" = "ptl" ]; then
	skip "NETTYPE=$NETTYPE unsupported for liblustre"
    elif [ ! -x $LIBLUSTRETESTS/sanity ]; then
	skip "$LIBLUSTRETESTS/sanity: not found"
    else
	mkdir -p $MOUNT2
	echo $LIBLUSTRETESTS/sanity --target=$LIBLUSTRE_MOUNT_TARGET
	$LIBLUSTRETESTS/sanity --target=$LIBLUSTRE_MOUNT_TARGET
	if [ "$LIBLUSTRE_EXCEPT" ]; then
	    LIBLUSTRE_OPT="$LIBLUSTRE_OPT \
			$(echo ' '$LIBLUSTRE_EXCEPT  | sed -re 's/\s+/ -e /g')"
	fi
	echo $LIBLUSTRETESTS/sanity --target=$LIBLUSTRE_MOUNT_TARGET $LIBLUSTRE_OPT
	$LIBLUSTRETESTS/sanity --target=$LIBLUSTRE_MOUNT_TARGET $LIBLUSTRE_OPT
    fi
}
run_test 1 "liblustre sanity"

complete $SECONDS
check_and_cleanup_lustre
exit_status
