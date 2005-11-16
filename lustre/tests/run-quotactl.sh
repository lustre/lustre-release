#!/bin/bash
PATH=`dirname $0`:`dirname $0`/../utils:$PATH
TMP=${TMP:-/tmp}
OBD=${1:-obdfilter}

TARGET=`ls /proc/fs/lustre/$OBD | grep -v num_refs | head -n 1`
[ -z "$TARGET" ] && echo "no TARGET available, skipping quotactl test" && exit 0

insmod ../lvfs/quotactl_test.ko || exit 1
lctl modules > $TMP/ogdb-`hostname`
echo "NOW reload debugging syms.."

RC=0
lctl <<EOT || RC=2
newdev
attach quotactl_test qctl_name qctl_uuid
setup $TARGET
EOT

# Using ignore_errors will allow lctl to cleanup even if the test fails.
lctl <<EOC
cfg_device qctl_name
ignore_errors
cleanup
detach
EOC
rmmod quotactl_test || RC2=3
[ $RC -eq 0 -a "$RC2" ] && RC=$RC2

exit $RC
