#!/bin/bash
PATH=`dirname $0`:`dirname $0`/../utils:$PATH
TMP=${TMP:-/tmp}

MDS=`ls /proc/fs/lustre/mds | grep -v num_refs | head -1`
[ -z "$MDS" ] && echo "no MDS available, skipping llog test" && exit 0

insmod ../obdclass/llog_test.o || exit 1
lctl modules > $TMP/ogdb-`hostname`
echo "NOW reload debugging syms.."

RC=0
lctl <<EOT || RC=2
newdev
attach llog_test llt_name llt_uuid
setup $MDS
EOT

# Using ignore_errors will allow lctl to cleanup even if the test fails.
lctl <<EOC
cfg_device llt_name
ignore_errors
cleanup
detach
EOC
rmmod llog_test || RC2=3
[ $RC -eq 0 -a "$RC2" ] && RC=$RC2

exit $RC
