#!/bin/bash
PATH=`dirname $0`:`dirname $0`/../utils:$PATH
insmod ../obdclass/llog_test.o || exit 1
lctl modules > /r/tmp/ogdb-`hostname`
echo "NOW reload debugging syms.."

RC=0
lctl <<EOT || RC=2
newdev
attach llog_test llt_name llt_uuid
setup mds1
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
