#!/bin/bash
PATH=`dirname $0`:`dirname $0`/../utils:$PATH
TMP=${TMP:-/tmp}

MDS=`ls /proc/fs/lustre/mdt | grep -v num_refs | head -n 1`
[ -z "$MDS" ] && echo "no MDS available, skipping llog test" && exit 0

case `uname -r` in
2.4.*) insmod ../obdclass/llog_test.o || exit 1 ;;
2.6.*) insmod ../obdclass/llog_test.ko || exit 1 ;;
*) echo "unknown kernel version `uname -r`" && exit 99 ;;
esac
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
