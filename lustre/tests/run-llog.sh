#!/bin/bash
insmod ../obdclass/llog_test.o
../utils/lctl modules > /r/tmp/ogdb-localhost.localdomain
echo "NOW reload debugging syms.."

# Using ignore_errors will allow lctl to cleanup even if the test
# fails.
../utils/lctl <<EOF
ignore_errors
newdev
attach llog_test llt_name llt_uuid
setup mds1
cleanup
detach
EOF
rmmod llog_test
