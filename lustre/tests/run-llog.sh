#!/bin/bash

insmod ../obdclass/llog_test.o
../utils/lctl modules > /r/tmp/ogdb-localhost.localdomain
echo "NOW reload debugging syms.."

../utils/lctl <<EOF
newdev
attach llog_test llt_name llt_uuid
setup mds1
cleanup
detach
EOF
rmmod llog_test
