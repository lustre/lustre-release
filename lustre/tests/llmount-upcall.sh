#!/bin/sh
LUSTRE=`dirname $0`/..
exec >> /tmp/recovery-`hostname`.log
exec 2>&1

$LUSTRE/utils/lconf --recover --verbose --tgt_uuid $2 --client_uuid $3 --conn_uuid $4 $LUSTRE/tests/local.xml
