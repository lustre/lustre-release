#!/bin/sh
LUSTRE=`dirname $0`/..
$LUSTRE/utils/lctl --device %$3 recover || logger -p kern.info recovery failed: $@
