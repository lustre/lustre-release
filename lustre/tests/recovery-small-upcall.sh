#!/bin/sh
LUSTRE=`dirname $0`/..
PATH=$LUSTRE/utils:$PATH
lctl --device %$3 recover || logger -p kern.info recovery failed: $@
