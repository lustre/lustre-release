#!/bin/sh


TESTDIR=`dirname $0`
LUSTRE=$TESTDIR/..

exec >> $TESTDIR/recovery-`hostname`.log
exec 2>&1

set -xv

failed_import() {
#    $LUSTRE/utils/lctl --device %$3 recover ||
#        logger -p kern.info recovery failed: $@

    source $LUSTRE/tests/mdsactive

    $LUSTRE/utils/lconf --verbose --recover --node client_facet  \
      --select mds1=${mdsactive}_facet\
     --tgt_uuid $2 --client_uuid $3 --conn_uuid $4 $TESTDIR/replay-single.xml

}

recovery_over() {
    logger -p kern.info upcall: $@
}


case "$1" in
FAILED_IMPORT) failed_import $@
               ;;
RECOVERY_OVER) recovery_over $@
               ;;
esac
