#!/bin/sh


TESTDIR=`dirname $0`
LUSTRE=$TESTDIR/..

exec >> $TESTDIR/recovery-`hostname`.log
exec 2>&1

set -xv

failed_import() {
    if [ -f $LUSTRE/tests/ostactive ] ; then
        source $LUSTRE/tests/mdsactive
    else
        mdsactive=mds
    fi

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
