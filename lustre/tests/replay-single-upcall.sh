#!/bin/sh


TESTDIR=`dirname $0`
LUSTRE=$TESTDIR/..

mkdir -p $TESTDIR/logs

exec >> $TESTDIR/logs/recovery-`hostname`.log
exec 2>&1

echo ==========================================
echo "start upcall: `date`"
echo "command line: $0 $*"

set -xv

failed_import() {
    if [ -f $TESTDIR/XMLCONFIG ] ; then
	source $TESTDIR/XMLCONFIG
	if [ ! -f $TESTDIR/XMLCONFIG ]; then
	    echo "config file not found: $XMLCONFIG"
	    exit 1
	 fi
    else
	echo "$TESTDIR/XMLCONFIG: not found"
	exit 1
    fi
	
    if [ -f $TESTDIR/mdsactive ] ; then
        source $TESTDIR/mdsactive
	MDSSELECT="--select mds_svc=${mdsactive}_facet"
    fi

    if [ -f $TESTDIR/ostactive ] ; then
        source $TESTDIR/ostactive
	OSTSELECT="--select ost_svc=${ostactive}_facet"
    fi

    $LUSTRE/utils/lconf --verbose --recover --node client_facet  \
      $MDSSELECT $OSTSELECT \
     --tgt_uuid $2 --client_uuid $3 --conn_uuid $4 $XMLCONFIG

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
