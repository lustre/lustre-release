#!/bin/sh
export PATH=/sbin:/usr/sbin:$PATH

SRCDIR="`dirname $0`/"
. $SRCDIR/common.sh

runthreads() {
	THR=$1
	DO=$2
	CNT=$3
	V=$4
	PGS=$5

	case $DO in
	test_getattr)
		RW=
		;;
	test_brw_write)
		DO=test_brw
		RW=w
		;;

	test_brw_read)
		DO=test_brw
		RW=r
		;;
	esac

	$OBDCTL --threads $THR v '$OSCDEV' $DO $CNT $RW $V $PGS $OID || exit 1

	if [ -e endrun ]; then
		rm endrun
		echo "exiting because endrun file was found"
		exit 0
	fi
}

if [  -z "`$OBDCTL device_list 2> /dev/null | grep osc`" ]; then
	setup_opts $@

	setup_portals
	setup_lustre

	setup_server || exit -1
	setup_client || exit -1
fi

OID=`$OBDCTL --device '$OSCDEV' create 1 | awk '/is object id/ { print $6 }'`
[ -z "$OID" ] && echo "error creating object" 1>&2 && exit 1

# TODO: obdctl needs to check on the progress of each forked thread
#       (IPC SHM, sockets?) to see if it hangs.
while date; do
	PG=1
	PGVW=16
	case $OSTNODE in
	ba*) PGVR= ;; # disabled until the BA OST code is updated
	*) PGVR=16 ;;
	esac

	# We use '--threads 1 X' instead of '--device X' so that
	# obdctl can monitor the forked thread for progress (TODO).
	debug_server_off
	debug_client_off
	runthreads 1 test_brw_write 1000 -30 $PG
	runthreads 1 test_brw_read 1000 -30 $PG

	[ "$PGVW" ] && runthreads 1 test_brw_write 100 -30 $PGVW
	[ "$PGVW" ] && runthreads 1 test_brw_read 1600 -30 $PG
	[ "$PGVR" ] && runthreads 1 test_brw_read 100 -30 $PGVR

	runthreads 1 test_brw_write 10000000 -30 $PG
	runthreads 1 test_brw_read 10000000 -30 $PG

	[ "$PGVW" ] && runthreads 1 test_brw_write 1000000 -30 $PGVW
	[ "$PGVW" ] && runthreads 1 test_brw_read 16000000 -30 $PG
	[ "$PGVR" ] && runthreads 1 test_brw_read 1000000 -30 $PGVR

	runthreads 2 test_brw_write 10000000 -30 $PG
	runthreads 2 test_brw_read 10000000 -30 $PG

	[ "$PGVW" ] && runthreads 2 test_brw_write 1000000 -30 $PGVW
	[ "$PGVW" ] && runthreads 1 test_brw_read 16000000 -30 $PG
	[ "$PGVR" ] && runthreads 2 test_brw_read 1000000 -30 $PGVR

	runthreads 10 test_brw_write 1000000 -30 $PG
	runthreads 1 test_brw_read 16000000 -30 $PG
	runthreads 10 test_brw_read 1000000 -30 $PG

	[ "$PGVW" ] && runthreads 10 test_brw_write 100000 -60 $PGVW
	[ "$PGVW" ] && runthreads 1 test_brw_read 1600000 -30 $PG
	[ "$PGVR" ] && runthreads 10 test_brw_read 100000 -60 $PGVR

	runthreads 32 test_brw_write 1000000 -30 $PG
	runthreads 1 test_brw_read 16000000 -30 $PG
	runthreads 32 test_brw_read 1000000 -30 $PG

	[ "$PGVW" ] && runthreads 32 test_brw_write 100000 -60 $PGVW
	[ "$PGVW" ] && runthreads 1 test_brw_read 1600000 -30 $PG
	[ "$PGVR" ] && runthreads 32 test_brw_read 100000 -60 $PGVR

	runthreads 64 test_brw_write 1000000 -30 $PG
	runthreads 1 test_brw_read 16000000 -30 $PG
	runthreads 64 test_brw_read 1000000 -30 $PG

	[ "$PGVW" ] && runthreads 64 test_brw_write 100000 -60 $PGVW
	[ "$PGVW" ] && runthreads 1 test_brw_read 1600000 -30 $PG
	[ "$PGVR" ] && runthreads 64 test_brw_read 100000 -60 $PGVR

	runthreads 100 test_brw_write 100000 -60 $PG
	runthreads 1 test_brw_read 1600000 -30 $PG
	runthreads 100 test_brw_read 100000 -60 $PG

	[ "$PGVW" ] && runthreads 100 test_brw_write 100000 -60 $PGVW
	[ "$PGVW" ] && runthreads 1 test_brw_read 1600000 -30 $PG
	[ "$PGVR" ] && runthreads 100 test_brw_read 100000 -60 $PGVR
done

$OBDCTL --device '$OSCDEV' destroy $OID

cleanup_client || exit -1
cleanup_server || exit -1
cleanup_lustre
cleanup_portals
