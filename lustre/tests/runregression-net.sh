#!/bin/sh
export PATH=/sbin:/usr/sbin:$PATH

SRCDIR="`dirname $0`/"
. $SRCDIR/common.sh

setup_opts $@

setup_portals
setup_lustre

runthreads() {
	THR=$1
	DO=$2
	CNT=$3
	V=$4
	PGS=$5

	case $CMD in
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

	if [ -e endrun ]; then
		rm endrun
		echo "exiting because of endrun"
		exit 0
	fi

	$OBDCTL --threads $THR v '$OSCDEV' $DO $CNT $RW $V $PGS $OID || exit 1
}

# TODO: obdctl needs to check on the progress of each forked thread
#       (IPC SHM, sockets?) to see if it hangs.
for CMD in test_getattr test_brw_write test_brw_read; do
	setup_server || exit -1
	setup_client || exit -1

	case $CMD in
	test_getattr)
		PG=
		PGV=
		OID=`$OBDCTL --device '$OSCDEV' create 1 | \
			awk '/is object id/ { print $6 }'`
		;;
	test_brw_write)
		PG=1
		PGV=16
		;;

	test_brw_read)
		PG=1
		PGV=16
		;;
	esac

	# We use '--threads 1 X' instead of '--device X' so that
	# obdctl can monitor the forked thread for progress (TODO).
	runthreads 1 $CMD 1 1 $PG
	runthreads 1 $CMD 100 1 $PG

	#cleanup_client || exit -1
	#cleanup_server || exit -1

	#setup_server || exit -1
	#setup_client || exit -1

	debug_server_off
	debug_client_off
	runthreads 1 $CMD 10000 100 $PG
	[ "$PGV" ] && runthreads 1 $CMD 1000 100 $PGV

	runthreads 1 $CMD 1000000 -30 $PG
	[ "$PGV" ] && runthreads 1 $CMD 100000 -30 $PGV

	debug_server_on
	debug_client_on
	runthreads 1 $CMD 100 1 $PG

	debug_server_off
	debug_client_off
	runthreads 2 $CMD 10000 100 $PG
	[ "$PGV" ] && runthreads 2 $CMD 1000 100 $PGV

	runthreads 2 $CMD 1000000 -30 $PG
	[ "$PGV" ] && runthreads 2 $CMD 100000 -30 $PGV

	runthreads 10 $CMD 10000 1000 $PG
	[ "$PGV" ] && runthreads 10 $CMD 1000 1000 $PGV

	runthreads 100 $CMD 10000 -30 $PG

	[ "$CMD" = "test_brw_read" ] && $OBDCTL --device '$OSCDEV' destroy $OID

	cleanup_client || exit -1
	cleanup_server || exit -1
done

cleanup_lustre
cleanup_portals
