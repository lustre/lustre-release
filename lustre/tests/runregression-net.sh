#!/bin/sh
export PATH=/sbin:/usr/sbin:$PATH

SRCDIR="`dirname $0`/"
. $SRCDIR/common.sh

COUNT=${COUNT:-10000000}
COUNT_10=`expr $COUNT / 10`
COUNT_100=`expr $COUNT / 100`
COUNT_1000=`expr $COUNT / 1000`

ENDRUN=endrun-`hostname`

ECHONAME="`$OBDCTL device_list 2> /dev/null | awk '/ echo_client / { print $4 }' | tail -1`"

if [ -z "$ECHONAME" ]; then
	echo "$0: needs an ECHO_CLIENT set up first" 1>&2
	exit 1
fi

runthreads() {
	THR=$1
	DO=$2
	CNT=$3
	V=$4
	PGS=$5

	case $DO in
	test_getattr)
		RW=

	test_brw_write)
		DO=test_brw
		RW=w
		;;

	test_brw_read)
		DO=test_brw
		RW=r
		;;
	esac

	$OBDCTL --threads $THR v \$$ECHONAME $DO $CNT $RW $V $PGS $OID || exit 1

	if [ -e endrun ]; then
		rm endrun
		echo "exiting because endrun file was found"
		exit 0
	fi
}

[ -z "$OID" ] && OID=`$OBDCTL --device \\$$ECHONAME create 1 | awk '/is object id/ { print $6 }'`
[ -z "$OID" ] && echo "error creating object" 1>&2 && exit 1

# TODO: obdctl needs to check on the progress of each forked thread
#       (IPC SHM, sockets?) to see if it hangs.
for CMD in test_getattr test_brw_write test_brw_read; do
	case $CMD in
	test_getattr)
		PG=
		PGV=
		;;
	test_brw_write)
		PG=1
		PGV=16
		;;

	test_brw_read)
		PG=1
		case $OSTNODE in
		ba*) PGV= ;; # disabled until the BA OST code is updated
		*) PGV=16 ;;
		esac
		;;
	esac

	# We use '--threads 1 X' instead of '--device X' so that
	# obdctl can monitor the forked thread for progress (TODO).
	runthreads 1 $CMD 1 1 $PG
	runthreads 1 $CMD 100 1 $PG

	debug_server_off
	debug_client_off
	runthreads 1 $CMD $COUNT_100 -10 $PG
	[ "$PGV" ] && runthreads 1 $CMD $COUNT_1000 -10 $PGV

	runthreads 1 $CMD $COUNT -30 $PG
	[ "$PGV" ] && runthreads 1 $CMD $COUNT_10 -30 $PGV

	runthreads 1 $CMD 100 -10 $PG

	runthreads 2 $CMD $COUNT_100 -30 $PG
	[ "$PGV" ] && runthreads 2 $CMD $COUNT_1000 -30 $PGV

	runthreads 2 $CMD $COUNT -30 $PG
	[ "$PGV" ] && runthreads 2 $CMD $COUNT_10 -30 $PGV

	runthreads 10 $CMD $COUNT_10 -30 $PG
	[ "$PGV" ] && runthreads 10 $CMD $COUNT_100 -30 $PGV

	runthreads 100 $CMD $COUNT_100 -30 $PG
	[ "$PGV" ] && runthreads 100 $CMD $COUNT_1000 -30 $PGV
done

$OBDCTL --device \$$ECHONAME destroy $OID
