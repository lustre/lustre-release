#!/bin/sh
SRCDIR="`dirname $0`/"
export PATH=/sbin:/usr/sbin:$SRCDIR:$PATH

LOOPS=${LOOPS:-1}
COUNT=${COUNT:-1000000}
COUNT_10=`expr $COUNT / 10`
COUNT_100=`expr $COUNT / 100`

ENDRUN=endrun-`hostname`

ECHONAME="`lctl device_list 2> /dev/null | awk '/ echo_client / { print $4 }' | tail -1`"

if [ -z "$ECHONAME" ]; then
	echo "$0: needs an ECHO_CLIENT set up first" 1>&2
	exit 1
fi

cleanup () {
	lctl --device \$$ECHONAME destroy $OID
}
	
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

	lctl --threads $THR v \$$ECHONAME $DO $CNT $RW $V $PGS $OID || exit 1

	if [ -e $ENDRUN ]; then
		rm $ENDRUN
		echo "exiting because $ENDRUN file was found"
		cleanup
	fi
}

[ -z "$OID" ] && OID=`lctl --device \\$$ECHONAME create 1 | awk '/is object id/ { print $6 }'` && echo "created object $OID"
[ -z "$OID" ] && echo "error creating object" 1>&2 && exit 1

# TODO: obdctl needs to check on the progress of each forked thread
#       (IPC SHM, sockets?) to see if it hangs.
for i in `seq $LOOPS`; do
	PG=1
	PGVW=${PGVW:-16}
	PGVR=${PGVR:-16}

	# We use '--threads 1 X' instead of '--device X' so that
	# obdctl can monitor the forked thread for progress (TODO).
	debug_server_off
	debug_client_off
	runthreads 1 test_brw_write 1000 -30 $PG
	runthreads 1 test_brw_read 1000 -30 $PG

	[ "$PGVW" ] && runthreads 1 test_brw_write 100 -30 $PGVW
	[ "$PGVW" ] && runthreads 1 test_brw_read 1600 -30 $PG
	[ "$PGVR" ] && runthreads 1 test_brw_read 100 -30 $PGVR

	runthreads 1 test_brw_write $COUNT -30 $PG
	runthreads 1 test_brw_read $COUNT -30 $PG

	[ "$PGVW" ] && runthreads 1 test_brw_write $COUNT_10 -30 $PGVW
	[ "$PGVR" ] && runthreads 1 test_brw_read $COUNT_10 -30 $PGVR

	runthreads 2 test_brw_write $COUNT -30 $PG
	runthreads 2 test_brw_read $COUNT -30 $PG

	[ "$PGVW" ] && runthreads 2 test_brw_write $COUNT_10 -30 $PGVW
	[ "$PGVR" ] && runthreads 2 test_brw_read $COUNT_10 -30 $PGVR

	runthreads 10 test_brw_write $COUNT_10 -30 $PG
	runthreads 10 test_brw_read $COUNT_10 -30 $PG

	[ "$PGVW" ] && runthreads 10 test_brw_write $COUNT_100 -60 $PGVW
	[ "$PGVR" ] && runthreads 10 test_brw_read $COUNT_100 -60 $PGVR

	runthreads 32 test_brw_write $COUNT_10 -30 $PG
	runthreads 32 test_brw_read $COUNT_10 -30 $PG

	[ "$PGVW" ] && runthreads 32 test_brw_write $COUNT_100 -60 $PGVW
	[ "$PGVR" ] && runthreads 32 test_brw_read $COUNT_100 -60 $PGVR

	runthreads 64 test_brw_write $COUNT_10 -30 $PG
	runthreads 64 test_brw_read $COUNT_10 -30 $PG

	[ "$PGVW" ] && runthreads 64 test_brw_write $COUNT_100 -60 $PGVW
	[ "$PGVR" ] && runthreads 64 test_brw_read $COUNT_100 -60 $PGVR

	runthreads 100 test_brw_write $COUNT_100 -60 $PG
	runthreads 100 test_brw_read $COUNT_100 -60 $PG

	[ "$PGVW" ] && runthreads 100 test_brw_write $COUNT_100 -60 $PGVW
	[ "$PGVR" ] && runthreads 100 test_brw_read $COUNT_100 -60 $PGVR
done

cleanup
