#!/bin/sh
export PATH=/sbin:/usr/sbin:$PATH

SRCDIR="`dirname $0`"
. $SRCDIR/common.sh

setup_opts $@

setup_portals
setup_lustre

# TODO: obdctl needs to check on the progress of each forked thread
#       (IPC SHM, sockets?) to see if it hangs.
for CMD in test_getattr test_brw_read test_brw_write; do
	case $CMD in
	test_brw_read)	CMD=test_brw; RW=r ;;
	test_brw_write)	CMD=test_brw; RW=w ;;
	*)		RW= ;;
	esac

	setup_server || exit -1
	setup_client || exit -1

	# We use '--threads 1 X' instead of '--device X' so that
	# obdctl can modnitor the forked thread for progress (TODO).
	$OBDCTL --threads 1 v $OSC_DEVNO $CMD 1 $RW v || exit -1
	$OBDCTL --threads 1 v $OSC_DEVNO $CMD 100 $RW v || exit -1

	#cleanup_client || exit -1
	#cleanup_server || exit -1

	#setup_server || exit -1
	#setup_client || exit -1

	debug_server_off
	debug_client_off
	$OBDCTL --threads 1 v $OSC_DEVNO $CMD 10000 $RW 100 || exit -1
	$OBDCTL --threads 1 v $OSC_DEVNO $CMD 1000000 $RW -10 || exit -1

	debug_server_on
	debug_client_on
	$OBDCTL --threads 2 v $OSC_DEVNO $CMD 100 $RW v || exit -1

	debug_server_off
	debug_client_off
	$OBDCTL --threads 2 v $OSC_DEVNO $CMD 10000 $RW 100 || exit -1
	$OBDCTL --threads 2 v $OSC_DEVNO $CMD 1000000 $RW -30 || exit -1

	$OBDCTL --threads 10 v $OSC_DEVNO $CMD 10000 $RW 1000 || exit -1
	$OBDCTL --threads 100 v $OSC_DEVNO $CMD 10000 $RW -30 || exit -1

	cleanup_client || exit -1
	cleanup_server || exit -1
done

cleanup_lustre
cleanup_portals
