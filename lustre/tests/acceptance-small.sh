#!/bin/sh
# script which _must_ complete successfully (at minimum) before checkins to
# the CVS HEAD are allowed.
set -e

. common.sh

TESTDESC="Minimum Acceptance Test"
TESTNAME="acceptance-small"
TESTGROUP="correctness"
LVER="head" # This has to be made dynamic
NET="tcp"   # This has to be made dynamic

buffalo_init

if [ "$LOCAL" != no ]; then
	export NAME=${LOCAL:-local}
	sh ${NAME}.sh
	[ "$RUNTESTS" != "no" ] && start_test "runtests-local" && sh runtests --reformat ${NAME}.xml

	mount | grep lustre_lite || sh llmount.sh
	[ "$SANITY" != "no" ] && start_test "sanity-local" && sh sanity.sh
	[ "$DBENCH" != "no" ]  && start_test "rundbench-local" && sh rundbench 1
	[ "$BONNIE" != "no" ] && start_test "bonnie-local" && bonnie++ -s 0 -n 10 -u 0 -d /mnt/lustre
	sync; sync
	sh llmountcleanup.sh
fi

if [ "$LOV" != no ]; then
	export NAME=${LOV:-lov}
	sh ${NAME}.sh
	[ "$RUNTESTS" != "no" ] && start_test "runtests-lov" && sh runtests --reformat ${NAME}.xml
	mount | grep lustre_lite || sh llmount.sh
	[ "$SANITY" != "no" ] && start_test "sanity-lov" && sh sanity.sh
	[ "$DBENCH" != "no" ] && start_test "rundbench-lov" && sh rundbench 1
	[ "$BONNIE" != "no" ] && start_test "bonnie-lov" && bonnie++ -s 0 -n 10 -u 0 -d /mnt/lustre
	sync; sync
	sh llmountcleanup.sh
fi
