#!/bin/sh
# script which _must_ complete successfully (at minimum) before checkins to
# the CVS HEAD are allowed.
set -vxe

if [ "$LOCAL" != no ]; then
	export NAME=${LOCAL:-local}
	sh ${NAME}.sh
	[ "$RUNTESTS" != "no" ] && sh runtests --reformat ${NAME}.xml

	mount | grep lustre_lite || sh llmount.sh
	[ "$SANITY" != "no" ] && sh sanity.sh
	[ "$DBENCH" != "no" ]  && sh rundbench 1
	[ "$BONNIE" != "no" ] && bonnie++ -s 0 -n 10 -u 0 -d /mnt/lustre
	sync; sync
	sh llmountcleanup.sh
fi

if [ "$LOV" != no ]; then
	export NAME=${LOV:-lov}
	sh ${NAME}.sh
	[ "$RUNTESTS" != "no" ] && sh runtests --reformat ${NAME}.xml
	mount | grep lustre_lite || sh llmount.sh
	[ "$SANITY" != "no" ] && sh sanity.sh
	[ "$DBENCH" != "no" ] && sh rundbench 1
	[ "$BONNIE" != "no" ] && bonnie++ -s 0 -n 10 -u 0 -d /mnt/lustre
	sync; sync
	sh llmountcleanup.sh
fi
