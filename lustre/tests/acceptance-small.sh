#!/bin/sh
# script which _must_ complete successfully (at minimum) before checkins to
# the CVS HEAD are allowed.
set -vxe

if [ "$RUNTESTS" != "no" ]; then
	sh local.sh
	sh runtests --reformat local.xml

	sh lov.sh
	sh runtests --reformat lov.xml
fi

export NAME=local
sh llmount.sh
[ "$SANITY" != "no" ] && sh sanity.sh
[ "$DBENCH" != "no" ]  && sh rundbench 1
[ "$BONNIE" != "no" ] && bonnie++ -s 0 -n 10 -u 0 -d /mnt/lustre
sync; sync
sh llmountcleanup.sh

export NAME=lov
llmount.sh
[ "$SANITY" != "no" ] && sh sanity.sh
[ "$DBENCH" != "no" ] && sh rundbench 1
[ "$BONNIE" != "no" ] && bonnie++ -s 0 -n 10 -u 0 -d /mnt/lustre
sync; sync
sh llmountcleanup.sh
