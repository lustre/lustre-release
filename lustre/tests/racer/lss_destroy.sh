#!/bin/bash
trap 'kill $(jobs -p)' EXIT

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/../..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

while /bin/true; do
	sleep $((RANDOM % 9 + 11))
	ssname=$(do_facet mgs "$LCTL snapshot_list -F $FSNAME 2>/dev/null" |
		 awk '/snapshot_name.*lss_/ { print $2; exit; }')
	[ ! -z "$ssname" ] && lsnapshot_destroy -n $ssname -f || true
done
