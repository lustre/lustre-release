#!/bin/sh

SRCDIR="`dirname $0`/"
[ -f $SRCDIR/common.sh ] || SRCDIR="/lib/lustre"

. $SRCDIR/common.sh

setup_opts "$@"

[ -c /dev/portals ] || mknod /dev/portals c 10 240
do_insmod $PORTALS/linux/oslib/portals.o || exit -1
case $NETWORK in
elan)  do_insmod $PORTALS/linux/qswnal/kqswnal.o || exit -1
	    ;;
tcp)   do_insmod $PORTALS/linux/socknal/ksocknal.o || exit -1
	   ;;
*) 	fail "$0: unknown NETWORK '$NETWORK'" ;;
esac

[ -c /dev/obd ] || mknod /dev/obd c 10 241

do_insmod $LUSTRE/obdclass/obdclass.o || exit -1
do_insmod $LUSTRE/ptlrpc/ptlrpc.o || exit -1
do_insmod $LUSTRE/ldlm/ldlm.o || exit -1
do_insmod $LUSTRE/extN/extN.o || \
    echo "info: can't load extN.o module, not fatal if using ext3"
do_insmod $LUSTRE/mds/mds.o || exit -1
do_insmod $LUSTRE/mds/mds_extN.o || \
    echo "info: can't load mds_extN.o module, needs extN.o"
do_insmod $LUSTRE/obdecho/obdecho.o || exit -1
do_insmod $LUSTRE/obdfilter/obdfilter.o || exit -1
do_insmod $LUSTRE/ost/ost.o || exit -1
do_insmod $LUSTRE/osc/osc.o || exit -1
do_insmod $LUSTRE/mdc/mdc.o || exit -1
do_insmod $LUSTRE/lov/lov.o || exit -1
do_insmod $LUSTRE/llite/llite.o || exit -1
echo "$R/tmp/lustre-log" > /proc/sys/portals/debug_path

list_mods


