export PATH=$PATH:/sbin:/usr/sbin

if [ -d /r ]; then
  R=/r
fi

PTLCTL=$SRCDIR/../../portals/linux/utils/ptlctl
OBDCTL=$SRCDIR/../../obd/utils/obdctl
DEBCTL=$SRCDIR/../../portals/linux/utils/debugctl
ACCEPTOR=$SRCDIR/../../portals/linux/utils/acceptor

LOOPNUM=0; export LOOPNUM
if [ -b /dev/loop0 ]; then
  LOOP=/dev/loop
else
  if [ -b /dev/loop/0 ]; then
    LOOP=/dev/loop/
  else
    echo "Cannot find /dev/loop0 or /dev/loop/0";
    exit -1
  fi
fi

next_loop_dev() {
	NEXT=
	while [ -b ${LOOP}${LOOPNUM} ]; do
		LOOPDEV=${LOOP}${LOOPNUM}
		losetup ${LOOPDEV} > /dev/null 2>&1 || NEXT=${LOOPDEV}
		LOOPNUM=`expr ${LOOPNUM} + 1`
		[ "$NEXT" ] && echo ${NEXT} && break
	done
}

list_mods() {
    $DEBCTL modules > $R/tmp/ogdb
    echo "The GDB module script is in /tmp/ogdb.  Press enter to continue"
    read
}

new_fs () {
    dd if=/dev/zero of=$2 bs=1k count=$3 1>&2 || exit -1
    mkfs.$1 -b 4096 -F $2 1>&2 || exit -1
    LOOPDEV=`next_loop_dev`
    losetup ${LOOPDEV} $2 1>&2 || exit -1
}

old_fs () {
    [ -e $2 ] || exit -1
    LOOPDEV=`next_loop_dev`
    losetup ${LOOPDEV} $2 1>&2 || exit -1
}

setup() {
    [ -c /dev/portals ] || mknod /dev/portals c 10 240

    insmod $SRCDIR/../../portals/linux/oslib/portals.o || exit -1
    insmod $SRCDIR/../../portals/linux/qswnal/kqswnal.o
    insmod $SRCDIR/../../portals/linux/socknal/ksocknal.o || exit -1

    [ "$NETWORK" = "tcp" ] && ($ACCEPTOR $PORT &)

    [ -c /dev/obd ] || mknod /dev/obd c 10 241

    insmod $SRCDIR/../../obd/class/obdclass.o || exit -1
    insmod $SRCDIR/../../obd/rpc/ptlrpc.o || exit -1
    insmod $SRCDIR/../../obd/ldlm/ldlm.o || exit -1
    insmod $SRCDIR/../../obd/ext2obd/obdext2.o || exit -1
    insmod $SRCDIR/../../obd/ost/ost.o || exit -1
    insmod $SRCDIR/../../obd/osc/osc.o || exit -1
    insmod $SRCDIR/../../obd/obdecho/obdecho.o || exit -1
    insmod $SRCDIR/../../obd/mds/mds.o || exit -1
    insmod $SRCDIR/../../obd/mdc/mdc.o || exit -1
    insmod $SRCDIR/../../obd/llight/llight.o || exit -1

    list_mods

    [ -d /mnt/obd ] || mkdir /mnt/obd
}

setup_portals() {
	if [ -z "$NETWORK" -o -z "$LOCALHOST" -o -z "$SERVER" ]; then
		echo "$0: NETWORK or LOCALHOST or SERVER is not set"
		exit -1
	fi

	case $NETWORK in
	elan)	if [ "$PORT" ]; then
			echo "$0: NETWORK is elan but PORT is set"
			exit -1
		fi
		;;
	tcp)	if [ -z "$PORT" ]; then
			echo "$0: NETWORK is tcp but PORT is not set"
			exit -1
		fi
		;;
	*) 	echo "$0: unknown NETWORK \'$NETWORK\'"
		exit -1
		;;
	esac

	$PTLCTL <<- EOF
	setup $NETWORK
	mynid $LOCALHOST
	connect $SERVER $PORT
	add_uuid self
	add_uuid mds
	add_uuid ost
	quit
	EOF
}

setup_ldlm() {
    [ -c /dev/portals ] || mknod /dev/portals c 10 240

    insmod $SRCDIR/../../portals/linux/oslib/portals.o || exit -1

    insmod $SRCDIR/../../obd/class/obdclass.o || exit -1
    insmod $SRCDIR/../../obd/ldlm/ldlm.o || exit -1

    list_mods
}
