if [ -d /r ]; then
  R=/r
fi

PTLCTL=$R/usr/src/portals/linux/utils/ptlctl
OBDCTL=$R/usr/src/obd/utils/obdctl
DEBCTL=$R/usr/src/portals/linux/utils/debugctl
ACCEPTOR=$R/usr/src/portals/linux/utils/acceptor

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

list_mods() {
    $DEBCTL modules > $R/tmp/ogdb
    echo "The GDB module script is in /tmp/ogdb.  Press enter to continue"
    read
}

new_fs () {
    dd if=/dev/zero of=$2 bs=1k count=$3 1>&2 || exit -1
    mkfs.$1 -b 4096 -F $2 1>&2 || exit -1
    LOOPDEV=${LOOP}${LOOPNUM}
    losetup ${LOOPDEV} $2 1>&2 || exit -1
    LOOPNUM=`expr ${LOOPNUM} + 1`
}

setup() {
    [ -c /dev/portals ] || mknod /dev/portals c 10 240

    insmod $R/usr/src/portals/linux/oslib/portals.o || exit -1
    insmod $R/usr/src/portals/linux/socknal/ksocknal.o || exit -1

    $ACCEPTOR 1234 &

    [ -c /dev/obd ] || mknod /dev/obd c 10 241

    insmod $R/usr/src/obd/class/obdclass.o || exit -1
    insmod $R/usr/src/obd/rpc/ptlrpc.o || exit -1
    insmod $R/usr/src/obd/ext2obd/obdext2.o || exit -1
    insmod $R/usr/src/obd/ost/ost.o || exit -1
    insmod $R/usr/src/obd/osc/osc.o || exit -1
    insmod $R/usr/src/obd/obdecho/obdecho.o || exit -1
    insmod $R/usr/src/obd/mds/mds.o || exit -1
    insmod $R/usr/src/obd/mdc/mdc.o || exit -1
    insmod $R/usr/src/obd/llight/llight.o || exit -1

    list_mods

    [ -d /mnt/obd ] || mkdir /mnt/obd
}

setup_ldlm() {
    [ -c /dev/portals ] || mknod /dev/portals c 10 240

    insmod $R/usr/src/portals/linux/oslib/portals.o || exit -1

    insmod $R/usr/src/obd/class/obdclass.o || exit -1
    insmod $R/usr/src/obd/ldlm/ldlm.o || exit -1

    list_mods
}
