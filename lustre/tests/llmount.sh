#!/bin/sh

LOOP0=/dev/loop0
LOOP1=/dev/loop1

if [ ! -e $LOOP0 ]; then 
    echo "$LOOP0 doesn't exist - check devfs"
    exit 1
fi

mknod /dev/portals c 10 240

insmod $R/usr/src/portals/linux/oslib/portals.o
insmod $R/usr/src/portals/linux/socknal/ksocknal.o

$R/usr/src/portals/linux/utils/acceptor 1234 &

$R/usr/src/portals/linux/utils/ptlctl <<EOF
mynid
setup tcp localhost 1234
connect self
connect mds
EOF

insmod $R/usr/src/obd/rpc/ptlrpc.o
insmod $R/usr/src/obd/class/obdclass.o 
insmod $R/usr/src/obd/ext2obd/obdext2.o
insmod $R/usr/src/obd/ost/ost.o
insmod $R/usr/src/obd/osc/osc.o
insmod $R/usr/src/obd/mds/mds.o
insmod $R/usr/src/obd/mdc/mdc.o
insmod $R/usr/src/obd/llight/llight.o

dd if=/dev/zero of=/tmp/ost bs=1024 count=10000
mke2fs -b 4096 -F /tmp/ost
losetup $LOOP0 /tmp/ost

dd if=/dev/zero of=/tmp/mds bs=1024 count=10000
mke2fs -b 4096 -F /tmp/mds
losetup $LOOP1 /tmp/mds

mknod /dev/obd c 10 241
echo 8291 > /proc/sys/obd/debug
echo 8291 > /proc/sys/obd/trace
$R/usr/src/obd/utils/obdctl <<EOF
device 0
attach mds
setup $LOOP1 ext2
device 1
attach obdext2
setup $LOOP0
device 2
attach ost
setup 1
device 3
attach osc
setup 2
quit
EOF

mkdir /mnt/obd
# mount -t lustre_light -o device=3 none /mnt/obd
