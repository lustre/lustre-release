#!/bin/sh

R=/r

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

dd if=/dev/zero of=/tmp/fs bs=1024 count=10000
mke2fs -b 4096 -F /tmp/fs
losetup /dev/loop/0 /tmp/fs

mknod /dev/obd c 10 241

$R/usr/src/obd/utils/obdctl <<EOF
device 0
attach mds
setup /dev/loop/0 ext2
quit
EOF

mknod /dev/request c 10 244
# $R/usr/src/obd/tests/testreq


