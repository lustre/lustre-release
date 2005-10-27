#!/bin/sh

MDIR=/lib/modules/`uname -r`/lustre

KVER=24
EXT=o
FSFLT=fsfilt_ext3
MODFILE="/etc/modules.conf"
if [ `uname -r | cut -c 3` -eq 6 ]; then
    KVER=26
    EXT=ko
    FSFLT=fsfilt_ldiskfs
    MODFILE="/etc/modprobe.conf"
fi

echo "Copying modules from local build dir to "$MDIR

mkdir -p $MDIR

cp ../../lnet/libcfs/libcfs.$EXT $MDIR
cp ../../lnet/lnet/lnet.$EXT $MDIR
cp ../../lnet/klnds/socklnd/ksocklnd.$EXT $MDIR
cp ../lvfs/lvfs.$EXT $MDIR
cp ../obdclass/obdclass.$EXT $MDIR
cp ../ptlrpc/ptlrpc.$EXT $MDIR
cp ../mdc/mdc.$EXT $MDIR
cp ../osc/osc.$EXT $MDIR
cp ../lov/lov.$EXT $MDIR
cp ../mds/mds.$EXT $MDIR
cp ../lvfs/$FSFLT.$EXT $MDIR
[ $KVER == "26" ] && cp ../ldiskfs/ldiskfs.$EXT $MDIR
cp ../ost/ost.$EXT $MDIR
cp ../obdfilter/obdfilter.$EXT $MDIR
cp ../llite/llite.$EXT $MDIR

echo "Depmod"
depmod -a -e

echo "Copying mount from local build dir to "$MDIR
cp ../utils/mount.lustre /sbin/.

MP="/sbin/modprobe"
MPI="$MP --ignore-install"

[ -e $MODFILE ] || touch $MODFILE
if [ `egrep -c "lustre|lnet" $MODFILE` -eq 0 ]; then
    echo Modifying $MODFILE
    echo "# Lustre modules added by $0" >> $MODFILE
    echo "# Networking options, see /sys/module/lnet/parameters" >> $MODFILE
    echo "options lnet networks=tcp" >> $MODFILE
    echo "alias lustre llite" >> $MODFILE
    echo "# end Lustre modules" >> $MODFILE
fi
