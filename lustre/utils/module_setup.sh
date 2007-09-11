#!/bin/sh

MDIR=/lib/modules/`uname -r`/lustre
mkdir -p $MDIR

KVER=26
EXT=ko
FSFLT=fsfilt_ldiskfs
if [ -d /etc/modprobe.d ]; then
    MODFILE="/etc/modprobe.d/Lustre"
else
    MODFILE="/etc/modprobe.conf"
fi
if [ `uname -r | cut -c 3` -eq 4 ]; then
    KVER=24
    EXT=o
    FSFLT=fsfilt_ext3
    MODFILE="/etc/modules.conf"
fi

echo "Copying modules from local build dir to "$MDIR

cp -u ../../lnet/libcfs/libcfs.$EXT $MDIR
cp -u ../../lnet/lnet/lnet.$EXT $MDIR
cp -u ../../lnet/klnds/socklnd/ksocklnd.$EXT $MDIR
cp -u ../lvfs/lvfs.$EXT $MDIR
cp -u ../obdclass/obdclass.$EXT $MDIR
cp -u ../ptlrpc/ptlrpc.$EXT $MDIR
cp -u ../mdc/mdc.$EXT $MDIR
cp -u ../osc/osc.$EXT $MDIR
cp -u ../lov/lov.$EXT $MDIR
cp -u ../mds/mds.$EXT $MDIR
cp -u ../lvfs/$FSFLT.$EXT $MDIR
[ $KVER == "26" ] && cp -u ../../ldiskfs/ldiskfs/ldiskfs.$EXT $MDIR
cp -u ../ost/ost.$EXT $MDIR
cp -u ../obdfilter/obdfilter.$EXT $MDIR
cp -u ../llite/lustre.$EXT $MDIR
cp -u ../mgc/mgc.$EXT $MDIR
cp -u ../mgs/mgs.$EXT $MDIR
cp -u ../quota/lquota.$EXT $MDIR
cp -u ../obdecho/obdecho.$EXT $MDIR

# prevent warnings on my uml
rm -f /lib/modules/`uname -r`/modules.*
echo "Depmod"
depmod -A -e

echo "Copying mount from local build dir to "$MDIR
cp -u ../utils/mount.lustre /sbin/.

MP="/sbin/modprobe"
MPI="$MP --ignore-install"

[ -e $MODFILE ] || touch $MODFILE
if [ `egrep -c "lustre|lnet" $MODFILE` -eq 0 ]; then
    echo Modifying $MODFILE
    echo "# Lustre modules added by $0" >> $MODFILE
    echo "# Networking options, see /sys/module/lnet/parameters" >> $MODFILE
    echo "options lnet networks=tcp" >> $MODFILE
    echo "# end Lustre modules" >> $MODFILE
fi

#  To generate gdb debug file:
# modprobe lustre; modprobe mds; modprobe obdfilter; modprobe mgs; modprobe mgc
# rm -f /r/tmp/ogdb-`hostname`
# ./lctl modules > /r/tmp/ogdb-`hostname`
