#!/bin/sh

MDIR=/lib/modules/`uname -r`/lustre
/bin/rm -rf $MDIR
mkdir -p $MDIR

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

cp -u ../../lnet/lnet/lnet.$EXT $MDIR
cp -u ../../lnet/libcfs/libcfs.$EXT $MDIR
cp -u ../../lnet/klnds/socklnd/ksocklnd.$EXT $MDIR
cp -u ../../lnet/tests/pingcli.$EXT $MDIR
cp -u ../../lnet/tests/pingsrv.$EXT $MDIR
cp -u ../../lustre/mgs/mgs.$EXT $MDIR
cp -u ../../lustre/quota/lquota.$EXT $MDIR
cp -u ../../lustre/quota/quotacheck_test.$EXT $MDIR
cp -u ../../lustre/quota/quotactl_test.$EXT $MDIR
cp -u ../../lustre/ptlrpc/ptlrpc.$EXT $MDIR
cp -u ../../lustre/fld/fld.$EXT $MDIR
cp -u ../../lustre/lov/lov.$EXT $MDIR
cp -u ../../lustre/mdc/mdc.$EXT $MDIR
cp -u ../../lustre/llite/lustre.$EXT $MDIR
cp -u ../../lustre/obdclass/llog_test.$EXT $MDIR
cp -u ../../lustre/obdclass/obdclass.$EXT $MDIR
cp -u ../../lustre/mdt/mdt.$EXT $MDIR
cp -u ../../lustre/fid/fid.$EXT $MDIR
cp -u ../../lustre/mds/mds.$EXT $MDIR
cp -u ../../lustre/osd/osd.$EXT $MDIR
cp -u ../../lustre/obdecho/obdecho.$EXT $MDIR
cp -u ../../lustre/obdfilter/obdfilter.$EXT $MDIR
cp -u ../../lustre/cmm/cmm.$EXT $MDIR
cp -u ../../lustre/ldiskfs/ldiskfs.$EXT $MDIR
cp -u ../../lustre/ldiskfs/quotafmt_test.$EXT $MDIR
cp -u ../../lustre/mdd/mdd.$EXT $MDIR
cp -u ../../lustre/osc/osc.$EXT $MDIR
cp -u ../../lustre/ost/ost.$EXT $MDIR
cp -u ../../lustre/mgc/mgc.$EXT $MDIR
cp -u ../../lustre/lvfs/fsfilt_ldiskfs.$EXT $MDIR
cp -u ../../lustre/lvfs/lvfs.$EXT $MDIR
cp -u ../../lustre/lmv/lmv.$EXT $MDIR

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
