#!/bin/sh

MDIR=/lib/modules/`uname -r`/lustre
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

cp -u ../../lustre/mds/mds.ko $MDIR
cp -u ../../lustre/osd/osd.ko $MDIR
cp -u ../../lustre/obdfilter/obdfilter.ko $MDIR
cp -u ../../lustre/ost/ost.ko $MDIR
cp -u ../../lustre/mgs/mgs.ko $MDIR
cp -u ../../lustre/lov/lov.ko $MDIR
cp -u ../../lustre/ptlrpc/ptlrpc.ko $MDIR
cp -u ../../lustre/obdecho/obdecho.ko $MDIR
cp -u ../../lustre/llite/llite.ko $MDIR
cp -u ../../lustre/mgc/mgc.ko $MDIR
cp -u ../../lustre/ldiskfs/ldiskfs.ko $MDIR
cp -u ../../lustre/ldiskfs/quotafmt_test.ko $MDIR
cp -u ../../lustre/osc/osc.ko $MDIR
cp -u ../../lustre/mdt/mdt.ko $MDIR
cp -u ../../lustre/quota/lquota.ko $MDIR
cp -u ../../lustre/quota/quotactl_test.ko $MDIR
cp -u ../../lustre/quota/quotacheck_test.ko $MDIR
cp -u ../../lustre/cmm/cmm.ko $MDIR
cp -u ../../lustre/mdc/mdc.ko $MDIR
cp -u ../../lustre/lvfs/fsfilt_ldiskfs.ko $MDIR
cp -u ../../lustre/lvfs/lvfs.ko $MDIR
cp -u ../../lustre/obdclass/llog_test.ko $MDIR
cp -u ../../lustre/obdclass/obdclass.ko $MDIR
cp -u ../../lustre/mdd/mdd.ko $MDIR
cp -u ../../lustre/fld/fld.ko $MDIR
cp -u ../../lustre/fid/fid.ko $MDIR
cp -u ../../lnet/libcfs/libcfs.ko $MDIR
cp -u ../../lnet/tests/pingcli.ko $MDIR
cp -u ../../lnet/tests/spingsrv.ko $MDIR
cp -u ../../lnet/tests/pingsrv.ko $MDIR
cp -u ../../lnet/tests/spingcli.ko $MDIR
cp -u ../../lnet/lnet/lnet.ko $MDIR
cp -u ../../lnet/klnds/socklnd/ksocklnd.ko $MDIR


# prevent warnings on my uml
rm -f /lib/modules/`uname -r`/modules.*
echo "Depmod"
depmod -a -e

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
    echo "alias lustre llite" >> $MODFILE
    echo "# end Lustre modules" >> $MODFILE
fi

#  To generate gdb debug file:
# modprobe lustre; modprobe mds; modprobe obdfilter; modprobe mgs; modprobe mgc
# rm -f /r/tmp/ogdb-`hostname`
# ./lctl modules > /r/tmp/ogdb-`hostname`
