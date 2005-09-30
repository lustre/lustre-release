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

cp ../../portals/libcfs/libcfs.$EXT $MDIR
cp ../../portals/portals/portals.$EXT $MDIR
cp ../../portals/knals/socknal/ksocknal.$EXT $MDIR
cp ../lvfs/lvfs.$EXT $MDIR
cp ../obdclass/obdclass.$EXT $MDIR
cp ../ptlrpc/ptlrpc.$EXT $MDIR
#cp ../obdclass/confobd.$EXT $MDIR
cp ../mdc/mdc.$EXT $MDIR
cp ../osc/osc.$EXT $MDIR
cp ../lov/lov.$EXT $MDIR
cp ../mds/mds.$EXT $MDIR
cp ../lvfs/$FSFLT.$EXT $MDIR
[ $KVER == "26" ] && cp ../ldiskfs/ldiskfs.$EXT $MDIR
cp ../ost/ost.$EXT $MDIR
cp ../obdfilter/obdfilter.$EXT $MDIR
cp ../llite/llite.$EXT $MDIR

# prevent warnings on my uml
rm -f /lib/modules/`uname -r`/modules.*
echo "Depmod"
depmod -a -e

echo "Copying mount and acceptor from local build dir to "$MDIR
cp ../../portals/utils/acceptor /sbin/.
cp ../utils/mount.lustre /sbin/.

[ -e $MODFILE ] || touch $MODFILE
if [ `grep -c lustre $MODFILE` -eq 0 ]; then
    echo Modifying $MODFILE
    echo "# Lustre modules added by $0" >> $MODFILE
    if [ $KVER -eq 24 ]; then
	echo alias lustre null >> $MODFILE
	echo above lustre llite osc mdc >> $MODFILE
	echo above mds llite confobd osc >> $MODFILE
	echo alias oss ost >> $MODFILE
	echo above ost llite confobd obdfilter >> $MODFILE
	echo above confobd $FSFLT >> $MODFILE
	echo below ptlrpc ksocknal >> $MODFILE
    else
	MP="/sbin/modprobe"
	MPI="$MP --ignore-install"
	echo "install ptlrpc $MP ksocknal && $MPI ptlrpc" >> $MODFILE
	echo "install confobd $MP $FSFLT && $MPI confobd" >> $MODFILE
	echo "install ost $MP llite confobd obdfilter && $MPI ost" >> $MODFILE
	echo "install oss $MP ost && $MPI oss" >> $MODFILE
	echo "install mds $MP llite confobd osc && $MPI mds" >> $MODFILE
	echo "install lustre $MP llite osc mdc" >> $MODFILE
    fi
    echo "# end Lustre modules" >> $MODFILE
fi
