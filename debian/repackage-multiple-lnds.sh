#!/bin/bash
# Repackage LNDs into multiple packages:
KVERS=$1
VER=$2
LMDEB=$(ls $3)

origin=$(dirname $(realpath $LMDEB))
modpkg=$(basename -s .deb $LMDEB)
arch=$(echo $modpkg | cut -d_ -f3)
kfipkg="lustre-lnet-module-kfilnd-${KVERS}_${VER}_${arch}"
gnipkg="lustre-lnet-module-gnilnd-${KVERS}_${VER}_${arch}"
sockpkg="lustre-lnet-module-socklnd-${KVERS}_${VER}_${arch}"
o2ibpkg="lustre-lnet-module-o2iblnd-${KVERS}_${VER}_${arch}"
in_kernel_o2ibpkg="lustre-lnet-module-in-kernel-o2iblnd-${KVERS}_${VER}_${arch}"

VERBOSE=''

# expand the modules package:
cd debian/tmp/re-pkg/${modpkg}
ar x ../../../../$LMDEB
cd DEBIAN; tar xf ../control.tar*; cd ..
tar xf data.tar*
mv debian-binary DEBIAN
rm data.tar* control.tar*
modpath=$(dirname $(find . -name ksocklnd.ko))
cd ..

# NOTE: pwd is debian/tmp/re-pkg

if [[ "x${VERBOSE}" = "x-v" ]] ; then
	echo "repackage-multiple-lnds"
	echo "  DEB:      '${LMDEB}'"
	echo "  KVERS:    '${KVERS}'"
	echo "  VER:      '${VER}"
	echo "  arch:     '${arch}"
	echo "  origin:   '${origin}'"
	echo "  modpath:  '${modpath}'"
fi

for pkg in ${modpkg} ${kfipkg} ${gnipkg} ${sockpkg} ${o2ibpkg} ${in_kernel_o2ibpkg}
do
    mkdir -p ${pkg}/DEBIAN
    mkdir -p ${pkg}/${modpath}
done

# Migate individual lnds to new packages
if [[ -f ${modpkg}/${modpath}/kkfilnd.ko ]] ; then
    [[ x${VERBOSE} = 'x-v' ]] && echo "Repackage kkfilnd.ko"
    mv ${modpkg}/${modpath}/kkfilnd.ko ${kfipkg}/${modpath}/
    cp ${modpkg}/DEBIAN/* ${kfipkg}/DEBIAN
    grep kkfilnd.ko ${modpkg}/DEBIAN/md5sums > ${kfipkg}/DEBIAN/md5sums
    sed -e "s:_KVERS_:${KVERS}:g" -e "s:_VERS_:${VER}:g" -e "s:_ARCH_:${arch}:g" \
        ../../control-lnet-kfilnd.in > ${kfipkg}/DEBIAN/control
    dpkg-deb --build ${kfipkg}
    cp ${VERBOSE} ${kfipkg}.deb ${origin}
fi
if [[ -f ${modpkg}/${modpath}/kgnilnd.ko ]] ; then
    [[ x${VERBOSE} = 'x-v' ]] && echo "Repackage kgnilnd.ko"
    mv ${modpkg}/${modpath}/kgnilnd.ko ${gnipkg}/${modpath}/
    cp ${modpkg}/DEBIAN/* ${gnipkg}/DEBIAN
    grep kgnilnd.ko ${modpkg}/DEBIAN/md5sums > ${gnipkg}/DEBIAN/md5sums
    sed -e "s:_KVERS_:${KVERS}:g" -e "s:_VERS_:${VER}:g" -e "s:_ARCH_:${arch}:g" \
        ../../control-lnet-gnilnd.in > ${gnipkg}/DEBIAN/control
    dpkg-deb --build ${gnipkg}
    cp ${VERBOSE} ${gnipkg}.deb ${origin}
fi
if [[ -f ${modpkg}/${modpath}/ksocklnd.ko ]] ; then
    [[ x${VERBOSE} = 'x-v' ]] && echo "Repackage ksocklnd.ko"
    mv ${modpkg}/${modpath}/ksocklnd.ko ${sockpkg}/${modpath}/
    cp ${modpkg}/DEBIAN/* ${sockpkg}/DEBIAN
    grep ksocklnd.ko ${modpkg}/DEBIAN/md5sums > ${sockpkg}/DEBIAN/md5sums
    sed -e "s:_KVERS_:${KVERS}:g" -e "s:_VERS_:${VER}:g" -e "s:_ARCH_:${arch}:g" \
        ../../control-lnet-socklnd.in > ${sockpkg}/DEBIAN/control
    dpkg-deb --build ${sockpkg}
    cp ${VERBOSE} ${sockpkg}.deb ${origin}
fi
if [[ -f ${modpkg}/${modpath}/ko2iblnd.ko ]] ; then
    [[ x${VERBOSE} = 'x-v' ]] && echo "Repackage ko2iblnd.ko"
    mv ${modpkg}/${modpath}/ko2iblnd.ko ${o2ibpkg}/${modpath}/
    cp ${modpkg}/DEBIAN/* ${o2ibpkg}/DEBIAN
    grep ko2iblnd.ko ${modpkg}/DEBIAN/md5sums > ${o2ibpkg}/DEBIAN/md5sums
    sed -e "s:_KVERS_:${KVERS}:g" -e "s:_VERS_:${VER}:g" -e "s:_ARCH_:${arch}:g" \
        ../../control-lnet-o2iblnd.in > ${o2ibpkg}/DEBIAN/control
    dpkg-deb --build ${o2ibpkg}
    cp ${VERBOSE} ${o2ibpkg}.deb ${origin}
fi
if [[ -f ${modpkg}/${modpath}/in-kernel-ko2iblnd.ko ]] ; then
    [[ x${VERBOSE} = 'x-v' ]] && echo "Repackage in-kernel-ko2iblnd.ko as ko2iblnd.ko"
    mv ${modpkg}/${modpath}/in-kernel-ko2iblnd.ko ${in_kernel_o2ibpkg}/${modpath}/ko2iblnd.ko
    cp ${modpkg}/DEBIAN/* ${in_kernel_o2ibpkg}/DEBIAN
    grep in-kernel-ko2iblnd.ko ${modpkg}/DEBIAN/md5sums > ${in_kernel_o2ibpkg}/DEBIAN/md5sums
    sed -e "s:_KVERS_:${KVERS}:g" -e "s:_VERS_:${VER}:g" -e "s:_ARCH_:${arch}:g" \
        ../../control-lnet-in-kernel-o2iblnd.in > ${in_kernel_o2ibpkg}/DEBIAN/control
    dpkg-deb --build ${in_kernel_o2ibpkg}
    cp ${VERBOSE} ${in_kernel_o2ibpkg}.deb ${origin}
fi

# Rebuilding lustre-[client|server]-modules without lnet lnd drivers
dpkg-deb --build ${modpkg}
cp ${VERBOSE} ${modpkg}.deb ${origin}
