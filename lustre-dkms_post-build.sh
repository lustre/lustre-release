#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#
# lustre-dkms_post-build.sh
#
# Script run after dkms build
#

#
# $1 : $module
# $2 : $module_version
# $3 : $kernelver
# $4 : $kernel_source_dir
# $5 : $arch
# $6 : $source_tree
# $7 : $dkms_tree
# $8 : $kmoddir
#
# This script ensure that ALL Lustre kernel modules that have been built
# during DKMS build step of lustre[-client]-dkms module will be moved in
# DKMS vault/repository, and this before the build directory content will be
# trashed.
# This is required because dkms.conf file is only sourced at the very
# beginning of the DKMS build step when its content has to be on-target
# customized during pre_build script. This can lead to incomplete list
# of built Lustre kernel modules then to be saved for next DKMS install step.
#

#
# Use this place to also save config.log that has been generated during
# pre_build.
# $7/$1/$2/$3/$5/log repository should have already been created to save
# make.log and $kernel_config
#

mkdir -p "$7/$1/$2/$3/$5/log"
cp -f "$7/$1/$2/build/config.log" "$7/$1/$2/$3/$5/log/config.log" 2>/dev/null
cp -f "$7/$1/$2/build/config.h" \
    "$7/$1/$2/build/Module.symvers" \
    "$7/$1/$2/$3/$5/" 2> /dev/null

case $1 in
    lustre-zfs|lustre-all)
	# To satisfy the content of lustre-osd-zfs-mount install these scripts:
	for script in statechange-lustre.sh \
		      vdev_attach-lustre.sh \
		      vdev_clear-lustre.sh \
		      vdev_remove-lustre.sh
	do
		install -D -m 0755 lustre/scripts/${script} /etc/zfs/zed.d/${script}
	done
	;;
esac

flavor=$(echo $3 | tr '-' '\n' | tail -1)
# for non-suse distros flavor should be 'default'
elcheck=$(echo ${flavor} | tr '.' '\n' | tail -1)
[[ ${elcheck} == $5 ]] && flavor='default'

# includes for this kapi module:
rm -fr $7/$1/$2/$3/$5/kapi
kapi=$7/$1/$2/$3/$5/kapi/include
mkdir -p ${kapi}/$5/$flavor
ln -s $7/$1/$2/$3/$5/config.h ${kapi}/$5/$flavor
ln -s $7/$1/$2/$3/$5/Module.symvers ${kapi}/$5/$flavor

# LNet headers:
for fname in $(find lnet/include -type f -name \*.h); do
    target=$(echo ${fname} | sed -e 's:^lnet/include/::g')
    if [[ ${target} == uapi/* ]]; then
        header=$(echo ${target} | sed -e 's:^uapi/linux/lnet/::g')
        install -D -m 0644 ${fname} ${kapi}/uapi/linux/lnet/${header}
        install -D -m 0644 ${fname} ${kapi}/linux/lnet/${header}
        >&2 echo "installing ${fname} => ${kapi}/uapi/linux/lnet/${header}"
        >&2 echo "installing ${fname} => ${kapi}/linux/lnet/${header}"
    else
        install -D -m 0644 ${fname} ${kapi}/${target}
        >&2 echo "installing ${fname} => ${kapi}/${target}"
    fi
done

## Lustre headers:
for fname in $(find libcfs/include/libcfs -type f -name \*.h); do
    target=$(echo ${fname} | sed -e 's:^libcfs/include/::g')
    install -D -m 0644 ${fname} ${kapi}/${target}
    >&2 echo "installing ${fname} => ${kapi}/${target}"
done

alternatives --install /usr/src/lustre lustre ${kapi} 90

