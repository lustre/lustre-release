#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#
# lustre-dkms_pre-build.sh
#
# Script run before dkms build
#

#
# $1 : $module
# $2 : $module_version
# $3 : $kernelver
# $4 : $kernel_source_dir
# $5 : $arch
# $6 : $source_tree
# $7 : $dkms_tree
# $8 : $kmoddir [lustre-client either 'extra|updates']

case $1 in
    lustre-client)
	SERVER="--disable-server --enable-client"
	ksrc="$(dirname $4)/source"
	KERNEL_STUFF="--with-linux=$(realpath $ksrc) --with-linux-obj=$(realpath $4)"
	name=$1
	kmoddir=$8
	flavor=$(echo $3 | tr '-' '\n' | tail -1)
	if [ -f /usr/src/kfabric/${flavor}/Module.symvers ]; then
		KERNEL_STUFF="${KERNEL_STUFF} --with-kfi=/usr/src/kfabric/${flavor}"
	elif [ -f /usr/src/kfabric/default/Module.symvers ]; then
		KERNEL_STUFF="${KERNEL_STUFF} --with-kfi=/usr/src/kfabric/default"
	fi
	O2IBPATH=""
	if [ -d /usr/src/ofa_kernel/${flavor} ]; then
		O2IBPATH=/usr/src/ofa_kernel/${flavor}
	elif [ -d /usr/src/ofa_kernel/default ]; then
		O2IBPATH=/usr/src/ofa_kernel/default
	fi
	if [ -n ${O2IBPATH} ]; then
		KERNEL_STUFF="${KERNEL_STUFF} --with-o2ib=${O2IBPATH}"
	fi
	if [ -n ${kmoddir} ]; then
		KERNEL_STUFF="${KERNEL_STUFF} --with-kmp-moddir=${kmoddir}/${name}"
	fi
	sh ./autogen.sh
	;;

    lustre-zfs|lustre-all)
	LDISKFS=""
	if [ "$1" == "lustre-zfs" ]; then
	    LDISKFS="--disable-ldiskfs"
	fi

	# ZFS and SPL are version locked
	ZFS_VERSION=$(dkms status -m zfs -k $3 -a $5 2>/dev/null |
		      sed -e 's:zfs/::g' -e 's:,.*::g' | cut -d: -f1 |
		      sort -V | head -n1)
	if [ -z $ZFS_VERSION ] ; then
		echo "zfs-dkms package must already be installed and built under DKMS control"
		exit 1
	fi

	SERVER="--enable-server $LDISKFS \
		--with-linux=$4 --with-linux-obj=$4 \
		--with-spl=$(realpath $7/spl/${ZFS_VERSION}/source) \
		--with-spl-obj=$(realpath $7/spl/kernel-$3-$5) \
		--with-zfs=$(realpath $7/zfs/${ZFS_VERSION}/source) \
		--with-zfs-obj=$(realpath $7/zfs/kernel-$3-$5)"

	KERNEL_STUFF="--with-linux=$4 --with-linux-obj=$4"
	;;

    lustre-ldiskfs)
	SERVER="--enable-server --without-zfs --without-spl \
		--with-linux=$4 --with-linux-obj=$4"

	KERNEL_STUFF="--with-linux=$4 --with-linux-obj=$4"
	;;
esac

PACKAGE_CONFIG="/etc/sysconfig/lustre"
DKMS_CONFIG_OPTS=$(
    [[ -r ${PACKAGE_CONFIG} ]] \
    && source ${PACKAGE_CONFIG} \
    && shopt -q -s extglob \
    && \
    {
	if [[ -n ${LUSTRE_DKMS_DISABLE_CDEBUG} ]] ; then
		[[ ${LUSTRE_DKMS_DISABLE_CDEBUG,,} == @(y|yes) ]] &&
			echo --disable-libcfs-cdebug ||
			echo --enable-libcfs-cdebug
	fi
	if [[ -n ${LUSTRE_DKMS_DISABLE_TRACE} ]] ; then
		[[ ${LUSTRE_DKMS_DISABLE_TRACE,,} == @(y|yes) ]] &&
			echo --disable-libcfs-trace ||
			echo --enable-libcfs-trace
	fi
	if [[ -n ${LUSTRE_DKMS_DISABLE_ASSERT} ]] ; then
		[[ ${LUSTRE_DKMS_DISABLE_ASSERT,,} == @(y|yes) ]] &&
			echo --disable-libcfs-assert ||
			echo --enable-libcfs-assert
	fi
	if [[ -n ${LUSTRE_DKMS_ENABLE_GSS} ]] ; then
		[[ ${LUSTRE_DKMS_ENABLE_GSS,,} == @(y|yes) ]] &&
			echo --enable-gss ||
			echo --disable-gss
	fi
	if [[ -n ${LUSTRE_DKMS_ENABLE_GSS_KEYRING} ]] ; then
		[[ ${LUSTRE_DKMS_ENABLE_GSS_KEYRING,,} == @(y|yes) ]] &&
			echo --enable-gss-keyring ||
			echo --disable-gss-keyring
	fi
	if [[ -n ${LUSTRE_DKMS_ENABLE_CRYPTO} ]] ; then
		[[ ${LUSTRE_DKMS_ENABLE_CRYPTO,,} == @(y|yes) ]] &&
			echo --enable-crypto ||
			echo --disable-crypto
	fi
	if [[ -n ${LUSTRE_DKMS_ENABLE_IOKIT} ]] ; then
		[[ ${LUSTRE_DKMS_ENABLE_IOKIT,,} == @(y|yes) ]] &&
			echo --enable-iokit ||
			echo --disable-iokit
	fi
	[[ -n ${LUSTRE_DKMS_CONFIGURE_EXTRA} ]] &&
		echo ${LUSTRE_DKMS_CONFIGURE_EXTRA}
    }
)

echo "${DKMS_CONFIG_OPTS} " | grep -E -q -- '--disable-gss[^-]|--enable-gss[^-]'
if [ $? != 0 ] ; then
	# User did not force, guess for rpm distros
	rpm -qa | grep krb5-devel >/dev/null
	[[ $? == 0 ]] && GSS="--enable-gss" || GSS="--disable-gss"
fi

# run a configure pass to clean "--enable-dist" only effect and also to
# ensure local/on-target environment to be taken into account for
# dkms.mkconf script customizations and before next build/MAKE step
./configure --prefix=/usr --enable-modules --disable-iokit \
	--disable-doc --disable-utils --disable-tests --disable-maintainer-mode \
	$KERNEL_STUFF $GSS $SERVER $DKMS_CONFIG_OPTS \
	--disable-manpages --disable-mpitests

if [ $? != 0 ] ; then
	echo "configure error, check $7/$1/$2/build/config.log"
	exit 1
fi
