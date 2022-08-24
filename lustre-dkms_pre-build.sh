#!/bin/bash
# $1 : $module
# $2 : $module_version
# $3 : $kernelver
# $4 : $kernel_source_dir
# $5 : $arch
# $6 : $source_tree
# $7 : $dkms_tree

case $1 in
    lustre-client)
	SERVER="--disable-server"
	KERNEL_STUFF=""
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
      if [[ ${LUSTRE_DKMS_DISABLE_CDEBUG,,} == @(y|yes) ]]
      then
	echo --disable-libcfs-cdebug
      fi
      if [[ ${LUSTRE_DKMS_DISABLE_TRACE,,} == @(y|yes) ]]
      then
	echo --disable-libcfs-trace
      fi
      if [[ ${LUSTRE_DKMS_DISABLE_ASSERT,,} == @(y|yes) ]]
      then
	echo --disable-libcfs-assert
      fi
    }
  )

rpm -qa | grep krb5-devel >/dev/null
if [ $? == 0 ] ; then
	GSS="--enable-gss"
else
	GSS="--disable-gss"
fi

# run a configure pass to clean "--enable-dist" only effect and also to
# ensure local/on-target environment to be taken into account for
# dkms.mkconf script customizations and before next build/MAKE step
./configure --prefix=/usr --enable-modules --disable-iokit --disable-snmp \
	--disable-doc --disable-utils --disable-tests --disable-maintainer-mode \
	$KERNEL_STUFF $GSS $SERVER $DKMS_CONFIG_OPTS \
	--disable-manpages --disable-mpitests

if [ $? != 0 ] ; then
	echo "configure error, check $7/$1/$2/build/config.log"
	exit 1
fi
