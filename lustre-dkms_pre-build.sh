#!/bin/bash
# $1 : $module
# $2 : $module_version
# $3 : $kernelver
# $4 : $kernel_source_dir
# $5 : $arch
# $6 : $source_tree
# $7 : $dkms_tree

if [ $1 = "lustre-client" ] ; then
	SERVER="--disable-server"
	KERNEL_STUFF=""
else
	SPL_VERSION=$(dkms status -m spl -k $3 -a $5 | awk -F', ' '{print $2; exit 0}' | grep -v ': added$')
	if [ -z $SPL_VERSION ] ; then
		echo "spl-dkms package must already be installed and built under DKMS control"
		exit 1
	fi
	ZFS_VERSION=$(dkms status -m zfs -k $3 -a $5 | awk -F', ' '{print $2; exit 0}' | grep -v ': added$')
	if [ -z $ZFS_VERSION ] ; then
		echo "zfs-dkms package must already be installed and built under DKMS control"
		exit 1
	fi

	SERVER="--enable-server --disable-ldiskfs --with-linux=$4 --with-linux-obj=$4 \
	       --with-spl=$6/spl-${SPL_VERSION} \
	       --with-spl-obj=$7/spl/${SPL_VERSION}/$3/$5 \
	       --with-zfs=$6/zfs-${ZFS_VERSION} \
	       --with-zfs-obj=$7/zfs/${ZFS_VERSION}/$3/$5"

	KERNEL_STUFF="--with-linux=$4 --with-linux-obj=$4"
fi

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
	--disable-manpages --disable-dlc

if [ $? != 0 ] ; then
	echo "configure error, check $7/$1/$2/build/config.log"
	exit 1
fi
