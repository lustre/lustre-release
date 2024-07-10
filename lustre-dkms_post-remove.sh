#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#
# lustre-dkms_post-remove.sh
#
# Script run after dkms remove
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

kapi=$7/$1/$2/$3/$5/kapi/include
alternatives --remove lustre ${kapi}
rm -fr $7/$1/$2/$3/$5/kapi
