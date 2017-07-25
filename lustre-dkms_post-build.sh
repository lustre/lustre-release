#!/bin/bash
# $1 : $module
# $2 : $module_version
# $3 : $kernelver
# $4 : $kernel_source_dir
# $5 : $arch
# $6 : $source_tree
# $7 : $dkms_tree
#
# This script ensure that ALL Lustre kernel modules that have been built
# during DKMS build step of lustre[-client]-dkms module will be moved in
# DKMS vault/repository, and this before the build directory content will be
# trashed.
# This is required because dkms.conf file is only sourced at the very
# beginning of the DKMS build step when its content has to be on-target
# customized during pre_build script. This can lead to incomplete list
# of built Lustre kernel modules then to be saved for next DKMS install step.

# Use this place to also save config.log that has been generated during
# pre_build.
# $7/$1/$2/$3/$5/log repository should have already been created to save
# make.log and $kernel_config
mkdir -p "$7/$1/$2/$3/$5/log"
cp -f "$7/$1/$2/build/config.log" "$7/$1/$2/$3/$5/log/config.log" 2>/dev/null
cp -f "$7/$1/$2/build/config.h" \
    "$7/$1/$2/build/Module.symvers" \
    "$7/$1/$2/$3/$5/" 2> /dev/null
