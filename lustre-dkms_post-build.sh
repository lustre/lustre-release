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
mv -f "$7/$1/$2/build/config.log" "$7/$1/$2/$3/$5/log/config.log" 2>/dev/null

# read last dkms.conf version that has just been customized during pre_build
source $6/$1-$2/dkms.conf

# Make sure all the modules built successfully
for ((count=0; count < ${#BUILT_MODULE_NAME[@]}; count++)); do
	# Lustre supported kernels are >= 2.5, so don't need to check for old .o
	# module suffix
	[[ -e ${BUILT_MODULE_LOCATION[$count]}${BUILT_MODULE_NAME[$count]}.ko ]] && continue
	echo "Build of ${BUILT_MODULE_NAME[$count]}.ko failed for: $3 ($5)" \
	     "Consult logs in $7/$1/$2/$3/$5/log/ for more information."
done

# Strip modules ?
for ((count=0; count < ${#BUILT_MODULE_NAME[@]}; count++)); do
	[[ ${STRIP[$count]} = '' ]] && STRIP[$count]=${STRIP[0]:-yes}
	[[ ${STRIP[$count]} != no ]] && strip -g "$7/$1/$2/build/${BUILT_MODULE_LOCATION[$count]}${BUILT_MODULE_NAME[$count]}.ko"

	# Save a copy of the new module in save area that should have been created in previous build steps
	mkdir -p "$7/$1/$2/$3/$5/module" >/dev/null
	# if DEST_MODULE_NAME[] is different than BUILD_MODULE_NAME[], need to use it as the module name in save area
	# this is not presently the case for none of the Lustre kernel modules.
	cp -f "$7/$1/$2/build/${BUILT_MODULE_LOCATION[$count]}${BUILT_MODULE_NAME[$count]}.ko" \
	      "$7/$1/$2/$3/$5/module/${BUILT_MODULE_NAME[$count]}.ko" >/dev/null
done

