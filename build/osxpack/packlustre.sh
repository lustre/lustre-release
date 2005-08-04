#!/bin/sh
#
# This script is used to create package directory tree used
# by PackageMaker in OS X.

PREFIX=$1
STAGE=$2

RESOURCE=$PWD/build/osxpack
if ! [ -d $RESOURCE ]; then
	echo "Your tree seems to be missing $RESOURCE." >&2
fi

if [ "x$PREFIX" == "x" ]; then
	PREFIX=/home/cfs/package
fi

if [ "x$STAGE" == "x" ]; then
	STAGE=/System/Library/Extensions
fi

if ! [ -d $STAGE/llite.kext ]; then
	echo "Sorry, cannot find stage files for package"
	exit 1
fi

if ! [ -d $PREFIX ]; then
	mkdir -p $PREFIX
fi

if ! [ -d $PREFIX/Install_resources ]; then
	mkdir -p $PREFIX/Install_resources
fi

if ! [ -d $PREFIX/Package_contents ]; then
	mkdir -p $PREFIX/Package_contents
fi

CONTENTS=$PREFIX/Package_contents

if ! [ -d $CONTENTS/System/Libraray/Extensions ]; then
	mkdir -p $CONTENTS/System/Library/Extensions
fi
# IMPORTANT
# /etc is symlink of /private/etc in OS X, if we 
# just use $CONTENTS/etc, it will OVERWRITE /etc in
# installation target, that means all files in /etc 
# will be lost, the system will be corrupted.
if ! [ -d $CONTENTS/private/etc ]; then
	mkdir -p $CONTENTS/private/etc
fi

if ! [ -d $CONTENTS/sbin ]; then
	mkdir -p $CONTENTS/sbin
fi

cp -f $RESOURCE/*.txt $PREFIX/Install_resources/
cp -f $RESOURCE/*flight $PREFIX/Install_resources/
cp -f $RESOURCE/sysctl.conf $CONTENTS/private/etc
cp -f $RESOURCE/uninstall_lustre $CONTENTS/sbin
cp -f $RESOURCE/unload_lustre $CONTENTS/sbin
cp -rf $STAGE/llite.kext $CONTENTS/System/Library/Extensions
cp -rf $STAGE/mdc.kext $CONTENTS/System/Library/Extensions
cp -rf $STAGE/lov.kext $CONTENTS/System/Library/Extensions
cp -rf $STAGE/osc.kext $CONTENTS/System/Library/Extensions
cp -rf $STAGE/ptlrpc.kext $CONTENTS/System/Library/Extensions
cp -rf $STAGE/ptlrpcs.kext $CONTENTS/System/Library/Extensions
cp -rf $STAGE/obdclass.kext $CONTENTS/System/Library/Extensions
cp -rf $STAGE/lvfs.kext $CONTENTS/System/Library/Extensions
cp -rf $STAGE/ksocknal.kext $CONTENTS/System/Library/Extensions
cp -rf $STAGE/portals.kext $CONTENTS/System/Library/Extensions
cp -rf $STAGE/libcfs.kext $CONTENTS/System/Library/Extensions
