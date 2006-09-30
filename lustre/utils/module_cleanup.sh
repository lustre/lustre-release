#!/bin/sh

MDIR=/lib/modules/`uname -r`/lustre
mkdir -p $MDIR

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

echo "Removing Lustre modules from "$MDIR

rm -f $MDIR/*
depmod -a
rm -f /sbin/mount.lustre
rm -f /usr/sbin/l_getidentity
rm -f /usr/sbin/l_facl
