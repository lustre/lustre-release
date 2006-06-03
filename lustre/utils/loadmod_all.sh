#!/bin/sh

dmesg -c >/dev/null
dmesg -n 8

modprobe mgs
modprobe fid
modprobe fld
modprobe mgc
modprobe osd
modprobe ost
modprobe obdfilter
modprobe mdd
modprobe cmm
modprobe mdt
modprobe mds
modprobe osc
modprobe mdc

HOST=`hostname`
echo -1 >/proc/sys/lnet/debug
echo "/r/tmp/$HOST.debug" >/proc/sys/lnet/daemon_file

