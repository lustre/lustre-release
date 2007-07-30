#!/bin/sh

dmesg -c >/dev/null
dmesg -n 8


modprobe mds
modprobe osd
modprobe obdfilter
modprobe ost
modprobe mgs
modprobe lov
modprobe ptlrpc
modprobe obdecho
modprobe lustre
modprobe mgc
modprobe ldiskfs
modprobe osc
modprobe mdt
modprobe lquota
modprobe cmm
modprobe mdc
modprobe fsfilt_ldiskfs
modprobe lvfs
modprobe obdclass
modprobe mdd
modprobe fld
modprobe fid
modprobe lmv
modprobe libcfs
modprobe pingcli
modprobe spingsrv
modprobe pingsrv
modprobe spingcli
modprobe lnet
modprobe ksocklnd


#  To generate gdb debug file:
rm -f /r/tmp/ogdb-`hostname`
./lctl modules > /r/tmp/ogdb-`hostname`


HOST=`hostname`
echo -1 >/proc/sys/lnet/debug
echo "/r/tmp/$HOST.debug" >/proc/sys/lnet/daemon_file

