#!/bin/bash

# Requires the pre-configured samba machine
# RPMS required are :
# server:
#      samba
#      samba-common
#      cifs-utils
# clients:
#      samba-client
#      samba-common
#      cifs-utils

#set -vx

smb_status() {
	local smbsrv=${1}
	local rc=0

	do_node $smbsrv "service smb status" || rc=$?
	return $rc
}

configure_smb() {
	local smbsrv=${1}
	local smbshare=${2}
	local smbuser=${3}
	local smbpasswd=${4}
	local path=${5}
	local smbconftmp=${6}
	local smbconf
	local path

	smbconf=$(do_node $smbsrv \
		smbd -b | grep CONFIGFILE | sed -re 's/\s+CONFIGFILE: //g')
	grep -q $smbshare $smbconf && return

	do_node $smbsrv "cp $smbconf $smbconftmp"
	do_node $smbsrv "cat <<EOF >> $smbconf
	[$smbshare]
	path = $path
	browseable = yes
	writable = yes
	guest ok = yes
	write list = $smbuser
EOF"
	# The samba daemons are constantly (once every 60 seconds) checking the
	# smb.conf file, so it is good practice to keep this file small.
	local smbsmall=$(do_nodes $smbsrv "mktemp -t smb.conf.small.XXX")
	do_node $smbsrv "testparm -s >$smbsmall"
	do_node $smbsrv "testparm -s $smbsmall >$smbconf"

	do_node $smbsrv "echo $smbpasswd | tee - | smbpasswd -a $smbuser -s" ||
		do_node $smbsrv "printf '$smbpasswd\n$smbpasswd\n' |\
			tee - | smbpasswd -a $smbuser -s"
}

restore_config_smb() {
	local smbsrv=${1}
	local smbconftmp=${2}
	local smbconf

	smbconf=$(do_node $smbsrv \
		smbd -b | grep CONFIGFILE | sed -re 's/\s+CONFIGFILE: //g')

	echo -e "\nRestoring smb config from $smbconftmp ..."
	do_node $smbsrv "cp $smbconftmp $smbconf"
}

setup_cifs() {
	local smbsrv=${1}
	local smbshare=${2}
	local smbclimntpt=${3}
	local smbuser=${4}
	local smbpasswd=${5}
	local smbclients=${6}

	do_node $smbsrv "service smb restart" || return 1
	local parameter_path=$(do_node $smbsrv \
		"testparm -s --section-name $smbshare --parameter-name path 2> /dev/null")
	[[ -z $parameter_path ]] && return 1
	do_nodesv $smbsrv "chmod a+xrw $parameter_path"
	do_nodesv $smbsrv "ls -ald $parameter_path"

	local cmd="mount -t cifs //$smbsrv/$smbshare $smbclimntpt -o user=$smbuser,pass=$smbpasswd"
	echo -e "\nMounting CIFS clients $smbclients : $cmd"
	do_nodesv $smbclients "$cmd" || return 1
	do_nodesv $smbclients mount | grep $smbclimntpt
}

cleanup_cifs() {
	local smbsrv=${1}
	local smbclimntpt=${2}
	local smbclients=${3}

	echo -e "\nUnmounting CIFS clients..."
	do_nodes $smbclients "umount -f $smbclimntpt" || return 1
	do_node $smbsrv "service smb stop"
}
