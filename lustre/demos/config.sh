#!/bin/sh
# File which holds configuation parameters in a single place to avoid any
# mismatch between scripts (especially the cleanup scripts, which are
# destructive).
#set -vx

# Major number for OBD devices
OBDMAJ=186

# If LOOPDEV is empty (""), then no loopback device will be configured.
# If TMPFILE is empty (""), then no temporary file will be created for loop.
TMPFILE="/tmp/obdfs.tmpfile"
LOOPDEV="/dev/loop0"

# If LOOPDEV is empty, then it is assumed that BASEDEV is a real block device
# that doesn't mind being overwritten - don't use a partition with data on it!!
BASEDEV="$LOOPDEV"

# The following are mount points for the filesystems during the test.
MNTOBD="/mnt/obd"
MNTSNAP="/mnt/snap"
MNTSNAP2="/mnt/snap2"

# This is where the snapshot table will be stored:
SNAPTABLE="/tmp/obdfs.snaptable"

# A simple routine called by most of the scripts to help debugging.  The
# kernel code has a lot of debugging statements, so this helps us keep
# track of what is going on in user-land to generate the kernel messages.
# We append directly to the messages file instead of using logger so that
# our checkpoints are not lost when the syslogd is very busy.
plog () {
    if [ "$1" = "log" ]; then
	shift
	echo "******** $* **********" >> /var/log/messages
	echo "$*"
    else
	echo "****start**** $* *****" >> /var/log/messages
	echo "$*"
	$*
	# sleep 3 # to allow messages to be flushed
	echo "*****end***** $* *****" >> /var/log/messages
    fi
}

