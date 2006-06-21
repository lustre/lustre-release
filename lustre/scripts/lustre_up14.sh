#!/bin/bash
#
# Reads old MDS config logs for transferring to a MGS
#
###############################################################################

TMP=${TMP:-/tmp/logs}

# Usage
usage() {
	cat >&2 <<EOF

Usage:  `basename $0` <mdsdev> <newfsname>

	<mdsdev>		the MDS disk device (e.g. /dev/sda1)
	<newfsname>		the name of the new filesystem (e.g. testfs)

	This script will extract old config logs from an MDS device to a
	temporary location ($TMP). During the upgrade procedure, mount the
	MGS disk as type ldiskfs (e.g. mount -t ldiskfs /dev/sda
	/mnt/temp), then copy these logs into the CONFIGS directory on the
	MGS (e.g. /mnt/temp/CONFIGS).  Logs from many MDS's can be added
	in this way.  When done, unmount the MGS, and then re-mount it as
	type lustre to start the service.

EOF
	exit 1
}

if [ $# -lt 2 ]; then
        usage
fi

DEV=$1
FSNAME=$2
DEBUGFS="debugfs -c -R"
mkdir -p $TMP

FILES=`$DEBUGFS "ls -l LOGS" $DEV | awk '{print $9}' | awk '/[a-z]/ {print $1}'`

for FILE in ${FILES}; do 
    $DEBUGFS "dump LOGS/$FILE $TMP/temp" $DEV 2> /dev/null
    MDC=`strings $TMP/temp | grep MDC`
    LOV=`strings $TMP/temp | grep lov`
    if [ -n "$MDC" ]; then
	TYPE=client
    else
	if [ -n "$LOV" ]; then
	    TYPE=MDT0000
	else
	    echo "Can't determine type for log '$FILE', skipping"
	    continue 
	fi
    fi
    echo -n "Copying log '$FILE' to '${FSNAME}-${TYPE}'. Okay [y/n]?"
    read OK
    if [ "$OK" = "y" ]; then
	mv $TMP/temp $TMP/${FSNAME}-${TYPE}
    else
	rm $TMP/temp
    fi
done

echo ls -l $TMP
ls -l $TMP

