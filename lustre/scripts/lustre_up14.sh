#!/bin/bash
#
# Reads old MDS config logs for transferring to a MGS
#
###############################################################################

TMP=/tmp/logs

# Usage
usage() {
	cat >&2 <<EOF

Usage:  `basename $0` <mdsdev> <newfsname>

	<mdsdev>		the MDS disk device (e.g. /dev/sda1)
	<newfsname>		the name of the new filesystem (e.g. testfs)

	This program will copy old config logs from an MDS device to 
	a temporary location ($TMP), from where they can be added to 
	the CONFIGS directory on an MGS during the upgrade procedure.

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
    CLI=`strings $TMP/temp | grep MDC`
    if [ -n "$CLI" ]; then
	TYPE=client
    else
	TYPE=MDT0000
    fi
    echo -n "Copying log $FILE to ${FSNAME}-${TYPE}. Okay [y/n]?"
    read OK
    if [ "$OK" = "y" ]; then
	mv $TMP/temp $TMP/${FSNAME}-${TYPE}
    else
	rm $TMP/temp
    fi
done

echo ls -l $TMP
ls -l $TMP

