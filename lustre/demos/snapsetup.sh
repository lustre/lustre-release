#! /bin/bash
# Utility script to create an OBD snapshot.  If an existing filesystem is
# not already mounted on /mnt/obd, we call the basic OBD setup script to
# create and mount a filesystem for us.
#
# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

OBDDIR="`dirname $0`/.."
. $OBDDIR/demos/config.sh


# prepare the snapshot drive with a file to be COW'd
if [ ! -d /mnt/obd/lost+found ]; then 
    $OBDDIR/demos/obdfssetup.sh
    if [ x$? != x0 ]; then 
	echo "Error running obdfssetup.sh"
	exit 4
   fi
fi

if [ ! -f $MNTOBD/hello ]; then
	$OBDDIR/demos/obdtest.sh
	if [ x$? != x0 ]; then 
	    echo "Error in obdfssetup.sh"
	exit 4
    fi
fi

plog umount $MNTOBD

#plog insmod $OBDDIR/snap/obdsnap.o

rm -f $SNAPTABLE

plog log "NEW SNAP SETUP"
# Create two snapshots using the OBD snapshot driver.  One will be the
# "current" snapshot (in obd device 1), where changes will take place.
# The current snapshot is required in order to use the filesystem.  The
# second will be a snapshot of the filesystem taken "now" (in obd device 2)
# that will remain static (historical read-only) filesystem as changes
# are made to the current snapshot.
$OBDDIR/utils/obdcontrol -f << EOF
snaptable
$SNAPTABLE
a
1
current
a
2
now
q
y
snapset 0 $SNAPTABLE
device /dev/obd1
attach obdsnap 0 1 0
setup
device /dev/obd2
attach obdsnap 0 2 0
setup
quit
EOF

# Mount the two filesystems.  The filesystem under $MNTOBD will be the
# one where changes are made, while $MNTSNAP will contain the original
# files at the point when the snapshot was taken.

[ ! -d "$MNTOBD" ] &&  mkdir $MNTOBD
[ ! -d "$MNTSNAP" ] &&  mkdir $MNTSNAP
plog mount -t obdfs -odevice=/dev/obd1 none $MNTOBD
plog mount -t obdfs -oro,device=/dev/obd2 none $MNTSNAP
