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

[ ! -d $MNTOBD/lost+found ] && $OBDDIR/demos/obdfssetup.sh

echo "echo yesterday >> $MNTOBD/hello"	# create a file
echo "yesterday" > $MNTOBD/hello
echo "echo testing > $MNTOBD/goodbye"	# create a file
echo "testing" > $MNTOBD/goodbye
plog ln -s hello $MNTOBD/link		# create a symbolic link
cd $MNTOBD ; plog touch a b c ; cd -		# create a file
