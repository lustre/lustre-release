#! /bin/bash
# Utility script to create an OBD snapshot.  If an existing filesystem is
# not already mounted on /mnt/obd, we call the basic OBD setup script to
# create and mount a filesystem for us.
OBDDIR="`dirname $0`/.."
[ "$OBDDIR" = "" ] && OBDDIR=".."
. $OBDDIR/demos/config.sh

[ ! -d $MNTOBD/lost+found ] && $OBDDIR/demos/obdfssetup.sh

echo "yesterday" > $MNTOBD/hello	# create a file
echo "testing" > $MNTOBD/goodbye	# create a file
ln -s hello $MNTOBD/link		# create a symbolic link
cd $MNTOBD ; touch a b c ; cd -		# create a file
