SRCDIR="`dirname $0`/"
. $SRCDIR/common.sh

# Setup the portals and lustre RPC bits.  For now
# that means we need to set 4 additional variables
# here for ptlctl to use during its config.  There
# should be some XML aware solution soon.  Also
# the code to load only the nessisary modules 
# should go in to obdctl.

NETWORK=tcp
LOCALHOST=localhost
SERVER=localhost
PORT=2432

setup_portals || exit $?
setup_lustre || exit $?

# Loopback devices are still only supported in the
# scripts so we're borrowing that functionality.
new_fs ext3 /tmp/mds 25000
new_fs ext3 /tmp/ost 10000

# Configure the node based on the XML provided.
$OBDCTL --xml $1 || exit $?

export DEBUG_WAIT=no

# The mountpoint information in the XML is currently
# neglected so this needs to be done here.

echo
echo "To mount the filesystem:"
echo "mount -t lustre_lite -o ost=`$OBDCTL name2dev osc-srv`,mds=`$OBDCTL name2dev mdc-srv` none /mnt/lustre"

