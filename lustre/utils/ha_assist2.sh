#!/bin/bash 
set -vx
date
echo "ha assist checking for problems"
sleep 3
if [ ! -e /tmp/halog ]; then
   echo "no problems, exiting"
    exit 
fi

echo "removing /tmp/halog"
rm /tmp/halog

echo secondary start `date`
echo "- please supply a new mds"

# invoke ldap client here


/usr/src/portals/linux/utils/ptlctl <<EOF3
setup tcp
close_uuid mds
del_uuid mds
connect dev5 988
add_uuid mds
quit
EOF3

echo "connected to new MDS!"

/usr/src/obd/utils/obdctl  <<EOF2
name2dev RPCDEV
newconn
quit
EOF2
