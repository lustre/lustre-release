#!/bin/sh

echo -n `date` >> /tmp/halog
echo "- please supply a new mds" >> /tmp/halog

echo "- suppose we have a new one" >> /tmp/halog
sleep 1

/usr/src/obd/utils/obdctl  <<EOF
name2dev RPCDEV
newconn
EOF

