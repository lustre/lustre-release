#!/bin/sh

SIMPLE=${SIMPLE:-1}

if [ $SIMPLE -eq 0 ]; then
	PING=spingsrv
else
	PING=pingsrv
fi

rmmod $PING
NAL=`cat /tmp/nal`;
rmmod $NAL
killall -9 acceptor
rm -f /var/run/acceptor-9999.pid
rmmod portals
