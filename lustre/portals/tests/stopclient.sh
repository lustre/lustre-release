#!/bin/sh

SIMPLE=${SIMPLE:-1}

if [ $SIMPLE -eq 0 ]; then
	PING=spingcli
else
	PING=pingcli
fi

rmmod $PING
NAL=`cat /tmp/nal`;
rmmod $NAL
rmmod portals
