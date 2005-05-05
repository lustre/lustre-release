#!/bin/sh

SIMPLE=${SIMPLE:-0}

if [ $SIMPLE -eq 0 ]; then
	PING=pingcli.o
else
	PING=spingcli.o
fi

case "$1" in
	tcp)
		/sbin/insmod  ../oslib/portals.o
		/sbin/insmod ../socknal/ksocknal.o
		/sbin/insmod ./$PING 
		echo ksocknal > /tmp/nal
	;;
	
	elan)
		/sbin/insmod  ../oslib/portals.o
		/sbin/insmod ../qswnal/kqswnal.o
		/sbin/insmod ./$PING
		echo kqswnal > /tmp/nal
	;;

	gm)
		/sbin/insmod  portals
		/sbin/insmod kgmnal
		/sbin/insmod ./$PING
		echo kgmnal > /tmp/nal
	;;
	
	*)
		echo "Usage : ${0} < tcp | elan | gm>"
		exit 1;
esac
exit 0;
