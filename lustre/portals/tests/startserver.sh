#!/bin/sh

SIMPLE=${SIMPLE:-0}

if [ $SIMPLE -eq 0 ]; then
	PING=pingsrv.o
else
	PING=spingsrv.o
fi

case "$1" in
	toe)
		/sbin/insmod  ../oslib/portals.o
		/sbin/insmod ../toenal/ktoenal.o
		/sbin/insmod ./$PING nal=4
		echo ktoenal > /tmp/nal
	;;
	
	tcp)
		/sbin/insmod  ../oslib/portals.o
		/sbin/insmod ../socknal/ksocknal.o
		/sbin/insmod ./$PING nal=2
		echo ksocknal > /tmp/nal
	;;
	
	elan)
		/sbin/insmod  ../oslib/portals.o
		/sbin/insmod ../qswnal/kqswnal.o
		/sbin/insmod ./$PING nal=4
		echo kqswnal > /tmp/nal
	;;
	
	*)
		echo "Usage : ${0} < tcp | toe | elan >"
		exit 1;
esac
../utils/acceptor 9999&
exit 0;
