#!/bin/sh

SIMPLE=${SIMPLE:-0}

if [ $SIMPLE -eq 0 ]; then
	PING=pingsrv.o
else
	PING=spingsrv.o
fi

case "$1" in
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

	gm)
		/sbin/insmod  portals
		/sbin/insmod kgmnal
		/sbin/insmod ./$PING nal=3
		echo kgmnal > /tmp/nal
	;;
	
	*)
		echo "Usage : ${0} < tcp | elan | gm>"
		exit 1;
esac
../utils/acceptor 9999&
exit 0;
