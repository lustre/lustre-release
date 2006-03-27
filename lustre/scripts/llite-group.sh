#!/bin/sh
#
# llite-group.sh : Cluster Manager service script for Lustre
#
# This must be named llite-<group>.sh, where group is the device 
# group that is being managed by the cluster manager service.
#

set -e
set -vx

[ -f ${LUSTRE_CFG:=/etc/lustre/lustre.cfg} ] && . ${LUSTRE_CFG}

LDAPURL=${LDAPURL:-ldap://localhost}
CONFIG=${CONFIG:-test23}

LACTIVE=${LACTIVE:-/usr/sbin/lactive}
LCONF=${LCONF:-/usr/sbin/lconf}

group=`basename $0 .sh| cut -d- -f2`
confopt="--ldapurl $LDAPURL --config $CONFIG"

[ -z "$group" ] && exit 0

node=`hostname -s`

[ -d ${STATUS_DIR:=/var/lustre} ] || mkdir -p $STATUS_DIR

start() {
        echo -n "Starting $SERVICE: "
	python2 $LACTIVE $confopt --group $group --active $node
        python2 $LCONF -v $confopt
        RETVAL=$?
	echo done
}

stop() {
        echo -n "Shutting down $SERVICE: "
        python2 $LCONF -v --cleanup --force --failover $confopt
        RETVAL=$?
        echo done
}

status() {
        RETVAL=0
}


case "$1" in
  start)
	start
	;;
  stop)
	stop
	;;
  restart)
	restart
	;;
  status)
	status $SERVICE
	;;
  *)
	echo "Usage: $0 {start|stop|status}"
	exit 1
esac

exit $RETVAL
