#!/bin/sh

export PATH=`dirname $0`/../utils:$PATH

LCONF=${LCONF:-lconf}
NAME=${NAME:-local}
TMP=${TMP:-/tmp}

config=$NAME.xml
mkconfig=$NAME.sh

if [ "$PORTALS" ]; then
  portals_opt="--portals=$PORTALS"
fi

if [ "$LUSTRE" ]; then
  lustre_opt="--lustre=$LUSTRE"
fi

if [ "$LDAPURL" ]; then
    conf_opt="--ldapurl $LDAPURL --config $NAME"
else
    if [ ! -f $config ]; then
	sh $mkconfig $config || exit 1
    fi
    conf_opt="$config"
fi    

[ "$NODE" ] && node_opt="--node $NODE"

[ "$MOUNT2" ] && umount $MOUNT2

#${LCONF} $NOMOD $portals_opt $lustre_opt $node_opt --cleanup $@ \
    --dump $TMP/debug $conf_opt

echo FIXME this must be umount of some sort
exit 1

rc=$?
echo "lconf DONE"
BUSY=`dmesg | grep -i destruct`
if [ "$BUSY" ]; then
	echo "$BUSY" 1>&2
	mv $TMP/debug $TMP/debug-busy.`date +%s`
	exit 255
fi
LEAK_LUSTRE=`dmesg | tail -n 30 | grep "obd mem.*leaked"`
LEAK_PORTALS=`dmesg | tail -n 20 | grep "Portals memory leaked"`
if [ "$LEAK_LUSTRE" -o "$LEAK_PORTALS" ]; then
	echo "$LEAK_LUSTRE" 1>&2
	echo "$LEAK_PORTALS" 1>&2
	mv $TMP/debug $TMP/debug-leak.`date +%s`
	echo "Memory leaks detected"
	exit 254
fi
lsmod | grep lnet && echo "modules still loaded" && exit 1

exit $rc
