#!/bin/sh
# vim:expandtab:shiftwidth=4:softtabstop=4:tabstop=4:

export PATH=`dirname $0`/../utils:$PATH

LCONF=${LCONF:-lconf}
NAME=${NAME:-local}
LLMOUNT=${LLMOUNT:-llmount}

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
    if [ ! -f $config -o $mkconfig -nt $config ]; then
	sh $mkconfig $config || exit 1
    fi
    conf_opt="$config"
fi    

[ "$NODE" ] && node_opt="--node $NODE"
[ "$DEBUG" ] && portals_opt="$portals_opt --ptldebug=$DEBUG"
[ "$PTLDEBUG" ] && portals_opt="$portals_opt --ptldebug=$PTLDEBUG"

${LCONF} $NOMOD $portals_opt $lustre_opt $node_opt $@ $conf_opt || {
    # maybe acceptor error, dump tcp port usage
    netstat -tpn
    exit 2
}


if [ "$MOUNT2" ]; then
	$LLMOUNT -v -o user_xattr,acl `hostname`:/mds1/client $MOUNT2 || exit 3
fi
