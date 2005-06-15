#!/bin/sh
# suggested boilerplate for test script

export PATH=`dirname $0`/../utils:$PATH

LCONF=${LCONF:-lconf}
NAME=${NAME:-local}
LLMOUNT=${LLMOUNT:-llmount}
SECURITY=${SECURITY:-"null"}

config=$(dirname $0)/$NAME.xml
mkconfig=$(dirname $0)/$NAME.sh

. krb5_env.sh
start_krb5_kdc || exit 1
start_lsvcgssd || exit 2
start_lgssd || exit 3

if [ "$PORTALS" ]; then
    portals_opt="--portals=$PORTALS"
fi

if [ "$LUSTRE" ]; then
    lustre_opt="--lustre=$LUSTRE"
fi

if [ "$LDAPURL" ]; then
    conf_opt="--ldapurl $LDAPURL --config $NAME"
else
    sh $mkconfig $config || exit 4
    conf_opt="$config"
fi    

[ "$NODE" ] && node_opt="--node $NODE"
[ "$DEBUG" ] && debug_opt="--ptldebug=$DEBUG"

${LCONF} $NOMOD --mds_sec $SECURITY $portals_opt $lustre_opt $node_opt \
         ${REFORMAT:---reformat} $@ $conf_opt  || exit 5

if [ "$MOUNT2" ]; then
       $LLMOUNT -v -o mds_sec=$SECURITY `hostname`:/mds1/client $MOUNT2 || exit 6
fi

