#!/bin/sh
# suggested boilerplate for test script

export PATH=`dirname $0`/../utils:$PATH

LCONF=${LCONF:-lconf}
NAME=${NAME:-local}
LLMOUNT=${LLMOUNT:-llmount}
SECURITY=${SECURITY:-"null"}

config=$NAME.xml
mkconfig=$NAME.sh

. krb5_env.sh
start_krb5_kdc || exit 1

if [ "$PORTALS" ]; then
    portals_opt="--portals=$PORTALS"
fi

if [ "$LUSTRE" ]; then
    lustre_opt="--lustre=$LUSTRE"
fi

if [ "$LDAPURL" ]; then
    conf_opt="--ldapurl $LDAPURL --config $NAME"
else
    sh $mkconfig $config || exit 2
    conf_opt="$config"
fi    

[ "$NODE" ] && node_opt="--node $NODE"

# We'd better start lsvcgssd after gss modules loaded.
# remove this if we don't depend on lsvcgssd in the future
${LCONF} --nosetup --sec $SECURITY $portals_opt $node_opt $@ $conf_opt || exit 3
start_lsvcgssd || exit 4
start_lgssd || exit 5

${LCONF} $NOMOD --sec $SECURITY $portals_opt $lustre_opt $node_opt \
         ${REFORMAT:---reformat} $@ $conf_opt  || exit 6

if [ "$MOUNT2" ]; then
       $LLMOUNT -v -o sec=$SECURITY `hostname`:/mds1/client $MOUNT2 || exit 7
fi

