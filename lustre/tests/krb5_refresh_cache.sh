#!/bin/sh

KRB5DIR=${KRB5DIR:-"/usr/kerberos"}

$KRB5DIR/bin/klist -5 -s
invalid=$?

if [ $invalid -eq 0 ]; then
    exit 0
fi

#
# check installed service keytab for root
#
if [ $UID -eq 0 ]; then
    output=`$KRB5DIR/bin/klist -5 -k`
    if [ $? == 0 ]; then
        item=`echo $output | egrep "lustre_mds/.*@"`
        if [ "x$item" != "x" ]; then
            echo "Using service keytab"
            exit 0
        fi
    fi
fi

echo "***** refresh Kerberos V5 TGT for uid $UID *****"
$KRB5DIR/bin/kinit
ret=$?
exit $ret
