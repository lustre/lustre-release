#!/bin/sh

KRB5DIR=${KRB5DIR:-"/usr/kerberos"}

$KRB5DIR/bin/klist -5 -s
invalid=$?

if [ $invalid -eq 0 ]; then
    exit 0
fi

echo "***** refresh Kerberos V5 TGT for uid $UID *****"
$KRB5DIR/bin/kinit
ret=$?
exit $ret
