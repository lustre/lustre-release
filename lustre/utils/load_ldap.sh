#!/bin/bash
#
# Load a lustre config xml into an openldap database.
# See https://projects.clusterfs.com/lustre/LustreLDAP
# for more details.
#
# Usage: load_ldap.sh <xml_file>
set -e

LDAP_BASE=${LDAP_BASE:-fs=lustre}
LDAP_ROOTDN=${LDAP_ROOTDN:-cn=Manager,fs=lustre}
LDAP_PW=${LDAP_PW:-secret}
LDAP_AUTH="-x -D $LDAP_ROOTDN -w $LDAP_PW"
LUSTRE=${LUSTRE:-`dirname $0`/..}

[ ! -z $LDAPURL ] && LDAP_AUTH="$LDAP_AUTH -H $LDAPURL"

XML=${XML:-$1}

if [ -z "$XML" ] || [  ! -r $XML ]; then
     echo "usage: $0 xmlfile"
     exit 1
fi

NAME=`basename $XML .xml`
LDIF=/tmp/$NAME.ldif

# add the top level record, if needed
ldapsearch $LDAP_AUTH -b $LDAP_BASE > /dev/null 2>&1 ||
    ldapadd $LDAP_AUTH -f $LUSTRE/conf/top.ldif

# If this config already exists, then delete it
ldapsearch $LDAP_AUTH -b config=$NAME,$LDAP_BASE > /dev/null 2>&1 && 
    ldapdelete $LDAP_AUTH -r config=$NAME,$LDAP_BASE

4xslt --define config=$NAME $XML $LUSTRE/conf/lustre2ldif.xsl  > $LDIF

echo "Loading config to 'config=$NAME,$LDAP_BASE' ..."
ldapadd $LDAP_AUTH -f $LDIF

rm -f $LDIF
