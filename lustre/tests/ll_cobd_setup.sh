#!/bin/sh
#Assumption run in UML

export PATH=`dirname $0`/../utils:$PATH

LCONF=${LCONF:-lconf}
NAME=${NAME:-uml_cobd}
NODE=${NODE:-`hostname`}
SETUP=${SETUP:-"cmobd_cobd_setup"}

config=$NAME.xml
mkconfig=$NAME.sh

sh $mkconfig $config || exit 1

echo "make cmobd xml"
${LCONF} --node $NODE --reformat $config

echo "setup test script"
sh ${SETUP}.sh
 
