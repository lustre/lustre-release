#!/bin/sh
#Assumption run in UML

export PATH=`dirname $0`/../utils:$PATH

LCONF=${LCONF:-lconf}
NAME=${NAME:-uml_cobd}
NODE=${NODE:-`hostname`}
CLEAN=${CLEAN:-"cmobd_cobd_cleanup"}
config=$NAME.xml

echo "setup test script"
sh ${CLEAN}.sh

echo "cleanup cmobd xml"
${LCONF} --node $NODE --cleanup $config

