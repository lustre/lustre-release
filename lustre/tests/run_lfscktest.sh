#!/bin/sh

set -e

. ./lfscktest_config.sh

#create xml file for config
${CONFIG} ${CONFIGXML} || exit 1

#Mount lustre
${LCONF} --reformat ${CONFIGXML} || exit 1

export LUSTRE_BUILD=${LUSTRE_BUILD:-`$LCTL lustre_build_version | awk '/^lctl/ {print $3}'`}
rm -f ${LOG}
#Run test 
sh -vx lfscktest.sh 2>&1 | tee $LOG
RESULT=$?
[ ${RESULT} -eq 0 ] && echo PASS || echo FAIL

#Umount Lustre 
$LCONF --cleanup $CONFIGXML
exit $RESULT
