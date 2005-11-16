#!/bin/bash

# liblustre sanity test. specially written for UML for now

LCONF=${LCONF:-../utils/lconf}

LLIP=127.0.0.1

LTREE_KERNEL=${LTREE_KERNEL:-../../lustre}
LTREE_USER=${LTREE_USER:-../../lustre-lib}
HOSTNAME=`hostname`

# checking
if [ ! -e $LTREE_KERNEL ]; then
	echo "$LTREE_KERNEL dosen't exits"
	exit 1
fi

if [ ! -e $LTREE_USER ]; then
	echo "$LTREE_USER dosen't exits"
	exit 1
fi

if [ ! -e $LTREE_USER/liblustre/lltest ]; then
	echo "$LTREE_USER/liblustre/lltest dosen't exits"
	exit 1
fi

workdir=`pwd`

cleanup()
{
	curdir=`pwd`
	cd $LTREE_KERNEL/tests
	$LCONF --node $HOSTNAME --cleanup --force $LTREE_USER/tests/$configfile 2>&1 > /dev/null
	cd $curdir
}

configfile=liblustre_sanity_uml.xml

# generate config file
rm -f $configfile
MDSNODE=$HOSTNAME OSTNODES=$HOSTNAME CLIENTS=$LLIP sh uml.sh $configfile
if [ ! -e $configfile ]; then
	echo "fail to generate config file $configfile"
	exit 1
fi

# generate dump file
rm -f /tmp/DUMP_FILE
$LCONF --lctl_dump /tmp/DUMP_FILE --node $LLIP $configfile
if [ ! -e /tmp/DUMP_FILE ]; then
	echo "error creating dumpfile"
	exit 1
fi

#setup lustre server
cd $LTREE_KERNEL/tests
$LCONF --node $HOSTNAME --reformat $LTREE_USER/tests/$configfile
rc=$?
if [ $rc -ne 0 ]; then
	echo "setup lustre server: error $rc"
	cleanup
	exit 1
fi
cd $workdir

#do liblustre testing
$LTREE_USER/liblustre/lltest
rc=$?
if [ $rc -ne 0 ]; then
	echo "liblustre test error $rc"
	cleanup
	exit 1
fi

echo "===== liblustre sanity test complete sucessfully ====="

echo -n "===== cleanup... "; cleanup; echo "done ====="

cd $workdir

exit 0
