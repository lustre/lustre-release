#!/bin/sh -e 

CVS=cvs

if [ ! -f .mergeinfo ] ; then
    echo ".mergeinfo doesn't exist - exit"
    exit 
fi

. .mergeinfo

if [ "$OPERATION" != "Land" ] ; then
    echo "OPERATION must be Land - is $OPERATION"
    echo "You should probably be running ${OPERATION}2.sh"
    exit
fi

if [ -f "$CONFLICTS" ] ; then
    echo "$CONFLICTS exists - clean up first"
    cat $CONFLICTS
    exit 
fi

cvs update $dir 2>&1 | grep "^M" && echo "uncommitted changes" && exit 1

echo -n "Tagging as ${CHILD}_BASE_$date ..."
$CVS rtag -r $parent ${CHILD}_BASE_$date $module
echo "done"
echo -n "Tagging as ${CHILD}_BASE ..."
$CVS rtag -F -r $parent ${CHILD}_BASE $module

echo "saving .mergeinfo as .mergeinfo-$date"
mv .mergeinfo .mergeinfo-$date
echo "done"
