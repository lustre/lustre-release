#!/bin/sh -e 

CVS=cvs

if [ ! -f .mergeinfo ] ; then
    echo ".mergeinfo doesn't exist - exit"
    exit 
fi

. .mergeinfo

if [ "$OPERATION" -ne "Replace" ] ; then
    echo "OPERATION must be Replace - is $OPERATION"
    echo "You should probably be running ${OPERATION}2.sh"
    exit
fi

if [ -f "$CONFLICTS" ] ; then
    echo "$CONFLICTS exists - clean up first"
    cat $CONFLICTS
    exit 
fi

cvs update $dir 2>&1 | grep "^M" && echo "uncommitted changes" && exit 1

# Tag parent
echo -n "Tagging as ${CHILD}_REPLACED_${PARENT}_$date ..."
$CVS tag -F ${CHILD}_REPLACED_${PARENT}_$date $dir
echo "done"
# In case someone tries to re-land later
echo -n "Tagging as ${CHILD}_BASE ..."
$CVS tag -F ${CHILD}_BASE $dir

echo "saving .mergeinfo as .mergeinfo-$date"
mv .mergeinfo .mergeinfo-$date
echo "done"
