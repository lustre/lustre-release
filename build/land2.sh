#!/bin/sh -e 

CVS=cvs

if [ ! -f .mergeinfo ] ; then
    echo ".mergeinfo doesn't exist - exit"
    exit 
fi

. .mergeinfo

if [ -f "$CONFLICTS" ] ; then
    echo "$CONFLICTS exists - clean up first"
    cat $CONFLICTS
    exit 
fi

#cvs update $dir 2>&1 | grep "^M" && echo "uncommitted changes" && exit 1

echo -n "Tagging as ${CHILD}_BASE_$date ..."
$CVS tag -F ${CHILD}_BASE_$date $dir
echo "done"
echo -n "Tagging as ${CHILD}_BASE ..."
$CVS tag -F ${CHILD}_BASE $dir

echo "saving .mergeinfo as .mergeinfo-$date"
mv .mergeinfo .mergeinfo-$date
echo "done"
