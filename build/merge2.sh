#!/bin/bash -e 

if [ ! -f .mergeinfo ] ; then
    echo ".mergeinfo doesn't exist - exit"
    exit 
fi

. .mergeinfo

if [ "$OPERATION" != "Merge" ] ; then
    echo "OPERATION must be Merge - is $OPERATION"
    echo "You should probably be running ${OPERATION}2.sh"
    exit
fi

if [ -f $CONFLICTS ] ; then
    echo "$CONFLICTS exists - clean up first"
    cat $CONFLICTS
    exit 
fi

cvs update $dir 2>&1 | grep "^M" && echo "uncommitted changes" && exit 1

echo -n "Tagging ${PARENT}_${CHILD}_UPDATE_PARENT_$date as ${CHILD}_BASE_$date ..."
cvs rtag -r ${PARENT}_${CHILD}_UPDATE_PARENT_$date ${CHILD}_BASE_$date $module
echo  "done"
echo -n "Tagging ${CHILD}_BASE as ${CHILD}_BASE_PREV ...."
cvs rtag -F -r ${CHILD}_BASE ${CHILD}_BASE_PREV $module
echo  "done"
echo "${CHILD}_BASE_$date as ${CHILD}_BASE ..."
cvs rtag -F -r ${CHILD}_BASE_$date ${CHILD}_BASE $module

echo "saving .mergeinfo as .mergeinfo-$date"
mv .mergeinfo .mergeinfo-$date
echo  "done"
