#!/bin/sh -e 

CVS=cvs

if [ -f .mergeinfo ] ; then
    echo ".mergeinfo exists - clean up first"
    exit 
fi

if [ -f merge-conflicts ] ; then
    echo "cvs-merge-conflicts exists - clean up first"
    exit 
fi

if [ $# != 2 ]; then
    echo "This is phase 1 of merging branches. Usage: $0 parent child"
    exit
fi

parent=$1
PARENT=`echo $parent | tr '[a-z]' '[A-Z]'`
child=$2
CHILD=`echo $child | tr '[a-z]' '[A-Z]'`
date=`date +%Y%m%d_%H%M`
module=lustre

if [ $parent != "HEAD" ]; then
  parent="b_$parent"
fi
if [ $child != "HEAD" ]; then
  child="b_$child"
fi

cat << EOF > .mergeinfo
parent=$parent
PARENT=$PARENT
child=$child
CHILD=$CHILD
date=$date
module=$module
EOF

echo PARENT $PARENT parent $parent CHILD $CHILD child $child date $date

echo -n "tagging $parent as ${PARENT}_${CHILD}_UPDATE_PARENT_$date ...."
$CVS rtag -r $parent ${PARENT}_${CHILD}_UPDATE_PARENT_$date $module
echo "done"
echo -n "tagging $child as ${PARENT}_${CHILD}_UPDATE_CHILD_$date ...."
$CVS rtag -r $child ${PARENT}_${CHILD}_UPDATE_CHILD_$date $module
echo "done"
echo "Updating: -j ${CHILD}_BASE -j ${PARENT}_${CHILD}_UPDATE_PARENT_$date ...."
$CVS update -j ${CHILD}_BASE -j ${PARENT}_${CHILD}_UPDATE_PARENT_$date -dP
echo "done"
echo -n "Recording conflicts in cvs-merge-conflicts ..."
if $CVS update | grep '^C' > cvs-merge-conflicts; then
    echo "Conflicts found, fix before committing."
    cat cvs-merge-conflicts
else 
    echo "No conflicts found"
fi
echo "Test, commit and then run merge2.sh (no arguments)"
