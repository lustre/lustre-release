#!/bin/sh -e 

CONFLICTS=cvs-merge-conflicts
CVS=cvs

if [ -f .mergeinfo ] ; then
    echo ".mergeinfo exists - clean up first"
    exit 
fi

if [ -f $CONFLICTS ] ; then
    echo "$CONFLICTS exists - clean up first"
    exit 
fi

if [ $# -lt 2 -o $# -gt 3 ]; then
    echo "This is phase 1 of merging branches. Usage: $0 parent child [dir]"
    exit
fi

parent=$1
PARENT=`echo $parent | sed -e "s/^b_//" | tr "[a-z]" "[A-Z]"`
child=$2
CHILD=`echo $child | sed -e "s/^b_//" | tr "[a-z]" "[A-Z]"`
date=`date +%Y%m%d_%H%M`
module=lustre

case $parent in
  HEAD) : ;;
  b_*|b1*) : ;;
  *) parent="b_$parent" ;;
esac
case $child in
  HEAD) : ;;
  b_*|b1*) : ;;
  *) child="b_$child"
esac

if [ "$parent" != "HEAD" -a "`cat CVS/Tag`" != "T$parent" ]; then
        echo "This script must be run within the $parent branch"
	exit 1
fi

dir=$3

cat << EOF > .mergeinfo
parent=$parent
PARENT=$PARENT
child=$child
CHILD=$CHILD
date=$date
module=$module
dir=$dir
CONFLICTS=$CONFLICTS
EOF

echo PARENT $PARENT parent $parent CHILD $CHILD child $child date $date

# Update your tree to the PARENT branch; HEAD is not really a branch, so you
# need to update -A instead of update -r HEAD, or the commit will fail. -p
echo -n "Updating to $parent ...."
if [ $parent == "HEAD" ]; then
  $CVS update -AdP $dir
else
  $CVS update -r $parent -dP $dir
fi
echo "done"

echo -n "Tagging as ${PARENT}_${CHILD}_LAND_PARENT_$date ..."
$CVS tag ${PARENT}_${CHILD}_LAND_PARENT_$date $dir
echo "done"

echo -n "Create land point on ${child} ${PARENT}_${CHILD}_LAND_CHILD_$date ..."
$CVS rtag -r ${child} ${PARENT}_${CHILD}_LAND_CHILD_$date $module $dir
echo "done"

echo -n "Preserve old base tag ${CHILD}_BASE as ${CHILD}_BASE_PREV ..."
$CVS tag -F -r ${CHILD}_BASE ${CHILD}_BASE_PREV $dir
echo "done"

# Apply all of the changes to your local tree:
echo -n "Updating as -j ${CHILD}_BASE -j ${PARENT}_${CHILD}_LAND_CHILD_$date ..."
$CVS update -j ${CHILD}_BASE -j ${PARENT}_${CHILD}_LAND_CHILD_$date $dir
echo "done"

echo -n "Recording conflicts in $CONFLICTS ..."
if $CVS update | grep '^C' > $CONFLICTS; then
    echo "Conflicts found, fix before committing."
    cat $CONFLICTS
else 
    echo "No conflicts found"
    rm -f $CONFLICTS
fi
echo "done"

echo "Test, commit and then run land2.sh (no arguments)"
